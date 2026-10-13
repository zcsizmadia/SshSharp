using System.Globalization;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    private const int MaxProxyDepth = 8;

    /// <summary>
    /// Connects like <c>ssh destination</c> does: <paramref name="destination"/> (<c>[user@]host</c>, an alias, or
    /// <c>ssh://[user@]host[:port]</c>) is resolved with <c>ssh_config</c>, and the connection follows it: HostName, Port, User,
    /// IdentityFile keys, known_hosts with StrictHostKeyChecking, Ciphers/KexAlgorithms/HostKeyAlgorithms/MACs, ProxyJump chains,
    /// ProxyCommand, ServerAliveInterval/ServerAliveCountMax, ConnectTimeout and AddressFamily.
    /// </summary>
    /// <exception cref="SshHostKeyException">The host key is not trusted under the configured policy.</exception>
    /// <exception cref="SshAuthenticationException">No configured key or password was accepted.</exception>
    public static async Task<SshClient> ConnectAsync(string destination, SshConfigConnectOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        options ??= new SshConfigConnectOptions();
        var config = options.Config ?? SshConfig.LoadDefault(options.ResolveOptions?.HomeDirectory);
        var (user, host, port) = ParseDestination(destination);
        return await ConnectHopAsync(host, user, port, config, options, via: null, depth: 0, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Connects to one host of a chain. With <paramref name="via"/>, the connection is tunnelled through that client (the hop's own
    /// proxy settings are ignored, as an explicit ProxyJump chain overrides them); otherwise the host's ProxyJump, ProxyCommand or TCP is used.
    /// </summary>
    private static async Task<SshClient> ConnectHopAsync(string host, string? user, int? port, SshConfig config, SshConfigConnectOptions options,
        SshClient? via, int depth, CancellationToken cancellationToken)
    {
        if (depth > MaxProxyDepth)
        {
            throw new SshException(SshFailureReason.ConnectFailed, "ProxyJump/ProxyCommand chains nest too deeply (is there a loop in ssh_config?).");
        }

        var resolveOptions = (options.ResolveOptions ?? new SshConfigResolveOptions()).With(user, port);
        var hostConfig = config.Resolve(host, resolveOptions);
        var logger = options.Logger ?? NullLogger.Instance;

        using var timeout = hostConfig.ConnectTimeout is { } limit ? new CancellationTokenSource(limit) : null;
        using var linked = timeout is null ? null : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var token = linked?.Token ?? cancellationToken;

        // Everything this connection needs released when it ends (or fails to start): keys, then the socket, process or tunnel.
        Owned? owner = new();
        var keys = await LoadIdentitiesAsync(hostConfig, options, logger, token).ConfigureAwait(false);
        owner.Add(keys);
        try
        {
            Stream stream;
            if (via is not null)
            {
                Owned tunnel;
                (stream, tunnel) = await TunnelAsync(via, hostConfig, ownsVia: false, token).ConfigureAwait(false);
                owner.Add(tunnel);
            }
            else if (hostConfig.ProxyJump.Count > 0)
            {
                // Each hop is reached through the one before; the first hop uses its own configuration.
                SshClient? hop = null;
                try
                {
                    foreach (var jump in hostConfig.ProxyJump)
                    {
                        var (jumpUser, jumpHost, jumpPort) = ParseDestination(jump);
                        hop = await ConnectHopAsync(jumpHost, jumpUser, jumpPort, config, options, hop, depth + 1, token).ConfigureAwait(false);
                    }
                }
                catch
                {
                    if (hop is not null)
                    {
                        await hop.DisposeAsync().ConfigureAwait(false);
                    }

                    throw;
                }

                Owned tunnel;
                (stream, tunnel) = await TunnelAsync(hop!, hostConfig, ownsVia: true, token).ConfigureAwait(false);
                owner.Add(tunnel);
            }
            else if (hostConfig.ProxyCommand is { } command)
            {
                if (!options.AllowProxyCommand)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, "The configuration names a ProxyCommand, and AllowProxyCommand is off.");
                }

                var process = ProxyCommandStream.Start(command);
                owner.Add(process);
                stream = process;
            }
            else
            {
                var connector = options.TcpConnector ?? ConnectTcpAsync;
                var (tcpStream, tcpOwner) = await connector(hostConfig.HostName, hostConfig.Port, hostConfig.AddressFamily, token).ConfigureAwait(false);
                if (tcpOwner is not null)
                {
                    owner.Add(tcpOwner);
                }

                stream = tcpStream;
            }

            var clientOptions = new SshClientOptions
            {
                UserName = hostConfig.User,
                Password = hostConfig.PasswordAuthentication ? options.Password : null,
                PrivateKeys = hostConfig.PubkeyAuthentication ? [.. options.PrivateKeys, .. keys] : [],
                HostKeyVerifier = options.HostKeyVerifier ?? KnownHostsVerifier.FromConfig(hostConfig, hostConfig.BatchMode ? null : options.AskHostKey),
                HostKeyAlias = hostConfig.HostKeyAlias,
                KeepAliveInterval = hostConfig.ServerAliveInterval,
                KeepAliveCountMax = hostConfig.ServerAliveCountMax,
                AlgorithmPreferences = AlgorithmPreferences.FromConfig(hostConfig),
                Logger = options.Logger,
                TimeProvider = options.TimeProvider,
            };

            var client = await ConnectCoreAsync(stream, clientOptions, leaveOpen: false, owner, hostConfig.HostName, hostConfig.Port, token).ConfigureAwait(false);
            owner = null; // the client owns it now
            return client;
        }
        catch (OperationCanceledException) when (timeout?.IsCancellationRequested == true && !cancellationToken.IsCancellationRequested)
        {
            throw new SshException(SshFailureReason.Timeout, $"Connecting took longer than ConnectTimeout ({hostConfig.ConnectTimeout!.Value.TotalSeconds.ToString(CultureInfo.InvariantCulture)} s).");
        }
        finally
        {
            if (owner is not null)
            {
                await owner.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Opens a <c>direct-tcpip</c> channel through <paramref name="via"/> to the host's HostName and Port, as a stream.</summary>
    private static async Task<(Stream Stream, Owned Owner)> TunnelAsync(SshClient via, SshHostConfig hostConfig, bool ownsVia, CancellationToken cancellationToken)
    {
        try
        {
            var channel = await via.Connection.OpenDirectTcpIpAsync(hostConfig.HostName, hostConfig.Port, "127.0.0.1", 0, cancellationToken).ConfigureAwait(false);
            var stream = new SshChannelStream(channel);
            var owner = new Owned(stream);
            if (ownsVia)
            {
                owner.Add(via);
            }

            return (stream, owner);
        }
        catch (SshException ex) when (ex is not SshProtocolException)
        {
            if (ownsVia)
            {
                await via.DisposeAsync().ConfigureAwait(false);
            }

            throw new SshException(SshFailureReason.ConnectFailed, "The jump host could not open a connection to the next host: " + ex.Message, ex);
        }
    }

    private static async ValueTask<(Stream Stream, IAsyncDisposable? Owner)> ConnectTcpAsync(string host, int port, SshAddressFamily family, CancellationToken cancellationToken)
    {
        var tcp = family switch
        {
            SshAddressFamily.Inet => new TcpClient(AddressFamily.InterNetwork),
            SshAddressFamily.Inet6 => new TcpClient(AddressFamily.InterNetworkV6),
            _ => new TcpClient(),
        };
        tcp.NoDelay = true;
        try
        {
            await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            return (tcp.GetStream(), new Owned(tcp));
        }
        catch (SocketException ex)
        {
            tcp.Dispose();
            throw new SshException(SshFailureReason.ConnectFailed, $"Could not connect to the server: {ex.SocketErrorCode}.", ex);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>Loads the IdentityFile keys that exist; encrypted ones only when a passphrase is provided. Missing files are skipped, as ssh does.</summary>
    private static async Task<List<SshPrivateKey>> LoadIdentitiesAsync(SshHostConfig hostConfig, SshConfigConnectOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        var keys = new List<SshPrivateKey>();
        var paths = new List<string>();
        if (!hostConfig.PubkeyAuthentication)
        {
            return keys;
        }

        foreach (var path in hostConfig.IdentityFiles)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            var fileName = Path.GetFileName(path); // never the full path: it contains the user name
            var text = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            try
            {
                keys.Add(SshPrivateKey.Parse(text));
                paths.Add(path);
                continue;
            }
            catch (FormatException ex) when (ex.Message.Contains("passphrase is required", StringComparison.Ordinal))
            {
                // Encrypted: ask, unless in batch mode.
            }
            catch (FormatException ex)
            {
                SshLog.IdentitySkipped(logger, fileName, ex.Message);
                continue;
            }

            if (hostConfig.BatchMode || options.PassphraseProvider is null
                || await options.PassphraseProvider(path, cancellationToken).ConfigureAwait(false) is not { } passphrase)
            {
                SshLog.IdentitySkipped(logger, fileName, "encrypted, and no passphrase was provided");
                continue;
            }

            try
            {
                keys.Add(SshPrivateKey.Parse(text, passphrase));
                paths.Add(path);
            }
            catch (FormatException ex)
            {
                SshLog.IdentitySkipped(logger, fileName, ex.Message);
            }
        }

        // Certificates, as ssh finds them: CertificateFile entries and "<identity>-cert.pub" next to each key. A key with a certificate is
        // offered with it first, then on its own.
        var certificates = new List<SshCertificate>();
        foreach (var path in hostConfig.CertificateFiles.Concat(paths.Select(p => p + "-cert.pub")).Distinct(StringComparer.Ordinal))
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                certificates.Add(SshCertificate.Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false)));
            }
            catch (FormatException ex)
            {
                var certificateName = Path.GetFileName(path);
                SshLog.IdentitySkipped(logger, certificateName, ex.Message);
            }
        }

        var certified = new List<SshPrivateKey>();
        foreach (var key in keys)
        {
            certified.AddRange(certificates
                .Where(c => c.Type == SshCertificateType.User && c.PublicKey.Span.SequenceEqual(key.PublicKey.Span))
                .Select(key.WithCertificate));
        }

        return [.. certified, .. keys];
    }

    /// <summary>Parses <c>[user@]host</c>, or <c>ssh://[user@]host[:port]</c> (the only form that carries a port, as with ssh).</summary>
    internal static (string? User, string Host, int? Port) ParseDestination(string destination)
    {
        string? user = null;
        int? port = null;
        var rest = destination.Trim();
        var uri = rest.StartsWith("ssh://", StringComparison.OrdinalIgnoreCase);
        if (uri)
        {
            rest = rest[6..].TrimEnd('/');
        }

        var at = rest.LastIndexOf('@');
        if (at >= 0)
        {
            user = rest[..at];
            rest = rest[(at + 1)..];
        }

        if (uri || rest.StartsWith('['))
        {
            // [ipv6]:port or host:port (ProxyJump entries and URIs carry ports).
            var close = rest.StartsWith('[') ? rest.IndexOf(']', StringComparison.Ordinal) : -1;
            var colon = rest.LastIndexOf(':');
            if (colon > close && (close >= 0 || rest.IndexOf(':', StringComparison.Ordinal) == colon))
            {
                port = int.Parse(rest[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture);
                rest = rest[..colon];
            }

            rest = rest.Trim('[', ']');
        }
        else if (rest.Count(c => c == ':') == 1)
        {
            // ProxyJump's host:port form.
            var colon = rest.IndexOf(':', StringComparison.Ordinal);
            port = int.Parse(rest[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture);
            rest = rest[..colon];
        }

        if (rest.Length == 0 || port is < 1 or > 65535 || user?.Length == 0)
        {
            throw new ArgumentException($"'{destination}' is not a valid destination ([user@]host[:port] or ssh://[user@]host[:port]).", nameof(destination));
        }

        return (user, rest, port);
    }

    /// <summary>Things a client owns and releases when it is disposed (socket, proxy process, jump-host client, loaded keys), last added first.</summary>
    internal sealed class Owned : IAsyncDisposable
    {
        private readonly List<object> _items = [];

        public Owned(object? item = null)
        {
            if (item is not null)
            {
                _items.Add(item);
            }
        }

        public void Add(object item) => _items.Add(item);

        public void Add(IEnumerable<SshPrivateKey> keys) => _items.AddRange(keys);

        public async ValueTask DisposeAsync()
        {
            for (var i = _items.Count - 1; i >= 0; i--)
            {
                switch (_items[i])
                {
                    case IAsyncDisposable asyncDisposable:
                        await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                        break;
                    case IDisposable disposable:
                        disposable.Dispose();
                        break;
                }
            }

            _items.Clear();
        }
    }
}
