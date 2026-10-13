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
        try
        {
            var keys = await LoadIdentitiesAsync(hostConfig, options, logger, token).ConfigureAwait(false);
            owner.Add(keys);

            Stream stream;
            if (via is not null)
            {
                // Each hop owns the one before it, so disposing the destination tears down the whole chain (ProxyJump a,b: the client
                // owns b, and b owns a).
                Owned tunnel;
                (stream, tunnel) = await TunnelAsync(via, hostConfig, ownsVia: true, token).ConfigureAwait(false);
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
                Password = hostConfig.PasswordAuthentication || hostConfig.KbdInteractiveAuthentication ? options.Password : null,
                PrivateKeys = hostConfig.PubkeyAuthentication ? [.. options.PrivateKeys, .. keys] : [],
                KeyboardInteractive = hostConfig.BatchMode ? null : options.KeyboardInteractive,
                AuthenticationBanner = options.AuthenticationBanner,
                AuthenticationOrder = AuthenticationOrder(hostConfig),
                ForwardAgent = hostConfig.ForwardAgent ? ResolveAgent(hostConfig, options) : null,
                HostKeyVerifier = options.HostKeyVerifier ?? KnownHostsVerifier.FromConfig(hostConfig, hostConfig.BatchMode ? null : options.AskHostKey,
                    hostConfig.BatchMode ? null : options.ConfirmHostKeyUpdate),
                HostKeyAlias = hostConfig.HostKeyAlias,
                KeepAliveInterval = hostConfig.ServerAliveInterval,
                KeepAliveCountMax = hostConfig.ServerAliveCountMax,
                AlgorithmPreferences = AlgorithmPreferences.FromConfig(hostConfig),
                Logger = options.Logger,
                TimeProvider = options.TimeProvider,
            };

            var client = await ConnectCoreAsync(stream, clientOptions, leaveOpen: false, owner, hostConfig.HostName, hostConfig.Port, token).ConfigureAwait(false);
            owner = null; // the client owns it now
            if (depth == 0 && options.StartForwardings)
            {
                // Only the destination's forwardings: jump hosts are a way to get there.
                try
                {
                    await client.StartConfiguredForwardingsAsync(hostConfig, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await client.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }

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

    /// <summary>
    /// The keys to offer, in ssh's order: identity files the agent holds (signed by the agent, so an encrypted file needs no passphrase),
    /// the agent's other keys (not with <c>IdentitiesOnly</c>), then the remaining identity files that exist (encrypted ones only when a
    /// passphrase is provided; missing files are skipped, as ssh does). Keys with a certificate come first, paired with it.
    /// </summary>
    private static async Task<List<SshPrivateKey>> LoadIdentitiesAsync(SshHostConfig hostConfig, SshConfigConnectOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        var keys = new List<SshPrivateKey>();
        try
        {
            return await LoadIdentitiesAsync(keys, hostConfig, options, logger, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Cancelled, timed out, or a passphrase provider that threw: the keys loaded so far are wiped, not left to the collector.
            foreach (var key in keys)
            {
                key.Dispose();
            }

            throw;
        }
    }

    private static async Task<List<SshPrivateKey>> LoadIdentitiesAsync(List<SshPrivateKey> keys, SshHostConfig hostConfig, SshConfigConnectOptions options,
        ILogger logger, CancellationToken cancellationToken)
    {
        var paths = new List<string>();
        if (!hostConfig.PubkeyAuthentication)
        {
            return keys;
        }

        var agentKeys = await AgentKeysAsync(hostConfig, options, logger, cancellationToken).ConfigureAwait(false);
        var fromAgent = new List<SshPrivateKey>();
        foreach (var path in hostConfig.IdentityFiles)
        {
            if (agentKeys.Count > 0 && ReadPublicKey(path + ".pub") is { } publicKey
                && agentKeys.FirstOrDefault(k => k.PublicKey.Span.SequenceEqual(publicKey)) is { } held)
            {
                if (!fromAgent.Contains(held))
                {
                    fromAgent.Add(held);
                    paths.Add(path);
                }

                continue;
            }

            if (!File.Exists(path))
            {
                continue;
            }

            var fileName = Path.GetFileName(path); // never the full path: it contains the user name
            string text;
            try
            {
                text = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                SshLog.IdentitySkipped(logger, fileName, "the file cannot be read"); // as ssh: an unreadable identity file is skipped
                continue;
            }

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

        // The agent's keys: those matching an identity file, then (unless IdentitiesOnly) the rest; a key loaded from a file too is offered once.
        IEnumerable<SshPrivateKey> offered = fromAgent;
        if (!hostConfig.IdentitiesOnly)
        {
            offered = offered.Concat(agentKeys.Where(k => !fromAgent.Contains(k)));
        }

        offered = offered.Where(a => !keys.Any(k => k.PublicKey.Span.SequenceEqual(a.PublicKey.Span)));
        List<SshPrivateKey> plain = [.. offered, .. keys];

        var certified = new List<SshPrivateKey>();
        foreach (var key in plain.Where(k => k.Certificate is null))
        {
            certified.AddRange(certificates
                .Where(c => c.Type == SshCertificateType.User && c.PublicKey.Span.SequenceEqual(key.PublicKey.Span))
                .Select(key.WithCertificate));
        }

        return [.. certified, .. plain];
    }

    /// <summary>The agent's keys for this host, or none: no agent configured, <c>IdentityAgent none</c>, or the agent is not running.</summary>
    private static async Task<IReadOnlyList<SshPrivateKey>> AgentKeysAsync(SshHostConfig hostConfig, SshConfigConnectOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        if (ResolveAgent(hostConfig, options) is not { } agent)
        {
            return [];
        }

        try
        {
            return await agent.GetKeysAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.AgentFailed)
        {
            SshLog.AgentUnavailable(logger, ex.Message); // like ssh: no agent is not an error
            return [];
        }
    }

    /// <summary>The agent ssh would use: <see cref="SshConfigConnectOptions.Agent"/>, else <c>IdentityAgent</c> (a path, <c>none</c>, or <c>SSH_AUTH_SOCK</c>), else the environment's.</summary>
    internal static SshAgent? ResolveAgent(SshHostConfig hostConfig, SshConfigConnectOptions options, Func<SshAgent?>? fromEnvironment = null)
    {
        if (!options.UseAgent)
        {
            return null;
        }

        if (options.Agent is { } agent)
        {
            return agent;
        }

        return hostConfig.IdentityAgent switch
        {
            null or "SSH_AUTH_SOCK" => (fromEnvironment ?? SshAgent.FromEnvironment)(),
            var none when none.Equals("none", StringComparison.OrdinalIgnoreCase) => null,
            var path => new SshAgent(path),
        };
    }

    /// <summary>The key in a <c>.pub</c> file (<c>type base64 [comment]</c>), or null when there is none to read.</summary>
    private static byte[]? ReadPublicKey(string path)
    {
        try
        {
            var fields = File.ReadAllText(path).Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
            return fields.Length >= 2 ? Convert.FromBase64String(fields[1]) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The methods to try, as ssh picks them: <c>PreferredAuthentications</c> (or the default order), without the ones this library does not
    /// implement and the ones turned off by <c>PubkeyAuthentication</c>, <c>KbdInteractiveAuthentication</c> or <c>PasswordAuthentication</c>.
    /// </summary>
    internal static IReadOnlyList<string> AuthenticationOrder(SshHostConfig hostConfig)
    {
        var preferred = hostConfig.PreferredAuthentications.Count > 0 ? hostConfig.PreferredAuthentications : DefaultAuthenticationOrder;
        return [.. preferred.Distinct(StringComparer.Ordinal).Where(method => method switch
        {
            "publickey" => hostConfig.PubkeyAuthentication,
            "keyboard-interactive" => hostConfig.KbdInteractiveAuthentication,
            "password" => hostConfig.PasswordAuthentication,
            _ => false,
        })];
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
