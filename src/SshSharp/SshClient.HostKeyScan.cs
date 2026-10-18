using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    /// <summary>
    /// Fetches the server's host keys without authenticating, as <c>ssh-keyscan</c> does: one key exchange per key type the server offers,
    /// each disconnected before user authentication. Each key is one the server proved it holds (it signed the exchange), but nothing
    /// says the server is the one you meant to reach: compare the fingerprints out of band before trusting them, or use host certificates.
    /// </summary>
    /// <param name="host">The server's host name or address.</param>
    /// <param name="port">The server's port.</param>
    /// <param name="options">Which key types to ask for; by default every plain key type SshSharp supports.</param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>The keys found, one per key type, in the order of <see cref="SshHostKeyScanOptions.HostKeyAlgorithms"/>'s preference; empty
    /// when the server offers none of the requested types.</returns>
    /// <exception cref="SshException">A connection or key exchange failed for another reason than an unsupported key type.</exception>
    /// <remarks>To add the keys to <c>known_hosts</c>, pass each one's <see cref="SshHostKey.KeyType"/> and <see cref="SshHostKey.PublicKey"/>
    /// to <see cref="Config.KnownHostsFile.Add(string, int, string, ReadOnlySpan{byte}, bool, string?, Config.KnownHostsMarker)"/>.</remarks>
    public static Task<IReadOnlyList<SshHostKey>> ScanHostKeysAsync(string host, int port = 22, SshHostKeyScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        return ScanHostKeysAsync(async ct =>
        {
            var tcp = new TcpClient { NoDelay = true };
            try
            {
                await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
                return tcp.GetStream(); // owns the socket: disposing the stream closes it
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
        }, options, cancellationToken);
    }

    /// <summary>
    /// Fetches the server's host keys without authenticating, over streams that <paramref name="connect"/> opens: one per key type, so
    /// it is called several times. For a host behind a jump host, open each stream with <see cref="OpenTcpTunnelAsync"/>.
    /// </summary>
    /// <param name="connect">Opens a new connected stream to the server; the scan disposes it.</param>
    /// <param name="options">Which key types to ask for; by default every plain key type SshSharp supports.</param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>The keys found, one per key type; empty when the server offers none of the requested types.</returns>
    /// <exception cref="SshException">A connection or key exchange failed for another reason than an unsupported key type.</exception>
    public static async Task<IReadOnlyList<SshHostKey>> ScanHostKeysAsync(Func<CancellationToken, ValueTask<Stream>> connect, SshHostKeyScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connect);
        options ??= new SshHostKeyScanOptions();
        var requested = RequestedScanAlgorithms(options);

        // One group per key type: the RSA signature algorithms share one key, and a certificate is distinct from its plain key.
        var remaining = requested.GroupBy(ScanKeyFamily).Select(g => g.ToList()).ToList();
        var found = new List<SshHostKey>();
        IReadOnlyList<string>? offered = null;
        while (remaining.Count > 0)
        {
            // The first connection offers every requested algorithm, which also tells us what the server has; later ones ask for one
            // key type at a time, and only for types the server offered.
            List<string> offer;
            if (offered is null)
            {
                offer = [.. remaining.SelectMany(g => g)];
            }
            else if (remaining.FirstOrDefault(g => g.Any(offered.Contains)) is { } next)
            {
                offer = next;
            }
            else
            {
                break;
            }

            var (key, serverAlgorithms) = await ScanOnceAsync(connect, offer, options, cancellationToken).ConfigureAwait(false);
            offered ??= serverAlgorithms;
            if (key is null)
            {
                break; // the server offers none of the requested types
            }

            found.Add(key);
            var family = ScanKeyFamily(key.Algorithm);
            if (remaining.RemoveAll(g => ScanKeyFamily(g[0]) == family) == 0)
            {
                break; // cannot happen (we only offer remaining types), but never loop on it
            }
        }

        return found;
    }

    private static List<string> RequestedScanAlgorithms(SshHostKeyScanOptions options)
    {
        IReadOnlyList<string> list = options.HostKeyAlgorithms
            ?? (options.IncludeCertificates ? [.. SshAlgorithms.CertificateHostKeys, .. SshAlgorithms.DefaultHostKeys] : SshAlgorithms.DefaultHostKeys);
        foreach (var name in list)
        {
            if (name is null || !(SshAlgorithms.DefaultHostKeys.Contains(name) || SshAlgorithms.CertificateHostKeys.Contains(name)))
            {
                throw new ArgumentException($"'{name}' is not a host key algorithm SshSharp supports.", nameof(options));
            }
        }

        if (options.FipsMode)
        {
            list = SshAlgorithms.FilterFips(list, AlgorithmKind.HostKey);
        }

        return [.. list.Distinct()];
    }

    private static string ScanKeyFamily(string algorithm) => SshCertificate.IsCertificateAlgorithm(algorithm)
        ? ScanKeyFamily(SshCertificate.BaseAlgorithm(algorithm)) + "-cert"
        : algorithm is SshAlgorithms.RsaSha2_256 or SshAlgorithms.RsaSha2_512 ? "ssh-rsa" : algorithm;

    /// <summary>One key exchange offering <paramref name="hostKeyAlgorithms"/>; null when no host key algorithm matched.</summary>
    private static async Task<(SshHostKey? Key, IReadOnlyList<string>? ServerAlgorithms)> ScanOnceAsync(
        Func<CancellationToken, ValueTask<Stream>> connect, List<string> hostKeyAlgorithms, SshHostKeyScanOptions options, CancellationToken cancellationToken)
    {
        // Each connection gets options.Timeout, as ssh-keyscan -T: a server that accepts and then says nothing does not hang the scan.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        try
        {
            return await ScanOnceCoreAsync(connect, hostKeyAlgorithms, options, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new SshException(SshFailureReason.Timeout,
                $"The server did not complete a key exchange within {options.Timeout.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)} s.");
        }
    }

    private static async Task<(SshHostKey? Key, IReadOnlyList<string>? ServerAlgorithms)> ScanOnceCoreAsync(
        Func<CancellationToken, ValueTask<Stream>> connect, List<string> hostKeyAlgorithms, SshHostKeyScanOptions options, CancellationToken cancellationToken)
    {
        var defaults = options.FipsMode ? AlgorithmPreferences.Fips() : new AlgorithmPreferences();
        SshHostKey? key = null;
        var stream = await connect(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The connect callback returned no stream.");
        var transport = new SshTransport(stream, new SshTransportOptions
        {
            Preferences = new AlgorithmPreferences
            {
                Kex = defaults.Kex,
                HostKeys = hostKeyAlgorithms,
                Ciphers = defaults.Ciphers,
                Macs = defaults.Macs,
            },
            MinimumRsaBits = 0, // report small RSA keys too; KeySizeBits says how big each one is
            Logger = options.Logger ?? NullLogger.Instance,
            VerifyHostKey = (info, _) =>
            {
                key = new SshHostKey(info.Algorithm, info.KeyType, info.Fingerprint, info.Blob, info.KeySizeBits) { Certificate = info.Certificate };
                return ValueTask.FromResult(true);
            },
        });
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return (key, transport.ServerHostKeyAlgorithms);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.KeyExchangeFailed && key is null && transport.ServerHostKeyAlgorithms is { } serverAlgorithms
            && !hostKeyAlgorithms.Any(serverAlgorithms.Contains))
        {
            return (null, serverAlgorithms);
        }
        catch (IOException ex)
        {
            throw SshConnection.ConnectionLost(ex);
        }
        finally
        {
            try
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                await stream.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception cleanup) when (cleanup is IOException or ObjectDisposedException)
            {
                // Already broken.
            }
        }
    }
}
