using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SshSharp;

/// <summary>The kind of proxy an <see cref="SshProxy"/> speaks.</summary>
public enum SshProxyType
{
    /// <summary>An HTTP proxy, through the <c>CONNECT</c> method (RFC 9110 section 9.3.6).</summary>
    Http,

    /// <summary>SOCKS 4, or 4a when the destination is a host name (resolved by the proxy).</summary>
    Socks4,

    /// <summary>SOCKS 5 (RFC 1928), with username and password authentication (RFC 1929) when credentials are given.</summary>
    Socks5,
}

/// <summary>
/// An HTTP or SOCKS proxy to reach the SSH server through, for networks that allow outbound connections only that way. Set it as
/// <see cref="SshClientOptions.Proxy"/> or <see cref="SshConfigConnectOptions.Proxy"/>, or open a stream with <see cref="ConnectAsync(string, int, CancellationToken)"/>
/// and pass it to <see cref="SshClient.ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>.
/// </summary>
/// <remarks>
/// Destination host names are sent to the proxy, which resolves them (as <c>curl --socks5-hostname</c> does), so names the proxy's
/// network knows work, and local DNS does not see them. HTTP Basic and SOCKS 5 credentials cross the network to the proxy in the
/// clear (as with every client of these protocols), so use them only with a proxy on a network you trust.
/// </remarks>
public sealed class SshProxy
{
    private const int MaxHttpResponseHeader = 16 * 1024;

    private SshProxy(SshProxyType type, string host, int port, NetworkCredential? credentials)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        if (credentials is not null && type != SshProxyType.Http && type != SshProxyType.Socks5 && !string.IsNullOrEmpty(credentials.Password))
        {
            throw new ArgumentException("SOCKS 4 has no passwords; only a user id.", nameof(credentials));
        }

        if (type == SshProxyType.Socks5 && credentials is not null
            && (Encoding.UTF8.GetByteCount(credentials.UserName) is 0 or > 255 || Encoding.UTF8.GetByteCount(credentials.Password) > 255))
        {
            throw new ArgumentException("SOCKS 5 user names are 1 to 255 bytes, and passwords at most 255.", nameof(credentials));
        }

        if (type == SshProxyType.Socks4 && credentials is not null && credentials.UserName.Any(c => char.IsControl(c) || c > '~'))
        {
            throw new ArgumentException("A SOCKS 4 user id is printable ASCII.", nameof(credentials));
        }

        Type = type;
        Host = host;
        Port = port;
        Credentials = credentials;
    }

    /// <summary>The kind of proxy.</summary>
    public SshProxyType Type { get; }

    /// <summary>The proxy's host name or address.</summary>
    public string Host { get; }

    /// <summary>The proxy's port.</summary>
    public int Port { get; }

    /// <summary>The credentials sent to the proxy, if any (for SOCKS 4, just the user id).</summary>
    public NetworkCredential? Credentials { get; }

    /// <summary>How long the proxy has, once connected to, to complete its handshake (30 seconds); replaceable in tests.</summary>
    internal TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>An HTTP proxy, reached with <c>CONNECT</c>; <paramref name="credentials"/> are sent with Basic authentication.</summary>
    public static SshProxy Http(string host, int port, NetworkCredential? credentials = null) => new(SshProxyType.Http, host, port, credentials);

    /// <summary>A SOCKS 5 proxy; <paramref name="credentials"/> are sent with username and password authentication (RFC 1929).</summary>
    public static SshProxy Socks5(string host, int port, NetworkCredential? credentials = null) => new(SshProxyType.Socks5, host, port, credentials);

    /// <summary>A SOCKS 4 proxy (4a for host names), with an optional user id.</summary>
    public static SshProxy Socks4(string host, int port, string? userId = null) =>
        new(SshProxyType.Socks4, host, port, userId is null ? null : new NetworkCredential(userId, (string?)null));

    /// <summary>
    /// A proxy from a URI, as proxy settings are usually written: <c>http://proxy:3128</c>, <c>socks5://proxy:1080</c>,
    /// <c>socks5h://</c> (the same: names are always resolved by the proxy), <c>socks4://</c> or <c>socks4a://</c>, with optional
    /// <c>user:password@</c> (percent-encoded). The port defaults to 8080 for HTTP and 1080 for SOCKS.
    /// </summary>
    /// <exception cref="ArgumentException">The scheme is not one of those, or the URI has a path or query.</exception>
    public static SshProxy FromUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri)
        {
            throw new ArgumentException("The proxy URI must be absolute, for example http://proxy:3128.", nameof(uri));
        }

        var type = uri.Scheme.ToLowerInvariant() switch
        {
            "http" => SshProxyType.Http,
            "socks5" or "socks5h" => SshProxyType.Socks5,
            "socks4" or "socks4a" => SshProxyType.Socks4,
            var other => throw new ArgumentException($"Unsupported proxy scheme '{other}' (http, socks5, socks5h, socks4 or socks4a).", nameof(uri)),
        };
        if (uri.AbsolutePath is not ("/" or "") || uri.Query.Length > 0 || uri.Fragment.Length > 0)
        {
            throw new ArgumentException("A proxy URI has only a scheme, optional credentials, a host and a port.", nameof(uri));
        }

        NetworkCredential? credentials = null;
        if (uri.UserInfo.Length > 0)
        {
            var colon = uri.UserInfo.IndexOf(':', StringComparison.Ordinal);
            var user = Uri.UnescapeDataString(colon < 0 ? uri.UserInfo : uri.UserInfo[..colon]);
            var password = colon < 0 ? null : Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]);
            credentials = new NetworkCredential(user, password);
        }

        var port = uri.IsDefaultPort || uri.Port < 0 ? (type == SshProxyType.Http ? 8080 : 1080) : uri.Port;
        return new SshProxy(type, uri.IdnHost, port, credentials);
    }

    /// <summary>
    /// Connects to the proxy and asks it for a connection to <paramref name="host"/>:<paramref name="port"/>. The returned stream carries
    /// that connection; disposing it closes the connection to the proxy.
    /// </summary>
    /// <exception cref="SshException">The proxy could not be reached, refused the connection or the credentials, or answered something
    /// that is not its protocol (<see cref="SshFailureReason.ConnectFailed"/>); or, once connected, did not complete its handshake within 30
    /// seconds (<see cref="SshFailureReason.Timeout"/>).</exception>
    /// <exception cref="ArgumentException"><paramref name="host"/> is not an ASCII host name or address (give an internationalized name in
    /// its punycode form).</exception>
    public Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default) =>
        ConnectAsync(host, port, null, cancellationToken);

    /// <summary>Connects like <see cref="ConnectAsync(string, int, CancellationToken)"/>, from <paramref name="local"/> when given.</summary>
    internal async Task<Stream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (host.Any(c => char.IsControl(c) || c == ' '))
        {
            throw new ArgumentException("The host name must not contain spaces or control characters.", nameof(host));
        }

        // Every proxy protocol carries the name as ASCII; anything else would reach the proxy as '?' (another name). Internationalized
        // names go in their punycode form (System.Globalization.IdnMapping).
        if (host.Any(c => c > '~'))
        {
            throw new ArgumentException("A host name given to a proxy must be ASCII; use its punycode form.", nameof(host));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        var stream = await Protocol.TcpConnector.ConnectAsync(Host, Port, local, Config.SshAddressFamily.Any, "the proxy", cancellationToken).ConfigureAwait(false);
        try
        {
            // A proxy that accepts the connection and then says nothing must not hang the caller: the handshake has a time limit.
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshake.CancelAfter(HandshakeTimeout);
            try
            {
                switch (Type)
                {
                    case SshProxyType.Http:
                        await HttpConnectAsync(stream, host, port, handshake.Token).ConfigureAwait(false);
                        break;
                    case SshProxyType.Socks5:
                        await Socks5ConnectAsync(stream, host, port, handshake.Token).ConfigureAwait(false);
                        break;
                    default:
                        await Socks4ConnectAsync(stream, host, port, handshake.Token).ConfigureAwait(false);
                        break;
                }
            }
            catch (IOException ex)
            {
                throw new SshException(SshFailureReason.ConnectFailed, "The proxy closed the connection during its handshake.", ex);
            }
            catch (OperationCanceledException) when (handshake.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new SshException(SshFailureReason.Timeout,
                    $"The proxy did not complete its handshake within {HandshakeTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)} s.");
            }

            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    // ---- HTTP CONNECT ----

    private async Task HttpConnectAsync(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        // An IPv6 literal is bracketed in the authority (RFC 9110 section 4.2.3 via RFC 3986).
        var authority = (IPAddress.TryParse(host, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]" : host)
            + ":" + port.ToString(CultureInfo.InvariantCulture);
        var request = new StringBuilder()
            .Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n")
            .Append("Host: ").Append(authority).Append("\r\n");
        if (Credentials is { } credentials)
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials.UserName + ":" + credentials.Password));
            request.Append("Proxy-Authorization: Basic ").Append(token).Append("\r\n");
        }

        request.Append("\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()), cancellationToken).ConfigureAwait(false);

        // Read the response header one byte at a time: the SSH server's first bytes may follow it at once, and must stay in the stream.
        var header = new List<byte>(256);
        var one = new byte[1];
        while (!(header.Count >= 4 && header[^4] == '\r' && header[^3] == '\n' && header[^2] == '\r' && header[^1] == '\n'))
        {
            if (header.Count == MaxHttpResponseHeader)
            {
                throw new SshException(SshFailureReason.ConnectFailed, "The HTTP proxy's response header is too long.");
            }

            await stream.ReadExactlyAsync(one, cancellationToken).ConfigureAwait(false);
            header.Add(one[0]);
        }

        var statusLine = Encoding.ASCII.GetString([.. header]).Split("\r\n", 2)[0];
        var parts = statusLine.Split(' ', 3);
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/1.", StringComparison.Ordinal) || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var status))
        {
            throw new SshException(SshFailureReason.ConnectFailed, "The proxy did not answer as an HTTP proxy.");
        }

        if (status is < 200 or > 299)
        {
            var reason = parts.Length > 2 ? new string(parts[2].Where(c => !char.IsControl(c)).Take(100).ToArray()) : string.Empty;
            throw new SshException(SshFailureReason.ConnectFailed, status == 407
                ? "The HTTP proxy requires authentication (407), or refused the credentials."
                : $"The HTTP proxy refused the connection: {status.ToString(CultureInfo.InvariantCulture)} {reason}".TrimEnd());
        }
    }

    // ---- SOCKS 5 (RFC 1928, RFC 1929) ----

    private async Task Socks5ConnectAsync(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        byte[] greeting = Credentials is null ? [5, 1, 0] : [5, 2, 0, 2];
        await stream.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);
        var choice = await ReadAsync(stream, 2, cancellationToken).ConfigureAwait(false);
        if (choice[0] != 5)
        {
            throw new SshException(SshFailureReason.ConnectFailed, "The proxy did not answer as a SOCKS 5 proxy.");
        }

        switch (choice[1])
        {
            case 0:
                break;
            case 2 when Credentials is { } credentials:
            {
                var user = Encoding.UTF8.GetBytes(credentials.UserName);
                var password = Encoding.UTF8.GetBytes(credentials.Password);
                byte[] login = [1, (byte)user.Length, .. user, (byte)password.Length, .. password];
                try
                {
                    await stream.WriteAsync(login, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    Array.Clear(login);
                    Array.Clear(password);
                }

                // RFC 1929: VER (the sub-negotiation's version, 1) | STATUS (0 for success).
                var verdict = await ReadAsync(stream, 2, cancellationToken).ConfigureAwait(false);
                if (verdict[0] != 1)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, "The SOCKS 5 proxy's authentication reply has the wrong version.");
                }

                if (verdict[1] != 0)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, "The SOCKS 5 proxy refused the user name or password.");
                }

                break;
            }

            case 0xFF:
                throw new SshException(SshFailureReason.ConnectFailed, Credentials is null
                    ? "The SOCKS 5 proxy requires authentication."
                    : "The SOCKS 5 proxy accepts none of the offered authentication methods.");
            default:
                throw new SshException(SshFailureReason.ConnectFailed, $"The SOCKS 5 proxy chose an authentication method that was not offered ({choice[1]}).");
        }

        // CONNECT: an address as such, or a name for the proxy to resolve.
        byte[] destination;
        if (IPAddress.TryParse(host, out var address))
        {
            destination = [address.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)4 : (byte)1, .. address.GetAddressBytes()];
        }
        else
        {
            var name = Encoding.ASCII.GetBytes(host);
            if (name.Length > 255 || host.Any(c => c > '~'))
            {
                throw new ArgumentException("A SOCKS 5 host name is ASCII and at most 255 bytes; use its punycode form.", nameof(host));
            }

            destination = [3, (byte)name.Length, .. name];
        }

        var portBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(portBytes, (ushort)port);
        byte[] connect = [5, 1, 0, .. destination, .. portBytes];
        await stream.WriteAsync(connect, cancellationToken).ConfigureAwait(false);

        // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. Read exactly its length, so nothing of the SSH server's is consumed.
        var reply = await ReadAsync(stream, 4, cancellationToken).ConfigureAwait(false);
        if (reply[0] != 5)
        {
            throw new SshException(SshFailureReason.ConnectFailed, "The SOCKS 5 proxy's reply has the wrong version.");
        }

        if (reply[1] != 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed, "The SOCKS 5 proxy refused the connection: " + reply[1] switch
            {
                1 => "general failure",
                2 => "not allowed by its rules",
                3 => "network unreachable",
                4 => "host unreachable",
                5 => "connection refused",
                6 => "TTL expired",
                7 => "command not supported",
                8 => "address type not supported",
                var other => $"error {other}",
            } + ".");
        }

        var boundLength = reply[3] switch
        {
            1 => 4,
            4 => 16,
            3 => (await ReadAsync(stream, 1, cancellationToken).ConfigureAwait(false))[0],
            _ => throw new SshException(SshFailureReason.ConnectFailed, "The SOCKS 5 proxy's reply has an unknown address type."),
        };
        await ReadAsync(stream, boundLength + 2, cancellationToken).ConfigureAwait(false);
    }

    // ---- SOCKS 4 / 4a ----

    private async Task Socks4ConnectAsync(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        var userId = Encoding.ASCII.GetBytes(Credentials?.UserName ?? string.Empty);
        byte[] request;
        var portBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(portBytes, (ushort)port);
        if (IPAddress.TryParse(host, out var address))
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("SOCKS 4 reaches IPv4 addresses and host names only.", nameof(host));
            }

            request = [4, 1, .. portBytes, .. address.GetAddressBytes(), .. userId, 0];
        }
        else
        {
            // 4a: the address 0.0.0.1 says a host name follows, for the proxy to resolve.
            request = [4, 1, .. portBytes, 0, 0, 0, 1, .. userId, 0, .. Encoding.ASCII.GetBytes(host), 0];
        }

        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        var reply = await ReadAsync(stream, 8, cancellationToken).ConfigureAwait(false);
        if (reply[0] != 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed, "The proxy did not answer as a SOCKS 4 proxy.");
        }

        if (reply[1] != 0x5A)
        {
            throw new SshException(SshFailureReason.ConnectFailed, $"The SOCKS 4 proxy refused the connection (code 0x{reply[1]:X2}).");
        }
    }

    private static async Task<byte[]> ReadAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }

    /// <summary>The proxy's address and kind; never the credentials.</summary>
    public override string ToString() => $"{Type} proxy {Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
}
