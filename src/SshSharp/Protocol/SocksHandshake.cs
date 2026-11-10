using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>A CONNECT request read from a SOCKS client: where to connect, and which protocol version to answer in.</summary>
internal readonly record struct SocksRequest(string Host, int Port, int Version);

/// <summary>
/// The user name and password a SOCKS 5 client must give (RFC 1929). Only keyed digests of the two are kept, not the password, and a
/// client's attempt is compared with them in constant time: both are digested (the time that takes depends only on what the client
/// sent, which it knows) and the two digests, side by side, are compared with the expected pair in one
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>, which does not stop at the first byte that differs. So the time to answer
/// tells nothing about the expected values, their lengths included, nor about which of the two was wrong.
/// </summary>
internal sealed class SocksCredentials
{
    /// <summary>RFC 1929's limit on each field.</summary>
    public const int MaxLength = 255;

    private const int DigestSize = HMACSHA256.HashSizeInBytes;

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    /// <summary>The user name's digest, then the password's.</summary>
    private readonly byte[] _expected = new byte[2 * DigestSize];

    /// <summary>Keeps digests of <paramref name="credentials"/>' user name and password, under a key made for this instance.</summary>
    /// <exception cref="ArgumentException">The user name or password is empty or longer than 255 bytes in UTF-8.</exception>
    public SocksCredentials(NetworkCredential credentials, string parameterName)
    {
        // Stryker disable once String : NetworkCredential gives an empty string, never null, so these fallbacks are never used
        var userName = Encoding.UTF8.GetBytes(credentials.UserName ?? string.Empty);
        // Stryker disable once String : as above
        var password = Encoding.UTF8.GetBytes(credentials.Password ?? string.Empty);
        try
        {
            if (userName.Length is 0 or > MaxLength || password.Length is 0 or > MaxLength)
            {
                // Stryker disable once String : the message is for people
                throw new ArgumentException("A SOCKS 5 user name and password are each 1 to 255 bytes in UTF-8 (RFC 1929).", parameterName);
            }

            Digests(userName, password, _expected);
        }
        // Stryker disable once Block,Statement : wiping the buffer is hygiene no test can see; nothing reads it afterwards
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    /// <summary>Whether the client's user name and password are the expected ones; constant time in the expected values.</summary>
    public bool Matches(ReadOnlySpan<byte> userName, ReadOnlySpan<byte> password)
    {
        Span<byte> given = stackalloc byte[2 * DigestSize];
        Digests(userName, password, given);
        return CryptographicOperations.FixedTimeEquals(given, _expected);
    }

    private void Digests(ReadOnlySpan<byte> userName, ReadOnlySpan<byte> password, Span<byte> destination)
    {
        HMACSHA256.HashData(_key, userName, destination[..DigestSize]);
        HMACSHA256.HashData(_key, password, destination[DigestSize..]);
    }
}

/// <summary>A SOCKS client that did not authenticate: the proxy has said so where the protocol allows, and closes the connection.</summary>
internal sealed class SocksAuthenticationException(string message) : IOException(message);

/// <summary>
/// The server side of SOCKS 4, 4a (with host names) and 5 (RFC 1928), CONNECT only, as <c>ssh -D</c> implements it: over a local socket
/// for <c>-D</c>, and over a forwarded channel for remote dynamic forwarding (<c>-R port</c>). Without credentials, no authentication,
/// as in ssh; with them, SOCKS 5 username/password authentication (RFC 1929) is required and SOCKS 4, which has none, is refused.
/// </summary>
internal static class SocksHandshake
{
    private const byte Socks4 = 4;
    private const byte Socks5 = 5;
    private const byte Connect = 1;
    private const byte NoAuthentication = 0;
    private const byte UserNamePassword = 2;
    private const byte UserNamePasswordVersion = 1;
    private const int MaxName = 255;

    /// <summary>
    /// Reads the client's greeting and CONNECT request. Returns null (after telling the client why, where the protocol allows it) for
    /// anything this proxy does not do; the caller then closes the connection.
    /// </summary>
    /// <exception cref="IOException">The client went away or sent a malformed request.</exception>
    public static Task<SocksRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken) =>
        ReadRequestAsync(stream, credentials: null, cancellationToken);

    /// <summary>
    /// Reads the client's greeting and CONNECT request, as <see cref="ReadRequestAsync(Stream, CancellationToken)"/> does, requiring
    /// <paramref name="credentials"/> when given.
    /// </summary>
    /// <exception cref="SocksAuthenticationException">Credentials are required and the client did not give the right ones, or spoke
    /// SOCKS 4.</exception>
    /// <exception cref="IOException">The client went away or sent a malformed request.</exception>
    public static async Task<SocksRequest?> ReadRequestAsync(Stream stream, SocksCredentials? credentials, CancellationToken cancellationToken)
    {
        var version = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (version == Socks4 && credentials is not null)
        {
            // SOCKS 4's user id is no password; a client that cannot do SOCKS 5 is turned away. The whole request is read first: closing
            // with unread data sends a reset, and on Windows a reset can discard the refusal before the client has read it.
            // A request this proxy would not do anyway (not CONNECT, port 0, a bad 4a name) has had its refusal from ReadSocks4Async;
            // the client gets one reply, not two.
            if (await ReadSocks4Async(stream, cancellationToken).ConfigureAwait(false) is not null)
            {
                await SendAsync(stream, [0, 0x5B, 0, 0, 0, 0, 0, 0], cancellationToken).ConfigureAwait(false);
            }

            // Stryker disable once String : the message is for people
            throw new SocksAuthenticationException("SOCKS 4 has no password authentication");
        }

        return version switch
        {
            Socks4 => await ReadSocks4Async(stream, cancellationToken).ConfigureAwait(false),
            Socks5 => await ReadSocks5Async(stream, credentials, cancellationToken).ConfigureAwait(false),
            _ => null,
        };
    }

    /// <summary>Tells the client whether the connection was made, in the version it spoke.</summary>
    public static Task ReplyAsync(Stream stream, SocksRequest request, bool success, CancellationToken cancellationToken) =>
        request.Version == Socks4
            ? SendAsync(stream, [0, success ? (byte)0x5A : (byte)0x5B, 0, 0, 0, 0, 0, 0], cancellationToken)
            : SendSocks5ReplyAsync(stream, success ? (byte)0x00 : (byte)0x05, cancellationToken); // succeeded, or connection refused

    private static async Task<SocksRequest?> ReadSocks4Async(Stream stream, CancellationToken cancellationToken)
    {
        // VN=4 (already read) | CD | DSTPORT(2) | DSTIP(4) | USERID | NUL [| HOSTNAME | NUL for 4a]
        var header = await ReadExactlyAsync(stream, 7, cancellationToken).ConfigureAwait(false);
        var command = header[0];
        var port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(1));
        var address = header[3..7];
        await ReadNulTerminatedAsync(stream, cancellationToken).ConfigureAwait(false); // the user id, unused

        // 4a: an address of 0.0.0.x (x not 0) means "a name follows".
        var host = address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] != 0
            ? await ReadNulTerminatedAsync(stream, cancellationToken).ConfigureAwait(false)
            : new IPAddress(address).ToString();

        var request = new SocksRequest(host, port, Socks4);
        if (command != Connect || port == 0 || !IsValidHost(host))
        {
            await ReplyAsync(stream, request, success: false, cancellationToken).ConfigureAwait(false);
            return null;
        }

        return request;
    }

    private static async Task<SocksRequest?> ReadSocks5Async(Stream stream, SocksCredentials? credentials, CancellationToken cancellationToken)
    {
        // Greeting: VER=5 (already read) | NMETHODS | METHODS. The one method chosen is "no authentication" (0), or username/password
        // (2) when credentials are required, which nothing else then gets past.
        var methodCount = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        var methods = await ReadExactlyAsync(stream, methodCount, cancellationToken).ConfigureAwait(false);
        var method = credentials is null ? NoAuthentication : UserNamePassword;
        if (Array.IndexOf(methods, method) < 0)
        {
            await SendAsync(stream, [Socks5, 0xFF], cancellationToken).ConfigureAwait(false); // no acceptable method
            if (credentials is not null)
            {
                // Stryker disable once String : the message is for people
                throw new SocksAuthenticationException("the client did not offer username/password authentication");
            }

            return null;
        }

        await SendAsync(stream, [Socks5, method], cancellationToken).ConfigureAwait(false);
        if (credentials is not null)
        {
            await AuthenticateAsync(stream, credentials, cancellationToken).ConfigureAwait(false);
        }

        // Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        var header = await ReadExactlyAsync(stream, 4, cancellationToken).ConfigureAwait(false);
        if (header[0] != Socks5)
        {
            // Stryker disable once String : the message is for people
            throw new IOException("The SOCKS 5 request has the wrong version.");
        }

        string? host = header[3] switch
        {
            1 => new IPAddress(await ReadExactlyAsync(stream, 4, cancellationToken).ConfigureAwait(false)).ToString(),
            4 => new IPAddress(await ReadExactlyAsync(stream, 16, cancellationToken).ConfigureAwait(false)).ToString(),
            3 => Encoding.ASCII.GetString(await ReadExactlyAsync(stream, await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false)),
            _ => null,
        };
        if (host is null)
        {
            await SendSocks5ReplyAsync(stream, 0x08, cancellationToken).ConfigureAwait(false); // address type not supported
            return null;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(await ReadExactlyAsync(stream, 2, cancellationToken).ConfigureAwait(false));
        if (header[1] != Connect)
        {
            await SendSocks5ReplyAsync(stream, 0x07, cancellationToken).ConfigureAwait(false); // command not supported (BIND, UDP)
            return null;
        }

        if (port == 0 || !IsValidHost(host))
        {
            await SendSocks5ReplyAsync(stream, 0x01, cancellationToken).ConfigureAwait(false); // general failure
            return null;
        }

        return new SocksRequest(host, port, Socks5);
    }

    /// <summary>
    /// RFC 1929: VER=1 | ULEN | UNAME | PLEN | PASSWD, answered with VER=1 | STATUS (0 for success). On a failure the server must close
    /// the connection, which the caller does on the exception.
    /// </summary>
    private static async Task AuthenticateAsync(Stream stream, SocksCredentials credentials, CancellationToken cancellationToken)
    {
        if (await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false) != UserNamePasswordVersion)
        {
            // Stryker disable once String : the message is for people
            throw new IOException("The SOCKS 5 username/password request has the wrong version.");
        }

        var userName = await ReadExactlyAsync(stream, await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        var password = await ReadExactlyAsync(stream, await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        bool matches;
        try
        {
            matches = credentials.Matches(userName, password);
        }
        // Stryker disable once Block,Statement : wiping the buffer is hygiene no test can see; nothing reads it afterwards
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }

        await SendAsync(stream, [UserNamePasswordVersion, matches ? (byte)0 : (byte)1], cancellationToken).ConfigureAwait(false);
        if (!matches)
        {
            // Stryker disable once String : the message is for people
            throw new SocksAuthenticationException("wrong user name or password");
        }
    }

    private static bool IsValidHost(string host) => host.Length is > 0 and <= MaxName && !host.Any(c => c <= ' ' || c > '~');

    /// <summary>A SOCKS 5 reply with an all-zero bound address, as OpenSSH sends.</summary>
    private static Task SendSocks5ReplyAsync(Stream stream, byte reply, CancellationToken cancellationToken) =>
        SendAsync(stream, [Socks5, reply, 0, 1, 0, 0, 0, 0, 0, 0], cancellationToken);

    private static async Task SendAsync(Stream stream, byte[] data, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken) =>
        (await ReadExactlyAsync(stream, 1, cancellationToken).ConfigureAwait(false))[0];

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var received = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (received == 0)
            {
                // Stryker disable once String : the message is for people
                throw new IOException("The SOCKS client closed the connection during the handshake.");
            }

            read += received;
        }

        return buffer;
    }

    /// <summary>A NUL-terminated field (SOCKS 4 user id or 4a host name), at most 255 bytes.</summary>
    private static async Task<string> ReadNulTerminatedAsync(Stream stream, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        while (await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false) is var b and not 0)
        {
            if (text.Length == MaxName)
            {
                // Stryker disable once String : the message is for people
                throw new IOException("A SOCKS 4 field is longer than 255 bytes.");
            }

            text.Append((char)b);
        }

        return text.ToString();
    }
}
