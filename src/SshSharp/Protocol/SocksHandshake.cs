using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>A CONNECT request read from a SOCKS client: where to connect, and which protocol version to answer in.</summary>
internal readonly record struct SocksRequest(string Host, int Port, int Version);

/// <summary>
/// The server side of SOCKS 4, 4a (with host names) and 5 (RFC 1928, no authentication), CONNECT only, as <c>ssh -D</c> implements it.
/// </summary>
internal static class SocksHandshake
{
    private const byte Socks4 = 4;
    private const byte Socks5 = 5;
    private const byte Connect = 1;
    private const int MaxName = 255;

    /// <summary>
    /// Reads the client's greeting and CONNECT request. Returns null (after telling the client why, where the protocol allows it) for
    /// anything this proxy does not do; the caller then closes the connection.
    /// </summary>
    /// <exception cref="IOException">The client went away or sent a malformed request.</exception>
    public static async Task<SocksRequest?> ReadRequestAsync(Socket socket, CancellationToken cancellationToken)
    {
        var version = await ReadByteAsync(socket, cancellationToken).ConfigureAwait(false);
        return version switch
        {
            Socks4 => await ReadSocks4Async(socket, cancellationToken).ConfigureAwait(false),
            Socks5 => await ReadSocks5Async(socket, cancellationToken).ConfigureAwait(false),
            _ => null,
        };
    }

    /// <summary>Tells the client whether the connection was made, in the version it spoke.</summary>
    public static Task ReplyAsync(Socket socket, SocksRequest request, bool success, CancellationToken cancellationToken) =>
        request.Version == Socks4
            ? SendAsync(socket, [0, success ? (byte)0x5A : (byte)0x5B, 0, 0, 0, 0, 0, 0], cancellationToken)
            : SendSocks5ReplyAsync(socket, success ? (byte)0x00 : (byte)0x05, cancellationToken); // succeeded, or connection refused

    private static async Task<SocksRequest?> ReadSocks4Async(Socket socket, CancellationToken cancellationToken)
    {
        // VN=4 (already read) | CD | DSTPORT(2) | DSTIP(4) | USERID | NUL [| HOSTNAME | NUL for 4a]
        var header = await ReadExactlyAsync(socket, 7, cancellationToken).ConfigureAwait(false);
        var command = header[0];
        var port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(1));
        var address = header[3..7];
        await ReadNulTerminatedAsync(socket, cancellationToken).ConfigureAwait(false); // the user id, unused

        string host;
        if (address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] != 0)
        {
            host = await ReadNulTerminatedAsync(socket, cancellationToken).ConfigureAwait(false); // 4a: 0.0.0.x means "a name follows"
        }
        else
        {
            host = new IPAddress(address).ToString();
        }

        var request = new SocksRequest(host, port, Socks4);
        if (command != Connect || port == 0 || !IsValidHost(host))
        {
            await ReplyAsync(socket, request, success: false, cancellationToken).ConfigureAwait(false);
            return null;
        }

        return request;
    }

    private static async Task<SocksRequest?> ReadSocks5Async(Socket socket, CancellationToken cancellationToken)
    {
        // Greeting: VER=5 (already read) | NMETHODS | METHODS. Only "no authentication" (0) is offered back.
        var methodCount = await ReadByteAsync(socket, cancellationToken).ConfigureAwait(false);
        var methods = await ReadExactlyAsync(socket, methodCount, cancellationToken).ConfigureAwait(false);
        if (Array.IndexOf(methods, (byte)0) < 0)
        {
            await SendAsync(socket, [Socks5, 0xFF], cancellationToken).ConfigureAwait(false); // no acceptable method
            return null;
        }

        await SendAsync(socket, [Socks5, 0], cancellationToken).ConfigureAwait(false);

        // Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        var header = await ReadExactlyAsync(socket, 4, cancellationToken).ConfigureAwait(false);
        if (header[0] != Socks5)
        {
            throw new IOException("The SOCKS 5 request has the wrong version.");
        }

        string? host = header[3] switch
        {
            1 => new IPAddress(await ReadExactlyAsync(socket, 4, cancellationToken).ConfigureAwait(false)).ToString(),
            4 => new IPAddress(await ReadExactlyAsync(socket, 16, cancellationToken).ConfigureAwait(false)).ToString(),
            3 => Encoding.ASCII.GetString(await ReadExactlyAsync(socket, await ReadByteAsync(socket, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false)),
            _ => null,
        };
        if (host is null)
        {
            await SendSocks5ReplyAsync(socket, 0x08, cancellationToken).ConfigureAwait(false); // address type not supported
            return null;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(await ReadExactlyAsync(socket, 2, cancellationToken).ConfigureAwait(false));
        if (header[1] != Connect)
        {
            await SendSocks5ReplyAsync(socket, 0x07, cancellationToken).ConfigureAwait(false); // command not supported (BIND, UDP)
            return null;
        }

        if (port == 0 || !IsValidHost(host))
        {
            await SendSocks5ReplyAsync(socket, 0x01, cancellationToken).ConfigureAwait(false); // general failure
            return null;
        }

        return new SocksRequest(host, port, Socks5);
    }

    private static bool IsValidHost(string host) => host.Length is > 0 and <= MaxName && !host.Any(c => c <= ' ' || c > '~');

    /// <summary>A SOCKS 5 reply with an all-zero bound address, as OpenSSH sends.</summary>
    private static Task SendSocks5ReplyAsync(Socket socket, byte reply, CancellationToken cancellationToken) =>
        SendAsync(socket, [Socks5, reply, 0, 1, 0, 0, 0, 0, 0, 0], cancellationToken);

    private static async Task SendAsync(Socket socket, byte[] data, CancellationToken cancellationToken)
    {
        var sent = 0;
        while (sent < data.Length)
        {
            sent += await socket.SendAsync(data.AsMemory(sent), SocketFlags.None, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<byte> ReadByteAsync(Socket socket, CancellationToken cancellationToken) =>
        (await ReadExactlyAsync(socket, 1, cancellationToken).ConfigureAwait(false))[0];

    private static async Task<byte[]> ReadExactlyAsync(Socket socket, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var received = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (received == 0)
            {
                throw new IOException("The SOCKS client closed the connection during the handshake.");
            }

            read += received;
        }

        return buffer;
    }

    /// <summary>A NUL-terminated field (SOCKS 4 user id or 4a host name), at most 255 bytes.</summary>
    private static async Task<string> ReadNulTerminatedAsync(Socket socket, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        while (await ReadByteAsync(socket, cancellationToken).ConfigureAwait(false) is var b and not 0)
        {
            if (text.Length == MaxName)
            {
                throw new IOException("A SOCKS 4 field is longer than 255 bytes.");
            }

            text.Append((char)b);
        }

        return text.ToString();
    }
}
