using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Dynamic forwarding (ssh -D): SOCKS 4, 4a and 5 clients against the proxy, with the fake server making the connections.</summary>
public class SocksProxyTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<(FakeSessionServer Server, SshClient Client, SshDynamicPortForwarder Proxy)> StartAsync(Func<string, int, Stream?> route)
    {
        var server = new FakeSessionServer { DirectTcpIp = route };
        _ = server.StartAsync();
        var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
        var proxy = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), Timeout());
        return (server, client, proxy);
    }

    /// <summary>A service that answers each request with its upper-case form, once the request has ended.</summary>
    private static DuplexStream UpperCase()
    {
        var (near, far) = DuplexStream.CreatePair();
        _ = Task.Run(async () =>
        {
            using var buffer = new MemoryStream();
            await far.CopyToAsync(buffer);
            await far.WriteAsync(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(buffer.ToArray()).ToUpperInvariant()));
            await far.DisposeAsync();
        });
        return near;
    }

    private static async Task<Socket> OpenAsync(SshDynamicPortForwarder proxy)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy.LocalEndPoint, Timeout());
        return socket;
    }

    private static async Task SendAsync(Socket socket, byte[] data) => await socket.SendAsync(data, SocketFlags.None, Timeout());

    private static async Task<byte[]> ReceiveAsync(Socket socket, int count)
    {
        var buffer = new byte[count];
        var read = 0;
        try
        {
            while (read < count && await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, Timeout()) is var n and > 0)
            {
                read += n;
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            // Closed with our request still unread, which resets the connection instead of ending it: the same "go away".
        }

        return buffer[..read];
    }

    private static async Task<string> ExchangeAsync(Socket socket, string request)
    {
        await SendAsync(socket, Encoding.ASCII.GetBytes(request));
        socket.Shutdown(SocketShutdown.Send);
        var received = new MemoryStream();
        var buffer = new byte[4096];
        while (await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout()) is var n and > 0)
        {
            received.Write(buffer, 0, n);
        }

        return Encoding.ASCII.GetString(received.ToArray());
    }

    private static byte[] Socks5Connect(byte addressType, byte[] address, int port)
    {
        var request = new List<byte> { 5, 1, 0, addressType };
        if (addressType == 3)
        {
            request.Add((byte)address.Length);
        }

        request.AddRange(address);
        request.Add((byte)(port >> 8));
        request.Add((byte)port);
        return [.. request];
    }

    private static async Task<byte> Socks5Async(Socket socket, byte addressType, byte[] address, int port)
    {
        await SendAsync(socket, [5, 2, 2, 0]); // offers username/password and "none"; "none" is chosen
        await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        await SendAsync(socket, Socks5Connect(addressType, address, port));
        var reply = await ReceiveAsync(socket, 10);
        await Assert.That(reply.Length).IsEqualTo(10);
        await Assert.That(reply[0]).IsEqualTo((byte)5);
        return reply[1];
    }

    private static byte[] Socks4Connect(int port, byte[] address, string? host = null)
    {
        var request = new List<byte> { 4, 1, (byte)(port >> 8), (byte)port };
        request.AddRange(address);
        request.AddRange("someone"u8.ToArray());
        request.Add(0);
        if (host is not null)
        {
            request.AddRange(Encoding.ASCII.GetBytes(host));
            request.Add(0);
        }

        return [.. request];
    }

    [Test]
    public async Task Socks5_WithAHostName_ConnectsThroughTheServer()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await Assert.That(await Socks5Async(socket, 3, "db.internal"u8.ToArray(), 5432)).IsEqualTo((byte)0);
            await Assert.That(await ExchangeAsync(socket, "select")).IsEqualTo("SELECT");
            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });
        }
    }

    [Test]
    public async Task Socks5_WithIPv4AndIPv6Addresses()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        await using (proxy)
        {
            using (var v4 = await OpenAsync(proxy))
            {
                await Assert.That(await Socks5Async(v4, 1, [10, 1, 2, 3], 80)).IsEqualTo((byte)0);
                await Assert.That(await ExchangeAsync(v4, "a")).IsEqualTo("A");
            }

            using (var v6 = await OpenAsync(proxy))
            {
                await Assert.That(await Socks5Async(v6, 4, IPAddress.Parse("2001:db8::7").GetAddressBytes(), 443)).IsEqualTo((byte)0);
                await Assert.That(await ExchangeAsync(v6, "b")).IsEqualTo("B");
            }

            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "10.1.2.3:80", "2001:db8::7:443" });
        }
    }

    [Test]
    public async Task Socks4_AndSocks4a()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        await using (proxy)
        {
            using (var socks4 = await OpenAsync(proxy))
            {
                await SendAsync(socks4, Socks4Connect(8080, [192, 0, 2, 1]));
                await Assert.That((await ReceiveAsync(socks4, 8))[1]).IsEqualTo((byte)0x5A);
                await Assert.That(await ExchangeAsync(socks4, "four")).IsEqualTo("FOUR");
            }

            using (var socks4a = await OpenAsync(proxy))
            {
                await SendAsync(socks4a, Socks4Connect(25, [0, 0, 0, 1], "mail.internal"));
                await Assert.That((await ReceiveAsync(socks4a, 8))[1]).IsEqualTo((byte)0x5A);
                await Assert.That(await ExchangeAsync(socks4a, "helo")).IsEqualTo("HELO");
            }

            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "192.0.2.1:8080", "mail.internal:25" });
        }
    }

    [Test]
    public async Task ATargetTheServerCannotReach_IsReportedToTheApplication()
    {
        var (server, client, proxy) = await StartAsync((_, _) => null);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using (var socks5 = await OpenAsync(proxy))
            {
                await Assert.That(await Socks5Async(socks5, 3, "nowhere"u8.ToArray(), 1)).IsEqualTo((byte)5); // connection refused
            }

            using (var socks4 = await OpenAsync(proxy))
            {
                await SendAsync(socks4, Socks4Connect(1, [192, 0, 2, 9]));
                await Assert.That((await ReceiveAsync(socks4, 8))[1]).IsEqualTo((byte)0x5B); // rejected
            }

            await Assert.That(client.IsConnected).IsTrue();
        }
    }

    [Test]
    public async Task UnsupportedRequests_AreRefusedWithTheRightCode()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        await using (proxy)
        {
            // Only username/password offered: no acceptable method.
            using (var socket = await OpenAsync(proxy))
            {
                await SendAsync(socket, [5, 1, 2]);
                await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 0xFF });
            }

            // BIND: command not supported.
            using (var socket = await OpenAsync(proxy))
            {
                await SendAsync(socket, [5, 1, 0]);
                await ReceiveAsync(socket, 2);
                var bind = Socks5Connect(1, [10, 0, 0, 1], 80);
                bind[1] = 2;
                await SendAsync(socket, bind);
                await Assert.That((await ReceiveAsync(socket, 10))[1]).IsEqualTo((byte)7);
            }

            // An unknown address type.
            using (var socket = await OpenAsync(proxy))
            {
                await SendAsync(socket, [5, 1, 0]);
                await ReceiveAsync(socket, 2);
                await SendAsync(socket, [5, 1, 0, 9]);
                await Assert.That((await ReceiveAsync(socket, 10))[1]).IsEqualTo((byte)8);
            }

            // A host name with a control character, and port 0.
            using (var socket = await OpenAsync(proxy))
            {
                await Assert.That(await Socks5Async(socket, 3, "bad\nhost"u8.ToArray(), 80)).IsEqualTo((byte)1);
            }

            using (var socket = await OpenAsync(proxy))
            {
                await Assert.That(await Socks5Async(socket, 3, "host"u8.ToArray(), 0)).IsEqualTo((byte)1);
            }

            // Not SOCKS at all: the connection is just closed.
            using (var socket = await OpenAsync(proxy))
            {
                await SendAsync(socket, "GET / HTTP/1.1\r\n\r\n"u8.ToArray());
                await Assert.That((await ReceiveAsync(socket, 1)).Length).IsEqualTo(0);
            }

            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
            await Assert.That(client.IsConnected).IsTrue();
        }
    }

    [Test]
    public async Task DisposingTheProxy_StopsListening()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        {
            var endPoint = proxy.LocalEndPoint;
            await Assert.That(endPoint.Port).IsNotEqualTo(0);
            await proxy.DisposeAsync();
            await Assert.That(proxy.ActiveConnections).IsEqualTo(0);
            await Assert.That(proxy.IsListening).IsFalse(); // not probed: a parallel test may already have the freed port
        }
    }

    [Test]
    public async Task AnOverlongSocks4Field_ClosesTheConnection()
    {
        var (server, client, proxy) = await StartAsync((_, _) => UpperCase());
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            var request = new byte[8 + 300];
            request[0] = 4;
            request[1] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 80);
            request.AsSpan(8).Fill((byte)'u'); // a user id with no terminator in sight
            await SendAsync(socket, request);
            await Assert.That((await ReceiveAsync(socket, 1)).Length).IsEqualTo(0);
            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
        }
    }
}
