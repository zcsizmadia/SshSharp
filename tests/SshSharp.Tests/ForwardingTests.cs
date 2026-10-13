using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Tunnels (direct-tcpip, direct-streamlocal) and local port forwarding, against the fake server relaying to in-memory services.</summary>
public class ForwardingTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>A service at the far end: reads until end of input, then answers with what it read in upper case and hangs up.</summary>
    private static DuplexStream UpperCaseService()
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

    /// <summary>A service that says something and hangs up without reading.</summary>
    private static DuplexStream GreetingService(string greeting)
    {
        var (near, far) = DuplexStream.CreatePair();
        _ = Task.Run(async () =>
        {
            await far.WriteAsync(Encoding.ASCII.GetBytes(greeting));
            await far.DisposeAsync();
        });
        return near;
    }

    private static async Task<string> ReadAllAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, Timeout());
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task<string> ExchangeAsync(IPEndPoint endPoint, string request)
    {
        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(endPoint, Timeout());
        await socket.SendAsync(Encoding.ASCII.GetBytes(request), SocketFlags.None, Timeout());
        socket.Shutdown(SocketShutdown.Send); // the half-close travels to the service as channel EOF
        return await ReceiveAllAsync(socket);
    }

    /// <summary>Everything the socket receives until the other side shuts down its sending direction.</summary>
    private static async Task<string> ReceiveAllAsync(Socket socket)
    {
        var received = new MemoryStream();
        var buffer = new byte[8192];
        while (await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout()) is var read and > 0)
        {
            received.Write(buffer, 0, read);
        }

        return Encoding.ASCII.GetString(received.ToArray());
    }

    [Test]
    public async Task ATcpTunnel_ReachesWhatTheServerConnectsTo()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var tunnel = await client.OpenTcpTunnelAsync("db.internal", 5432, Timeout());

        await tunnel.WriteAsync("select 1"u8.ToArray(), Timeout());
        await tunnel.DisposeAsync(); // EOF, then CLOSE: the service sees the end of its input but the reply is lost
        await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });
        await Assert.That(server.DirectTcpIpOriginators).IsEquivalentTo(new[] { "127.0.0.1:0" });
    }

    [Test]
    public async Task ATcpTunnel_StreamsBothWays()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => GreetingService("220 smtp.internal ready\r\n") };
        await using var client = await ConnectAsync(server);
        await using var tunnel = await client.OpenTcpTunnelAsync("smtp.internal", 25, Timeout());
        await Assert.That(await ReadAllAsync(tunnel)).IsEqualTo("220 smtp.internal ready\r\n");
    }

    [Test]
    public async Task AUnixSocketTunnel_NamesThePathOnTheServer()
    {
        await using var server = new FakeSessionServer { DirectStreamLocal = _ => GreetingService("HTTP/1.1 200 OK\r\n") };
        await using var client = await ConnectAsync(server);
        await using var tunnel = await client.OpenUnixSocketTunnelAsync("/var/run/docker.sock", Timeout());
        await Assert.That(await ReadAllAsync(tunnel)).IsEqualTo("HTTP/1.1 200 OK\r\n");
        await Assert.That(server.DirectStreamLocalRequests).IsEquivalentTo(new[] { "/var/run/docker.sock" });
    }

    [Test]
    public async Task ARefusedTunnel_IsAChannelError()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => null };
        await using var client = await ConnectAsync(server);
        var error = await Assert.ThrowsAsync<SshException>(() => client.OpenTcpTunnelAsync("nowhere", 1, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        error = await Assert.ThrowsAsync<SshException>(() => client.OpenUnixSocketTunnelAsync("/nothing", Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task InvalidDestinations_AreRejectedBeforeAnythingIsSent()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenTcpTunnelAsync("", 80, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenTcpTunnelAsync("host\nX", 80, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.OpenTcpTunnelAsync("host", 0, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.OpenTcpTunnelAsync("host", 65536, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenUnixSocketTunnelAsync("", Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenUnixSocketTunnelAsync("/a\0b", Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "host", -1, Timeout()));
        await Assert.That(server.Channels).IsEmpty();
    }

    [Test]
    public async Task LocalForwarding_RelaysEachConnection_WithHalfCloseBothWays()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "echo.internal", 7, Timeout());
        await Assert.That(forwarder.LocalEndPoint.Port).IsNotEqualTo(0);
        await Assert.That(forwarder.RemoteHost).IsEqualTo("echo.internal");
        await Assert.That(forwarder.RemotePort).IsEqualTo(7);

        // Several at once: each gets its own channel and its own answer.
        var answers = await Task.WhenAll(Enumerable.Range(0, 5).Select(i => ExchangeAsync(forwarder.LocalEndPoint, $"request {i}")));
        await Assert.That(answers).IsEquivalentTo(Enumerable.Range(0, 5).Select(i => $"REQUEST {i}"));

        await Assert.That(server.DirectTcpIpRequests.Distinct()).IsEquivalentTo(new[] { "echo.internal:7" });
        await Assert.That(server.DirectTcpIpOriginators.All(o => o.StartsWith("127.0.0.1:", StringComparison.Ordinal) && !o.EndsWith(":0", StringComparison.Ordinal))).IsTrue();
        for (var i = 0; i < 500 && forwarder.ActiveConnections > 0; i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(forwarder.ActiveConnections).IsEqualTo(0);
    }

    [Test]
    public async Task LocalForwarding_DeliversWhatTheServerSentBeforeClosing()
    {
        // The service talks first and hangs up; the local client never writes.
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => GreetingService(new string('x', 200_000)) };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "big.internal", 9, Timeout());

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(forwarder.LocalEndPoint, Timeout());
        await Assert.That((await ReceiveAllAsync(socket)).Length).IsEqualTo(200_000);
    }

    [Test]
    public async Task ARefusedForwardedConnection_IsDropped_AndForwardingCarriesOn()
    {
        var refuse = true;
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => refuse ? null : UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "flaky.internal", 80, Timeout());

        // Closed without an answer: an orderly end, or a reset because the request was never read (as with ssh -L).
        string? first;
        try
        {
            first = await ExchangeAsync(forwarder.LocalEndPoint, "first");
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            first = "";
        }

        await Assert.That(first).IsEqualTo("");
        refuse = false;
        await Assert.That(await ExchangeAsync(forwarder.LocalEndPoint, "second")).IsEqualTo("SECOND");
    }

    [Test]
    public async Task DisposingTheForwarder_StopsListening_AndClosesOpenConnections()
    {
        var (near, far) = DuplexStream.CreatePair(); // a service that never answers
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => near };
        await using var client = await ConnectAsync(server);
        var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "idle.internal", 22, Timeout());
        var endPoint = forwarder.LocalEndPoint;

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(endPoint, Timeout());
        for (var i = 0; i < 500 && forwarder.ActiveConnections == 0; i++)
        {
            await Task.Delay(10);
        }

        await forwarder.DisposeAsync();
        await forwarder.DisposeAsync(); // twice is harmless
        await Assert.That(forwarder.ActiveConnections).IsEqualTo(0);

        // The open connection was closed (an orderly end, or a reset: disposing aborts it), and nothing listens any more.
        var buffer = new byte[1];
        int received;
        try
        {
            received = await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout());
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            received = 0;
        }

        await Assert.That(received).IsEqualTo(0);

        // Not probed by connecting: with tests running in parallel, another test may already have been given the freed port.
        await Assert.That(forwarder.IsListening).IsFalse();
        await far.DisposeAsync();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task Forwarding_StopsWhenTheConnectionEnds()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService() };
        var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "echo.internal", 7, Timeout());
        await client.DisposeAsync();

        // The listener closes shortly after the connection is gone.
        for (var i = 0; i < 500 && forwarder.IsListening; i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(forwarder.IsListening).IsFalse();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "x", 1, Timeout()));
    }

    [Test]
    public async Task APortInUse_FailsToBind()
    {
        using var taken = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        taken.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        taken.Listen();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<SocketException>(() => client.ForwardLocalPortAsync((IPEndPoint)taken.LocalEndPoint!, "x", 1, Timeout()));
    }
}
