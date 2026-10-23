using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Remote port forwarding (ssh -R): the fake server plays connections arriving at the forwarded port.</summary>
public class RemoteForwardingTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>A local service: reads until end of input, answers in upper case, then shuts down its side.</summary>
    private sealed class UpperCaseListener : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public UpperCaseListener()
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    Socket socket;
                    try
                    {
                        socket = await _listener.AcceptAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }

                    _ = Task.Run(async () =>
                    {
                        using (socket)
                        {
                            var text = await ReceiveAllAsync(socket);
                            await socket.SendAsync(Encoding.ASCII.GetBytes(text.ToUpperInvariant()), SocketFlags.None);
                            socket.Shutdown(SocketShutdown.Send);
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        public void Dispose() => _listener.Dispose();
    }

    private static async Task<string> ReceiveAllAsync(Socket socket)
    {
        var received = new MemoryStream();
        var buffer = new byte[8192];
        while (await socket.ReceiveAsync(buffer, SocketFlags.None) is var read and > 0)
        {
            received.Write(buffer, 0, read);
        }

        return Encoding.ASCII.GetString(received.ToArray());
    }

    /// <summary>What a remote client connecting to the forwarded port gets back for <paramref name="request"/>.</summary>
    private static async Task<string> ExchangeAsync(Stream remote, string request)
    {
        await remote.WriteAsync(Encoding.ASCII.GetBytes(request), Timeout());
        ((DuplexStream)remote).CloseWrite();
        using var buffer = new MemoryStream();
        await remote.CopyToAsync(buffer, Timeout());
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    [Test]
    public async Task ConnectionsToTheServersPort_ReachTheLocalService()
    {
        using var service = new UpperCaseListener();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", service.Port, Timeout());

        // Port 0: the server picked one and said which.
        await Assert.That(forwarder.RemotePort).IsEqualTo(40000);
        await Assert.That(forwarder.BindAddress).IsEqualTo("localhost");
        await Assert.That(forwarder.LocalPort).IsEqualTo(service.Port);
        await Assert.That(server.RemoteForwards[40000]).IsEqualTo("localhost");

        var answers = await Task.WhenAll(Enumerable.Range(0, 3).Select(async i =>
        {
            var remote = await server.ConnectForwardedAsync(forwarder.RemotePort);
            await using (remote!)
            {
                return await ExchangeAsync(remote!, $"hello {i}");
            }
        }));
        await Assert.That(answers).IsEquivalentTo(new[] { "HELLO 0", "HELLO 1", "HELLO 2" });
    }

    [Test]
    public async Task AChosenPort_IsUsedAsIs()
    {
        using var service = new UpperCaseListener();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemotePortAsync("", 8080, "localhost", service.Port, Timeout());
        await Assert.That(forwarder.RemotePort).IsEqualTo(8080);
        var remote = await server.ConnectForwardedAsync(8080, connectedAddress: "0.0.0.0");
        await Assert.That(await ExchangeAsync(remote!, "x")).IsEqualTo("X");
    }

    [Test]
    public async Task ARefusingServer_FailsTheRequest()
    {
        await using var server = new FakeSessionServer { RefuseRemoteForwarding = true };
        await using var client = await ConnectAsync(server);
        var error = await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", 80, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task ChannelsForPortsNotForwarded_AreRefused()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        // Nothing forwarded yet, then a different port: the client refuses both, and the connection stays up.
        await Assert.That(await server.ConnectForwardedAsync(9999)).IsNull();
        using var service = new UpperCaseListener();
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", service.Port, Timeout());
        await Assert.That(await server.ConnectForwardedAsync(forwarder.RemotePort + 1)).IsNull();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task NothingListeningLocally_ClosesTheForwardedConnection()
    {
        // Port 1 on loopback: nothing listens there. A port bound and released could be taken by another test's listener before it is
        // used (a stress run saw a SOCKS proxy answer on one).
        const int unusedPort = 1;

        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", unusedPort, Timeout());
        var remote = await server.ConnectForwardedAsync(forwarder.RemotePort);
        using var buffer = new MemoryStream();
        await remote!.CopyToAsync(buffer, Timeout()); // ends: the client closed the channel
        await Assert.That(buffer.Length).IsEqualTo(0);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task DisposingTheForwarder_CancelsItOnTheServer()
    {
        using var service = new UpperCaseListener();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var forwarder = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", service.Port, Timeout());
        var port = forwarder.RemotePort;
        await forwarder.DisposeAsync();
        await forwarder.DisposeAsync(); // twice is harmless

        await Assert.That(server.CancelledRemoteForwards).IsEquivalentTo(new[] { port });
        await Assert.That(server.RemoteForwards).IsEmpty();
        await Assert.That(await server.ConnectForwardedAsync(port)).IsNull(); // a late connection is refused

        // The same port can be forwarded again.
        await using var again = await client.ForwardRemotePortAsync("localhost", port, "127.0.0.1", service.Port, Timeout());
        await Assert.That(again.RemotePort).IsEqualTo(port);
    }

    [Test]
    public async Task InvalidArguments_AreRejectedBeforeAnythingIsSent()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardRemotePortAsync("local\nhost", 0, "127.0.0.1", 80, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemotePortAsync("localhost", -1, "127.0.0.1", 80, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemotePortAsync("localhost", 70000, "127.0.0.1", 80, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", 0, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardRemotePortAsync("localhost", 0, "", 80, Timeout()));
        await Assert.That(server.RemoteForwards).IsEmpty();
    }
}
