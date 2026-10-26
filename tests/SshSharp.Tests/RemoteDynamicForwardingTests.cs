using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Remote dynamic forwarding (<c>ssh -R port</c>, #114): the fake server plays applications on its side connecting to the forwarded port
/// and speaking SOCKS, and the client connects to local services for them.
/// </summary>
public class RemoteDynamicForwardingTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    /// <summary>A local service: reads until end of input, answers in upper case, then shuts down its side. Counts connections.</summary>
    private sealed class UpperCaseService : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private int _accepted;

        public UpperCaseService()
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

                    Interlocked.Increment(ref _accepted);
                    _ = Task.Run(async () =>
                    {
                        using (socket)
                        {
                            using var received = new MemoryStream();
                            var buffer = new byte[4096];
                            while (await socket.ReceiveAsync(buffer, SocketFlags.None) is var read and > 0)
                            {
                                received.Write(buffer, 0, read);
                            }

                            await socket.SendAsync(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(received.ToArray()).ToUpperInvariant()), SocketFlags.None);
                            socket.Shutdown(SocketShutdown.Send);
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        public int Accepted => Volatile.Read(ref _accepted);

        public void Dispose() => _listener.Dispose();
    }

    private static byte[] Socks5Greeting => [5, 1, 0];

    private static byte[] Socks5Connect(string host, int port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var request = new byte[4 + 1 + name.Length + 2];
        request[0] = 5;
        request[1] = 1; // CONNECT
        request[3] = 3; // domain name
        request[4] = (byte)name.Length;
        name.CopyTo(request, 5);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(5 + name.Length), (ushort)port);
        return request;
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, Timeout());
        return buffer;
    }

    private static async Task<string> ReadToEndAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, Timeout());
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    [Test]
    public async Task ASocks5Connection_ReachesTheLocalService()
    {
        using var service = new UpperCaseService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, cancellationToken: Timeout());

        await Assert.That(forwarder.IsDynamic).IsTrue();
        await Assert.That(forwarder.LocalHost).IsEqualTo(string.Empty);
        await Assert.That(forwarder.LocalPort).IsEqualTo(0);
        await Assert.That(server.RemoteForwards[forwarder.RemotePort]).IsEqualTo("localhost");

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync(Socks5Greeting, Timeout());
        await Assert.That(await ReadExactlyAsync(remote, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        await remote.WriteAsync(Socks5Connect("localhost", service.Port), Timeout());
        var reply = await ReadExactlyAsync(remote, 10);
        await Assert.That(reply[1]).IsEqualTo((byte)0); // succeeded

        await remote.WriteAsync("hello through socks"u8.ToArray(), Timeout());
        ((DuplexStream)remote).CloseWrite();
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo("HELLO THROUGH SOCKS");
    }

    [Test]
    public async Task ASocks4aConnection_ByName_ReachesTheLocalService()
    {
        using var service = new UpperCaseService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("", 9050, cancellationToken: Timeout());

        await using var remote = (await server.ConnectForwardedAsync(9050))!;
        byte[] request = [4, 1, 0, 0, 0, 0, 0, 1, 0, .. "localhost"u8, 0];
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)service.Port);
        await remote.WriteAsync(request, Timeout());
        var reply = await ReadExactlyAsync(remote, 8);
        await Assert.That(reply[1]).IsEqualTo((byte)0x5A); // granted

        await remote.WriteAsync("four a"u8.ToArray(), Timeout());
        ((DuplexStream)remote).CloseWrite();
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo("FOUR A");
    }

    [Test]
    public async Task DataSentWithTheRequest_IsNotLost()
    {
        // An optimistic client sends its greeting, request and first data in one go, so they arrive in one channel packet: the bytes
        // after the request were read with it, and must still reach the service.
        using var service = new UpperCaseService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, cancellationToken: Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync((byte[])[.. Socks5Greeting, .. Socks5Connect("127.0.0.1", service.Port), .. "early data"u8], Timeout());
        ((DuplexStream)remote).CloseWrite();

        await Assert.That(await ReadExactlyAsync(remote, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        await Assert.That((await ReadExactlyAsync(remote, 10))[1]).IsEqualTo((byte)0);
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo("EARLY DATA");
    }

    [Test]
    public async Task ADestinationTheFilterRefuses_IsNotConnected()
    {
        using var service = new UpperCaseService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var asked = new List<(string, int)>();
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, (host, port) =>
        {
            lock (asked)
            {
                asked.Add((host, port));
            }

            return host == "allowed.example";
        }, Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync((byte[])[.. Socks5Greeting, .. Socks5Connect("localhost", service.Port)], Timeout());

        await Assert.That(await ReadExactlyAsync(remote, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        await Assert.That((await ReadExactlyAsync(remote, 10))[1]).IsEqualTo((byte)5); // connection refused
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo(string.Empty); // and the channel closes
        await Assert.That(asked).IsEquivalentTo(new[] { ("localhost", service.Port) });
        await Assert.That(service.Accepted).IsEqualTo(0);
    }

    [Test]
    public async Task NothingListeningAtTheDestination_IsRefused()
    {
        // Port 1 on loopback: nothing listens there. A port bound and released could be taken by another test's listener before it is
        // used (a stress run saw a SOCKS proxy answer on one).
        const int unused = 1;

        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, cancellationToken: Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync((byte[])[.. Socks5Greeting, .. Socks5Connect("127.0.0.1", unused)], Timeout());

        await Assert.That(await ReadExactlyAsync(remote, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        await Assert.That((await ReadExactlyAsync(remote, 10))[1]).IsEqualTo((byte)5);
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task SomethingThatIsNotSocks_IsClosed()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, cancellationToken: Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync("GET / HTTP/1.1\r\n\r\n"u8.ToArray(), Timeout());

        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo(string.Empty);
        await Assert.That(client.IsConnected).IsTrue(); // only that connection ends
    }

    [Test]
    public async Task DisposingTheForwarder_CancelsItOnTheServer()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 7000, cancellationToken: Timeout());
        await Assert.That(server.RemoteForwards.ContainsKey(7000)).IsTrue();

        await forwarder.DisposeAsync();

        await Assert.That(server.RemoteForwards.ContainsKey(7000)).IsFalse();
    }

    [Test]
    public async Task RemoteForwardWithOnlyAPort_InSshConfig_IsDynamic()
    {
        var server = new FakeSessionServer();
        await using (server)
        {
            var dir = Directory.CreateTempSubdirectory("sshsharp-rdf-");
            try
            {
                await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
                {
                    Config = SshConfig.Parse("Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n RemoteForward 1080\n RemoteForward 0 127.0.0.1:3000\n"),
                    ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = dir.FullName },
                    Password = TestSecrets.Password,
                    UseAgent = false,
                    StartForwardings = true,
                    TcpConnector = (_, _, _, _) =>
                    {
                        _ = server.StartAsync();
                        return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                    },
                }, Timeout());

                await Assert.That(client.RemoteForwardings.Count).IsEqualTo(2);
                await Assert.That(client.RemoteForwardings[0].IsDynamic).IsTrue();
                await Assert.That(client.RemoteForwardings[0].RemotePort).IsEqualTo(1080);
                await Assert.That(server.RemoteForwards[1080]).IsEqualTo("localhost");
                await Assert.That(client.RemoteForwardings[1].IsDynamic).IsFalse();
            }
            finally
            {
                dir.Delete(recursive: true);
            }
        }
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await Assert.That(async () => await client.ForwardRemoteDynamicPortAsync(null!, 1080)).Throws<ArgumentNullException>();
        await Assert.That(async () => await client.ForwardRemoteDynamicPortAsync("local\nhost", 1080)).Throws<ArgumentException>();
        await Assert.That(async () => await client.ForwardRemoteDynamicPortAsync("localhost", 70000)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(server.RemoteForwards).IsEmpty();
    }
}
