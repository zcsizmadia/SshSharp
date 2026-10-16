using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Remote forwarding against a server (or remote applications) that misbehave: destination filters that address spellings must not get
/// past, filters that throw, too many forwarded connections, requests cancelled after the server accepted them, and what is logged.
/// </summary>
public class ForwardingHardeningTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, int maxForwarded = 1000, ILogger? logger = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            MaxForwardedConnections = maxForwarded,
            Logger = logger,
        }, leaveOpen: true, Timeout());
    }

    /// <summary>A local service on loopback (IPv4) that counts connections and holds each one open until the other side ends it.</summary>
    private sealed class HoldingService : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private int _accepted;

        public HoldingService()
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
                            var buffer = new byte[1024];
                            while (await socket.ReceiveAsync(buffer, SocketFlags.None) > 0)
                            {
                            }
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        public int Accepted => Volatile.Read(ref _accepted);

        public void Dispose() => _listener.Dispose();
    }

    private static byte[] Socks5ConnectByName(string host, int port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        byte[] request = [5, 1, 0, 5, 1, 0, 3, (byte)name.Length, .. name, 0, 0];
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(request.Length - 2), (ushort)port);
        return request;
    }

    private static async Task<byte> SocksReplyAsync(Stream remote)
    {
        var reply = new byte[12]; // method choice (2) and the CONNECT reply (10)
        await remote.ReadExactlyAsync(reply, Timeout());
        return reply[3];
    }

    [Test]
    [Arguments("127.1")]
    [Arguments("2130706433")]
    [Arguments("0x7f.1")]
    [Arguments("::ffff:127.0.0.1")]
    [Arguments("[::1]")]
    [Arguments("localhost")]
    public async Task AFilterThatRefusesLoopback_CannotBeBypassedWithAnotherSpelling(string spelling)
    {
        using var service = new HoldingService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var asked = new List<string>();
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, (host, _) =>
        {
            lock (asked)
            {
                asked.Add(host);
            }

            // A filter written for the obvious spellings only.
            return host is not ("127.0.0.1" or "::1");
        }, Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync(Socks5ConnectByName(spelling, service.Port), Timeout());

        await Assert.That(await SocksReplyAsync(remote)).IsEqualTo((byte)5); // refused
        await Assert.That(service.Accepted).IsEqualTo(0);
        string[] seen;
        lock (asked)
        {
            seen = [.. asked];
        }

        // Literals are checked in canonical form; a name is checked as given and then as each address it resolves to.
        await Assert.That(seen.Intersect(["127.0.0.1", "::1"]).Any()).IsTrue();
    }

    [Test]
    public async Task AnAllowedName_ConnectsOnlyToTheAddressesTheFilterAllowed()
    {
        using var service = new HoldingService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var asked = new List<string>();
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, (host, _) =>
        {
            lock (asked)
            {
                asked.Add(host);
            }

            return host is "localhost" or "127.0.0.1"; // the name, and its IPv4 address (the service listens there)
        }, Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync(Socks5ConnectByName("localhost", service.Port), Timeout());

        await Assert.That(await SocksReplyAsync(remote)).IsEqualTo((byte)0);
        string[] seen;
        lock (asked)
        {
            seen = [.. asked];
        }

        await Assert.That(seen[0]).IsEqualTo("localhost");
        await Assert.That(seen).Contains("127.0.0.1");
    }

    [Test]
    public async Task AFilterThatThrows_RefusesTheConnection_AndDisposeDoesNotThrow()
    {
        using var service = new HoldingService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0,
            (_, _) => throw new InvalidOperationException("filter bug"), Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await remote.WriteAsync(Socks5ConnectByName("127.0.0.1", service.Port), Timeout());

        await Assert.That(await SocksReplyAsync(remote)).IsEqualTo((byte)5);
        await Assert.That(service.Accepted).IsEqualTo(0);
        await forwarder.DisposeAsync(); // must not rethrow anything from the connection
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task TooManyForwardedConnections_AreRefused_UntilOneEnds()
    {
        using var service = new HoldingService();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, maxForwarded: 2);
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", service.Port, Timeout());

        var first = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await using var second = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        await Assert.That(await server.ConnectForwardedAsync(forwarder.RemotePort)).IsNull(); // the third is refused

        // Ending one frees its slot.
        await first.DisposeAsync();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (client.ForwardedConnections > 1 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        await using var third = await server.ConnectForwardedAsync(forwarder.RemotePort);
        await Assert.That(third).IsNotNull();
        await Assert.That(() => new SshClientOptions { UserName = "u", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:x"), MaxForwardedConnections = 0 })
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task ASocketForwardCancelledAfterTheServerAccepted_IsWithdrawn_AndCanBeRetried()
    {
        await using var server = new FakeSessionServer { HoldForwardReplies = new TaskCompletionSource() };
        await using var client = await ConnectAsync(server);

        using var cancel = new CancellationTokenSource();
        var attempt = client.ForwardRemoteUnixSocketAsync("/run/app.sock", "127.0.0.1", 1, cancel.Token);
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!server.RemoteSocketForwards.Contains("/run/app.sock") && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10); // the server has accepted it, but not yet answered
        }

        await cancel.CancelAsync();
        await Assert.That(async () => await attempt).Throws<OperationCanceledException>();

        // The client withdraws it (the cancel follows the request, so the server handles it after accepting).
        server.HoldForwardReplies!.SetResult();
        while (!server.CancelledRemoteSocketForwards.Contains("/run/app.sock") && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        await Assert.That(server.RemoteSocketForwards).DoesNotContain("/run/app.sock");

        // Not left registered: trying again works.
        server.HoldForwardReplies = null;
        await using var retry = await client.ForwardRemoteUnixSocketAsync("/run/app.sock", "127.0.0.1", 1, Timeout());
        await Assert.That(server.RemoteSocketForwards).Contains("/run/app.sock");
    }

    [Test]
    public async Task APortForwardCancelledAfterTheServerAccepted_IsWithdrawn()
    {
        await using var server = new FakeSessionServer { HoldForwardReplies = new TaskCompletionSource() };
        await using var client = await ConnectAsync(server);

        using var cancel = new CancellationTokenSource();
        var attempt = client.ForwardRemotePortAsync("localhost", 7100, "127.0.0.1", 1, cancel.Token);
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!server.RemoteForwards.ContainsKey(7100) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        await cancel.CancelAsync();
        await Assert.That(async () => await attempt).Throws<OperationCanceledException>();
        server.HoldForwardReplies!.SetResult();
        while (!server.CancelledRemoteForwards.Contains(7100) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        await Assert.That(server.RemoteForwards.ContainsKey(7100)).IsFalse();
    }

    [Test]
    public async Task ASkippedConfiguredForwarding_IsLoggedWithoutItsHostsOrPaths()
    {
        var logger = new CapturingLogger();
        var server = new FakeSessionServer { RefuseRemoteForwarding = true };
        await using (server)
        {
            var dir = Directory.CreateTempSubdirectory("sshsharp-fwdlog-");
            try
            {
                await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
                {
                    Config = SshConfig.Parse("Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"
                        + " RemoteForward 8080 internal-db.example:5432\n RemoteForward /run/secret-app.sock 127.0.0.1:3000\n LocalForward unsupported\n"),
                    ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = dir.FullName },
                    Password = "secret",
                    UseAgent = false,
                    StartForwardings = true,
                    Logger = logger,
                    TcpConnector = (_, _, _, _) =>
                    {
                        _ = server.StartAsync();
                        return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                    },
                }, Timeout());

                var all = string.Join("\n", logger.Messages);
                await Assert.That(all).Contains("RemoteForward number 1 for this host was skipped");
                await Assert.That(all).Contains("RemoteForward number 2 for this host was skipped");
                await Assert.That(all).Contains("LocalForward number 1 for this host was skipped");
                await Assert.That(all).DoesNotContain("internal-db");
                await Assert.That(all).DoesNotContain("secret-app");
            }
            finally
            {
                dir.Delete(recursive: true);
            }
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AFailureBeforeTheHandshake_StillDisposesTheStream_UnlessLeftOpen(bool leaveOpen)
    {
        // The known_hosts lookup that comes before the handshake is cancelled: the stream handed over must not leak.
        var stream = new TrackingStream();
        await Assert.That(async () => await SshClient.ConnectAsync(stream, new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = new CancelledLookupVerifier(),
        }, leaveOpen, Timeout())).Throws<OperationCanceledException>();

        await Assert.That(stream.Disposed).IsEqualTo(!leaveOpen);
    }

    private sealed class TrackingStream : MemoryStream
    {
        public bool Disposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class CancelledLookupVerifier : SshHostKeyVerifier
    {
        public override ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("not reached");

        internal override ValueTask<bool> PrefersCertificatesAsync(string? host, int port, string? hostKeyAlias, CancellationToken cancellationToken) =>
            ValueTask.FromException<bool>(new OperationCanceledException());
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception));
            }
        }
    }
}
