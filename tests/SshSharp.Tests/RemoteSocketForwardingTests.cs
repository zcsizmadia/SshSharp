using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Remote Unix-socket forwarding (<c>ssh -R /remote/socket:target</c>, streamlocal-forward@openssh.com).</summary>
public sealed class RemoteSocketForwardingTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("ssr").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    /// <summary>
    /// A service that answers what it reads in upper case, on TCP or on a Unix socket: at the end of the stream, or at once when what it
    /// read ends with a newline (a framed request, which needs no end of stream; see <see cref="ExchangeAsync"/>).
    /// </summary>
    private sealed class UpperCaseService : IDisposable
    {
        private readonly Socket _listener;
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _events = new();

        public UpperCaseService(EndPoint endPoint)
        {
            _listener = new Socket(endPoint.AddressFamily, SocketType.Stream, endPoint is UnixDomainSocketEndPoint ? ProtocolType.Unspecified : ProtocolType.Tcp);
            _listener.Bind(endPoint);
            _listener.Listen();
            _ = Task.Run(async () =>
            {
                var connection = 0;
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

                    var n = ++connection;
                    Note($"#{n} accepted");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using (socket)
                            {
                                using var received = new MemoryStream();
                                var buffer = new byte[4096];
                                while (await socket.ReceiveAsync(buffer, SocketFlags.None) is var read and > 0)
                                {
                                    received.Write(buffer, 0, read);
                                    Note($"#{n} received {read} bytes");
                                    if (buffer[read - 1] == (byte)'\n')
                                    {
                                        break;
                                    }
                                }

                                Note($"#{n} end of the request after {received.Length} bytes; answering");
                                var sent = await socket.SendAsync(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(received.ToArray()).ToUpperInvariant()), SocketFlags.None);
                                socket.Shutdown(SocketShutdown.Send);
                                Note($"#{n} sent {sent} bytes and shut down its sending side");
                            }
                        }
                        catch (Exception ex)
                        {
                            Note($"#{n} failed: {ex.GetType().Name}: {ex.Message}");
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        /// <summary>What the service did, for a test that hangs.</summary>
        public string Events => string.Join("; ", _events);

        private void Note(string what) => _events.Enqueue($"{DateTime.UtcNow:HH:mm:ss.ffffff} {what}");

        public void Dispose() => _listener.Dispose();
    }

    /// <summary>
    /// Writes <paramref name="request"/>, ends the input, and reads the answer to its end. A hang reports how far it got, what the service
    /// did and (in the instrumented build) the relay's trace.
    /// </summary>
    /// <remarks>
    /// <paramref name="framed"/> ends the request with a newline instead, and reads the answer up to its newline, so neither side needs
    /// the other's end of stream. On Windows, a Unix socket sometimes never delivers the end of stream after a send and a shutdown of
    /// the sending side: about one exchange in a thousand, with plain sockets, no SSH, on .NET 8 and 10, with ReceiveAsync or a blocking
    /// Receive. That was the Unix-socket hang in #188. The relay's half-close is checked over TCP, where it is reliable.
    /// </remarks>
    private static async Task<string> ExchangeAsync(
        Stream remote, string request, UpperCaseService? service = null, string? relayEndPoint = null, bool framed = false)
    {
        var stage = "writing the request";
        using var buffer = new MemoryStream();
        try
        {
            await remote.WriteAsync(Encoding.ASCII.GetBytes(framed ? request + "\n" : request), Timeout());
            if (framed)
            {
                stage = "reading the answer up to its newline";
                var chunk = new byte[256];
                while (buffer.Length == 0 || buffer.GetBuffer()[buffer.Length - 1] != (byte)'\n')
                {
                    var read = await remote.ReadAsync(chunk, Timeout());
                    if (read == 0)
                    {
                        break;
                    }

                    buffer.Write(chunk, 0, read);
                }

                return Encoding.ASCII.GetString(buffer.ToArray()).TrimEnd('\n');
            }

            stage = "ending the input (EOF)";
            ((DuplexStream)remote).CloseWrite();
            stage = "reading the answer";
            await remote.CopyToAsync(buffer, Timeout());
            return Encoding.ASCII.GetString(buffer.ToArray());
        }
        catch (OperationCanceledException ex)
        {
            throw new TimeoutException($"Stuck {stage}; {buffer.Length} bytes of the answer came back. Service: {service?.Events ?? "(none)"}. Relay: {RelayTrace(relayEndPoint)}", ex);
        }
    }

    /// <summary>The instrumented build's trace of the relay for <paramref name="endPoint"/> (its start event names the socket), or of the last relays.</summary>
    private static string RelayTrace(string? endPoint)
    {
        if (!SshSharp.Protocol.Instrumentation.Enabled)
        {
            return "(not traced: build with -p:SshSharpInstrument=true)";
        }

        var start = endPoint is null ? null : SshSharp.Protocol.Instrumentation.RecentTrace(endPoint, max: 1);
        var id = start is { Length: > 0 } ? System.Text.RegularExpressions.Regex.Match(start, @"relay#\d+").Value : null;
        return Environment.NewLine + SshSharp.Protocol.Instrumentation.RecentTrace(id is { Length: > 0 } ? id + ":" : "relay#", max: id is { Length: > 0 } ? 60 : 30);
    }

    [Test]
    public async Task ConnectionsToTheRemoteSocket_ReachALocalTcpService()
    {
        using var service = new UpperCaseService(new IPEndPoint(IPAddress.Loopback, 0));
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await using var forwarder = await client.ForwardRemoteUnixSocketAsync("/run/app/db.sock", "127.0.0.1", service.Port, Timeout());

        await Assert.That(server.RemoteSocketForwards).Contains("/run/app/db.sock");
        await Assert.That(forwarder.RemoteSocketPath).IsEqualTo("/run/app/db.sock");
        await Assert.That((forwarder.LocalHost, forwarder.LocalPort, forwarder.LocalSocketPath)).IsEqualTo(("127.0.0.1", service.Port, (string?)null));
        var answers = await Task.WhenAll(Enumerable.Range(0, 3).Select(async i =>
        {
            await using var remote = (await server.ConnectForwardedSocketAsync("/run/app/db.sock"))!;
            return await ExchangeAsync(remote, $"query {i}", service);
        }));
        await Assert.That(answers).IsEquivalentTo(["QUERY 0", "QUERY 1", "QUERY 2"]);
    }

    [Test]
    public async Task ConnectionsToTheRemoteSocket_ReachALocalUnixSocket()
    {
        var local = Path.Combine(_dir, "agent.sock");
        using var service = new UpperCaseService(new UnixDomainSocketEndPoint(local));
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await using var forwarder = await client.ForwardRemoteUnixSocketAsync("/home/tester/.gnupg/S.gpg-agent", local, Timeout());

        await Assert.That(forwarder.LocalSocketPath).IsEqualTo(local);
        await using var remote = (await server.ConnectForwardedSocketAsync("/home/tester/.gnupg/S.gpg-agent"))!;
        await Assert.That(await ExchangeAsync(remote, "sign this", service, local, framed: true)).IsEqualTo("SIGN THIS");
    }

    [Test]
    public async Task ChannelsForSocketsNotForwarded_AreRefused_AndNothingListeningClosesTheConnection()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardRemoteUnixSocketAsync("/run/forwarded.sock", Path.Combine(_dir, "nothing-here.sock"), Timeout());

        await Assert.That(await server.ConnectForwardedSocketAsync("/run/other.sock")).IsNull();

        await using var remote = (await server.ConnectForwardedSocketAsync("/run/forwarded.sock"))!;
        await Assert.That(await ExchangeAsync(remote, "hello")).IsEqualTo(string.Empty);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task ARefusingServer_FailsTheRequest_AndDisposeCancelsIt()
    {
        await using (var refusing = new FakeSessionServer { RefuseRemoteForwarding = true })
        {
            await using var client = await ConnectAsync(refusing);
            await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("/run/x.sock", "127.0.0.1", 1, Timeout())).Throws<SshException>();

            // Not registered: a later try with an allowed path is not "already forwarded".
            await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("/run/x.sock", "127.0.0.1", 1, Timeout())).Throws<SshException>();
        }

        await using var server = new FakeSessionServer();
        await using var connected = await ConnectAsync(server);
        var forwarder = await connected.ForwardRemoteUnixSocketAsync("/run/y.sock", "127.0.0.1", 1, Timeout());
        await Assert.That(async () => await connected.ForwardRemoteUnixSocketAsync("/run/y.sock", "127.0.0.1", 2, Timeout())).Throws<SshException>();
        await forwarder.DisposeAsync();
        await Assert.That(server.CancelledRemoteSocketForwards).Contains("/run/y.sock");
        await Assert.That(server.RemoteSocketForwards).DoesNotContain("/run/y.sock");
    }

    [Test]
    public async Task RemoteForward_WithASocketPath_InSshConfig()
    {
        using var service = new UpperCaseService(new IPEndPoint(IPAddress.Loopback, 0));
        var dir = _dir.Replace('\\', '/');
        var server = new FakeSessionServer();
        await using (server)
        {
            await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse($"Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n RemoteForward /run/app.sock 127.0.0.1:{service.Port}\n RemoteForward /run/agent.sock {dir}/agent.sock\n"),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                Password = "secret",
                UseAgent = false,
                StartForwardings = true,
                TcpConnector = (_, _, _, _) =>
                {
                    _ = server.StartAsync();
                    return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                },
            }, Timeout());

            await Assert.That(client.RemoteSocketForwardings.Count).IsEqualTo(2);
            await Assert.That(client.RemoteSocketForwardings[0].LocalPort).IsEqualTo(service.Port);
            await Assert.That(client.RemoteSocketForwardings[1].LocalSocketPath).IsEqualTo($"{dir}/agent.sock");
            await using var remote = (await server.ConnectForwardedSocketAsync("/run/app.sock"))!;
            await Assert.That(await ExchangeAsync(remote, "from config", service)).IsEqualTo("FROM CONFIG");
        }
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("", "127.0.0.1", 1)).Throws<ArgumentException>();
        await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("/a\nb", "127.0.0.1", 1)).Throws<ArgumentException>();
        await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("/a", "127.0.0.1", 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(async () => await client.ForwardRemoteUnixSocketAsync("/a", "")).Throws<ArgumentException>();
        await Assert.That(server.RemoteSocketForwards).IsEmpty();
    }
}
