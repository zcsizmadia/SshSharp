using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>LocalForward, RemoteForward and DynamicForward from ssh_config: parsing, bind addresses, and starting them on connect.</summary>
public sealed class ConfigForwardingTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-cfgfwd-" + Guid.NewGuid().ToString("N"));

    public ConfigForwardingTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Test]
    [Arguments("8080 db:5432", null, 8080, "db", 5432)]
    [Arguments("127.0.0.1:8080 db.internal:5432", "127.0.0.1", 8080, "db.internal", 5432)]
    [Arguments("[::1]:8080 [2001:db8::1]:22", "::1", 8080, "2001:db8::1", 22)]
    [Arguments("*:0  web:80", "*", 0, "web", 80)]
    [Arguments("localhost:2222 localhost:22", "localhost", 2222, "localhost", 22)]
    public async Task Forwards_Parse(string spec, string? bind, int port, string host, int hostPort)
    {
        var (listen, target) = ForwardSpec.ParseForward(spec)!.Value;
        await Assert.That(listen).IsEqualTo(new ForwardListen(bind, port));
        await Assert.That(target).IsEqualTo(new ForwardTarget(host, hostPort));
    }

    [Test]
    [Arguments("8080")]
    [Arguments("8080 /var/run/db.sock")]
    [Arguments("/tmp/local.sock db:5432")]
    [Arguments("8080 db:")]
    [Arguments("8080 db:0")]
    [Arguments("8080 db:70000")]
    [Arguments("abc db:1")]
    [Arguments("70000 db:1")]
    [Arguments("8080 :22")]
    [Arguments("[::1 db:1")]
    [Arguments("8080 db:1 extra")]
    public async Task UnsupportedForwards_DoNotParse(string spec) =>
        await Assert.That(ForwardSpec.ParseForward(spec)).IsNull();

    [Test]
    [Arguments(null, false, "127.0.0.1")]
    [Arguments(null, true, "0.0.0.0")]
    [Arguments("localhost", true, "127.0.0.1")]
    [Arguments("*", false, "0.0.0.0")]
    [Arguments("", false, "0.0.0.0")]
    [Arguments("::1", false, "::1")]
    [Arguments("192.0.2.7", false, "192.0.2.7")]
    public async Task LocalBindAddresses_FollowSsh(string? bind, bool gatewayPorts, string expected) =>
        await Assert.That(SshClient.LocalBind(new ForwardListen(bind, 1080), gatewayPorts).Address.ToString()).IsEqualTo(expected);

    [Test]
    public async Task ABindAddressThatIsAName_IsNotSupported() =>
        await Assert.That(() => SshClient.LocalBind(new ForwardListen("myhost", 1), false)).Throws<FormatException>();

    private async Task<(FakeSessionServer Server, SshClient Client)> ConnectAsync(string forwardings, bool start = true)
    {
        var server = new FakeSessionServer { DirectTcpIp = (_, _) => Echo() };
        var config = $"Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n{forwardings}";
        var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = "secret",
            UseAgent = false,
            StartForwardings = start,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        return (server, client);
    }

    /// <summary>A service that answers each request with its upper-case form.</summary>
    private static DuplexStream Echo()
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

    [Test]
    public async Task ConfiguredForwardings_StartOnConnect_AndStopWithTheClient()
    {
        var (server, client) = await ConnectAsync(" LocalForward 0 db.internal:5432\n RemoteForward 0 127.0.0.1:3000\n DynamicForward 127.0.0.1:0\n");
        await using (server)
        {
            await Assert.That(client.LocalForwardings.Count).IsEqualTo(1);
            await Assert.That(client.RemoteForwardings.Count).IsEqualTo(1);
            await Assert.That(client.DynamicForwardings.Count).IsEqualTo(1);

            var local = client.LocalForwardings[0];
            await Assert.That(local.LocalEndPoint.Address).IsEqualTo(IPAddress.Loopback);
            await Assert.That((local.RemoteHost, local.RemotePort)).IsEqualTo(("db.internal", 5432));
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                await socket.ConnectAsync(local.LocalEndPoint, Timeout());
                await socket.SendAsync("ping"u8.ToArray(), SocketFlags.None, Timeout());
                socket.Shutdown(SocketShutdown.Send);
                var reply = new byte[4];
                var read = 0;
                while (read < 4 && await socket.ReceiveAsync(reply.AsMemory(read), SocketFlags.None, Timeout()) is var n and > 0)
                {
                    read += n;
                }

                await Assert.That(Encoding.ASCII.GetString(reply)).IsEqualTo("PING");
            }

            // ssh's default for RemoteForward without a bind address is the server's loopback.
            await Assert.That(server.RemoteForwards[client.RemoteForwardings[0].RemotePort]).IsEqualTo("localhost");

            await client.DisposeAsync();
            await Assert.That(local.IsListening).IsFalse();
            await Assert.That(client.DynamicForwardings[0].IsListening).IsFalse();
        }
    }

    [Test]
    public async Task WithoutStartForwardings_NothingIsStarted()
    {
        var (server, client) = await ConnectAsync(" LocalForward 0 db:5432\n DynamicForward 0\n", start: false);
        await using (server)
        await using (client)
        {
            await Assert.That(client.LocalForwardings).IsEmpty();
            await Assert.That(client.DynamicForwardings).IsEmpty();
        }
    }

    [Test]
    public async Task AForwardingThatCannotStart_IsSkipped_OrFailsTheConnectionWithExitOnForwardFailure()
    {
        var (server, client) = await ConnectAsync(" LocalForward 0 /var/run/db.sock\n DynamicForward 127.0.0.1:0\n");
        await using (server)
        await using (client)
        {
            await Assert.That(client.LocalForwardings).IsEmpty(); // a Unix-socket target is not supported
            await Assert.That(client.DynamicForwardings.Count).IsEqualTo(1); // the rest still start
        }

        await using var refusing = new FakeSessionServer { RefuseRemoteForwarding = true };
        var config = "Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n ExitOnForwardFailure yes\n RemoteForward 0 127.0.0.1:3000\n";
        var error = await Assert.ThrowsAsync<SshException>(() => SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = "secret",
            UseAgent = false,
            StartForwardings = true,
            TcpConnector = (_, _, _, _) =>
            {
                _ = refusing.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((refusing.ClientStream, null));
            },
        }, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.Message).Contains("RemoteForward");
    }

    [Test]
    public async Task ClearAllForwardings_EmptiesTheLists()
    {
        var resolved = SshConfig.Parse("Host *\n LocalForward 8080 a:80\n RemoteForward 9090 b:90\n DynamicForward 1080\n ClearAllForwardings yes\n GatewayPorts yes\n ExitOnForwardFailure yes\n")
            .Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir });
        await Assert.That(resolved.LocalForwards).IsEmpty();
        await Assert.That(resolved.RemoteForwards).IsEmpty();
        await Assert.That(resolved.DynamicForwards).IsEmpty();
        await Assert.That(resolved.GatewayPorts).IsTrue();
        await Assert.That(resolved.ExitOnForwardFailure).IsTrue();
    }
}
