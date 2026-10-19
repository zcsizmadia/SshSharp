using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Local forwarding with Unix sockets (<c>ssh -L /local.sock:host:port</c>, <c>-L port:/remote.sock</c>, <c>-L /local.sock:/remote.sock</c>),
/// in code and from <c>LocalForward</c>, against the fake server relaying to in-memory services.
/// </summary>
public sealed class LocalSocketForwardingTests : IDisposable
{
    // Short: a Unix socket path is limited to about 104 bytes (macOS) or 108 (Linux), and the temporary directory can be long.
    private readonly string _dir = Directory.CreateTempSubdirectory("ssl").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string SocketPath(string name = "fwd.sock") => Path.Combine(_dir, name);

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

    /// <summary>
    /// Sends <paramref name="request"/> over a new connection to <paramref name="endPoint"/>, ends its side, and reads as many bytes back.
    /// It reads a known length rather than to the end: Windows can lose the end of stream on a Unix socket (see docs/connecting.md).
    /// </summary>
    private static async Task<string> ExchangeAsync(EndPoint endPoint, string request)
    {
        using var socket = endPoint is UnixDomainSocketEndPoint
            ? new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)
            : new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(endPoint, Timeout());
        await socket.SendAsync(Encoding.ASCII.GetBytes(request), SocketFlags.None, Timeout());
        socket.Shutdown(SocketShutdown.Send);
        var reply = new byte[request.Length];
        var read = 0;
        while (read < reply.Length && await socket.ReceiveAsync(reply.AsMemory(read), SocketFlags.None, Timeout()) is var n and > 0)
        {
            read += n;
        }

        return Encoding.ASCII.GetString(reply, 0, read);
    }

    [Test]
    public async Task ALocalSocket_IsForwardedToAHostAndPort_FromLoopbackAsSshSays()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalUnixSocketAsync(SocketPath(), "db.internal", 5432, Timeout());

        await Assert.That(forwarder.LocalSocketPath).IsEqualTo(SocketPath());
        await Assert.That((forwarder.RemoteHost, forwarder.RemotePort, forwarder.RemoteSocketPath)).IsEqualTo(("db.internal", 5432, (string?)null));
        await Assert.That(await ExchangeAsync(new UnixDomainSocketEndPoint(SocketPath()), "ping")).IsEqualTo("PING");
        await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });

        // A Unix socket has no address: the originator is 127.0.0.1:65535, as ssh sends it.
        await Assert.That(server.DirectTcpIpOriginators).IsEquivalentTo(new[] { "127.0.0.1:65535" });
    }

    [Test]
    public async Task ALocalSocket_IsForwardedToASocketOnTheServer()
    {
        await using var server = new FakeSessionServer { DirectStreamLocal = _ => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalUnixSocketAsync(SocketPath(), "/var/run/docker.sock", Timeout());

        await Assert.That((forwarder.RemoteHost, forwarder.RemotePort, forwarder.RemoteSocketPath)).IsEqualTo(((string?)null, 0, "/var/run/docker.sock"));
        await Assert.That(await ExchangeAsync(new UnixDomainSocketEndPoint(SocketPath()), "info")).IsEqualTo("INFO");
        await Assert.That(server.DirectStreamLocalRequests).IsEquivalentTo(new[] { "/var/run/docker.sock" });
    }

    [Test]
    public async Task ALocalPort_IsForwardedToASocketOnTheServer()
    {
        await using var server = new FakeSessionServer { DirectStreamLocal = _ => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "/run/postgresql/.s.PGSQL.5432", Timeout());

        await Assert.That(forwarder.RemoteSocketPath).IsEqualTo("/run/postgresql/.s.PGSQL.5432");
        await Assert.That((forwarder.RemoteHost, forwarder.RemotePort)).IsEqualTo((string.Empty, 0));
        await Assert.That(await ExchangeAsync(forwarder.LocalEndPoint, "select")).IsEqualTo("SELECT");
        await Assert.That(server.DirectStreamLocalRequests).IsEquivalentTo(new[] { "/run/postgresql/.s.PGSQL.5432" });
        await Assert.That(server.DirectTcpIpRequests).IsEmpty();
    }

    [Test]
    public async Task TheSocketFile_IsOwnerOnly_AndRemovedWhenTheForwarderStops()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService() };
        await using var client = await ConnectAsync(server);
        var forwarder = await client.ForwardLocalUnixSocketAsync(SocketPath(), "db", 1, Timeout());

        await Assert.That(File.Exists(SocketPath())).IsTrue();
        if (OperatingSystem.IsWindows())
        {
            await Assert.That(IsOwnerOnly(SocketPath())).IsTrue();
        }
        else
        {
            await Assert.That(File.GetUnixFileMode(SocketPath())).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await forwarder.DisposeAsync();
        await Assert.That(forwarder.IsListening).IsFalse();
        await Assert.That(File.Exists(SocketPath())).IsFalse();
    }

    /// <summary>An ACL with the current user only, nothing inherited from the directory.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsOwnerOnly(string path)
    {
        var acl = new FileInfo(path).GetAccessControl();
        using var me = System.Security.Principal.WindowsIdentity.GetCurrent();
        var rules = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
        return acl.AreAccessRulesProtected && rules.Count > 0 && rules.All(r => !r.IsInherited && r.IdentityReference.Value == me.User!.Value);
    }

    [Test]
    public async Task TheSocketFile_IsRemovedWhenTheClientIsDisposed()
    {
        await using var server = new FakeSessionServer();
        var client = await ConnectAsync(server);
        var forwarder = await client.ForwardLocalUnixSocketAsync(SocketPath(), "db", 1, Timeout());
        await client.DisposeAsync(); // the connection ends: the listener stops, and removes its file
        await forwarder.DisposeAsync();
        await Assert.That(File.Exists(SocketPath())).IsFalse();
    }

    [Test]
    public async Task AnExistingFile_IsNotReplaced()
    {
        await File.WriteAllTextAsync(SocketPath(), "not a socket");
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<SocketException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "db", 1, Timeout()));
        await Assert.That(await File.ReadAllTextAsync(SocketPath())).IsEqualTo("not a socket");
    }

    [Test]
    public async Task ARefusedConnection_ClosesThatConnectionOnly()
    {
        await using var server = new FakeSessionServer { DirectStreamLocal = _ => null };
        await using var client = await ConnectAsync(server);
        await using var forwarder = await client.ForwardLocalUnixSocketAsync(SocketPath(), "/nothing.sock", Timeout());

        using (var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath()), Timeout());
            var buffer = new byte[1];
            int read;
            try
            {
                read = await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout());
            }
            catch (SocketException)
            {
                read = 0; // reset rather than closed: either way the connection ended
            }

            await Assert.That(read).IsEqualTo(0);
        }

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(File.Exists(SocketPath())).IsTrue(); // still listening
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalUnixSocketAsync("", "db", 1, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalUnixSocketAsync(SocketPath("a\nb"), "db", 1, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "", 1, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "db", 0, Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "", Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "", Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "/a\0b", Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardLocalUnixSocketAsync(Path.Combine(_dir, new string('x', 200)), "db", 1, Timeout()));
        await Assert.That(server.Channels).IsEmpty();
        await Assert.That(Directory.GetFiles(_dir)).IsEmpty();
    }

    private async Task<(FakeSessionServer Server, SshClient Client)> ConnectByConfigAsync(string forwardings)
    {
        var server = new FakeSessionServer { DirectTcpIp = (_, _) => UpperCaseService(), DirectStreamLocal = _ => UpperCaseService() };
        var config = $"Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n{forwardings}";
        var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
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
        return (server, client);
    }

    [Test]
    public async Task LocalForward_TakesEveryUnixSocketForm()
    {
        // ~ and tokens are expanded in the paths, as ssh does (%n is the alias).
        var (server, client) = await ConnectByConfigAsync(
            " LocalForward ~/to-tcp.sock db.internal:5432\n LocalForward %d/%n.sock /var/run/docker.sock\n LocalForward 127.0.0.1:0 /run/app.sock\n");
        await using (server)
        await using (client)
        {
            var toTcp = Path.Combine(_dir, "to-tcp.sock");
            var toSocket = Path.Combine(_dir, "target.sock");
            await Assert.That(client.LocalSocketForwardings.Select(f => Path.GetFullPath(f.LocalSocketPath))).IsEquivalentTo(new[] { toTcp, toSocket });
            await Assert.That(client.LocalSocketForwardings[0].RemoteHost).IsEqualTo("db.internal");
            await Assert.That(client.LocalSocketForwardings[1].RemoteSocketPath).IsEqualTo("/var/run/docker.sock");
            var portToSocket = client.LocalForwardings.Single();
            await Assert.That(portToSocket.RemoteSocketPath).IsEqualTo("/run/app.sock");
            await Assert.That(portToSocket.LocalEndPoint.Address).IsEqualTo(IPAddress.Loopback);

            await Assert.That(await ExchangeAsync(new UnixDomainSocketEndPoint(toTcp), "one")).IsEqualTo("ONE");
            await Assert.That(await ExchangeAsync(new UnixDomainSocketEndPoint(toSocket), "two")).IsEqualTo("TWO");
            await Assert.That(await ExchangeAsync(portToSocket.LocalEndPoint, "three")).IsEqualTo("THREE");
            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });
            await Assert.That(server.DirectStreamLocalRequests).IsEquivalentTo(new[] { "/var/run/docker.sock", "/run/app.sock" });

            await client.DisposeAsync();
            await Assert.That(File.Exists(toTcp)).IsFalse();
            await Assert.That(File.Exists(toSocket)).IsFalse();
        }
    }

    [Test]
    public async Task AStaleSocketFile_IsReplacedOnlyWithStreamLocalBindUnlink()
    {
        var stale = Path.Combine(_dir, "stale.sock");
        await File.WriteAllTextAsync(stale, "left behind");

        var (server, client) = await ConnectByConfigAsync($" LocalForward \"{stale}\" db:1\n");
        await using (server)
        await using (client)
        {
            await Assert.That(client.LocalSocketForwardings).IsEmpty(); // skipped, as ssh does without StreamLocalBindUnlink
            await Assert.That(await File.ReadAllTextAsync(stale)).IsEqualTo("left behind");
        }

        (server, client) = await ConnectByConfigAsync($" LocalForward \"{stale}\" db:1\n StreamLocalBindUnlink yes\n");
        await using (server)
        await using (client)
        {
            await Assert.That(Path.GetFullPath(client.LocalSocketForwardings.Single().LocalSocketPath)).IsEqualTo(stale);
            await Assert.That(await ExchangeAsync(new UnixDomainSocketEndPoint(stale), "fresh")).IsEqualTo("FRESH");
        }
    }

    [Test]
    public async Task ASocketForwardThatCannotStart_FailsTheConnectionWithExitOnForwardFailure()
    {
        var path = Path.Combine(_dir, "taken.sock");
        await File.WriteAllTextAsync(path, string.Empty);
        var error = await Assert.ThrowsAsync<SshException>(() => ConnectByConfigAsync($" LocalForward \"{path}\" db:1\n ExitOnForwardFailure yes\n"));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.Message).Contains("LocalForward number 1");
        await Assert.That(error.Message).DoesNotContain(path); // paths stay out of messages
    }
}
