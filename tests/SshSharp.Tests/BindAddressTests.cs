using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Connecting from a chosen local address or interface (#127): LocalEndPoint, BindAddress, BindInterface.</summary>
public sealed class BindAddressTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-bind-" + Guid.NewGuid().ToString("N"));

    public BindAddressTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>127.0.0.2 is loopback on Linux and Windows but not the address the system would pick, so seeing it proves the bind.</summary>
    private static readonly IPAddress Alternate = IPAddress.Parse("127.0.0.2");

    private static bool AlternateUsable()
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(Alternate, 0));
            return true;
        }
        catch (SocketException)
        {
            return false; // macOS configures only 127.0.0.1 on lo0 (CI adds 127.0.0.2 as an alias)
        }
    }

    /// <summary>A loopback listener that relays its one connection to a fake SSH server, and records where the connection came from.</summary>
    private sealed class Bridge : IAsyncDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly Task _serve;

        public Bridge(FakeSessionServer server)
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen();
            _serve = Task.Run(async () =>
            {
                using var socket = await _listener.AcceptAsync();
                Remote = (IPEndPoint)socket.RemoteEndPoint!;
                _ = server.StartAsync();
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                await Task.WhenAny(stream.CopyToAsync(server.ClientStream), server.ClientStream.CopyToAsync(stream));
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        public IPEndPoint? Remote { get; private set; }

        public async ValueTask DisposeAsync()
        {
            _listener.Dispose();
            try
            {
                await _serve.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception)
            {
                // Ended with the test.
            }
        }
    }

    [Test]
    public async Task LocalEndPoint_IsWhereTheConnectionComesFrom()
    {
        if (!AlternateUsable())
        {
            Skip.Test("127.0.0.2 is not configured on this machine.");
            return;
        }

        await using var server = new FakeSessionServer();
        await using var bridge = new Bridge(server);

        await using var client = await SshClient.ConnectAsync("127.0.0.1", bridge.Port, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            LocalEndPoint = new IPEndPoint(Alternate, 0),
        }, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(bridge.Remote!.Address).IsEqualTo(Alternate);
    }

    [Test]
    public async Task BindAddress_InSshConfig_IsWhereTheConnectionComesFrom()
    {
        if (!AlternateUsable())
        {
            Skip.Test("127.0.0.2 is not configured on this machine.");
            return;
        }

        await using var server = new FakeSessionServer();
        await using var bridge = new Bridge(server);

        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse($"Host target\n HostName 127.0.0.1\n Port {bridge.Port}\n User tester\n BindAddress 127.0.0.2\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = TestSecrets.Password,
            UseAgent = false,
        }, Timeout());

        await Assert.That(bridge.Remote!.Address).IsEqualTo(Alternate);
    }

    [Test]
    public async Task AnIpv4Bind_CannotReachAnIpv6OnlyDestination()
    {
        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("::1", 22, [new IPEndPoint(IPAddress.Loopback, 0)], SshAddressFamily.Any, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Message).Contains("family");
    }

    [Test]
    public async Task AnAddressNotOnThisMachine_IsABindFailure()
    {
        // TEST-NET-3 (RFC 5737): never a local address.
        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("127.0.0.1", 22, [new IPEndPoint(IPAddress.Parse("203.0.113.7"), 0)], SshAddressFamily.Any, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Message).Contains("bind to the local address");
    }

    [Test]
    [Arguments(SshAddressFamily.Inet)]
    [Arguments(SshAddressFamily.Inet6)]
    public async Task AnAddressFamily_ConnectsOverThatFamily(SshAddressFamily family)
    {
        var ipv6 = family == SshAddressFamily.Inet6;
        if (ipv6 && !Socket.OSSupportsIPv6)
        {
            Skip.Test("This machine has no IPv6.");
            return;
        }

        using var listener = new Socket(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        listener.Listen();
        var accepted = listener.AcceptAsync(Timeout()).AsTask();

        // Without a bind: the socket itself is of the family (AddressFamily inet or inet6 in ssh_config).
        await using var stream = await TcpConnector.ConnectAsync(ipv6 ? "::1" : "127.0.0.1", ((IPEndPoint)listener.LocalEndPoint!).Port, null, family, "the server", Timeout());
        using var server = await accepted.WaitAsync(Timeout());
        await Assert.That(server.RemoteEndPoint!.AddressFamily).IsEqualTo(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
    }

    [Test]
    public async Task AHostThatDoesNotResolve_WithABind_IsAConnectFailure()
    {
        // .invalid never resolves (RFC 6761). With a bind, the connector resolves the name itself to match families.
        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("sshsharp-test.invalid", 22, [new IPEndPoint(IPAddress.Loopback, 0)], SshAddressFamily.Any, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).Contains("resolve the address of the server");
    }

    [Test]
    public async Task AnAddressFamily_ThatExcludesEveryDestination_WithABind_SaysSo()
    {
        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("127.0.0.1", 22, [new IPEndPoint(IPAddress.Loopback, 0)], SshAddressFamily.Inet6, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Message).Contains("family");
    }

    [Test]
    public async Task ARefusedConnection_WithABind_IsAConnectFailure()
    {
        // Port 1 (tcpmux), where nothing listens, so the connection is refused at once. Not a port that was merely free a moment ago:
        // that can be taken by another test's listener, or be the very port the client's own bind gets, so that the socket connects to
        // itself (a Windows stress run connected). Port 1 is outside every ephemeral range, so neither can happen. Nor a port held by a
        // bound socket that does not listen: Windows and Linux refuse a connection to it, but macOS lets it time out.
        const int port = 1;

        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("127.0.0.1", port, [new IPEndPoint(IPAddress.Loopback, 0)], SshAddressFamily.Inet, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).Contains("Could not connect to the server");
    }

    [Test]
    public async Task TheConfigKeywords_AreRead_AndResolved()
    {
        var config = SshConfig.Parse("Host a\n BindAddress 10.1.2.3\nHost b\n BindInterface eth9\n").Resolve("a", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = _dir });
        await Assert.That(config.BindAddress).IsEqualTo("10.1.2.3");
        await Assert.That(TcpConnector.FromConfig(config.BindAddress, null)!.Single()).IsEqualTo(new IPEndPoint(IPAddress.Parse("10.1.2.3"), 0));
        await Assert.That(TcpConnector.FromConfig(null, null)).IsNull();
        await Assert.That(() => TcpConnector.FromConfig("not-an-address", null)).Throws<SshException>();
        await Assert.That(() => TcpConnector.FromConfig(null, "no-such-interface-" + Guid.NewGuid().ToString("N"))).Throws<SshException>();

        var b = SshConfig.Parse("Host a\n BindAddress 10.1.2.3\nHost b\n BindInterface eth9\n").Resolve("b", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = _dir });
        await Assert.That(b.BindInterface).IsEqualTo("eth9");
    }

    [Test]
    public async Task BindInterface_UsesTheInterfacesAddresses()
    {
        var loopback = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.NetworkInterfaceType == NetworkInterfaceType.Loopback);
        if (loopback is null)
        {
            Skip.Test("No loopback interface is listed.");
            return;
        }

        var addresses = TcpConnector.FromConfig(null, loopback.Name)!;

        await Assert.That(addresses.Select(e => e.Address)).Contains(IPAddress.Loopback);
        await Assert.That(addresses.All(e => e.Port == 0)).IsTrue();
    }
}
