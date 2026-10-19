using System.Net;
using System.Net.Sockets;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="TcpConnector"/> tries each address of a name with a socket of its own. One socket reused from address to address (as
/// <c>TcpClient.ConnectAsync(host, port)</c> does) cannot go on to the next address on Linux and macOS once a raw socket option is set
/// on it, as <c>IPQoS</c> does for IPv6 and <c>ConfigureSocket</c> may: the first refusal ended the connection.
/// </summary>
public sealed class TcpConnectorTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>
    /// A listener on 127.0.0.1 only, on a port nothing listens on at ::1, so that a name resolving to ::1 first is refused there and
    /// reaches the listener at its second address. Null where the system has no IPv6.
    /// </summary>
    private static Socket? ListenOnIpv4Only()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return null;
        }

        for (var tries = 0; tries < 20; tries++)
        {
            var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var port = ((IPEndPoint)listener.LocalEndPoint!).Port;

            // Nothing may be on ::1 at that port: binding it proves so, and closing it leaves the port free on IPv6, so a connection there
            // is refused at once.
            try
            {
                using var probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                probe.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port));
            }
            catch (SocketException)
            {
                listener.Dispose();
                continue;
            }

            listener.Listen();
            return listener;
        }

        throw new InvalidOperationException("No port was free on both 127.0.0.1 and ::1.");
    }

    /// <summary>Resolves every name to <paramref name="addresses"/>, in that order.</summary>
    private static Func<string, CancellationToken, Task<IPAddress[]>> Resolving(params IPAddress[] addresses) =>
        (_, _) => Task.FromResult(addresses);

    /// <summary>
    /// Sets SO_KEEPALIVE as a raw option, which is what stops a reused socket from trying the next address on Linux and macOS. Level and
    /// name are the platform's own numbers.
    /// </summary>
    private static void SetRawKeepAlive(Socket socket)
    {
        var (level, name) = OperatingSystem.IsLinux() ? (1, 9) : (0xffff, 8); // SOL_SOCKET and SO_KEEPALIVE: Linux, else BSD and Windows
        socket.SetRawSocketOption(level, name, BitConverter.GetBytes(1));
    }

    [Test]
    public async Task AName_WithARawOptionSet_GoesOnToItsNextAddress_WithANewSocket()
    {
        using var listener = ListenOnIpv4Only();
        if (listener is null)
        {
            Skip.Test("This machine has no IPv6.");
            return;
        }

        var accepted = listener.AcceptAsync(Timeout()).AsTask();
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;
        var configured = new List<Socket>();

        await using var stream = await TcpConnector.ConnectAsync("server.example.com", port, local: null, SshAddressFamily.Any, "the server",
            socket =>
            {
                configured.Add(socket);
                SetRawKeepAlive(socket);
            },
            Resolving(IPAddress.IPv6Loopback, IPAddress.Loopback), Timeout());
        using var server = await accepted.WaitAsync(Timeout());

        // One socket per address tried, each of the address's own family, each configured before it connected.
        await Assert.That(configured.Count).IsEqualTo(2);
        await Assert.That(configured[0]).IsNotSameReferenceAs(configured[1]);
        await Assert.That(configured[0].AddressFamily).IsEqualTo(AddressFamily.InterNetworkV6);
        await Assert.That(configured[1].AddressFamily).IsEqualTo(AddressFamily.InterNetwork);
        await Assert.That(stream.Socket).IsSameReferenceAs(configured[1]);
        await Assert.That(stream.Socket.NoDelay).IsTrue();
        await Assert.That((int)stream.Socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)!).IsNotEqualTo(0);
    }

    [Test]
    public async Task IPQoS_OnAnIpv6Socket_DoesNotStopTheNextAddress()
    {
        // The case the review found: ssh_config's IPQoS sets IPV6_TCLASS, a raw option, on an IPv6 socket.
        using var listener = ListenOnIpv4Only();
        if (listener is null)
        {
            Skip.Test("This machine has no IPv6.");
            return;
        }

        var accepted = listener.AcceptAsync(Timeout()).AsTask();
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;
        var configure = TcpConnector.Configure(keepAlive: true, typeOfService: 0x20, then: null, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        await using var stream = await TcpConnector.ConnectAsync("server.example.com", port, local: null, SshAddressFamily.Any, "the server",
            configure, Resolving(IPAddress.IPv6Loopback, IPAddress.Loopback), Timeout());
        using var server = await accepted.WaitAsync(Timeout());

        await Assert.That(((IPEndPoint)server.RemoteEndPoint!).Address).IsEqualTo(IPAddress.Loopback);
    }

    [Test]
    public async Task EveryAddressRefused_IsAConnectFailure_WithTheLastError()
    {
        // Port 1 (tcpmux) on 127.0.0.1, where nothing listens (see BindAddressTests for why not a merely free port), twice: a name may
        // well resolve to the same address more than once. Not port 1 on ::1, which went unanswered, not refused, under WSL.
        IPAddress[] addresses = [IPAddress.Loopback, IPAddress.Loopback];
        var sockets = 0;

        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("server.example.com", 1, local: null, SshAddressFamily.Any, "the server",
                _ => sockets++, Resolving(addresses), Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).IsEqualTo("Could not connect to the server: ConnectionRefused.");
        await Assert.That(((SocketException)ex.InnerException!).SocketErrorCode).IsEqualTo(SocketError.ConnectionRefused);
        await Assert.That(sockets).IsEqualTo(addresses.Length);
    }

    [Test]
    public async Task AnAddressFamily_LeavesOutTheOtherFamilysAddresses_WithoutABind()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        var accepted = listener.AcceptAsync(Timeout()).AsTask();
        var families = new List<AddressFamily>();

        await using var stream = await TcpConnector.ConnectAsync("server.example.com", ((IPEndPoint)listener.LocalEndPoint!).Port, local: null,
            SshAddressFamily.Inet, "the server", socket => families.Add(socket.AddressFamily), Resolving(IPAddress.IPv6Loopback, IPAddress.Loopback), Timeout());
        using var server = await accepted.WaitAsync(Timeout());

        await Assert.That(families).IsEquivalentTo([AddressFamily.InterNetwork]);
    }

    [Test]
    [Arguments(SshAddressFamily.Inet, "IPv4")]
    [Arguments(SshAddressFamily.Inet6, "IPv6")]
    public async Task ANameWithNoAddressOfTheFamily_SaysSo_WithoutTryingAny(SshAddressFamily family, string name)
    {
        var address = family == SshAddressFamily.Inet ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var sockets = 0;

        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("server.example.com", 22, local: null, family, "the server",
                _ => sockets++, Resolving(address), Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).IsEqualTo($"None of the addresses of the server is {name}, the only family AddressFamily allows.");
        await Assert.That(sockets).IsEqualTo(0);
    }

    [Test]
    public async Task ANameThatDoesNotResolve_IsAConnectFailure_WithoutABind()
    {
        // .invalid never resolves (RFC 6761).
        var ex = await Assert.That(async () => await TcpConnector.ConnectAsync("sshsharp-test.invalid", 22, null, SshAddressFamily.Any, "the server", Timeout()))
            .Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).Contains("resolve the address of the server");
        await Assert.That(ex.InnerException).IsTypeOf<SocketException>();
    }

    [Test]
    public async Task Cancelling_StopsBeforeTheNextAddress()
    {
        // The token is cancelled while the first socket is configured: the connect that follows sees it, and no other address is tried.
        using var cts = new CancellationTokenSource();
        var sockets = 0;

        await Assert.That(async () => await TcpConnector.ConnectAsync("server.example.com", 1, local: null, SshAddressFamily.Inet, "the server",
                _ =>
                {
                    sockets++;
                    cts.Cancel();
                },
                Resolving(IPAddress.Loopback, IPAddress.Loopback), cts.Token))
            .Throws<OperationCanceledException>();

        await Assert.That(sockets).IsEqualTo(1);
    }
}
