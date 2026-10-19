using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// The socket of a connection by ssh_config alias: <c>TCPKeepAlive</c> and <c>IPQoS</c>, then
/// <see cref="SshConfigConnectOptions.ConfigureSocket"/>, over a real loopback TCP connection to a fake server.
/// </summary>
public sealed class ConfigSocketOptionsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-cfgsocket-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A password made for the test run: never written in the source.</summary>
    private static readonly string Password = Guid.NewGuid().ToString("N");

    private const string Trusting = " User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n";

    /// <summary>What the caller's ConfigureSocket saw: ssh_config's settings are already on the socket by then.</summary>
    private sealed record Seen(bool KeepAlive, bool NoDelay, bool Connected, int? TrafficClass);

    /// <summary>Connects with <paramref name="directives"/>, checks the connection works and the hook ran once, and returns what it saw.</summary>
    private async Task<Seen> ConnectAsync(string directives)
    {
        await using var server = new FakeSessionServer { Password = Password };
        await using var bridge = new Bridge(server);
        Seen? seen = null;
        var calls = 0;
        await using var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse($"Host box\n HostName 127.0.0.1\n Port {bridge.EndPoint.Port}\n{directives}{Trusting}"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = Password,
            ConfigureSocket = socket =>
            {
                Interlocked.Increment(ref calls);
                seen = new Seen((int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)! != 0, socket.NoDelay, socket.Connected,
                    TrafficClass(socket));
            },
        }, Timeout());

        await Assert.That((await client.RunCommandAsync("true", Timeout())).ExitStatus).IsEqualTo(0);
        await Assert.That(calls).IsEqualTo(1);
        return seen!;
    }

    /// <summary>
    /// IP_TOS or IPV6_TCLASS, whichever the socket's family has, as the platform reports it, where the test knows how to read it (Linux
    /// and macOS; Windows accepts IP_TOS but ignores it); null elsewhere.
    /// </summary>
    private static int? TrafficClass(Socket socket)
    {
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
        {
            return null;
        }

        if (socket.AddressFamily == AddressFamily.InterNetwork)
        {
            return (int)socket.GetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService)!;
        }

        var value = new byte[4];
        socket.GetRawSocketOption(TcpConnector.Ipv6Level, TcpConnector.Ipv6TrafficClass!.Value, value);
        return BitConverter.ToInt32(value);
    }

    [Test]
    public async Task TcpKeepAlive_IsOnByDefault_AsInSsh_BeforeTheCallersOwnSettings()
    {
        var seen = await ConnectAsync("");
        await Assert.That(seen.KeepAlive).IsTrue();
        await Assert.That(seen.NoDelay).IsTrue();
        await Assert.That(seen.Connected).IsFalse();
    }

    [Test]
    public async Task TcpKeepAliveNo_LeavesTheSystemsDefault() =>
        await Assert.That((await ConnectAsync(" TCPKeepAlive no\n")).KeepAlive).IsFalse();

    [Test]
    public async Task IPQoS_SetsTheTypeOfService_OfTheBulkValue()
    {
        var seen = await ConnectAsync(" IPQoS af21 cs1\n");
        if (seen.TrafficClass is { } trafficClass)
        {
            await Assert.That(trafficClass).IsEqualTo(0x20); // cs1, the second value
        }
    }

    [Test]
    public async Task TheCallersSettings_Win()
    {
        await using var server = new FakeSessionServer { Password = Password };
        await using var bridge = new Bridge(server);
        Socket? configured = null;
        await using var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse($"Host box\n HostName 127.0.0.1\n Port {bridge.EndPoint.Port}\n TCPKeepAlive yes\n{Trusting}"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = Password,
            ConfigureSocket = socket =>
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, false);
                configured = socket;
            },
        }, Timeout());

        await Assert.That((int)configured!.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)!).IsEqualTo(0);
    }

    [Test]
    public async Task WhatConfigureSocketThrows_EndsTheAttempt_AsItIs()
    {
        await using var server = new FakeSessionServer { Password = Password };
        await using var bridge = new Bridge(server);
        var error = await Assert.That(async () =>
        {
            await SshClient.ConnectAsync("box", new SshConfigConnectOptions
            {
                UseAgent = false,
                Config = SshConfig.Parse($"Host box\n HostName 127.0.0.1\n Port {bridge.EndPoint.Port}\n{Trusting}"),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                ConfigureSocket = _ => throw new InvalidOperationException("no such option here"),
            }, Timeout());
        }).Throws<InvalidOperationException>();
        await Assert.That(error!.Message).IsEqualTo("no such option here");
    }

    [Test]
    public async Task WithNothingToSet_TheCallersHookIsUsedAsItIs()
    {
        Action<Socket> mine = _ => { };
        await Assert.That(TcpConnector.Configure(keepAlive: false, typeOfService: null, mine, NullLogger.Instance)).IsSameReferenceAs(mine);
        await Assert.That(TcpConnector.Configure(keepAlive: false, typeOfService: null, null, NullLogger.Instance)).IsNull();
    }

    [Test]
    public async Task TheTypeOfService_IsSetForEachFamily_AndAPlatformThatRefusesIsNotFatal()
    {
        using (var v4 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            TcpConnector.Configure(keepAlive: true, typeOfService: 0xb8, null, NullLogger.Instance)!(v4);
            await Assert.That((int)v4.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)!).IsNotEqualTo(0);
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                await Assert.That((int)v4.GetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService)!).IsEqualTo(0xb8);
            }
        }

        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var v6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp) { DualMode = false };
        TcpConnector.SetTypeOfService(v6, 0x48, NullLogger.Instance);
        if (TrafficClass(v6) is { } trafficClass)
        {
            await Assert.That(trafficClass).IsEqualTo(0x48);
        }
    }

    /// <summary>A loopback listener that relays its one connection to a fake SSH server.</summary>
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
                _ = server.StartAsync();
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                await Task.WhenAny(stream.CopyToAsync(server.ClientStream), server.ClientStream.CopyToAsync(stream));
            });
        }

        public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndPoint!;

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
}
