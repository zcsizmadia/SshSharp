using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Tunnels and local forwarding through a real server: the server connects back to its own sshd, whose identification line proves the
/// path works. Needs SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR.
/// </summary>
public class ForwardingInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient?> ConnectAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadFileAsync(keyFile) : null;
        return await SshClient.ConnectAsync(host, port, new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, Timeout());
    }

    /// <summary>The port sshd listens on inside the server's own network: 22 in the containers, the published port on the runner.</summary>
    private static int ServerSidePort => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD_INNER_PORT") is { } inner ? int.Parse(inner, System.Globalization.CultureInfo.InvariantCulture) : RealServer.Endpoint!.Value.Port;

    private static async Task<string> ReadLineAsync(Func<Memory<byte>, ValueTask<int>> read)
    {
        var line = new StringBuilder();
        var buffer = new byte[1];
        while (await read(buffer) == 1 && buffer[0] != '\n')
        {
            line.Append((char)buffer[0]);
        }

        return line.ToString().TrimEnd('\r');
    }

    /// <summary>
    /// Asks the server to listen on a random port from <paramref name="first"/> up, trying another one when it refuses: the port can be
    /// in use there, for example as the ephemeral port of another connection (Linux hands those out from 32768 to 60999).
    /// </summary>
    private static async Task<T> OnSomeHighPortAsync<T>(int first, Action<string> step, string what, Func<int, Task<T>> forward)
    {
        for (var attempt = 1; ; attempt++)
        {
            var port = first + Random.Shared.Next(2000);
            step($"asking the server to listen on localhost:{port}{what}");
            try
            {
                return await forward(port);
            }
            catch (SshException) when (attempt < 5)
            {
                // Refused: most likely taken. Another port.
            }
        }
    }

    [Test]
    public async Task ATcpTunnel_ReachesTheServersOwnSshd()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        await using var tunnel = await client.OpenTcpTunnelAsync("127.0.0.1", ServerSidePort, Timeout());
        var identification = await ReadLineAsync(buffer => tunnel.ReadAsync(buffer, Timeout()));
        await Assert.That(identification).StartsWith("SSH-2.0-");
    }

    [Test]
    public async Task RemoteForwarding_BringsTheServersConnectionsBackHere()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        // A local service; the server listens on a port of its own and sends its connections back to it.
        using var service = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        service.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Listen();
        var accepted = false;
        var serviceTask = Task.Run(async () =>
        {
            using var connection = await service.AcceptAsync(Timeout());
            accepted = true;
            await connection.SendAsync("hello from here\n"u8.ToArray(), SocketFlags.None, Timeout());
            connection.Shutdown(SocketShutdown.Send);
        });

        await Stages.RunAsync(async stages =>
        {
            // A fixed high port rather than 0: not every server reports the port it picked.
            await using var forwarder = await OnSomeHighPortAsync(41000, stages.Step, "",
                port => client.ForwardRemotePortAsync("localhost", port, "127.0.0.1", ((IPEndPoint)service.LocalEndPoint!).Port, Timeout()));

            // Reach the forwarded port from the server's side through a tunnel: here -> server -> its forwarded port -> back here.
            // "localhost", not 127.0.0.1: when another process holds that port on 127.0.0.1, sshd may have bound only ::1 for "localhost".
            stages.Step($"opening a tunnel to the server's localhost:{forwarder.Port}");
            await using var tunnel = await client.OpenTcpTunnelAsync("localhost", forwarder.Port, Timeout());
            stages.Step("reading the line the local service sends back through the forwarding");
            var line = await ReadLineAsync(buffer => tunnel.ReadAsync(buffer, Timeout()));
            await Assert.That(line).IsEqualTo("hello from here");
            stages.Step("waiting for the local service");
            await serviceTask;
        }, () => $"The local service {(accepted ? "accepted a forwarded connection" : "saw no forwarded connection")}; connected {client.IsConnected}.");
    }

    [Test]
    public async Task RemoteDynamicForwarding_ConnectsWhereTheServersSideAsks()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        // A local service only this machine reaches; the server's side names it in a SOCKS request.
        using var service = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        service.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Listen();
        var servicePort = ((IPEndPoint)service.LocalEndPoint!).Port;
        var accepted = false;
        var serviceTask = Task.Run(async () =>
        {
            using var connection = await service.AcceptAsync(Timeout());
            accepted = true;
            await connection.SendAsync("hello via socks\n"u8.ToArray(), SocketFlags.None, Timeout());
            connection.Shutdown(SocketShutdown.Send);
        });

        await Stages.RunAsync(async stages =>
        {
            await using var forwarder = await OnSomeHighPortAsync(43000, stages.Step, " (dynamic)",
                port => client.ForwardRemoteDynamicPortAsync("localhost", port, cancellationToken: Timeout()));

            // Play the server-side application through a tunnel: here -> server -> its forwarded port -> back here, as SOCKS.
            // "localhost", not 127.0.0.1: when another process holds that port on 127.0.0.1, sshd may have bound only ::1 for "localhost".
            stages.Step($"opening a tunnel to the server's localhost:{forwarder.Port}");
            await using var tunnel = await client.OpenTcpTunnelAsync("localhost", forwarder.Port, Timeout());
            stages.Step("SOCKS greeting");
            await tunnel.WriteAsync(new byte[] { 5, 1, 0 }, Timeout());
            var choice = new byte[2];
            await tunnel.ReadExactlyAsync(choice, Timeout());
            await Assert.That(choice).IsEquivalentTo(new byte[] { 5, 0 });
            stages.Step("SOCKS CONNECT");
            var request = new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, (byte)(servicePort >> 8), (byte)servicePort };
            await tunnel.WriteAsync(request, Timeout());
            var reply = new byte[10];
            await tunnel.ReadExactlyAsync(reply, Timeout());
            await Assert.That(reply[1]).IsEqualTo((byte)0);

            stages.Step("reading the line the local service sends back");
            var line = await ReadLineAsync(buffer => tunnel.ReadAsync(buffer, Timeout()));
            await Assert.That(line).IsEqualTo("hello via socks");
            stages.Step("waiting for the local service");
            await serviceTask;
        }, () => $"The local service {(accepted ? "accepted a connection" : "saw no connection")}; connected {client.IsConnected}.");
    }

    [Test]
    public async Task RemoteSocketForwarding_BringsConnectionsToTheServersSocketBackHere()
    {
        await using var client = await ConnectAsync();
        if (client is null || !(RealServer.IsOpenSsh || RealServer.IsAsyncSsh) || RealServer.IsWindows)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed, on an OpenSSH or AsyncSSH server with Unix sockets.");
            return;
        }

        using var service = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        service.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Listen();
        var serviceTask = Task.Run(async () =>
        {
            using var accepted = await service.AcceptAsync(Timeout());
            await accepted.SendAsync("hello through a socket\n"u8.ToArray(), SocketFlags.None, Timeout());
            accepted.Shutdown(SocketShutdown.Send);
        });

        // A fresh name: sshd does not replace an existing socket file (StreamLocalBindUnlink no).
        var socketPath = $"/tmp/sshsharp-{Guid.NewGuid():N}.sock";
        try
        {
            await using var forwarder = await client.ForwardRemoteUnixSocketAsync(socketPath, "127.0.0.1", ((IPEndPoint)service.LocalEndPoint!).Port, Timeout());

            // Play the server-side application: here -> server -> its socket -> back here.
            await using var tunnel = await client.OpenUnixSocketTunnelAsync(socketPath, Timeout());
            var line = await ReadLineAsync(buffer => tunnel.ReadAsync(buffer, Timeout()));
            await Assert.That(line).IsEqualTo("hello through a socket");
            await serviceTask;
        }
        finally
        {
            await client.RunCommandAsync($"rm -f {socketPath}", Timeout());
        }
    }

    [Test]
    [Arguments(SshProxyType.Socks5)]
    [Arguments(SshProxyType.Socks4)]
    public async Task AClientBehindASocksProxy_ConnectsThroughIt(SshProxyType type)
    {
        RealServer.SkipUnlessItRunsCommands();

        // The proxy is SshSharp's own ssh -D on a first connection; the second connection goes through it to the server's sshd, by name.
        await using var first = await ConnectAsync();
        if (first is null || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        await using var socks = await first.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), Timeout());
        var proxy = type == SshProxyType.Socks5
            ? SshProxy.Socks5("127.0.0.1", socks.LocalEndPoint.Port)
            : SshProxy.Socks4("127.0.0.1", socks.LocalEndPoint.Port, "tester");

        // The proxy's reply waits for the server to connect to its own sshd. On the Windows runner, with the other interop tests
        // connecting in parallel, that connection can wait in sshd's backlog past the 30 s default; the test has 60 s in all.
        proxy.HandshakeTimeout = TimeSpan.FromSeconds(60);

        await using var second = await SshClient.ConnectAsync("localhost", ServerSidePort, new SshClientOptions
        {
            UserName = options.UserName,
            Password = options.Password,
            PrivateKeys = options.PrivateKeys,
            HostKeyVerifier = options.HostKeyVerifier,
            Proxy = proxy,
        }, Timeout());

        var result = await second.RunCommandAsync("echo through-the-proxy", Timeout());
        await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("through-the-proxy");
    }

    [Test]
    public async Task TheSocksProxy_ReachesTheServersOwnSshd()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        await using var proxy = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), Timeout());
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy.LocalEndPoint, Timeout());

        // SOCKS 5, no authentication, CONNECT by name: "localhost" is resolved by the server.
        await socket.SendAsync(new byte[] { 5, 1, 0 }, SocketFlags.None, Timeout());
        var choice = new byte[2];
        await socket.ReceiveAsync(choice, SocketFlags.None, Timeout());
        var name = "localhost"u8.ToArray();
        var port = ServerSidePort;
        await socket.SendAsync((byte[])[5, 1, 0, 3, (byte)name.Length, .. name, (byte)(port >> 8), (byte)port], SocketFlags.None, Timeout());
        var reply = new byte[10];
        var read = 0;
        while (read < reply.Length)
        {
            read += await socket.ReceiveAsync(reply.AsMemory(read), SocketFlags.None, Timeout());
        }

        await Assert.That(choice).IsEquivalentTo(new byte[] { 5, 0 });
        await Assert.That(reply[1]).IsEqualTo((byte)0); // succeeded
        var identification = await ReadLineAsync(buffer => socket.ReceiveAsync(buffer, SocketFlags.None, Timeout()));
        await Assert.That(identification).StartsWith("SSH-2.0-");
    }

    [Test]
    public async Task LocalForwarding_ReachesTheServersOwnSshd()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        var received = 0;
        await Stages.RunAsync(async stages =>
        {
            stages.Step("listening locally");
            await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "127.0.0.1", ServerSidePort, Timeout());
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            stages.Step($"connecting to the forwarding at {forwarder.LocalEndPoint}");
            await socket.ConnectAsync(forwarder.LocalEndPoint, Timeout());
            stages.Step($"reading the identification line of the server's sshd (127.0.0.1:{ServerSidePort}, as the server sees it)");
            var identification = await ReadLineAsync(async buffer =>
            {
                var read = await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout());
                Interlocked.Add(ref received, read);
                return read;
            });
            await Assert.That(identification).StartsWith("SSH-2.0-");
        }, () => $"{Volatile.Read(ref received)} bytes came through; connected {client.IsConnected}.");
    }
}
