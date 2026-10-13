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
        var serviceTask = Task.Run(async () =>
        {
            using var accepted = await service.AcceptAsync(Timeout());
            await accepted.SendAsync("hello from here\n"u8.ToArray(), SocketFlags.None, Timeout());
            accepted.Shutdown(SocketShutdown.Send);
        });

        // A fixed high port rather than 0: not every server reports the port it picked.
        var port = 41000 + Random.Shared.Next(2000);
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", port, "127.0.0.1", ((IPEndPoint)service.LocalEndPoint!).Port, Timeout());

        // Reach the forwarded port from the server's side through a tunnel: here -> server -> its forwarded port -> back here.
        await using var tunnel = await client.OpenTcpTunnelAsync("127.0.0.1", forwarder.Port, Timeout());
        var line = await ReadLineAsync(buffer => tunnel.ReadAsync(buffer, Timeout()));
        await Assert.That(line).IsEqualTo("hello from here");
        await serviceTask;
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

        await using var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "127.0.0.1", ServerSidePort, Timeout());
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(forwarder.LocalEndPoint, Timeout());
        var identification = await ReadLineAsync(buffer => socket.ReceiveAsync(buffer, SocketFlags.None, Timeout()));
        await Assert.That(identification).StartsWith("SSH-2.0-");
    }
}
