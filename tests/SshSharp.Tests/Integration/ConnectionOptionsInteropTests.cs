using SshSharp.Sftp;

namespace SshSharp.Tests.Integration;

/// <summary>
/// The connection options and introspection of #266 against a real server (see <see cref="RealServer"/>): a forced key re-exchange, a
/// larger channel window and packet, the identification comment, and the endpoints and byte counters of a TCP connection.
/// </summary>
[Category("Integration")]
public class ConnectionOptionsInteropTests
{
    private const int BulkOutputBytes = 12_000_000;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    private static async Task<SshClient> ConnectAsync(int? window = null, int? maxPacket = null, string? versionAddendum = null)
    {
        var (host, port) = RealServer.Endpoint!.Value;
        var account = (await RealServer.OptionsAsync())!;
        var options = new SshClientOptions
        {
            UserName = account.UserName,
            Password = account.Password,
            PrivateKeys = account.PrivateKeys,
            HostKeyVerifier = account.HostKeyVerifier,
            ChannelWindowSize = window ?? 2 * 1024 * 1024,
            ChannelMaxPacketSize = maxPacket ?? 32 * 1024,
            VersionAddendum = versionAddendum,
        };
        return await SshClient.ConnectAsync(host, port, options, Timeout());
    }

    private static void SkipUnlessItRunsShellCommands()
    {
        if (!RealServer.HasAccount)
        {
            Skip.Test("No real server account configured.");
        }

        RealServer.SkipUnlessItRunsCommands();
        if (RealServer.SftpOnly || RealServer.IsWindows)
        {
            Skip.Test("The server runs no POSIX shell commands.");
        }
    }

    /// <summary>Base64 of zero bytes is all 'A': any corruption or reordering shows up in the text.</summary>
    private static async Task AssertIntactBulkOutputAsync(SshCommandResult result, int bytes)
    {
        var lines = result.StandardOutputText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(lines.Length).IsEqualTo((bytes * 4 / 3 / 76) + 1);
        await Assert.That(lines.Take(lines.Length - 1).All(l => l.Length == 76 && l.All(c => c == 'A'))).IsTrue();
    }

    [Test]
    public async Task RekeyAsync_ReExchangesKeys_AndTheConnectionCarriesOn()
    {
        if (!RealServer.HasAccount)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync();
        var sessionId = client.SessionId.ToArray();
        await client.RekeyAsync(Timeout());
        await client.RekeyAsync(Timeout());
        await Assert.That(client.Connection.KeyExchangeCount).IsEqualTo(3);
        await Assert.That(client.SessionId.ToArray().SequenceEqual(sessionId)).IsTrue();

        // Something that needs the server to answer under the new keys, on every server (Erlang runs no commands).
        await client.PingAsync(Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task RekeyAsync_WhileOutputStreamsIn_LosesNothing()
    {
        SkipUnlessItRunsShellCommands();

        await using var client = await ConnectAsync();
        var running = client.RunCommandAsync($"head -c {BulkOutputBytes} /dev/zero | base64", Timeout());
        while (!running.IsCompleted && client.BytesReceived < 1_000_000)
        {
            await Task.Delay(5);
        }

        await client.RekeyAsync(Timeout());
        await AssertIntactBulkOutputAsync(await running, BulkOutputBytes);
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task ALargerWindowAndPacket_CarryBulkOutput()
    {
        SkipUnlessItRunsShellCommands();

        await using var client = await ConnectAsync(window: 16 * 1024 * 1024, maxPacket: 255 * 1024);
        var before = client.BytesReceived;
        var result = await client.RunCommandAsync($"head -c {BulkOutputBytes} /dev/zero | base64", Timeout());
        await AssertIntactBulkOutputAsync(result, BulkOutputBytes);
        await Assert.That(client.BytesReceived - before).IsGreaterThanOrEqualTo(result.StandardOutput.Length);
    }

    [Test]
    public async Task ALargerWindowAndPacket_CarrySftp_BothWays()
    {
        if (!RealServer.HasAccount || !RealServer.HasSftp)
        {
            Skip.Test("No real server account with SFTP configured.");
        }

        var data = new byte[6 * 1024 * 1024];
        new Random(266).NextBytes(data);
        await using var client = await ConnectAsync(window: 16 * 1024 * 1024, maxPacket: 128 * 1024);
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var path = RealServer.SftpPath(".sshsharp-window-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            await sftp.WriteAllBytesAsync(path, data, Timeout());
            await Assert.That((await sftp.ReadAllBytesAsync(path, Timeout())).SequenceEqual(data)).IsTrue();
        }
        finally
        {
            await sftp.DeleteFileAsync(path, Timeout());
        }
    }

    [Test]
    public async Task AVersionAddendum_IsAccepted_AndTheTcpConnectionIsDescribed()
    {
        if (!RealServer.HasAccount)
        {
            Skip.Test("No real server account configured.");
        }

        var before = DateTimeOffset.UtcNow;
        await using var client = await ConnectAsync(versionAddendum: "interop-test/1.0");
        await Assert.That(client.ConnectedAt).IsGreaterThanOrEqualTo(before);
        await Assert.That(client.RemoteEndPoint).IsNotNull();
        await Assert.That(client.LocalEndPoint).IsNotNull();
        await Assert.That(((System.Net.IPEndPoint)client.RemoteEndPoint!).Port).IsEqualTo(RealServer.Endpoint!.Value.Port);
        await Assert.That(client.BytesSent).IsGreaterThan(0);
        await Assert.That(client.BytesReceived).IsGreaterThan(0);
        await Assert.That(client.SessionId.Length).IsGreaterThanOrEqualTo(32);
    }
}
