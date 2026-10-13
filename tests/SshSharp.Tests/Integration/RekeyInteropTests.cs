namespace SshSharp.Tests.Integration;

/// <summary>
/// Key re-exchange against a real OpenSSH server while channel data is in flight. OpenSSH only handles a re-exchange once the user has
/// authenticated, so these run real commands. They need the exec interop account (see <see cref="ExecInteropTests"/>); the server-initiated
/// ones also need sshd configured with a small RekeyLimit (for example "RekeyLimit 32K") and SSHSHARP_TEST_SSHD_REKEY=1. CI sets all of it.
/// </summary>
public class RekeyInteropTests
{
    private const string BulkOutputCommand = "head -c 3000000 /dev/zero | base64 -w 76";

    private static bool Configured =>
        RealServer.IsAvailable
        && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER"))
        && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"));

    private static bool ServerRekeys => Configured && Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD_REKEY") == "1";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    private static async Task<SshClient> ConnectAsync(long rekeyAfterBytes)
    {
        var (host, port) = RealServer.Endpoint!.Value;
        return await SshClient.ConnectAsync(host, port, new SshClientOptions
        {
            UserName = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER")!,
            Password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"),
            HostKeyVerifier = (_, _) => ValueTask.FromResult(true),
            RekeyAfterBytes = rekeyAfterBytes,
        }, Timeout());
    }

    /// <summary>Base64 of zero bytes is all 'A': any corruption or reordering around a re-exchange shows up in the text.</summary>
    private static async Task AssertIntactBulkOutputAsync(SshCommandResult result)
    {
        var text = result.StandardOutputText;
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(lines.Length).IsEqualTo((3_000_000 * 4 / 3 / 76) + 1);
        await Assert.That(lines.Take(lines.Length - 1).All(l => l.Length == 76 && l.All(c => c == 'A'))).IsTrue();
    }

    [Test]
    public async Task ClientInitiatedRekeysWhileOutputStreamsIn()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync(rekeyAfterBytes: 100_000);
        var result = await client.RunCommandAsync(BulkOutputCommand, Timeout());
        await AssertIntactBulkOutputAsync(result);
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(5);

        // And the connection is still good afterwards.
        var after = await client.RunCommandAsync("echo still-here", Timeout());
        await Assert.That(after.StandardOutputText).IsEqualTo("still-here\n");
    }

    [Test]
    public async Task ServerInitiatedRekeysWhileOutputStreamsIn()
    {
        if (!ServerRekeys)
        {
            Skip.Test("The test server is not configured with a small RekeyLimit.");
        }

        // The client's own threshold is the default (1 GiB), so every re-exchange here was started by sshd.
        await using var client = await ConnectAsync(rekeyAfterBytes: 1L << 30);
        var result = await client.RunCommandAsync(BulkOutputCommand, Timeout());
        await AssertIntactBulkOutputAsync(result);
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(3);
    }

    [Test]
    public async Task BothSidesRekeyingAtOnce_AndParallelCommands()
    {
        if (!ServerRekeys)
        {
            Skip.Test("The test server is not configured with a small RekeyLimit.");
        }

        await using var client = await ConnectAsync(rekeyAfterBytes: 60_000);
        var tasks = Enumerable.Range(0, 4).Select(_ => client.RunCommandAsync(BulkOutputCommand, Timeout())).ToArray();
        var results = await Task.WhenAll(tasks);
        foreach (var result in results)
        {
            await AssertIntactBulkOutputAsync(result);
        }

        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(8);
    }
}