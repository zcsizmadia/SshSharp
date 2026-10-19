namespace SshSharp.Tests.Integration;

/// <summary>
/// Key re-exchange against a real OpenSSH server while channel data is in flight. OpenSSH only handles a re-exchange once the user has
/// authenticated, so these run real commands. They need the interop account (see <see cref="ExecInteropTests"/>); the server-initiated
/// ones also need sshd configured with a small RekeyLimit (for example "RekeyLimit 32K") and SSHSHARP_TEST_SSHD_REKEY=1. CI sets all of it.
/// </summary>
[Category("Integration")]
public class RekeyInteropTests
{
    private const int BulkOutputBytes = 3_000_000;

    private static string BulkOutputCommand(int bytes = BulkOutputBytes) => $"head -c {bytes} /dev/zero | base64";

    private static bool Configured => RealServer.HasAccount;

    private static bool ServerRekeys => Configured && Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD_REKEY") == "1";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    private static async Task<SshClient> ConnectAsync(long rekeyAfterBytes)
    {
        var (host, port) = RealServer.Endpoint!.Value;
        return await SshClient.ConnectAsync(host, port, (await RealServer.OptionsAsync(rekeyAfterBytes: rekeyAfterBytes))!, Timeout());
    }

    /// <summary>
    /// Runs a test's body. In the instrumented build (the stress workflow), a failure also carries the recent key exchange trace: the
    /// messages each transport sent and received, in order, to compare with the server's log.
    /// </summary>
    private static async Task WithKexTraceAsync(Func<Task> body)
    {
        try
        {
            await body();
        }
        catch (Exception ex) when (SshSharp.Protocol.Instrumentation.Enabled)
        {
            throw new InvalidOperationException(
                $"{ex.Message}{Environment.NewLine}Recent key exchange trace:{Environment.NewLine}{SshSharp.Protocol.Instrumentation.RecentTrace("kex:", max: 400)}", ex);
        }
    }

    /// <summary>Base64 of zero bytes is all 'A': any corruption or reordering around a re-exchange shows up in the text.</summary>
    private static async Task AssertIntactBulkOutputAsync(SshCommandResult result, int bytes = BulkOutputBytes)
    {
        var text = result.StandardOutputText;
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(lines.Length).IsEqualTo((bytes * 4 / 3 / 76) + 1);
        await Assert.That(lines.Take(lines.Length - 1).All(l => l.Length == 76 && l.All(c => c == 'A'))).IsTrue();
    }

    [Test]
    public async Task ClientInitiatedRekeysWhileOutputStreamsIn()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await WithKexTraceAsync(async () =>
        {
            // How many re-exchanges happen depends on timing: the server keeps sending until it reads our KEXINIT, up to the whole channel
            // window (RFC 4253 section 9). What is certain is one completed re-exchange per threshold plus window of output: the server can
            // send no more before it answers, and our window adjustments wait for the exchange to end. About 16.2 MB of output at
            // 100 KB + 2 MiB per round is at least six completed re-exchanges, so five always hold. With 4 MB, one stress run saw only four.
            const int bytes = 12_000_000;
            await using var client = await ConnectAsync(rekeyAfterBytes: 100_000);
            var result = await client.RunCommandAsync(BulkOutputCommand(bytes), Timeout());
            await AssertIntactBulkOutputAsync(result, bytes);
            await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(5);

            // And the connection is still good afterwards.
            var after = await client.RunCommandAsync("echo still-here", Timeout());
            await Assert.That(after.StandardOutputText).IsEqualTo("still-here\n");
        });
    }

    [Test]
    public async Task ServerInitiatedRekeysWhileOutputStreamsIn()
    {
        if (!ServerRekeys)
        {
            Skip.Test("The test server is not configured with a small RekeyLimit.");
        }

        await WithKexTraceAsync(async () =>
        {
            // The client's own threshold is the default (1 GiB), so every re-exchange here was started by sshd.
            await using var client = await ConnectAsync(rekeyAfterBytes: 1L << 30);
            var result = await client.RunCommandAsync(BulkOutputCommand(), Timeout());
            await AssertIntactBulkOutputAsync(result);
            await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(3);
        });
    }

    [Test]
    public async Task BothSidesRekeyingAtOnce_AndParallelCommands()
    {
        if (!ServerRekeys)
        {
            Skip.Test("The test server is not configured with a small RekeyLimit.");
        }

        await WithKexTraceAsync(async () =>
        {
            await using var client = await ConnectAsync(rekeyAfterBytes: 60_000);
            var tasks = Enumerable.Range(0, 4).Select(_ => client.RunCommandAsync(BulkOutputCommand(), Timeout())).ToArray();
            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                await AssertIntactBulkOutputAsync(result);
            }

            await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(8);
        });
    }
}