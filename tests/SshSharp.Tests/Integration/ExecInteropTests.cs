namespace SshSharp.Tests.Integration;

/// <summary>
/// Runs commands against a real OpenSSH server over TCP. Needs SSHSHARP_TEST_SSHD (host:port) plus SSHSHARP_TEST_USER and
/// SSHSHARP_TEST_PASSWORD for an account on that server; skipped when any is missing. CI creates a throwaway account and password.
/// </summary>
public class ExecInteropTests
{
    private static SshClientOptions Options(string? password = null) => new()
    {
        UserName = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER")!,
        Password = password ?? Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"),
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
    };

    private static bool Configured =>
        RealServer.IsAvailable
        && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER"))
        && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"));

    private static async Task<SshClient> ConnectAsync(CancellationToken token)
    {
        var (host, port) = RealServer.Endpoint!.Value;
        return await SshClient.ConnectAsync(host, port, Options(), token);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    [Test]
    public async Task KeepAlivesAreAnswered_SoAnIdleConnectionStaysUp()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        var (host, port) = RealServer.Endpoint!.Value;
        var options = new SshClientOptions
        {
            UserName = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER")!,
            Password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"),
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KeepAliveInterval = TimeSpan.FromSeconds(2),
            KeepAliveCountMax = 10, // 20 s of silence: a busy runner can stall the test process for seconds
        };
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());

        // The claim itself, without timing: OpenSSH answers keepalive@openssh.com (with a failure, which is still an answer).
        var reply = await client.Connection.SendGlobalRequestAsync("keepalive@openssh.com", wantReply: true, null, Timeout());
        await Assert.That(reply.Success).IsFalse();

        // And an idle connection with keep-alives running stays up. The margins are generous: the interop tests run in parallel on
        // small CI runners, and a stalled test process is a genuine miss as far as the keep-alive is concerned.
        await Task.Delay(TimeSpan.FromSeconds(3));
        await Assert.That(client.ConnectionError).IsNull(); // shows the exception if the connection dropped
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That((await client.RunCommandAsync("echo alive", Timeout())).StandardOutputText).IsEqualTo("alive\n");
    }

    [Test]
    public async Task RunsACommand()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync(Timeout());
        var result = await client.RunCommandAsync("echo hello", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("hello\n");
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(client.ServerIdentification).StartsWith("SSH-2.0-" + RealServer.Software, StringComparison.OrdinalIgnoreCase);
    }

    [Test]
    public async Task SeparatesStderr_AndReportsTheExitStatus()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync(Timeout());
        var result = await client.RunCommandAsync("sh -c 'echo out; echo err 1>&2; exit 5'", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("out\n");
        await Assert.That(result.StandardErrorText).IsEqualTo("err\n");
        await Assert.That(result.ExitStatus).IsEqualTo(5);

        var missing = await client.RunCommandAsync("definitely-not-a-command-sshsharp", Timeout());
        await Assert.That(missing.ExitStatus).IsEqualTo(127);
    }

    [Test]
    public async Task ReportsASignal()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        if (RealServer.IsWindows)
        {
            Skip.Test("Windows has no signals: OpenSSH for Windows reports an exit status instead.");
        }

        await using var client = await ConnectAsync(Timeout());
        // The login shell kills itself: busybox ash does not exec a nested shell's last command, so 'sh -c kill' would exit 137 instead.
        var result = await client.RunCommandAsync("kill -9 $$", Timeout());
        await Assert.That(result.ExitStatus).IsNull();
        await Assert.That(result.ExitSignal).IsEqualTo("KILL");
    }

    [Test]
    public async Task ReadsOutputLargerThanTheWindow()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync(Timeout());
        // ~6.7 MB of base64 text: well over the 2 MiB window, so it only finishes if window adjustment works against OpenSSH.
        var result = await client.RunCommandAsync("head -c 5000000 /dev/zero | base64", Timeout());
        var lines = result.StandardOutputText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(lines.Length).IsGreaterThan(65_000);
        await Assert.That(lines.All(l => l.Length == 76 || l == lines[^1])).IsTrue();
    }

    [Test]
    public async Task ManyCommandsInParallelOnOneConnection()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var client = await ConnectAsync(Timeout());
        var tasks = Enumerable.Range(0, 12).Select(i => client.RunCommandAsync($"sh -c 'sleep 0.1; echo job-{i}'", Timeout())).ToArray();
        var results = await Task.WhenAll(tasks);
        for (var i = 0; i < results.Length; i++)
        {
            await Assert.That(results[i].StandardOutputText).IsEqualTo($"job-{i}\n");
        }
    }

    [Test]
    public async Task WrongPasswordIsRejected()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        var (host, port) = RealServer.Endpoint!.Value;
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(host, port, Options("definitely-wrong"), Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(ex.Message).Contains("password");
    }

    [Test]
    public async Task ConnectsOverAnExistingStream()
    {
        if (!Configured)
        {
            Skip.Test("No real server account configured.");
        }

        await using var stream = await RealServer.ConnectAsync();
        await using var client = await SshClient.ConnectAsync(stream, Options(), leaveOpen: true, Timeout());
        var result = await client.RunCommandAsync("echo via-stream", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("via-stream\n");
    }
}