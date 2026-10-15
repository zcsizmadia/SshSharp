using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>OpenSSH's connection extensions (PROTOCOL 2.1, 2.2, 2.6): eow@openssh.com, no-more-sessions@openssh.com, INFO@openssh.com.</summary>
public class OpenSshExtensionsTests
{
    private const string OpenSsh = "SSH-2.0-OpenSSH_9.9";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

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

    private static async Task WaitForAsync(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(25);
        }
    }

    [Test]
    [Arguments(OpenSsh, true)]
    [Arguments("SSH-2.0-dropbear_2024.86", false)]
    public async Task PreventNewSessions_TellsOnlyOpenSsh_AndRefusesSessionsHere(string identification, bool told)
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { Identification = identification }) { OnExec = script => script.FinishAsync(0) };
        await using var client = await ConnectAsync(server);
        var before = await client.RunCommandAsync("before", Timeout());
        await Assert.That(before.ExitStatus).IsEqualTo(0);

        await Assert.That(await client.PreventNewSessionsAsync(Timeout())).IsEqualTo(told);
        await WaitForAsync(() => !told || server.GlobalRequests.Contains("no-more-sessions@openssh.com"));

        await Assert.That(server.GlobalRequests.Contains("no-more-sessions@openssh.com")).IsEqualTo(told);
        await Assert.That(async () => await client.RunCommandAsync("after", Timeout())).Throws<InvalidOperationException>();
        await Assert.That(async () => await client.StartCommandAsync("after", cancellationToken: Timeout())).Throws<InvalidOperationException>();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AnEndOfWriteFromTheServer_FailsFurtherInput()
    {
        var closedInput = new TaskCompletionSource();
        await using var server = new FakeSessionServer(new FakeServerOptions { Identification = OpenSsh })
        {
            OnExec = async script =>
            {
                await script.ReadInputAsync(); // the first line, then the program closes its input
                await script.EndOfWriteAsync();
                closedInput.SetResult();
                await Task.Delay(Timeout().IsCancellationRequested ? 0 : 30_000);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("head -n 1", cancellationToken: Timeout());

        await session.StandardInput.WriteAsync("line\n"u8.ToArray(), Timeout());
        await closedInput.Task.WaitAsync(Timeout());
        await Task.Delay(100); // the request reaches the client after the script's signal

        var error = await Assert.ThrowsAsync<SshException>(async () => await session.StandardInput.WriteAsync("more\n"u8.ToArray(), Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments(OpenSsh, true)]
    [Arguments("SSH-2.0-dropbear_2024.86", false)]
    public async Task DisposingTheOutput_AsksOnlyOpenSshToStopSending(string identification, bool asked)
    {
        ExecScript? running = null;
        var started = new TaskCompletionSource();
        await using var server = new FakeSessionServer(new FakeServerOptions { Identification = identification })
        {
            OnExec = async script =>
            {
                running = script;
                started.SetResult();
                await Task.Delay(Timeout().IsCancellationRequested ? 0 : 30_000);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("yes", cancellationToken: Timeout());
        await started.Task.WaitAsync(Timeout());

        await session.StandardOutput.DisposeAsync();
        await WaitForAsync(() => !asked || running!.Requests.Any(r => r.Type == "eow@openssh.com"));

        await Assert.That(running!.Requests.Any(r => r.Type == "eow@openssh.com")).IsEqualTo(asked);

        // Output that still arrives is dropped (and its window given back), and the session goes on.
        await running.StdoutAsync(new byte[3 * 1024 * 1024]);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task Signals_AcceptExtensionNames_ButNotTheSigPrefix()
    {
        ExecScript? running = null;
        var started = new TaskCompletionSource();
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                running = script;
                started.SetResult();
                await Task.Delay(Timeout().IsCancellationRequested ? 0 : 30_000);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("sleep 30", cancellationToken: Timeout());
        await started.Task.WaitAsync(Timeout());

        await session.SendSignalAsync("INFO@openssh.com", Timeout());
        await session.SendSignalAsync("TERM", Timeout());
        await WaitForAsync(() => running!.Requests.Count(r => r.Type == "signal") == 2);
        await Assert.That(running!.Requests.Count(r => r.Type == "signal")).IsEqualTo(2);

        foreach (var bad in new[] { "SIGTERM", "INFO@", "@openssh.com", "TE RM", "INFO@open ssh.com", "INFO@openssh.com@x" })
        {
            await Assert.That(async () => await session.SendSignalAsync(bad, Timeout())).Throws<ArgumentException>().Because(bad);
        }
    }
}
