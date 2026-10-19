using System.Diagnostics;

namespace SshSharp.Tests.Integration;

/// <summary>
/// A real server behind a misbehaving network (<see cref="FaultyProxy"/>): connections cut mid-command, mid-handshake or after any number
/// of bytes in either direction, a network that goes silent in one direction or both, latency, small slices, low bandwidth. Every failure
/// must surface promptly as an SshException, never as a hang, and disposal must finish. Needs SSHSHARP_TEST_SSHD and an account.
/// </summary>
[Category("Integration")]
public class FaultInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    private static async Task<(FaultyProxy Proxy, SshClientOptions Options)?> SetUpAsync(TimeSpan? keepAlive = null, int keepAliveCountMax = 3)
    {
        if (await RealServer.OptionsAsync(keepAlive: keepAlive, keepAliveCountMax: keepAliveCountMax) is not { } options)
        {
            return null;
        }

        return (new FaultyProxy(RealServer.Endpoint!.Value), options);
    }

    [Test]
    public async Task ACutConnection_FailsTheRunningCommand_AndTheClientKnows()
    {
        RealServer.SkipUnlessItRunsCommands();

        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            var command = client.RunCommandAsync("sleep 60", Timeout());
            await Task.Delay(500);
            var watch = Stopwatch.StartNew();
            proxy.Cut();

            var error = await Assert.ThrowsAsync<SshException>(() => command);
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
            await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
            await Assert.That(client.IsConnected).IsFalse();
            await Assert.That(client.ConnectionClosed.IsCancellationRequested).IsTrue();
            await Assert.That(client.ConnectionError).IsNotNull();
        }
    }

    [Test]
    public async Task ASilentNetwork_IsDetectedByKeepAlive()
    {
        if (RealServer.IsWindows)
        {
            // OpenSSH for Windows 9.5 often fails to answer keepalive@openssh.com ("server_input_global_request: send reply: Connection
            // aborted" in its log); OpenSSH's own client with ServerAliveInterval times out against it the same way (checked in CI).
            Skip.Test("OpenSSH for Windows does not answer keep-alives reliably.");
        }

        // A busy CI runner's sshd has gone 4 s without answering anything (1 s x 3 declared a healthy connection dead before the stall):
        // 2 s x 4 needs 10 s of silence, and still detects the stall well within the test's time.
        if (await SetUpAsync(keepAlive: TimeSpan.FromSeconds(2), keepAliveCountMax: 4) is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            await client.RunCommandAsync("true", Timeout());
            proxy.Stall(); // no data, no FIN, no RST: only keep-alive can tell

            var command = client.RunCommandAsync("sleep 60", Timeout());
            var error = await Assert.ThrowsAsync<SshException>(() => command);
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
            await Assert.That(client.IsConnected).IsFalse();
        }
    }

    [Test]
    public async Task OnASilentNetwork_CancellationStillWorks()
    {
        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            proxy.Stall();
            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var watch = Stopwatch.StartNew();
            await Assert.ThrowsAsync<OperationCanceledException>(() => client.RunCommandAsync("echo never", cancel.Token));
            await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
        }
    }

    [Test]
    public async Task ACutDuringTheHandshake_FailsTheConnect()
    {
        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            proxy.Latency = TimeSpan.FromMilliseconds(300); // slow enough to be cut part-way
            var connect = SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            await Task.Delay(400);
            proxy.Cut();
            var error = await Assert.ThrowsAsync<SshException>(() => connect);
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        }
    }

    [Test]
    public async Task Latency_SlowsThingsDown_ButEverythingWorks()
    {
        RealServer.SkipUnlessItRunsCommands();

        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            proxy.Latency = TimeSpan.FromMilliseconds(100);
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            var result = await client.RunCommandAsync("head -c 300000 /dev/zero | wc -c", Timeout());
            await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("300000");
        }
    }

    /// <summary>Base64 of zero bytes is all 'A' in 76-character lines: any loss or reordering shows in the text.</summary>
    private static async Task AssertBase64OfZerosAsync(SshCommandResult result, int zeros)
    {
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        var text = result.StandardOutputText.Replace("\r", string.Empty, StringComparison.Ordinal);
        var expected = ((zeros + 2) / 3) * 4;
        await Assert.That(text.Count(c => c == 'A') + text.Count(c => c == '=')).IsEqualTo(expected);
        await Assert.That(text.All(c => c is 'A' or '=' or '\n')).IsTrue();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task OneDirectionStalled_DisposalStillFinishesPromptly(bool toServer)
    {
        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());

            // Traffic in the direction about to stall, so that its buffers fill: an upload into the server, or a download from it. The
            // other direction stays open, so the connection looks alive (#210 hung disposal in exactly this state).
            var session = await client.StartCommandAsync(toServer ? "cat > /dev/null" : "head -c 200000000 /dev/zero", cancellationToken: Timeout());
            var traffic = Task.Run(async () =>
            {
                var chunk = new byte[32 * 1024];
                try
                {
                    while (true)
                    {
                        if (toServer)
                        {
                            await session.StandardInput.WriteAsync(chunk, Timeout());
                        }
                        else if (await session.StandardOutput.ReadAsync(chunk, Timeout()) == 0)
                        {
                            return;
                        }
                    }
                }
                catch (Exception)
                {
                    // Disposed under it, or the connection ended.
                }
            });

            await Task.Delay(500);
            if (toServer)
            {
                proxy.StallToServer = true;
            }
            else
            {
                proxy.StallToClient = true;
            }

            await Task.Delay(1500); // the buffers between here and the stall fill up

            var watch = Stopwatch.StartNew();
            await client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15));
            await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(15));
            await traffic.WaitAsync(TimeSpan.FromSeconds(15));
        }
    }

    [Test]
    public async Task ACutAfterAnyNumberOfBytes_EitherWay_FailsCleanlyAndPromptly()
    {
        if (await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        // Cut points through the identification, the key exchange, authentication and the command, in each direction: each attempt
        // either completes (the cut came after it was done) or fails with an SshException, within its time.
        long[] cuts = [1, 8, 30, 100, 300, 600, 1000, 1500, 2000, 3000, 4500, 7000, 12000];
        var problems = new List<string>();
        foreach (var toServer in new[] { true, false })
        {
            foreach (var cut in cuts)
            {
                await using var proxy = new FaultyProxy(RealServer.Endpoint!.Value);
                proxy.CloseAfter(toServer, cut);
                var watch = Stopwatch.StartNew();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try
                {
                    await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, timeout.Token);
                    await client.RunCommandAsync("echo ok", timeout.Token);
                }
                catch (SshException)
                {
                    // A clean failure.
                }
                catch (Exception ex)
                {
                    problems.Add($"{(toServer ? "to the server" : "to the client")} after {cut} bytes: {ex.GetType().Name}: {ex.Message} ({proxy.Describe()})");
                }

                if (watch.Elapsed > TimeSpan.FromSeconds(15))
                {
                    problems.Add($"{(toServer ? "to the server" : "to the client")} after {cut} bytes: took {watch.Elapsed.TotalSeconds:F1} s ({proxy.Describe()})");
                }
            }
        }

        if (problems.Count > 0)
        {
            Assert.Fail(string.Join(Environment.NewLine, problems));
        }
    }

    [Test]
    public async Task DataInTinySlices_ArrivesWhole()
    {
        RealServer.SkipUnlessItRunsCommands();

        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            proxy.MaxSlice = 16; // every packet split across many reads, at arbitrary boundaries
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            await AssertBase64OfZerosAsync(await client.RunCommandAsync("head -c 200000 /dev/zero | base64", Timeout()), 200_000);
        }
    }

    [Test]
    public async Task ASlowLink_CarriesALargeOutputWhole()
    {
        RealServer.SkipUnlessItRunsCommands();

        if (await SetUpAsync() is not var (proxy, options))
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        await using (proxy)
        {
            proxy.BytesPerSecond = 512 * 1024;
            await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
            await AssertBase64OfZerosAsync(await client.RunCommandAsync("head -c 1000000 /dev/zero | base64", Timeout()), 1_000_000);
        }
    }

    [Test]
    public async Task TheServerKillingTheSession_FailsTheCommand_AndOtherConnectionsCarryOn()
    {
        // The session's own sshd process is killed (as an administrator would, or the OOM killer): its socket closes in the middle of
        // the session, with no CHANNEL_CLOSE or DISCONNECT. Only on OpenSSH on Unix: the shell's parent there is the user's own
        // per-connection sshd process, which the same user may kill. Dropbear's runs as root, AsyncSSH serves every connection from
        // one process, and Windows has no $PPID.
        if (!RealServer.IsOpenSsh || RealServer.IsWindows || RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("An OpenSSH server on Unix and an account are needed.");
            return;
        }

        await using var victim = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var session = await victim.StartCommandAsync("echo $PPID; exec sleep 60", cancellationToken: Timeout());
        var line = new List<byte>();
        var one = new byte[1];
        while (await session.StandardOutput.ReadAsync(one, Timeout()) == 1 && one[0] != (byte)'\n')
        {
            line.Add(one[0]);
        }

        var pid = System.Text.Encoding.ASCII.GetString([.. line]).Trim();
        await Assert.That(int.TryParse(pid, out _)).IsTrue();

        await using var admin = await SshClient.ConnectAsync(host, port, options, Timeout());
        var watch = Stopwatch.StartNew();
        var kill = await admin.RunCommandAsync($"kill -9 {pid}", Timeout());
        if (kill.ExitStatus != 0)
        {
            Assert.Fail($"kill -9 {pid} failed ({kill.ExitStatus}): {kill.StandardErrorText}");
        }

        var error = await Assert.ThrowsAsync<SshException>(() => session.WaitForExitAsync(Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(victim.IsConnected).IsFalse();
        await Assert.That((await admin.RunCommandAsync("echo still-here", Timeout())).StandardOutputText).IsEqualTo("still-here\n");
    }
}
