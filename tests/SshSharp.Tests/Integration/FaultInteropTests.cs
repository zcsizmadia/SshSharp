using System.Diagnostics;

namespace SshSharp.Tests.Integration;

/// <summary>
/// A real server behind a misbehaving network (<see cref="FaultyProxy"/>): connections cut mid-command or mid-handshake, a network that
/// goes silent, latency. Every failure must surface promptly as an SshException, never as a hang. Needs SSHSHARP_TEST_SSHD and an account.
/// </summary>
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
}
