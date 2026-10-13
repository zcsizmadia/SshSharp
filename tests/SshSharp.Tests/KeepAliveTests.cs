using Microsoft.Extensions.Time.Testing;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Keep-alive, dead-connection detection and connection state, on a fake clock.</summary>
public class KeepAliveTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, FakeTimeProvider time, int countMax = 2)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KeepAliveInterval = Interval,
            KeepAliveCountMax = countMax,
            TimeProvider = time,
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private static int Probes(FakeSessionServer server)
    {
        lock (server.GlobalRequests)
        {
            return server.GlobalRequests.Count(r => r == "keepalive@openssh.com");
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    /// <summary>Advances the clock by one interval and lets the keep-alive loop and the server react.</summary>
    private static async Task TickAsync(FakeTimeProvider time)
    {
        time.Advance(Interval);
        await Task.Delay(50);
    }

    /// <summary>Advances one interval; if that sends a probe, waits until the client has received the answer, so ticks never overtake replies.</summary>
    private static async Task TickAndSettleAsync(FakeTimeProvider time, FakeSessionServer server, SshClient client)
    {
        var before = Probes(server);
        time.Advance(Interval);
        for (var i = 0; i < 100; i++)
        {
            if (Probes(server) > before && client.Connection.LastReceived >= time.GetTimestamp())
            {
                return;
            }

            await Task.Delay(10);
        }
    }

    [Test]
    public async Task AnAnsweringServer_StaysConnectedForever()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, time, countMax: 3);

        for (var i = 0; i < 12; i++)
        {
            await TickAndSettleAsync(time, server, client);
        }

        await WaitUntilAsync(() => Probes(server) >= 3);
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.ConnectionClosed.IsCancellationRequested).IsFalse();
        var result = await client.RunCommandAsync("still-here", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task ASilentServer_IsDeclaredDead_AfterCountMaxProbes()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, time, countMax: 2);
        server.IgnoreGlobalRequests = true;

        // Probes go out each silent interval; the third silent interval exceeds CountMax = 2. Advancing the clock before the loop has
        // set its next timer does nothing (the timer then starts later), so keep advancing until the connection gives up: each timer
        // fires once, so the number of probes is exact however the advances and timers interleave.
        for (var i = 0; i < 100 && client.IsConnected; i++)
        {
            await Assert.That(Probes(server)).IsLessThanOrEqualTo(2);
            await TickAsync(time);
        }

        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(Probes(server)).IsEqualTo(2);
        await Assert.That(client.ConnectionClosed.IsCancellationRequested).IsTrue();
        var error = (SshException)client.ConnectionError!;
        await Assert.That(error.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(async () => await client.RunCommandAsync("too-late", Timeout())).Throws<SshException>();
    }

    [Test]
    public async Task RecentTraffic_MeansNoProbe()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, time);

        // Half an interval, a command (the server talks), then the tick: the server was heard from within the interval.
        time.Advance(Interval / 2);
        await client.RunCommandAsync("traffic", Timeout());
        time.Advance(Interval / 2);
        await Task.Delay(100);
        await Assert.That(Probes(server)).IsEqualTo(0);
    }

    [Test]
    public async Task ConnectionState_FollowsAServerDisconnectAndDisposal()
    {
        await using (var server = new FakeSessionServer())
        {
            await using var client = await ConnectAsync(server, new FakeTimeProvider());
            var closed = new TaskCompletionSource();
            using var registration = client.ConnectionClosed.Register(() => closed.TrySetResult());
            await Assert.That(client.IsConnected).IsTrue();
            await Assert.That(client.ConnectionError).IsNull();

            await server.Raw.CloseAsync();
            await closed.Task.WaitAsync(Timeout());
            await Assert.That(client.IsConnected).IsFalse();
            await Assert.That(client.ConnectionError).IsTypeOf<SshException>();
        }

        await using var server2 = new FakeSessionServer();
        var client2 = await ConnectAsync(server2, new FakeTimeProvider());
        await client2.DisposeAsync();
        await Assert.That(client2.IsConnected).IsFalse();
        await Assert.That(client2.ConnectionClosed.IsCancellationRequested).IsTrue();
    }

    [Test]
    public async Task GlobalRequestReplies_AreMatchedInOrder_AndAnUnaskedReplyIsIgnored()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, new FakeTimeProvider());

        // An unasked reply first (OpenSSH's client ignores those too): it must not be taken as the answer to the next request.
        await server.SendRawAsync([SshSharp.Protocol.SshMessage.RequestSuccess]);
        await client.RunCommandAsync("sync", Timeout());

        var first = client.Connection.SendGlobalRequestAsync("one@example.com", true, null, Timeout());
        var second = client.Connection.SendGlobalRequestAsync("two@example.com", true, null, Timeout());
        await Assert.That((await first).Success).IsFalse();
        await Assert.That((await second).Success).IsFalse();
        await Assert.That((await client.Connection.SendGlobalRequestAsync("no-reply@example.com", false, null, Timeout())).Success).IsTrue();
        await Assert.That(client.IsConnected).IsTrue();
    }
}
