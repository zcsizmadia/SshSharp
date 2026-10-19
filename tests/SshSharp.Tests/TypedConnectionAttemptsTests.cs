using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="SshClientOptions.ConnectionAttempts"/>: the typed connection retries, on a fake clock, through a custom proxy that fails a
/// given number of times before it reaches a fake server.
/// </summary>
public sealed class TypedConnectionAttemptsTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A password made for the test run: never written in the source.</summary>
    private static readonly string Password = Guid.NewGuid().ToString("N");

    private static SshException Unreachable(SocketError error) =>
        new(SshFailureReason.ConnectFailed, "Could not connect to the server.", new SocketException((int)error));

    /// <summary>A proxy whose first <paramref name="failures"/> connections fail with <paramref name="failure"/>, then reach <paramref name="server"/>.</summary>
    private static SshProxy FailingThen(int failures, Func<Exception> failure, FakeSessionServer? server, List<string> calls) =>
        SshProxy.FromConnector((host, port, cancellationToken) =>
        {
            lock (calls)
            {
                calls.Add($"{host}:{port}");
                if (calls.Count <= failures || server is null)
                {
                    throw failure();
                }
            }

            _ = server.StartAsync();
            return ValueTask.FromResult(server.ClientStream);
        });

    private static SshClientOptions Options(SshProxy proxy, int attempts, TimeProvider time, TimeSpan? connectTimeout = null, IReadOnlyList<SshJumpHost>? jumpHosts = null) => new()
    {
        UserName = "tester",
        Password = Password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        Proxy = proxy,
        ConnectionAttempts = attempts,
        ConnectTimeout = connectTimeout,
        JumpHosts = jumpHosts ?? [],
        TimeProvider = time,
    };

    [Test]
    public async Task TheDefault_IsOneAttempt_AndLessThanOneIsRefused()
    {
        var options = new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)) };
        await Assert.That(options.ConnectionAttempts).IsEqualTo(1);
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = options.HostKeyVerifier, ConnectionAttempts = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = options.HostKeyVerifier, ConnectionAttempts = -1 }).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task AnUnreachableServer_IsTriedAgain_OneSecondLater()
    {
        await using var server = new FakeSessionServer { Password = Password };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<string>();
        var connect = SshClient.ConnectAsync("db.example.com", 2222,
            Options(FailingThen(1, () => Unreachable(SocketError.ConnectionRefused), server, calls), 3, time), Timeout());

        // The wait after the first attempt is set, and nothing is tried again until the clock has moved a whole second.
        await time.WaitForTimersAsync(1);
        time.Advance(TimeSpan.FromMilliseconds(999));
        await Assert.That(calls.Count).IsEqualTo(1);
        time.Advance(TimeSpan.FromMilliseconds(1));

        await using var client = await connect;
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(calls).IsEquivalentTo(new[] { "db.example.com:2222", "db.example.com:2222" });
    }

    [Test]
    public async Task AfterTheLastAttempt_TheFailureIsThrown()
    {
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<string>();
        var connect = SshClient.ConnectAsync("db.example.com", 22,
            Options(FailingThen(int.MaxValue, () => Unreachable(SocketError.TimedOut), null, calls), 3, time), Timeout());

        await time.WaitForTimersAsync(1);
        time.Advance(TimeSpan.FromSeconds(1));
        await time.WaitForTimersAsync(2);
        time.Advance(TimeSpan.FromSeconds(1));

        var ex = await Assert.ThrowsAsync<SshException>(async () => await connect);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(((SocketException)ex.InnerException!).SocketErrorCode).IsEqualTo(SocketError.TimedOut);
        await Assert.That(calls.Count).IsEqualTo(3);
    }

    [Test]
    [Arguments(SocketError.HostNotFound)]
    [Arguments(SocketError.AddressNotAvailable)]
    [Arguments(SocketError.AccessDenied)]
    public async Task WhatAnotherAttemptWouldNotChange_IsNotTriedAgain(SocketError error)
    {
        var calls = new List<string>();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("db.example.com", 22,
            Options(FailingThen(int.MaxValue, () => Unreachable(error), null, calls), 5, TimeProvider.System), Timeout()));
        await Assert.That(calls.Count).IsEqualTo(1);

        // Nor a refusal with no socket error behind it, such as a proxy's.
        calls.Clear();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("db.example.com", 22,
            Options(FailingThen(int.MaxValue, () => new SshException(SshFailureReason.ConnectFailed, "The proxy refused."), null, calls), 5, TimeProvider.System),
            Timeout()));
        await Assert.That(calls.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ConnectTimeout_BoundsAllTheAttemptsTogether()
    {
        // The deadline and the waits are on the one clock: attempts at 0 s and 1 s, the deadline at 1.5 s, before the attempt at 2 s.
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<string>();
        var connect = SshClient.ConnectAsync("db.example.com", 22,
            Options(FailingThen(int.MaxValue, () => Unreachable(SocketError.ConnectionRefused), null, calls), 100, time, TimeSpan.FromMilliseconds(1500)),
            Timeout());

        await time.WaitForTimersAsync(2); // the deadline, and the wait after the first attempt
        time.Advance(TimeSpan.FromSeconds(1));
        await time.WaitForTimersAsync(3); // the wait after the second attempt
        time.Advance(TimeSpan.FromMilliseconds(500));

        var ex = await Assert.ThrowsAsync<SshException>(async () => await connect);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>();
        await Assert.That(calls.Count).IsEqualTo(2);
    }

    [Test]
    public async Task WithJumpHosts_TheConnectionToTheFirstHop_IsTheOneTriedAgain()
    {
        await using var target = new FakeSessionServer { Password = Password };
        await using var jump = new FakeSessionServer(new FakeServerOptions { HostKey = FakeHostKey.Ed25519() })
        {
            Password = Password,
            DirectTcpIp = (host, port) =>
            {
                _ = target.StartAsync();
                return host == "target.internal" && port == 22 ? target.ClientStream : null;
            },
        };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<string>();
        var hop = new SshJumpHost("jump.example.com", 22, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        });
        var connect = SshClient.ConnectAsync("target.internal", 22,
            Options(FailingThen(1, () => Unreachable(SocketError.HostUnreachable), jump, calls), 2, time, jumpHosts: [hop]), Timeout());

        await time.WaitForTimersAsync(1);
        time.Advance(TimeSpan.FromSeconds(1));

        await using var client = await connect;
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(calls).IsEquivalentTo(new[] { "jump.example.com:22", "jump.example.com:22" });
    }

    [Test]
    public async Task AJumpHostsConnectTimeout_IsOnTheSameClock_AsTheWaitsBetweenAttempts()
    {
        // The first hop's own ConnectTimeout (1.5 s) bounds its attempts at 0 s and 1 s, on the destination's clock: a deadline on the
        // system clock would never pass here, and the attempts would go on.
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<string>();
        var hop = new SshJumpHost("jump.example.com", 22, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ConnectTimeout = TimeSpan.FromMilliseconds(1500),
        });
        var connect = SshClient.ConnectAsync("target.example.com", 22,
            Options(FailingThen(int.MaxValue, () => Unreachable(SocketError.ConnectionRefused), null, calls), 100, time, jumpHosts: [hop]), Timeout());

        await time.WaitForTimersAsync(2); // the hop's deadline, and the wait after the first attempt
        time.Advance(TimeSpan.FromSeconds(1));
        await time.WaitForTimersAsync(3);
        time.Advance(TimeSpan.FromMilliseconds(500));

        var ex = await Assert.ThrowsAsync<SshException>(async () => await connect);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(calls.Count).IsEqualTo(2);
    }

    [Test]
    public async Task ConnectTimeout_OverAStream_IsOnTheOptionsClock()
    {
        // A server that never sends its identification: only the deadline, on the fake clock, ends the handshake.
        await using var server = new FakeSessionServer { Password = Password };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            TimeProvider = time,
        };
        var connect = SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());

        await time.WaitForTimersAsync(1);
        time.Advance(TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<SshException>(async () => await connect);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>();
    }

    /// <summary>A <see cref="FakeTimeProvider"/> that counts the timers created on it, so a test can advance it once they are set.</summary>
    private sealed class TimerCountingTimeProvider(FakeTimeProvider inner) : TimeProvider
    {
        private int _timers;

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();

        public override long GetTimestamp() => inner.GetTimestamp();

        public override long TimestampFrequency => inner.TimestampFrequency;

        public override TimeZoneInfo LocalTimeZone => inner.LocalTimeZone;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = inner.CreateTimer(callback, state, dueTime, period);
            Interlocked.Increment(ref _timers);
            return timer;
        }

        public void Advance(TimeSpan delta) => inner.Advance(delta);

        public async Task WaitForTimersAsync(int count)
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (Volatile.Read(ref _timers) < count)
            {
                await Task.Delay(5, limit.Token);
            }
        }
    }
}
