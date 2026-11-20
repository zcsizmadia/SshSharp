using System.Buffers.Binary;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// The limit on the log entries a server can trigger again and again (unimplemented messages, refused forwarded connections, refused
/// agent requests): a burst at their own level, the rest at Debug, and one summary when the window ends. All on a fake clock.
/// </summary>
public class PeerLogLimiterTests
{
    private const int UnimplementedEvent = 14;
    private const int RemoteDynamicEvent = 32;
    private const int SummaryEvent = 63;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Test]
    public async Task ABurstIsWrittenAtItsOwnLevel_TheRestAtDebug_AndOneSummaryEndsTheWindow()
    {
        var time = new FakeTimeProvider();
        var logger = new CapturingLogger();
        using var limiter = new PeerLogLimiter(logger, time);

        var levels = Enumerable.Range(0, 100).Select(_ => limiter.Admit(LogLevel.Warning)).ToList();

        await Assert.That(levels.Take(PeerLogLimiter.Burst)).All().Satisfy(l => l.IsEqualTo(LogLevel.Warning));
        await Assert.That(levels.Skip(PeerLogLimiter.Burst)).All().Satisfy(l => l.IsEqualTo(LogLevel.Debug));
        await Assert.That(logger.Entries).IsEmpty();

        // Nothing until the window ends, then one summary of the 92 lowered entries, at their level.
        time.Advance(PeerLogLimiter.Window - TimeSpan.FromSeconds(1));
        await Assert.That(logger.Entries).IsEmpty();
        time.Advance(TimeSpan.FromSeconds(1));
        var summary = logger.Entries.Single();
        await Assert.That(summary.EventId).IsEqualTo(SummaryEvent);
        await Assert.That(summary.Level).IsEqualTo(LogLevel.Warning);
        await Assert.That(summary.Message).StartsWith("92 more entries");
        await Assert.That(summary.Message).Contains($"at most {PeerLogLimiter.Burst} a minute");

        // The next window has its burst again, and a window with nothing lowered writes no summary.
        await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Warning);
        time.Advance(PeerLogLimiter.Window);
        await Assert.That(logger.Entries.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AWindowStartsWithItsFirstEntry_AndEndsAMinuteLater()
    {
        var time = new FakeTimeProvider();
        time.Advance(TimeSpan.FromMinutes(10)); // no window runs on a quiet connection
        var logger = new CapturingLogger();
        using var limiter = new PeerLogLimiter(logger, time);

        for (var i = 0; i < PeerLogLimiter.Burst; i++)
        {
            await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Warning);
        }

        time.Advance(PeerLogLimiter.Window - TimeSpan.FromTicks(1));
        await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Debug);
        time.Advance(TimeSpan.FromTicks(1));
        await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Warning);
        await Assert.That(logger.Entries.Single().Message).StartsWith("1 more entries");
    }

    [Test]
    public async Task TheSummary_IsWrittenAtTheHighestLevelItCounts()
    {
        var time = new FakeTimeProvider();
        var logger = new CapturingLogger();
        using var limiter = new PeerLogLimiter(logger, time);

        // Refused agent requests only (Information): the summary is no louder than they were.
        Admit(limiter, LogLevel.Warning, PeerLogLimiter.Burst);
        Admit(limiter, LogLevel.Information, 3);
        time.Advance(PeerLogLimiter.Window);

        // Both kinds: a Warning, whichever came first.
        Admit(limiter, LogLevel.Information, PeerLogLimiter.Burst);
        Admit(limiter, LogLevel.Warning, 1);
        Admit(limiter, LogLevel.Information, 1);
        time.Advance(PeerLogLimiter.Window);

        await Assert.That(logger.Entries.Select(e => (e.Level, e.Message[..e.Message.IndexOf(' ', StringComparison.Ordinal)])))
            .IsEquivalentTo(new[] { (LogLevel.Information, "3"), (LogLevel.Warning, "2") });
    }

    [Test]
    public async Task OneTimer_ForTheRestOfTheWindow_AndNoneWhileNothingIsLowered()
    {
        var clock = new ManualClock();
        var logger = new CapturingLogger();
        using var limiter = new PeerLogLimiter(logger, clock);

        Admit(limiter, LogLevel.Warning, PeerLogLimiter.Burst);
        await Assert.That(clock.Timers).IsEmpty();

        clock.Advance(TimeSpan.FromSeconds(20));
        Admit(limiter, LogLevel.Warning, 5);
        await Assert.That(clock.Timers).IsEquivalentTo(new[] { TimeSpan.FromSeconds(40) });
    }

    [Test]
    public async Task ASummaryStillOwed_IsWrittenBeforeTheNextWindowsFirstEntry()
    {
        // The timer has not run (a busy thread pool): the next window's first entry writes the summary before its own.
        var clock = new ManualClock();
        var logger = new CapturingLogger();
        using var limiter = new PeerLogLimiter(logger, clock);
        Admit(limiter, LogLevel.Warning, PeerLogLimiter.Burst + 2);
        clock.Advance(PeerLogLimiter.Window);

        await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Warning);
        await Assert.That(logger.Entries.Single().Message).StartsWith("2 more entries");

        // Counted afresh: a new burst, and a new timer once it is used up.
        Admit(limiter, LogLevel.Warning, PeerLogLimiter.Burst - 1);
        await Assert.That(clock.Timers.Count).IsEqualTo(1);
        await Assert.That(limiter.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Debug);
        await Assert.That(clock.Timers.Count).IsEqualTo(2);
        await Assert.That(clock.Disposed).IsEqualTo(1); // the first window's timer, stopped when its summary was written
    }

    [Test]
    public async Task Dispose_WritesTheSummaryStillOwed_AndStartsNoTimerAfterIt()
    {
        var clock = new ManualClock();
        var logger = new CapturingLogger();
        var limiter = new PeerLogLimiter(logger, clock);
        Admit(limiter, LogLevel.Warning, PeerLogLimiter.Burst);
        limiter.Dispose();
        await Assert.That(logger.Entries).IsEmpty();

        clock.Advance(PeerLogLimiter.Window);
        var quiet = new PeerLogLimiter(logger, clock);
        Admit(quiet, LogLevel.Warning, PeerLogLimiter.Burst + 4);
        quiet.Dispose();
        await Assert.That(logger.Entries.Single().Message).StartsWith("4 more entries");
        await Assert.That(clock.Disposed).IsEqualTo(1);

        // A forwarding can still log while the connection closes: it is still limited, but no timer outlives the connection.
        await Assert.That(quiet.Admit(LogLevel.Warning)).IsEqualTo(LogLevel.Debug);
        await Assert.That(clock.Timers.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AServerSendingAHundredUnknownMessages_GetsABurstOfWarnings_ThenASummary()
    {
        var time = new FakeTimeProvider();
        var logger = new CapturingLogger();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, logger, time);

        for (var i = 0; i < 100; i++)
        {
            await server.SendRawAsync([200, 1, 2, 3]);
        }

        await WaitUntilAsync(() => logger.Entries.Count(e => e.EventId == UnimplementedEvent) == 100);
        var unimplemented = logger.Entries.Where(e => e.EventId == UnimplementedEvent).ToList();
        await Assert.That(unimplemented.Count(e => e.Level == LogLevel.Warning)).IsEqualTo(PeerLogLimiter.Burst);
        await Assert.That(unimplemented.Count(e => e.Level == LogLevel.Debug)).IsEqualTo(100 - PeerLogLimiter.Burst);
        await Assert.That(logger.Entries.Any(e => e.EventId == SummaryEvent)).IsFalse();

        // The window ends on the connection's clock, and the summary follows. Every message is still answered.
        time.Advance(PeerLogLimiter.Window);
        var summary = logger.Entries.Single(e => e.EventId == SummaryEvent);
        await Assert.That(summary.Level).IsEqualTo(LogLevel.Warning);
        await Assert.That(summary.Message).StartsWith("92 more entries");
        await Assert.That(server.UnimplementedReceived).IsTrue();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AHundredRefusedRemoteDynamicRequests_GetABurstOfWarnings_ThenASummary()
    {
        var time = new FakeTimeProvider();
        var logger = new CapturingLogger();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, logger, time);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, (_, _) => false, Timeout());

        for (var i = 0; i < 100; i++)
        {
            await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
            await remote.WriteAsync(Socks5Connect("db.example.com", 5432), Timeout());
            await Assert.That(await SocksReplyAsync(remote)).IsEqualTo((byte)5); // refused
        }

        await WaitUntilAsync(() => logger.Entries.Count(e => e.EventId == RemoteDynamicEvent) == 100);
        var refused = logger.Entries.Where(e => e.EventId == RemoteDynamicEvent).ToList();
        await Assert.That(refused.Count(e => e.Level == LogLevel.Warning)).IsEqualTo(PeerLogLimiter.Burst);
        await Assert.That(refused.Count(e => e.Level == LogLevel.Debug)).IsEqualTo(100 - PeerLogLimiter.Burst);

        time.Advance(PeerLogLimiter.Window);
        await Assert.That(logger.Entries.Single(e => e.EventId == SummaryEvent).Message).StartsWith("92 more entries");
    }

    [Test]
    public async Task TheLimit_IsSharedByTheConnectionAndItsForwardings()
    {
        var time = new FakeTimeProvider();
        var logger = new CapturingLogger();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, logger, time);
        await using var forwarder = await client.ForwardRemoteDynamicPortAsync("localhost", 0, (_, _) => false, Timeout());

        for (var i = 0; i < PeerLogLimiter.Burst; i++)
        {
            await server.SendRawAsync([200]);
        }

        await WaitUntilAsync(() => logger.Entries.Count(e => e.EventId == UnimplementedEvent) == PeerLogLimiter.Burst);
        await using (var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!)
        {
            await remote.WriteAsync(Socks5Connect("db.example.com", 5432), Timeout());
            await Assert.That(await SocksReplyAsync(remote)).IsEqualTo((byte)5);
        }

        await WaitUntilAsync(() => logger.Entries.Any(e => e.EventId == RemoteDynamicEvent));
        await Assert.That(logger.Entries.Single(e => e.EventId == RemoteDynamicEvent).Level).IsEqualTo(LogLevel.Debug);

        // Closing the connection writes the summary the window still owes, rather than losing it.
        await client.DisposeAsync();
        await Assert.That(logger.Entries.Single(e => e.EventId == SummaryEvent).Message).StartsWith("1 more entries");
    }

    private static void Admit(PeerLogLimiter limiter, LogLevel level, int count)
    {
        for (var i = 0; i < count; i++)
        {
            limiter.Admit(level);
        }
    }

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, ILogger logger, TimeProvider time)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Logger = logger,
            TimeProvider = time,
        }, leaveOpen: true, Timeout());
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 6000 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    private static byte[] Socks5Connect(string host, int port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        byte[] request = [5, 1, 0, 5, 1, 0, 3, (byte)name.Length, .. name, 0, 0];
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(request.Length - 2), (ushort)port);
        return request;
    }

    private static async Task<byte> SocksReplyAsync(Stream remote)
    {
        var reply = new byte[12]; // method choice (2) and the CONNECT reply (10)
        await remote.ReadExactlyAsync(reply, Timeout());
        return reply[3];
    }

    internal sealed record Entry(LogLevel Level, int EventId, string Message);

    private sealed class CapturingLogger : ILogger
    {
        private readonly List<Entry> _entries = [];

        public IReadOnlyList<Entry> Entries
        {
            get
            {
                lock (_entries)
                {
                    return [.. _entries];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_entries)
            {
                _entries.Add(new Entry(logLevel, eventId.Id, formatter(state, exception)));
            }
        }
    }

    /// <summary>A clock whose timers never fire: they are recorded (their due time) and counted when disposed.</summary>
    private sealed class ManualClock : TimeProvider
    {
        // Not zero: a window must start with its first entry, not at the clock's origin.
        private long _now = TimeSpan.FromSeconds(30).Ticks;

        public List<TimeSpan> Timers { get; } = [];

        public int Disposed { get; private set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => _now;

        public void Advance(TimeSpan by) => _now += by.Ticks;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Timers.Add(dueTime);
            return new Timer(this);
        }

        private sealed class Timer(ManualClock clock) : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;

            public void Dispose() => clock.Disposed++;

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }
}
