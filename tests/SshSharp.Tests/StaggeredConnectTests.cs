using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="SshClientOptions.StaggeredConnectDelay"/>: <see cref="TcpConnector"/> racing a name's addresses as RFC 8305 describes, on
/// a fake clock, with a stand-in for the network that leaves some addresses unanswered, refuses others, and connects the rest to a
/// listener on 127.0.0.1. The addresses are from the documentation ranges, so nothing real is ever reached.
/// </summary>
public sealed class StaggeredConnectTests
{
    private static readonly TimeSpan Stagger = TimeSpan.FromMilliseconds(250);

    private static readonly IPAddress A = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress B = IPAddress.Parse("192.0.2.2");
    private static readonly IPAddress C = IPAddress.Parse("192.0.2.3");
    private static readonly IPAddress A6 = IPAddress.Parse("2001:db8::1");
    private static readonly IPAddress B6 = IPAddress.Parse("2001:db8::2");

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>
    /// The network: an address in <see cref="Silent"/> never answers (its attempt runs until cancelled), one in <see cref="Refused"/> is
    /// refused at once, one in <see cref="Held"/> connects once its gate opens, and any other connects to the listener at once.
    /// </summary>
    private sealed class Network : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public Network()
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen();
        }

        public HashSet<IPAddress> Silent { get; } = [];

        public HashSet<IPAddress> Refused { get; } = [];

        public Dictionary<IPAddress, TaskCompletionSource> Held { get; } = [];

        /// <summary>The addresses tried and their sockets, in the order the attempts started.</summary>
        public List<(IPAddress Address, Socket Socket)> Attempts { get; } = [];

        /// <summary>The attempts that ended because the race cancelled them.</summary>
        public List<IPAddress> Cancelled { get; } = [];

        public async ValueTask ConnectAsync(Socket socket, IPAddress address, int port, CancellationToken cancellationToken)
        {
            lock (Attempts)
            {
                Attempts.Add((address, socket));
            }

            if (Refused.Contains(address))
            {
                throw new SocketException((int)SocketError.ConnectionRefused);
            }

            try
            {
                if (Silent.Contains(address))
                {
                    await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken);
                }

                if (Held.TryGetValue(address, out var gate))
                {
                    await gate.Task.WaitAsync(cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                lock (Attempts)
                {
                    Cancelled.Add(address);
                }

                throw;
            }

            await socket.ConnectAsync((IPEndPoint)_listener.LocalEndPoint!, cancellationToken);
        }

        public IPAddress[] Tried()
        {
            lock (Attempts)
            {
                return [.. Attempts.Select(a => a.Address)];
            }
        }

        public void Dispose() => _listener.Dispose();
    }

    private static Task<NetworkStream> ConnectAsync(Network network, TimeProvider time, IPAddress[] addresses, Action<Socket>? configure = null,
        CancellationToken? cancellationToken = null) =>
        TcpConnector.ConnectAsync("server.example.com", 22, local: null, SshAddressFamily.Any, "the server", configure,
            (_, _) => Task.FromResult(addresses), _ => true, Stagger, time, network.ConnectAsync, cancellationToken ?? Timeout());

    private static bool IsClosed(Socket socket) => socket.SafeHandle.IsClosed;

    /// <summary>The addresses, in order, as one string to compare.</summary>
    private static string Order(params IPAddress[] addresses) => string.Join(" ", addresses.Select(a => a.ToString()));

    /// <summary>The cancelled attempts end in no particular order: they are compared sorted.</summary>
    private static readonly Comparer<IPAddress> Comparer = Comparer<IPAddress>.Create((x, y) => string.CompareOrdinal(x.ToString(), y.ToString()));

    private static SshClientOptions Options(TimeSpan? stagger) => new()
    {
        UserName = "tester",
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        StaggeredConnectDelay = stagger,
    };

    [Test]
    public async Task TheDelay_IsFrom10MillisecondsTo2Seconds_OrNull()
    {
        await Assert.That(Options(null).StaggeredConnectDelay).IsNull();
        await Assert.That(new SshConfigConnectOptions().StaggeredConnectDelay).IsNull();
        foreach (var valid in new[] { TimeSpan.FromMilliseconds(10), Stagger, TimeSpan.FromSeconds(2) })
        {
            await Assert.That(Options(valid).StaggeredConnectDelay).IsEqualTo(valid);
            await Assert.That(new SshConfigConnectOptions { StaggeredConnectDelay = valid }.StaggeredConnectDelay).IsEqualTo(valid);
        }

        foreach (var invalid in new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(9), TimeSpan.FromSeconds(2) + TimeSpan.FromTicks(1), System.Threading.Timeout.InfiniteTimeSpan })
        {
            await Assert.That(() => Options(invalid)).Throws<ArgumentOutOfRangeException>();
            await Assert.That(() => new SshConfigConnectOptions { StaggeredConnectDelay = invalid }).Throws<ArgumentOutOfRangeException>();
        }
    }

    [Test]
    public async Task AnAddressThatDoesNotAnswer_IsOvertaken_WhenTheDelayPasses()
    {
        using var network = new Network { Silent = { A } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var connect = ConnectAsync(network, time, [A, B]);

        // The first attempt has the whole delay to itself.
        await time.WaitForTimersAsync(1);
        time.Advance(Stagger - TimeSpan.FromMilliseconds(1));
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A));
        time.Advance(TimeSpan.FromMilliseconds(1));

        await using var stream = await connect.WaitAsync(Timeout());
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, B));
        await Assert.That(stream.Socket).IsSameReferenceAs(network.Attempts[1].Socket);

        // The attempt that lost is cancelled and its socket closed before ConnectAsync returns.
        await Assert.That(Order([.. network.Cancelled.Order(Comparer)])).IsEqualTo(Order(A));
        await Assert.That(IsClosed(network.Attempts[0].Socket)).IsTrue();
    }

    [Test]
    public async Task AFailedAttempt_StartsTheNext_WithoutWaitingForTheDelay()
    {
        using var network = new Network { Refused = { A } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());

        // The clock never moves.
        await using var stream = await ConnectAsync(network, time, [A, B]).WaitAsync(Timeout());

        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, B));
        await Assert.That(IsClosed(network.Attempts[0].Socket)).IsTrue();
    }

    [Test]
    public async Task AnEarlierAttempt_KeepsRunning_AndCanStillWin()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var network = new Network { Held = { [A] = gate }, Silent = { B } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var connect = ConnectAsync(network, time, [A, B]);

        await time.WaitForTimersAsync(1);
        time.Advance(Stagger);
        await WaitUntilAsync(() => network.Tried().Length == 2);
        gate.SetResult();

        await using var stream = await connect.WaitAsync(Timeout());
        await Assert.That(stream.Socket).IsSameReferenceAs(network.Attempts[0].Socket);
        await Assert.That(Order([.. network.Cancelled.Order(Comparer)])).IsEqualTo(Order(B));
        await Assert.That(IsClosed(network.Attempts[1].Socket)).IsTrue();
    }

    [Test]
    public async Task EachDelay_StartsOneMoreAttempt_AndEveryLoserIsClosed()
    {
        using var network = new Network { Silent = { A, B } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var connect = ConnectAsync(network, time, [A, B, C]);

        await time.WaitForTimersAsync(1);
        time.Advance(Stagger);
        await time.WaitForTimersAsync(2);
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, B));
        time.Advance(Stagger);

        await using var stream = await connect.WaitAsync(Timeout());
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, B, C));
        await Assert.That(Order([.. network.Cancelled.Order(Comparer)])).IsEqualTo(Order(A, B));
        await Assert.That(network.Attempts.Take(2).All(a => IsClosed(a.Socket))).IsTrue();
    }

    [Test]
    public async Task TheFamilies_TakeTurns_StartingWithTheResolversFirst()
    {
        if (!Socket.OSSupportsIPv6)
        {
            Skip.Test("This machine has no IPv6.");
            return;
        }

        // Every address refused, so each next attempt starts at once and the clock never moves.
        using var network = new Network { Refused = { A6, B6, A, B } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());

        var ex = await Assert.That(async () => await ConnectAsync(network, time, [A6, B6, A, B])).Throws<SshException>();

        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A6, A, B6, B));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).IsEqualTo("Could not connect to the server: ConnectionRefused.");
        await Assert.That(network.Attempts.All(a => IsClosed(a.Socket))).IsTrue();
    }

    [Test]
    public async Task AnIpv4AddressFirst_PutsIpv4First()
    {
        if (!Socket.OSSupportsIPv6)
        {
            Skip.Test("This machine has no IPv6.");
            return;
        }

        using var network = new Network { Refused = { A, A6, B6 } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());

        await Assert.That(async () => await ConnectAsync(network, time, [A, A6, B6])).Throws<SshException>();

        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, A6, B6));
    }

    [Test]
    public async Task WhatConfigureSocketThrows_EndsTheRace_AsItIs_AndClosesTheRunningAttempts()
    {
        using var network = new Network { Silent = { A } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var configured = 0;
        var connect = ConnectAsync(network, time, [A, B], _ =>
        {
            if (++configured == 2)
            {
                throw new InvalidOperationException("not this one");
            }
        });

        await time.WaitForTimersAsync(1);
        time.Advance(Stagger);

        await Assert.That(async () => await connect.WaitAsync(Timeout())).Throws<InvalidOperationException>();
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A));
        await Assert.That(Order([.. network.Cancelled.Order(Comparer)])).IsEqualTo(Order(A));
        await Assert.That(IsClosed(network.Attempts[0].Socket)).IsTrue();
    }

    [Test]
    public async Task Cancelling_EndsEveryAttempt()
    {
        using var network = new Network { Silent = { A, B } };
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        using var cts = new CancellationTokenSource();
        var connect = ConnectAsync(network, time, [A, B, C], cancellationToken: cts.Token);

        await time.WaitForTimersAsync(1);
        time.Advance(Stagger);
        await time.WaitForTimersAsync(2);
        await cts.CancelAsync();

        await Assert.That(async () => await connect.WaitAsync(Timeout())).Throws<OperationCanceledException>();
        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A, B));
        await Assert.That(network.Attempts.All(a => IsClosed(a.Socket))).IsTrue();
    }

    [Test]
    public async Task OneAddress_HasNothingToRace()
    {
        using var network = new Network();
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());

        await using var stream = await ConnectAsync(network, time, [A]).WaitAsync(Timeout());

        await Assert.That(Order(network.Tried())).IsEqualTo(Order(A));
        await Assert.That(time.Timers).IsEqualTo(0);
    }

    /// <summary>
    /// How many timers the race sets on <paramref name="time"/> when it connects to localhost: one at least where localhost has addresses
    /// of two families (::1 and 127.0.0.1, the first refused or the second answering), none where it has one address.
    /// </summary>
    private static int ExpectedRaceTimers() =>
        Dns.GetHostAddresses("localhost").Count(a => a.AddressFamily == AddressFamily.InterNetwork || (a.AddressFamily == AddressFamily.InterNetworkV6 && Socket.OSSupportsIPv6)) > 1 ? 1 : 0;

    [Test]
    public async Task SshClientOptions_StaggeredConnectDelay_IsWhatTheConnectionUses()
    {
        await using var server = new FakeSessionServer();
        await using var bridge = new BindAddressTests.Bridge(server);
        var time = new DelayRecordingTimeProvider();
        var delay = TimeSpan.FromMilliseconds(1234);

        await using var client = await SshClient.ConnectAsync("localhost", bridge.Port, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            StaggeredConnectDelay = delay,
            TimeProvider = time,
        }, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(Math.Min(time.Count(delay), 1)).IsEqualTo(ExpectedRaceTimers());
    }

    [Test]
    public async Task SshConfigConnectOptions_StaggeredConnectDelay_IsWhatTheConnectionUses()
    {
        var home = Path.Combine(Path.GetTempPath(), "sshsharp-stagger-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        try
        {
            await using var server = new FakeSessionServer();
            await using var bridge = new BindAddressTests.Bridge(server);
            var time = new DelayRecordingTimeProvider();
            var delay = TimeSpan.FromMilliseconds(1234);

            await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse($"Host target\n HostName localhost\n Port {bridge.Port}\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = home },
                Password = TestSecrets.Password,
                UseAgent = false,
                StaggeredConnectDelay = delay,
                TimeProvider = time,
            }, Timeout());

            await Assert.That(client.IsConnected).IsTrue();
            await Assert.That(Math.Min(time.Count(delay), 1)).IsEqualTo(ExpectedRaceTimers());
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }

    /// <summary>The system's clock, recording how long each timer made on it waits.</summary>
    private sealed class DelayRecordingTimeProvider : TimeProvider
    {
        private readonly List<TimeSpan> _delays = [];

        public int Count(TimeSpan delay)
        {
            lock (_delays)
            {
                return _delays.Count(d => d == delay);
            }
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (_delays)
            {
                _delays.Add(dueTime);
            }

            return System.CreateTimer(callback, state, dueTime, period);
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (!condition())
        {
            await Task.Delay(5, limit.Token);
        }
    }

    /// <summary>A fake clock that counts the timers made on it, so a test can wait for the race to set its next delay.</summary>
    private sealed class TimerCountingTimeProvider(FakeTimeProvider inner) : TimeProvider
    {
        private int _timers;

        public int Timers => Volatile.Read(ref _timers);

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
            while (Timers < count)
            {
                await Task.Delay(5, limit.Token);
            }
        }
    }
}
