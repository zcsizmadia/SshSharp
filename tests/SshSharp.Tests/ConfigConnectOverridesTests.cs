using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <c>ConnectionAttempts</c> on the connect path, and the <see cref="SshConfigConnectOptions"/> settings that override ssh_config:
/// Port, ConnectTimeout, ConnectionAttempts, AddressFamily and keep-alive.
/// </summary>
public sealed class ConfigConnectOverridesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-cfgoverrides-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private SshConfigResolveOptions Resolve => new() { LocalUser = "local", HomeDirectory = _dir };

    private const string Trusting = " User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n";

    private static SshException Refused() =>
        new(SshFailureReason.ConnectFailed, "Could not connect to the server: ConnectionRefused.", new SocketException((int)SocketError.ConnectionRefused));

    /// <summary>A connector that fails with <paramref name="failure"/> the first <paramref name="failures"/> times, then reaches <paramref name="server"/>.</summary>
    private static Func<string, int, SshAddressFamily, CancellationToken, ValueTask<(Stream, IAsyncDisposable?)>> FailingThen(
        int failures, Func<Exception> failure, FakeSessionServer? server, List<(string Host, int Port)> calls) =>
        (host, port, _, _) =>
        {
            lock (calls)
            {
                calls.Add((host, port));
                if (calls.Count <= failures || server is null)
                {
                    throw failure();
                }
            }

            _ = server.StartAsync();
            return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
        };

    [Test]
    public async Task ConnectionAttempts_TriesAnUnreachableServerAgain_OneSecondApart()
    {
        await using var server = new FakeSessionServer();
        var calls = new List<(string, int)>();
        var stopwatch = Stopwatch.StartNew();
        await using var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 3\n" + Trusting),
            ResolveOptions = Resolve,
            Password = TestSecrets.Password,
            TcpConnector = FailingThen(1, Refused, server, calls),
        }, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(calls.Count).IsEqualTo(2);
        await Assert.That(stopwatch.Elapsed).IsGreaterThanOrEqualTo(TimeSpan.FromMilliseconds(900));
    }

    [Test]
    public async Task ConnectionAttempts_GivesUpAfterTheLastAttempt()
    {
        var calls = new List<(string, int)>();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 2\n" + Trusting),
            ResolveOptions = Resolve,
            TcpConnector = FailingThen(int.MaxValue, Refused, null, calls),
        }, Timeout()));

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.InnerException).IsTypeOf<SocketException>();
        await Assert.That(calls.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(SocketError.HostNotFound)] // a name that does not resolve
    [Arguments(SocketError.AddressNotAvailable)] // a bind address that cannot be used
    [Arguments(SocketError.AccessDenied)]
    public async Task ConnectionAttempts_DoesNotRetryWhatAnotherAttemptWouldNotChange(SocketError error)
    {
        var calls = new List<(string, int)>();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 5\n" + Trusting),
            ResolveOptions = Resolve,
            TcpConnector = FailingThen(int.MaxValue, () => new SshException(SshFailureReason.ConnectFailed, "No.", new SocketException((int)error)), null, calls),
        }, Timeout()));
        await Assert.That(calls.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(SocketError.ConnectionRefused)]
    [Arguments(SocketError.TimedOut)]
    [Arguments(SocketError.HostUnreachable)]
    [Arguments(SocketError.NetworkUnreachable)]
    [Arguments(SocketError.HostDown)]
    [Arguments(SocketError.NetworkDown)]
    public async Task ConnectionAttempts_RetriesEveryWayOfNotReachingTheServer(SocketError error)
    {
        await using var server = new FakeSessionServer();
        var calls = new List<(string, int)>();
        await using var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n" + Trusting),
            ResolveOptions = Resolve,
            Password = TestSecrets.Password,
            ConnectionAttempts = 2, // the override, with nothing in the configuration
            TcpConnector = FailingThen(1, () => new SshException(SshFailureReason.ConnectFailed, "No.", new SocketException((int)error)), server, calls),
        }, Timeout());
        await Assert.That(calls.Count).IsEqualTo(2);
    }

    [Test]
    public async Task ConnectionAttempts_NeverRetriesOnceTheServerWasReached()
    {
        // The handshake fails (an unknown host key under StrictHostKeyChecking yes): that is not a connection-level failure.
        await using var server = new FakeSessionServer();
        var calls = new List<(string, int)>();
        await Assert.ThrowsAsync<SshHostKeyException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 3\n User tester\n StrictHostKeyChecking yes\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n"),
            ResolveOptions = Resolve,
            Password = TestSecrets.Password,
            TcpConnector = FailingThen(0, Refused, server, calls),
        }, Timeout()));
        await Assert.That(calls.Count).IsEqualTo(1);

        // A connection error without a socket error behind it (a proxy's refusal, say) is not retried either.
        calls.Clear();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 3\n" + Trusting),
            ResolveOptions = Resolve,
            TcpConnector = FailingThen(int.MaxValue, () => new SshException(SshFailureReason.ConnectFailed, "The proxy refused."), null, calls),
        }, Timeout()));
        await Assert.That(calls.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ConnectTimeout_BoundsAllTheAttemptsTogether()
    {
        // On a fake clock: on the real one, a starved thread pool could run a wait that ended after the deadline before the deadline's
        // own callback, and start one attempt too many (seen on a macOS runner). The clock moves only once the deadline's timer and each
        // wait's are set, so the count is exact: an attempt at 0 s and at 1 s, then the deadline at 1.5 s, before the next at 2 s.
        var time = new TimerCountingTimeProvider(new FakeTimeProvider());
        var calls = new List<(string, int)>();
        var connect = SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectionAttempts 100\n ConnectTimeout 300\n" + Trusting),
            ResolveOptions = Resolve,
            ConnectTimeout = TimeSpan.FromMilliseconds(1500), // overrides the configuration's 300 seconds
            TcpConnector = FailingThen(int.MaxValue, Refused, null, calls),
            TimeProvider = time,
        }, Timeout());

        await time.WaitForTimersAsync(2); // the deadline, and the wait after the first attempt
        time.Advance(TimeSpan.FromSeconds(1));
        await time.WaitForTimersAsync(3); // the wait after the second attempt
        time.Advance(TimeSpan.FromMilliseconds(500));

        var ex = await Assert.ThrowsAsync<SshException>(async () => await connect);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>();
        await Assert.That(calls.Count).IsEqualTo(2);
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

    [Test]
    public async Task AnInfiniteConnectTimeout_OverridesTheConfiguredOne()
    {
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ConnectTimeout 1\n" + Trusting),
            ResolveOptions = Resolve,
            ConnectTimeout = System.Threading.Timeout.InfiniteTimeSpan,
            TcpConnector = async (_, _, _, ct) =>
            {
                await Task.Delay(1500, ct); // longer than the configured second
                throw Refused();
            },
        }, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
    }

    [Test]
    [Arguments("box", 2300, 2300)] // the option overrides the configuration's Port 2222
    [Arguments("ssh://box:2201", 2300, 2201)] // a port in the destination wins
    public async Task Port_OverridesTheConfiguration(string destination, int optionPort, int expected)
    {
        var calls = new List<(string, int)>();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(destination, new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n Port 2222\n" + Trusting),
            ResolveOptions = Resolve,
            Port = optionPort,
            TcpConnector = FailingThen(int.MaxValue, Refused, null, calls),
        }, Timeout()));
        await Assert.That(calls.Single()).IsEqualTo(("box", expected));
    }

    [Test]
    public async Task Port_IsTheDestinations_NotAJumpHosts()
    {
        var calls = new List<(string, int)>();
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n ProxyJump jump\n" + Trusting),
            ResolveOptions = Resolve,
            Port = 2200,
            TcpConnector = FailingThen(int.MaxValue, Refused, null, calls),
        }, Timeout()));
        await Assert.That(calls.Single()).IsEqualTo(("jump", 22));
    }

    [Test]
    public async Task Port_IsSeenByResolution()
    {
        // %p in a Match exec command is the overriding port, as with ssh -p.
        string? command = null;
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n" + Trusting + "Match exec \"check %p\"\n Port 2400\n"),
            ResolveOptions = new SshConfigResolveOptions
            {
                LocalUser = "local",
                HomeDirectory = _dir,
                ExecMatcher = (text, _) =>
                {
                    command = text;
                    return ValueTask.FromResult(true);
                },
            },
            Port = 2200,
            TcpConnector = FailingThen(int.MaxValue, Refused, null, []),
        }, Timeout()));
        await Assert.That(command).IsEqualTo("check 2200");
    }

    [Test]
    [Arguments(null, SshAddressFamily.Inet)]
    [Arguments(SshAddressFamily.Inet6, SshAddressFamily.Inet6)]
    [Arguments(SshAddressFamily.Any, SshAddressFamily.Any)]
    public async Task AddressFamily_OverridesTheConfiguration(SshAddressFamily? option, SshAddressFamily expected)
    {
        SshAddressFamily? seen = null;
        await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n AddressFamily inet\n" + Trusting),
            ResolveOptions = Resolve,
            AddressFamily = option,
            TcpConnector = (_, _, family, _) =>
            {
                seen = family;
                throw Refused();
            },
        }, Timeout()));
        await Assert.That(seen).IsEqualTo(expected);
    }

    [Test]
    public async Task KeepAlive_FollowsTheConfiguration_UnlessOverridden()
    {
        const string KeepAlive = " ServerAliveInterval 30\n ServerAliveCountMax 5\n";
        await using (var server = new FakeSessionServer())
        await using (var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n" + KeepAlive + Trusting),
            ResolveOptions = Resolve,
            Password = TestSecrets.Password,
            TcpConnector = FailingThen(0, Refused, server, []),
        }, Timeout()))
        {
            await Assert.That(client.Options.KeepAliveInterval).IsEqualTo(TimeSpan.FromSeconds(30));
            await Assert.That(client.Options.KeepAliveCountMax).IsEqualTo(5);
        }

        await using (var server = new FakeSessionServer())
        await using (var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host box\n" + KeepAlive + Trusting),
            ResolveOptions = Resolve,
            Password = TestSecrets.Password,
            KeepAliveInterval = TimeSpan.FromSeconds(10),
            KeepAliveCountMax = 7,
            TcpConnector = FailingThen(0, Refused, server, []),
        }, Timeout()))
        {
            await Assert.That(client.Options.KeepAliveInterval).IsEqualTo(TimeSpan.FromSeconds(10));
            await Assert.That(client.Options.KeepAliveCountMax).IsEqualTo(7);
        }

        // Zero turns keep-alives off, whatever the configuration says; so does infinite, as SshClientOptions.KeepAliveInterval takes it.
        foreach (var off in new[] { TimeSpan.Zero, System.Threading.Timeout.InfiniteTimeSpan })
        {
            await using var server = new FakeSessionServer();
            await using var client = await SshClient.ConnectAsync("box", new SshConfigConnectOptions
            {
                UseAgent = false,
                Config = SshConfig.Parse("Host box\n" + KeepAlive + Trusting),
                ResolveOptions = Resolve,
                Password = TestSecrets.Password,
                KeepAliveInterval = off,
                TcpConnector = FailingThen(0, Refused, server, []),
            }, Timeout());
            await Assert.That(client.Options.KeepAliveInterval).IsNull();
            await Assert.That(client.Options.KeepAliveCountMax).IsEqualTo(5);
        }
    }

    [Test]
    public async Task InvalidOverrides_AreRefused()
    {
        await Assert.That(() => new SshConfigConnectOptions { Port = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { Port = 65536 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { ConnectTimeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { ConnectTimeout = TimeSpan.FromSeconds(-2) }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { ConnectTimeout = TimeSpan.FromDays(25) }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { ConnectionAttempts = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { KeepAliveInterval = TimeSpan.FromSeconds(-1) }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshConfigConnectOptions { KeepAliveCountMax = 0 }).Throws<ArgumentOutOfRangeException>();

        var valid = new SshConfigConnectOptions
        {
            Port = 65535,
            ConnectTimeout = TimeSpan.FromDays(24),
            ConnectionAttempts = 1,
            KeepAliveInterval = TimeSpan.Zero,
            KeepAliveCountMax = 1,
        };
        await Assert.That(valid.Port).IsEqualTo(65535);
        await Assert.That(new SshConfigConnectOptions { Port = 1 }.Port).IsEqualTo(1);
    }
}
