using System.Collections.Concurrent;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>ObscureKeystrokeTiming: typing in a terminal session goes out on a fixed grid, with chaff in the empty ticks, on a fake clock.</summary>
public class ObscureKeystrokeTimingTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(20);

    private static readonly Dictionary<string, string> PingExtension = new() { ["ping@openssh.com"] = "0" };

    private static readonly SshSessionOptions WithTerminal = new() { Terminal = new SshTerminalOptions() };

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static FakeSessionServer Server(ConcurrentQueue<string> typed, bool ping = true)
    {
        var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = ping ? PingExtension : new Dictionary<string, string>() })
        {
            OnShell = async script =>
            {
                while (await script.ReadInputAsync() is { } data)
                {
                    typed.Enqueue(System.Text.Encoding.ASCII.GetString(data));
                }
            },
        };
        return server;
    }

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, FakeTimeProvider time, TimeSpan? interval)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ObscureKeystrokeTiming = interval,
            TimeProvider = time,
        }, leaveOpen: true, Timeout());
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    /// <summary>Moves the clock tick by tick, giving the chaff loop a moment after each.</summary>
    private static async Task TicksAsync(FakeTimeProvider time, int ticks)
    {
        for (var i = 0; i < ticks; i++)
        {
            time.Advance(Interval);
            await Task.Delay(1);
        }
    }

    private static Task WriteAsync(SshSession session, string text) => session.StandardInput.WriteAsync(System.Text.Encoding.ASCII.GetBytes(text), Timeout()).AsTask();

    [Test]
    public async Task TheFirstKeystroke_GoesAtOnce_AndTheNextWaitsForTheNextTick()
    {
        var time = new FakeTimeProvider();
        var typed = new ConcurrentQueue<string>();
        await using var server = Server(typed);
        await using var client = await ConnectAsync(server, time, Interval);
        await using var session = await client.StartShellAsync(WithTerminal, Timeout());

        await WriteAsync(session, "a").WaitAsync(Timeout()); // no tick needed
        await WaitUntilAsync(() => typed.Count == 1);

        var second = WriteAsync(session, "b");
        await Task.Delay(100);
        time.Advance(Interval - TimeSpan.FromMilliseconds(1));
        await Task.Delay(100);
        await Assert.That(second.IsCompleted).IsFalse();
        await Assert.That(typed.Count).IsEqualTo(1);

        time.Advance(TimeSpan.FromMilliseconds(1));
        await second.WaitAsync(Timeout());
        await WaitUntilAsync(() => typed.Count == 2);
        await Assert.That(string.Concat(typed)).IsEqualTo("ab");
    }

    [Test]
    public async Task EmptyTicks_CarryChaff_ForOneToThreeSecondsAfterTheLastKeystroke()
    {
        var time = new FakeTimeProvider();
        var typed = new ConcurrentQueue<string>();
        await using var server = Server(typed);
        await using var client = await ConnectAsync(server, time, Interval);
        await using var session = await client.StartShellAsync(WithTerminal, Timeout());

        await WriteAsync(session, "a").WaitAsync(Timeout());
        await TicksAsync(time, 50); // 1 s: always within the chaff time
        await WaitUntilAsync(() => server.PingsReceived >= 10);

        await TicksAsync(time, 110); // 3.2 s in all: past the longest chaff time (3072 ms)
        await Task.Delay(200);
        var chaff = server.PingsReceived;
        await TicksAsync(time, 50);
        await Task.Delay(200);

        await Assert.That(server.PingsReceived).IsEqualTo(chaff); // stopped
        await Assert.That(chaff).IsLessThanOrEqualTo(3072 / 20); // at most one per tick
        await Assert.That(string.Concat(typed)).IsEqualTo("a"); // chaff is not channel data

        // Typing again starts over: the keystroke goes at once, and chaff follows.
        await WriteAsync(session, "b").WaitAsync(Timeout());
        await TicksAsync(time, 10);
        await WaitUntilAsync(() => server.PingsReceived > chaff);
        await WaitUntilAsync(() => typed.Count == 2);
    }

    [Test]
    public async Task AServerWithoutPings_GetsNoChaff_ButTheGridStill()
    {
        var time = new FakeTimeProvider();
        var typed = new ConcurrentQueue<string>();
        await using var server = Server(typed, ping: false);
        await using var client = await ConnectAsync(server, time, Interval);
        await using var session = await client.StartShellAsync(WithTerminal, Timeout());

        await WriteAsync(session, "a").WaitAsync(Timeout());
        var second = WriteAsync(session, "b");
        await Task.Delay(100);
        await Assert.That(second.IsCompleted).IsFalse();

        await TicksAsync(time, 60);
        await second.WaitAsync(Timeout());
        await Task.Delay(100);
        await Assert.That(server.PingsReceived).IsEqualTo(0);
    }

    [Test]
    public async Task APaste_GoesAtOnce_EvenWhileTyping()
    {
        var time = new FakeTimeProvider();
        var typed = new ConcurrentQueue<string>();
        await using var server = Server(typed);
        await using var client = await ConnectAsync(server, time, Interval);
        await using var session = await client.StartShellAsync(WithTerminal, Timeout());

        await WriteAsync(session, "a").WaitAsync(Timeout());
        await WriteAsync(session, new string('p', 256)).WaitAsync(Timeout()); // no tick needed
        await WriteAsync(session, "b").WaitAsync(Timeout()); // typing starts over: at once again

        await WaitUntilAsync(() => string.Concat(typed).Length == 258);
        await Assert.That(string.Concat(typed)).IsEqualTo("a" + new string('p', 256) + "b");
    }

    [Test]
    [Arguments(false, true)]
    [Arguments(true, false)]
    public async Task WithoutATerminal_OrWithoutTheOption_WritesGoAtOnce(bool terminal, bool option)
    {
        var time = new FakeTimeProvider();
        var typed = new ConcurrentQueue<string>();
        await using var server = Server(typed);
        await using var client = await ConnectAsync(server, time, option ? Interval : null);
        await using var session = await client.StartShellAsync(terminal ? WithTerminal : null, Timeout());

        await WriteAsync(session, "a").WaitAsync(Timeout());
        await WriteAsync(session, "b").WaitAsync(Timeout());
        await WriteAsync(session, "c").WaitAsync(Timeout());

        await WaitUntilAsync(() => typed.Count == 3);
        await TicksAsync(time, 20);
        await Task.Delay(100);
        await Assert.That(server.PingsReceived).IsEqualTo(0);
    }

    [Test]
    public async Task TheInterval_IsValidated()
    {
        static SshClientOptions With(TimeSpan interval) => new()
        {
            UserName = "u",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ObscureKeystrokeTiming = interval,
        };

        await Assert.That(() => With(TimeSpan.Zero)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => With(TimeSpan.FromSeconds(2))).Throws<ArgumentOutOfRangeException>();
        await Assert.That(With(TimeSpan.FromMilliseconds(1)).ObscureKeystrokeTiming).IsEqualTo(TimeSpan.FromMilliseconds(1));
        await Assert.That(With(TimeSpan.FromSeconds(1)).ObscureKeystrokeTiming).IsEqualTo(TimeSpan.FromSeconds(1));
    }

    [Test]
    [Arguments("", "20")]
    [Arguments("ObscureKeystrokeTiming yes", "20")]
    [Arguments("ObscureKeystrokeTiming no", "none")]
    [Arguments("ObscureKeystrokeTiming false", "none")]
    [Arguments("ObscureKeystrokeTiming interval:80", "80")]
    [Arguments("ObscureKeystrokeTiming interval:1000", "1000")]
    [Arguments("ObscureKeystrokeTiming interval:0", "20")]
    [Arguments("ObscureKeystrokeTiming interval:1001", "20")]
    [Arguments("ObscureKeystrokeTiming interval:-5", "20")]
    [Arguments("ObscureKeystrokeTiming sometimes", "20")]
    public async Task ObscureKeystrokeTiming_IsReadFromSshConfig(string line, string expected)
    {
        var host = SshConfig.Parse($"Host *\n {line}\n").Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h" });

        var actual = host.ObscureKeystrokeTiming is { } interval ? ((int)interval.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture) : "none";
        await Assert.That(actual).IsEqualTo(expected);
    }
}
