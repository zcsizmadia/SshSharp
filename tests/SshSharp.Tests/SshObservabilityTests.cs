using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

public class SshObservabilityTests
{
    private sealed class TestLogger : ILogger
    {
        private readonly object _lock = new();
        private readonly List<(LogLevel Level, string Message, Exception? Exception)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message, Exception? Exception)> Entries
        {
            get
            {
                lock (_lock)
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
            lock (_lock)
            {
                _entries.Add((logLevel, formatter(state, exception), exception));
            }
        }
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static SshClientOptions Options(ILogger? logger = null, string? password = "secret", long rekeyBytes = 1L << 30, bool fips = false) => new()
    {
        UserName = "tester",
        Password = password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        Logger = logger,
        RekeyAfterBytes = rekeyBytes,
        FipsMode = fips,
    };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions options)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    [Test]
    public async Task LogsTheLifecycle_ButNeverASecret()
    {
        const string command = "deploy --token=top-secret-xyz";
        var logger = new TestLogger();
        await using var server = new FakeSessionServer { Password = "hunter2" };
        await using (var client = await ConnectAsync(server, Options(logger, password: "hunter2")))
        {
            var result = await client.RunCommandAsync(command, Timeout());
            await Assert.That(result.ExitStatus).IsEqualTo(0);
        }

        var all = string.Join("\n", logger.Entries.Select(e => e.Message));
        await Assert.That(all).Contains("Connected: curve25519-sha256");
        await Assert.That(all).Contains("Authenticated with method password");
        await Assert.That(all).Contains("Authenticating with method password");
        await Assert.That(all).DoesNotContain("tester"); // user names are personal data
        await Assert.That(all).Contains($"Running a command ({command.Length} characters)");
        await Assert.That(all).Contains("finished with exit status 0");
        await Assert.That(all).Contains("Negotiated key exchange curve25519-sha256");
        await Assert.That(all).Contains("Server identification: SSH-2.0-FakeServer_1.0");
        await Assert.That(all).Contains("Channel 0 opened");
        await Assert.That(all).Contains("Channel 0 closed");
        await Assert.That(all).Contains("Disconnecting");

        // The point of the exercise: nothing sensitive in any message, at any level.
        await Assert.That(all).DoesNotContain("hunter2");
        await Assert.That(all).DoesNotContain("top-secret");
        await Assert.That(all).DoesNotContain("deploy");
        await Assert.That(logger.Entries.Any(e => e.Level >= LogLevel.Warning)).IsFalse();
    }

    [Test]
    public async Task LogsRekeys()
    {
        var logger = new TestLogger();
        await using var server = new FakeSessionServer { OnExec = async script => { await script.StdoutAsync(new byte[300_000]); await script.FinishAsync(0); } };
        await using var client = await ConnectAsync(server, Options(logger, rekeyBytes: 50_000));
        await client.RunCommandAsync("bulk", Timeout());

        // The command can finish while a re-exchange is still in flight: completion is logged when the server's NEWKEYS arrives on
        // the receive loop, so wait for it (bounded) instead of assuming it already happened.
        for (var i = 0; i < 500 && !logger.Entries.Any(e => e.Message.Contains("Key exchange 2 completed")); i++)
        {
            await Task.Delay(20);
        }

        var messages = logger.Entries.Select(e => e.Message).ToList();
        await Assert.That(messages.Any(m => m.Contains("Starting a key re-exchange (size or time threshold reached)"))).IsTrue();
        await Assert.That(messages.Any(m => m.Contains("Key exchange 2 completed"))).IsTrue();
    }

    [Test]
    public async Task LogsFailuresWithoutTheCredentials()
    {
        var wrong = new TestLogger();
        await using var server = new FakeSessionServer { Password = "correct-horse" };
        _ = server.StartAsync();
        await Assert.That(async () => await SshClient.ConnectAsync(server.ClientStream, Options(wrong, password: "wrong-battery"), true, Timeout())).Throws<SshException>();
        var text = string.Join("\n", wrong.Entries.Select(e => $"{e.Level}: {e.Message}"));
        await Assert.That(text).Contains("Warning: Authentication failed; the server accepts: password");
        await Assert.That(text).DoesNotContain("tester");
        await Assert.That(text).DoesNotContain("wrong-battery");
        await Assert.That(text).DoesNotContain("correct-horse");

        var rejected = new TestLogger();
        await using var second = new FakeSessionServer();
        _ = second.StartAsync();
        var options = new SshClientOptions { UserName = "tester", Password = "x", Logger = rejected, HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(false)) };
        await Assert.That(async () => await SshClient.ConnectAsync(second.ClientStream, options, true, Timeout())).Throws<SshException>();
        await Assert.That(rejected.Entries.Any(e => e.Level == LogLevel.Warning && e.Message.Contains("was not accepted") && e.Message.Contains("SHA256:"))).IsTrue();
    }

    [Test]
    public async Task LogsUnknownMessagesAndLostConnections()
    {
        var logger = new TestLogger();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, Options(logger));

        await server.SendRawAsync(new byte[] { 200 });
        for (var i = 0; i < 100 && !logger.Entries.Any(e => e.Message.Contains("Received message 200")); i++)
        {
            await Task.Delay(20);
        }

        await Assert.That(logger.Entries.Any(e => e.Level == LogLevel.Warning && e.Message.Contains("Received message 200"))).IsTrue();

        await server.Raw.CloseAsync();
        for (var i = 0; i < 100 && !logger.Entries.Any(e => e.Level == LogLevel.Error); i++)
        {
            await Task.Delay(20);
        }

        await Assert.That(logger.Entries.Any(e => e.Level == LogLevel.Error && e.Exception is SshException)).IsTrue();
    }

    [Test]
    public async Task RecordsMetrics()
    {
        var measurements = new List<(string Instrument, double Value, KeyValuePair<string, object?>[] Tags)>();
        var lockObject = new object();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == SshTelemetry.SourceName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((i, v, t, _) => { lock (lockObject) { measurements.Add((i.Name, v, t.ToArray())); } });
        listener.SetMeasurementEventCallback<int>((i, v, t, _) => { lock (lockObject) { measurements.Add((i.Name, v, t.ToArray())); } });
        listener.SetMeasurementEventCallback<double>((i, v, t, _) => { lock (lockObject) { measurements.Add((i.Name, v, t.ToArray())); } });
        listener.Start();

        await using var server = new FakeSessionServer { OnExec = async script => { await script.StdoutAsync(new byte[1000]); await script.FinishAsync(0); } };
        await using (var client = await ConnectAsync(server, Options()))
        {
            await client.RunCommandAsync("work", Timeout());
        }

        // The listener also sees other tests running in parallel, so assert presence rather than exact totals.
        List<(string Instrument, double Value, KeyValuePair<string, object?>[] Tags)> seen;
        lock (lockObject)
        {
            seen = [.. measurements];
        }

        double Sum(string name) => seen.Where(m => m.Instrument == name).Sum(m => m.Value);
        await Assert.That(Sum("sshsharp.bytes.sent")).IsGreaterThan(0);
        await Assert.That(Sum("sshsharp.bytes.received")).IsGreaterThan(1000);
        await Assert.That(Sum("sshsharp.key_exchanges")).IsGreaterThanOrEqualTo(1);
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.connect.duration" && m.Value > 0)).IsTrue();
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.connections" && m.Value > 0)).IsTrue();
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.connections" && m.Value < 0)).IsTrue();
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.channels" && m.Value > 0)).IsTrue();
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.channels" && m.Value < 0)).IsTrue();
        await Assert.That(seen.Any(m => m.Instrument == "sshsharp.commands" && m.Tags.Any(t => t.Key == "result" && (string?)t.Value == "success"))).IsTrue();
    }

    [Test]
    public async Task RecordsTraces()
    {
        var stopped = new List<Activity>();
        var lockObject = new object();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SshTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => { lock (lockObject) { stopped.Add(activity); } },
        };
        ActivitySource.AddActivityListener(listener);

        // A root activity of our own isolates this test's spans from tests running in parallel.
        using var root = new Activity("test-root").Start();
        await using var server = new FakeSessionServer { OnExec = script => script.FinishAsync(3) };
        await using (var client = await ConnectAsync(server, Options()))
        {
            await client.RunCommandAsync("failing", Timeout());
        }

        // The listener sees every test's activities, and tests run in parallel: snapshot under the lock before reading.
        List<Activity> mine;
        lock (lockObject)
        {
            mine = stopped.Where(a => a.TraceId == root.TraceId).ToList();
        }
        var connect = mine.Single(a => a.OperationName == "SshSharp.Connect");
        await Assert.That(connect.GetTagItem("ssh.kex")).IsEqualTo("curve25519-sha256");
        await Assert.That(connect.GetTagItem("ssh.cipher")).IsEqualTo("chacha20-poly1305@openssh.com");
        await Assert.That(connect.GetTagItem("ssh.host_key.type")).IsEqualTo("ssh-ed25519");
        await Assert.That(connect.Status).IsEqualTo(ActivityStatusCode.Unset);

        var command = mine.Single(a => a.OperationName == "SshSharp.Command");
        await Assert.That(command.GetTagItem("ssh.command.exit_status")).IsEqualTo(3);
        await Assert.That(command.Tags.Any(t => t.Value?.Contains("failing", StringComparison.Ordinal) == true)).IsFalse();
    }

    [Test]
    public async Task AFailedConnectIsMarkedAsAnErrorInTheTrace()
    {
        var stopped = new List<Activity>();
        var lockObject = new object();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SshTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => { lock (lockObject) { stopped.Add(activity); } },
        };
        ActivitySource.AddActivityListener(listener);

        using var root = new Activity("test-root-2").Start();
        await using var server = new FakeSessionServer { Password = "right" };
        _ = server.StartAsync();
        await Assert.That(async () => await SshClient.ConnectAsync(server.ClientStream, Options(password: "wrong"), true, Timeout())).Throws<SshException>();

        Activity connect;
        lock (lockObject)
        {
            connect = stopped.Single(a => a.TraceId == root.TraceId && a.OperationName == "SshSharp.Connect");
        }
        await Assert.That(connect.Status).IsEqualTo(ActivityStatusCode.Error);
        await Assert.That(connect.StatusDescription).IsEqualTo(nameof(SshAuthenticationException));
    }

    [Test]
    public async Task FipsModeKeepsOnlyApprovedAlgorithms()
    {
        var fips = AlgorithmPreferences.Fips();
        await Assert.That(fips.Kex.Any(k => k.StartsWith("curve25519", StringComparison.Ordinal))).IsFalse();
        await Assert.That(fips.HostKeys.Contains("ssh-ed25519")).IsFalse();
        await Assert.That(fips.Ciphers.Contains("chacha20-poly1305@openssh.com")).IsFalse();
        await Assert.That(fips.Ciphers.Contains("aes256-gcm@openssh.com")).IsTrue();

        // A server that only offers non-FIPS algorithms cannot be used...
        await using var nonFips = new FakeSessionServer();
        _ = nonFips.StartAsync();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(nonFips.ClientStream, Options(fips: true), true, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);

        // ...and one that offers approved ones works.
        await using var approved = new FakeSessionServer(new FakeServerOptions
        {
            Kex = SshAlgorithms.EcdhNistp256,
            Cipher = "aes256-gcm@openssh.com",
            HostKey = FakeHostKey.Ecdsa(256),
        });
        await using var client = await ConnectAsync(approved, Options(fips: true));
        var result = await client.RunCommandAsync("ok", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(client.HostKey.KeyType).IsEqualTo("ecdsa-sha2-nistp256");
    }
}