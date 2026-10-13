using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Benchmarks;

/// <summary>
/// Where a connect's time goes: the ssh_config route against a direct connect with the same algorithms, the phases as the debug log
/// shows them, and the cost of the managed X25519 and Ed25519 on this CPU. Run with <c>-- --connect-profile</c>.
/// </summary>
internal static class ConnectProfile
{
    private const int Rounds = 20;

    public static async Task RunAsync()
    {
        var (host, port, user, password) = ComparisonBenchmarks.Server;
        var direct = new SshClientOptions
        {
            UserName = user,
            Password = password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            AlgorithmPreferences = new AlgorithmPreferences { Kex = [SshAlgorithms.Curve25519Sha256], Ciphers = ["aes256-gcm@openssh.com"], HostKeys = [SshAlgorithms.SshEd25519] },
        };

        // Warm up both paths (JIT, first DNS and socket setup).
        await (await ComparisonBenchmarks.ConnectSshSharpAsync()).DisposeAsync();
        await (await SshClient.ConnectAsync(host, port, direct)).DisposeAsync();

        var watch = Stopwatch.StartNew();
        for (var i = 0; i < Rounds; i++)
        {
            await (await ComparisonBenchmarks.ConnectSshSharpAsync()).DisposeAsync();
        }

        Console.WriteLine($"ssh_config route: {watch.Elapsed.TotalMilliseconds / Rounds:F1} ms per connect (with dispose)");

        watch.Restart();
        for (var i = 0; i < Rounds; i++)
        {
            await (await SshClient.ConnectAsync(host, port, direct)).DisposeAsync();
        }

        Console.WriteLine($"direct:           {watch.Elapsed.TotalMilliseconds / Rounds:F1} ms per connect (with dispose)");

        watch.Restart();
        var clients = new List<SshClient>();
        for (var i = 0; i < Rounds; i++)
        {
            clients.Add(await SshClient.ConnectAsync(host, port, direct));
        }

        Console.WriteLine($"direct, no dispose: {watch.Elapsed.TotalMilliseconds / Rounds:F1} ms per connect");
        watch.Restart();
        foreach (var client in clients)
        {
            await client.DisposeAsync();
        }

        Console.WriteLine($"dispose alone:      {watch.Elapsed.TotalMilliseconds / Rounds:F1} ms");

        // Where each connect's time goes, averaged: the time at which each debug log event first appears, from the start of the connect.
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Debug).AddProvider(new TimingProvider()));
        var logged = new SshClientOptions
        {
            UserName = user,
            Password = password,
            HostKeyVerifier = direct.HostKeyVerifier,
            AlgorithmPreferences = direct.AlgorithmPreferences,
            Logger = factory.CreateLogger("profile"),
        };
        for (var i = 0; i < Rounds; i++)
        {
            TimingProvider.Start = Stopwatch.GetTimestamp();
            await using (await SshClient.ConnectAsync(host, port, logged))
            {
                TimingProvider.Record("connected");
            }
        }

        Report("direct");
        for (var i = 0; i < Rounds; i++)
        {
            TimingProvider.Start = Stopwatch.GetTimestamp();
            await using (await ComparisonBenchmarks.ConnectSshSharpAsync(logged.Logger))
            {
                TimingProvider.Record("connected");
            }
        }

        Report("ssh_config route");

        // The floor: a TCP connect and the server's identification line, with nothing of either library involved.
        watch.Restart();
        for (var i = 0; i < Rounds; i++)
        {
            using var socket = new System.Net.Sockets.TcpClient { NoDelay = true };
            await socket.ConnectAsync(host, port);
            var stream = socket.GetStream();
            var one = new byte[1];
            while (await stream.ReadAsync(one) == 1 && one[0] != '\n')
            {
            }
        }

        Console.WriteLine($"TCP connect + server identification: {watch.Elapsed.TotalMilliseconds / Rounds:F1} ms");

        var scalar = new byte[32];
        var point = new byte[32];
        var output = new byte[32];
        scalar[0] = 9;
        point[0] = 9;
        watch.Restart();
        for (var i = 0; i < 200; i++)
        {
            X25519.TryAgree(scalar, point, output);
        }

        Console.WriteLine($"X25519 agree: {watch.Elapsed.TotalMilliseconds / 200:F2} ms");

        var seed = new byte[32];
        var publicKey = new byte[32];
        var signature = new byte[64];
        Ed25519.GetPublicKey(seed, publicKey);
        Ed25519.Sign(seed, output, signature);
        watch.Restart();
        for (var i = 0; i < 200; i++)
        {
            Ed25519.Verify(publicKey, output, signature);
        }

        Console.WriteLine($"Ed25519 verify: {watch.Elapsed.TotalMilliseconds / 200:F2} ms");
    }

    private static void Report(string route)
    {
        Console.WriteLine($"Phases, {route} (average time from the start of the connect at which each log event first appears):");
        foreach (var (phase, total) in TimingProvider.Totals.OrderBy(p => p.Value))
        {
            Console.WriteLine($"  {total / Rounds,7:F2} ms  {phase}");
        }

        TimingProvider.Totals.Clear();
    }

    private sealed class TimingProvider : ILoggerProvider
    {
        public static long Start;

        public static Dictionary<string, double> Totals { get; } = [];

        public static void Record(string phase)
        {
            var elapsed = Stopwatch.GetElapsedTime(Start).TotalMilliseconds;
            Totals[phase] = Totals.GetValueOrDefault(phase) + elapsed;
        }

        public ILogger CreateLogger(string categoryName) => new Logger();

        public void Dispose()
        {
        }

        private sealed class Logger : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                Record($"{eventId.Id}: {eventId.Name}");
        }
    }
}
