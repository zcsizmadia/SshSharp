using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/keepalive-and-reconnect.md and docs/how-to/cancellation-and-timeouts.md.</summary>
internal static class Resilience
{
    public static async Task KeepAliveAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <keepalive>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await LoadKeysAsync(cancellationToken),
            HostKeyVerifier = verifier,
            KeepAliveInterval = TimeSpan.FromSeconds(15),  // ServerAliveInterval
            KeepAliveCountMax = 3,                         // ServerAliveCountMax: dead after about 45 s of silence
        }, cancellationToken);

        // Fires once, whatever ends the connection: the server, the network, missed keep-alives, or DisposeAsync.
        client.ConnectionClosed.Register(() => Console.WriteLine($"Disconnected: {client.ConnectionError?.Message ?? "disposed"}"));
        // </keepalive>
    }

    public static async Task PingAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <ping>
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));       // a silent server would otherwise be waited for until the connection ends
        var roundTrip = await client.PingAsync(timeout.Token);
        Console.WriteLine($"alive, {roundTrip.TotalMilliseconds:F1} ms");
        // </ping>
    }

    public static async Task LinkedAsync(SshClient client, CancellationToken stoppingToken)
    {
        // <linked>
        // Stop work when either the caller gives up or the connection ends.
        using var both = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, client.ConnectionClosed);
        await using var session = await client.StartCommandAsync("tail -F /var/log/app.log", cancellationToken: both.Token);
        using var reader = new StreamReader(session.StandardOutput);
        while (await reader.ReadLineAsync(both.Token) is { } line)
        {
            Console.WriteLine(line);
        }
        // </linked>
    }

    // <reconnecting>
    /// <summary>One connection, opened on first use and opened again after it drops. Safe to share between tasks.</summary>
    internal sealed class ReconnectingClient(Func<CancellationToken, Task<SshClient>> connect) : IAsyncDisposable
    {
        private readonly SemaphoreSlim _gate = new(1, 1);
        private SshClient? _client;

        public async Task<SshClient> GetAsync(CancellationToken cancellationToken)
        {
            if (_client is { IsConnected: true } current)
            {
                return current;
            }

            await _gate.WaitAsync(cancellationToken);
            try
            {
                if (_client is { IsConnected: true } other)  // another caller reconnected meanwhile
                {
                    return other;
                }

                if (_client is not null)
                {
                    await _client.DisposeAsync();
                    _client = null;
                }

                return _client = await connect(cancellationToken);
            }
            finally
            {
                _gate.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_client is not null)
            {
                await _client.DisposeAsync();
            }

            _gate.Dispose();
        }
    }
    // </reconnecting>

    public static async Task RetryAsync(ReconnectingClient connection, CancellationToken cancellationToken)
    {
        // <retry>
        // Retry what is safe to run twice, with a growing delay. A command that failed because the connection dropped may
        // or may not have run on the server: only you know whether running it again is harmless.
        var delay = TimeSpan.FromSeconds(1);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var client = await connection.GetAsync(cancellationToken);
                var result = await client.RunCommandAsync("cat /proc/loadavg", cancellationToken);
                Console.WriteLine(result.StandardOutputText);
                return;
            }
            catch (SshException ex) when (attempt < 5 && ex.Reason is SshFailureReason.ConnectFailed or SshFailureReason.ConnectionClosed
                or SshFailureReason.Timeout)
            {
                await Task.Delay(delay, cancellationToken);
                delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, TimeSpan.FromSeconds(30).Ticks));
            }
        }
        // </retry>
    }

    public static async Task ConnectTimeoutAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <connect-timeout>
        try
        {
            await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
            {
                UserName = "deploy",
                PrivateKeys = await LoadKeysAsync(cancellationToken),
                HostKeyVerifier = verifier,
                ConnectTimeout = TimeSpan.FromSeconds(15),   // TCP, key exchange and authentication together
            }, cancellationToken);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.Timeout)
        {
            Console.WriteLine($"Gave up: {ex.Message}");  // the caller cancelling is an OperationCanceledException instead
        }
        // </connect-timeout>
    }

    public static async Task ConnectTimeoutTokenAsync(SshClientOptions options, CancellationToken cancellationToken)
    {
        // <connect-timeout-token>
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));   // TCP, key exchange and authentication together
        try
        {
            await using var client = await SshClient.ConnectAsync("example.com", 22, options, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("example.com did not answer within 15 seconds.");
        }
        // </connect-timeout-token>
    }

    public static async Task CommandTimeoutAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <command-timeout>
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        // `timeout` on the server stops the program too; cancelling only closes this side's channel.
        var result = await client.RunCommandAsync("timeout 110 ./run-migrations.sh", timeout.Token);
        // </command-timeout>
        _ = result;
    }

    public static async Task StopOnCancelAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stop-on-cancel>
        await using var session = await client.StartCommandAsync("./long-job.sh", cancellationToken: cancellationToken);
        try
        {
            await session.StandardOutput.CopyToAsync(Stream.Null, cancellationToken);
            await session.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Ask the program to stop before the channel closes (OpenSSH delivers signals; some servers ignore them).
            await session.SendSignalAsync("TERM", CancellationToken.None);
            throw;
        }
        // </stop-on-cancel>
    }

    private static Task<IReadOnlyList<SshPrivateKey>> LoadKeysAsync(CancellationToken cancellationToken) =>
        SshAgent.FromEnvironment()?.GetKeysAsync(cancellationToken) ?? Task.FromResult<IReadOnlyList<SshPrivateKey>>([]);
}
