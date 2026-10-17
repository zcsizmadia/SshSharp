using System.Collections.Concurrent;
using SshSharp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/fleet-health-check.md.</summary>
internal static class FleetHealth
{
    // <fleet>
    public sealed record HostReport(string Host, bool Ok, string Detail, TimeSpan Elapsed);

    /// <summary>Checks many hosts at once, each with its own connection and time limit, and reports every host, reachable or not.</summary>
    public static async Task<IReadOnlyList<HostReport>> CheckAsync(IEnumerable<string> hosts, CancellationToken cancellationToken)
    {
        var reports = new ConcurrentBag<HostReport>();
        var parallel = new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = cancellationToken };

        await Parallel.ForEachAsync(hosts, parallel, async (host, ct) =>
        {
            var started = TimeProvider.System.GetTimestamp();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));   // one slow host must not hold up the report

            try
            {
                // Each host by its ssh_config alias (or user@host). No prompts are possible here, so an unknown host key fails.
                await using var client = await SshClient.ConnectAsync(host, cancellationToken: timeout.Token);
                var result = await client.RunCommandAsync(
                    "cat /proc/loadavg; df -P / | tail -1; systemctl is-system-running", timeout.Token);
                var lines = result.StandardOutputText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var diskUsed = lines.Length > 1 ? lines[1].Split(' ', StringSplitOptions.RemoveEmptyEntries)[4] : "?";
                var state = lines.Length > 2 ? lines[2] : "?";
                var ok = state is "running" && diskUsed.TrimEnd('%') is var d && int.TryParse(d, out var used) && used < 90;
                reports.Add(new(host, ok, $"load {lines.FirstOrDefault()?.Split(' ')[0]}, disk {diskUsed}, {state}", Elapsed(started)));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                reports.Add(new(host, false, "timed out", Elapsed(started)));
            }
            catch (SshException ex)
            {
                reports.Add(new(host, false, $"{ex.Reason}: {ex.Message}", Elapsed(started)));
            }
        });

        return [.. reports.OrderBy(r => r.Ok).ThenBy(r => r.Host, StringComparer.Ordinal)];
    }

    private static TimeSpan Elapsed(long started) => TimeProvider.System.GetElapsedTime(started);
    // </fleet>

    public static async Task<int> MainAsync(string[] args)
    {
        // <fleet-main>
        // fleet-check hosts.txt: one alias or user@host per line.
        var hosts = (await File.ReadAllLinesAsync(args[0])).Where(l => l.Length > 0 && !l.StartsWith('#'));
        var reports = await CheckAsync(hosts, CancellationToken.None);
        foreach (var r in reports)
        {
            Console.WriteLine($"{(r.Ok ? "ok  " : "FAIL")} {r.Host,-30} {r.Elapsed.TotalSeconds,5:F1}s  {r.Detail}");
        }

        return reports.All(r => r.Ok) ? 0 : 1;
        // </fleet-main>
    }
}
