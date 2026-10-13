using System.Diagnostics;

namespace SshSharp.Benchmarks;

/// <summary>
/// Streams a large command output (1 GiB by default) through one library, in a process of its own, and reports what it cost: peak
/// working set, bytes allocated, garbage collections, threads and time. Run once per library:
/// <c>-- --peak sshsharp [MiB]</c> and <c>-- --peak sshnet [MiB]</c>.
/// </summary>
internal static class PeakMemory
{
    /// <summary>Counts the runtime's GCAllocationTick events by type: where the garbage comes from, without a profiler.</summary>
    private sealed class AllocationSampler : System.Diagnostics.Tracing.EventListener
    {
        public System.Collections.Concurrent.ConcurrentDictionary<string, long> ByType { get; } = new();

        protected override void OnEventSourceCreated(System.Diagnostics.Tracing.EventSource source)
        {
            if (source.Name == "Microsoft-Windows-DotNETRuntime")
            {
                EnableEvents(source, System.Diagnostics.Tracing.EventLevel.Verbose, (System.Diagnostics.Tracing.EventKeywords)0x1);
            }
        }

        protected override void OnEventWritten(System.Diagnostics.Tracing.EventWrittenEventArgs e)
        {
            if (e.EventName?.StartsWith("GCAllocationTick", StringComparison.Ordinal) == true && e.Payload is { } p)
            {
                var name = e.PayloadNames!.IndexOf("TypeName") is var i and >= 0 ? p[i]?.ToString() ?? "?" : "?";
                ByType.AddOrUpdate(name, 1, (_, n) => n + 1);
            }
        }
    }

    public static async Task RunAsync(string library, int mebibytes)
    {
        using var allocations = new AllocationSampler();
        try
        {
            await RunCoreAsync(library, mebibytes);
        }
        finally
        {
            // The runtime reports a sample about every 100 KB allocated, with the type that crossed the mark.
            Console.WriteLine("  allocations by type (sampled):");
            foreach (var (type, count) in allocations.ByType.OrderByDescending(kv => kv.Value).Take(15))
            {
                Console.WriteLine($"  ~{count * 100} KB  {type}");
            }
        }
    }

    private static async Task RunCoreAsync(string library, int mebibytes)
    {
        var bytes = (long)mebibytes * 1024 * 1024;
        // dd, not head -c: BusyBox head copies in small pieces and caps the transfer at about 130 MiB/s.
        var command = $"dd if=/dev/zero bs=1048576 count={mebibytes} 2>/dev/null";
        var process = Process.GetCurrentProcess();
        var maxPoolThreads = 0;
        using var sampling = new CancellationTokenSource();

        // ThreadPool.ThreadCount is cheap to read; Process.Threads would allocate on every sample and skew the numbers.
        var sampler = Task.Run(async () =>
        {
            while (!sampling.IsCancellationRequested)
            {
                maxPoolThreads = Math.Max(maxPoolThreads, ThreadPool.ThreadCount);
                await Task.Delay(100);
            }
        });

        long counted;
        var allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);
        var collections = (GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2));
        var cpuBefore = process.TotalProcessorTime;
        var userBefore = process.UserProcessorTime;
        var watch = Stopwatch.StartNew();
        if (library == "sshsharp")
        {
            await using var client = await ComparisonBenchmarks.ConnectSshSharpAsync();
            await using var session = await client.StartCommandAsync(command);
            counted = await ComparisonBenchmarks.CountAsync(session.StandardOutput);
            await session.WaitForExitAsync();
        }
        else
        {
            using var client = await ComparisonBenchmarks.ConnectSshNetAsync();
            using var run = client.CreateCommand(command);
            var execution = run.ExecuteAsync();
            counted = await ComparisonBenchmarks.CountAsync(run.OutputStream);
            await execution;
        }

        watch.Stop();
        await sampling.CancelAsync();
        await sampler;
        process.Refresh();
        Console.WriteLine($"{library}: {counted / 1024 / 1024} MiB in {watch.Elapsed.TotalSeconds:F1} s ({counted / 1024.0 / 1024 / watch.Elapsed.TotalSeconds:F0} MiB/s)");
        // The server usually sets the pace (sshd encrypts each connection on one core), so client CPU per GiB is what tells libraries apart.
        var cpu = process.TotalProcessorTime - cpuBefore;
        var user = process.UserProcessorTime - userBefore;
        var gibibytes = counted / 1024.0 / 1024 / 1024;
        Console.WriteLine($"  client CPU {cpu.TotalSeconds:F1} s ({cpu.TotalSeconds / gibibytes:F2} s per GiB: user {user.TotalSeconds / gibibytes:F2}, kernel {(cpu - user).TotalSeconds / gibibytes:F2})");
        Console.WriteLine($"  peak working set {process.PeakWorkingSet64 / 1024 / 1024} MiB, allocated {(GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore) / 1024 / 1024} MiB");
        Console.WriteLine($"  GCs gen0/1/2: {GC.CollectionCount(0) - collections.Item1}/{GC.CollectionCount(1) - collections.Item2}/{GC.CollectionCount(2) - collections.Item3}, max pool threads {maxPoolThreads}, threads at the end {process.Threads.Count}");
    }
}
