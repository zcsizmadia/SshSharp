using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SshSharp.Protocol;

/// <summary>
/// Checks for troubleshooting, compiled in only with <c>-p:SshSharpInstrument=true</c> (the SSHSHARP_INSTRUMENT symbol; the stress
/// workflow builds that way). Every call site compiles away otherwise, so release builds carry none of it.
/// <list type="bullet">
/// <item>Pooled buffers: each buffer rented from <see cref="System.Buffers.ArrayPool{T}.Shared"/> is tracked until it is returned, and
/// returning one that is not out (a double return, which would hand one array to two renters) is reported with both stacks.</item>
/// <item>Received data: a checksum of each chunk is taken when it arrives and checked when it is read and when it is released, so a
/// buffer overwritten while queued is reported where it happens, not as wrong bytes somewhere later.</item>
/// </list>
/// Reports go to the file named by SSHSHARP_INSTRUMENT_LOG (appended), or to standard error.
/// </summary>
internal static class Instrumentation
{
    private static readonly ConcurrentDictionary<byte[], string> Outstanding = new(ReferenceEqualityComparer.Instance);
    private static readonly ConcurrentDictionary<byte[], string> LastReturned = new(ReferenceEqualityComparer.Instance);
    private static readonly object WriteLock = new();
    private static int _reports;

    /// <summary>Whether this build has the checks (they allocate, so allocation tests skip themselves).</summary>
#if SSHSHARP_INSTRUMENT
    public static bool Enabled => true;
#else
    public static bool Enabled => false;
#endif

    /// <summary>How many problems were reported in this process.</summary>
    public static int Reports => Volatile.Read(ref _reports);

    private static readonly ConcurrentQueue<string> TraceEvents = new();
    private const int MaxTraceEvents = 4000;

    /// <summary>
    /// Records an event in a bounded in-memory trace (the newest <see cref="MaxTraceEvents"/>), for a test that hangs to show what led
    /// to it (<see cref="RecentTrace"/>). Not a problem report: nothing is written, and the stress loop does not fail on it.
    /// </summary>
    [Conditional("SSHSHARP_INSTRUMENT")]
    public static void Trace(string message)
    {
        TraceEvents.Enqueue($"{DateTime.UtcNow:HH:mm:ss.ffffff} [{Environment.CurrentManagedThreadId}] {message}");
        while (TraceEvents.Count > MaxTraceEvents && TraceEvents.TryDequeue(out _))
        {
        }
    }

    /// <summary>The traced events containing <paramref name="filter"/>, oldest first (empty unless this build is instrumented).</summary>
    public static string RecentTrace(string filter, int max = 60) =>
        string.Join(Environment.NewLine, TraceEvents.Where(e => e.Contains(filter, StringComparison.Ordinal)).TakeLast(max));

    [Conditional("SSHSHARP_INSTRUMENT")]
    public static void Rented(byte[] buffer, string owner)
    {
        Outstanding[buffer] = owner;
        LastReturned.TryRemove(buffer, out _);
    }

    [Conditional("SSHSHARP_INSTRUMENT")]
    public static void Returning(byte[] buffer, string owner)
    {
        if (!Outstanding.TryRemove(buffer, out _))
        {
            LastReturned.TryGetValue(buffer, out var earlier);
            Report($"DOUBLE RETURN of a pooled buffer ({buffer.Length} bytes) by {owner}\n  now:\n{Environment.StackTrace}\n  earlier return:\n{earlier ?? "(not seen)"}");
            return;
        }

        LastReturned[buffer] = Environment.StackTrace;
    }

    /// <summary>A checksum of received data, to compare later (FNV-1a over 64-bit words, then the tail bytes).</summary>
    public static ulong Checksum(ReadOnlySpan<byte> data)
    {
        var hash = 14695981039346656037UL;
        var words = MemoryMarshal.Cast<byte, ulong>(data);
        foreach (var word in words)
        {
            hash = (hash ^ word) * 1099511628211UL;
        }

        foreach (var b in data[(words.Length * sizeof(ulong))..])
        {
            hash = (hash ^ b) * 1099511628211UL;
        }

        return hash;
    }

    [Conditional("SSHSHARP_INSTRUMENT")]
    public static void CheckData(ReadOnlySpan<byte> data, ulong expected, uint channel, string when)
    {
        if (Checksum(data) != expected)
        {
            Report($"RECEIVED DATA CHANGED on channel {channel} ({data.Length} bytes) {when}: the buffer was overwritten while queued\n{Environment.StackTrace}");
        }
    }

    public static void Report(string message)
    {
        Interlocked.Increment(ref _reports);
        var line = $"[{DateTime.UtcNow:O}] [SshSharp instrumentation] {message}{Environment.NewLine}";
        lock (WriteLock)
        {
            if (Environment.GetEnvironmentVariable("SSHSHARP_INSTRUMENT_LOG") is { Length: > 0 } path)
            {
                File.AppendAllText(path, line);
            }
            else
            {
                Console.Error.Write(line);
            }
        }
    }
}
