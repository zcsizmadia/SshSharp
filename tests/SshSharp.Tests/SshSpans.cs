using System.Collections.Concurrent;
using System.Diagnostics;

namespace SshSharp.Tests;

/// <summary>
/// Every SshSharp span the tests produce, through one listener for the whole run. Tests that each added and disposed a listener of
/// their own, in parallel, lost and doubled spans on .NET 8: its ActivitySource notifies listeners by walking a list that restarts
/// when another listener is added or removed (so a listener can be called twice for one span) and that checks the list's length
/// outside its lock (so a list that shrank meanwhile ends the walk before a listener is reached). .NET 10 notifies from a snapshot.
/// One listener that is never removed avoids both; spans are kept by span id, so a repeated call adds nothing.
/// </summary>
internal static class SshSpans
{
    private static readonly ConcurrentDictionary<ActivitySpanId, Activity> Stopped = new();

    private static readonly ActivityListener Listener = Start();

    /// <summary>Makes sure the listener is registered; call before starting the activities a test looks for.</summary>
    public static void Listen() => _ = Listener;

    /// <summary>The stopped SshSharp spans in <paramref name="trace"/>.</summary>
    public static List<Activity> InTrace(ActivityTraceId trace) => [.. Stopped.Values.Where(a => a.TraceId == trace)];

    private static ActivityListener Start()
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SshTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => Stopped.TryAdd(activity.SpanId, activity),
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }
}
