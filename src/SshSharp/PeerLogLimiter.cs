using Microsoft.Extensions.Logging;

namespace SshSharp;

/// <summary>
/// Limits the log entries the server can trigger again and again on one connection: forwarded connections that are refused or cannot be
/// made, messages this client does not implement, and forwarded agent requests ForwardAgentFilter refuses. Like OpenSSH, which
/// rate-limits its refused-forwarding messages, it lets a burst through and then quietens down: in each window of <see cref="Window"/>
/// that starts with an entry, the first <see cref="Burst"/> are written at their own level and the rest at Debug, and when the window
/// ends one summary says how many were lowered. A server that keeps provoking them costs a few entries a minute, not one per message.
/// </summary>
internal sealed class PeerLogLimiter : IDisposable
{
    /// <summary>How many entries each window writes at their own level.</summary>
    internal const int Burst = 8;

    /// <summary>How long a window lasts, from its first entry.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private bool _started;
    private long _windowStart;
    private int _written;

    // The entries lowered to Debug in this window, and the highest level among them, which the summary is written at.
    private int _lowered;
    private LogLevel _loweredLevel = LogLevel.Trace;

    // Writes the summary when the window ends. It exists only while entries have been lowered, so a quiet connection has no timer.
    private ITimer? _summary;
    private bool _disposed;

    public PeerLogLimiter(ILogger logger, TimeProvider time)
    {
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// The level to write an entry the server triggered at: <paramref name="level"/> within the window's burst, Debug beyond it. Call it
    /// once for each entry, as it counts them.
    /// </summary>
    public LogLevel Admit(LogLevel level)
    {
        (int Count, LogLevel Level) owed = default;
        LogLevel admitted;
        lock (_gate)
        {
            var now = _time.GetTimestamp();
            if (!_started || _time.GetElapsedTime(_windowStart, now) >= Window)
            {
                // A new window. A summary the last one still owes (its timer has not run yet) is written first, so it comes before this
                // entry rather than after it.
                owed = TakeLowered();
                _started = true;
                _windowStart = now;
                _written = 0;
            }

            if (_written < Burst)
            {
                _written++;
                admitted = level;
            }
            else
            {
                _lowered++;
                if (level > _loweredLevel)
                {
                    _loweredLevel = level;
                }

                if (_summary is null && !_disposed)
                {
                    var remaining = Window - _time.GetElapsedTime(_windowStart, now);
                    _summary = _time.CreateTimer(static state => ((PeerLogLimiter)state!).OnWindowEnded(), this, remaining, Timeout.InfiniteTimeSpan);
                }

                admitted = LogLevel.Debug;
            }
        }

        WriteSummary(owed);
        return admitted;
    }

    /// <summary>Writes the summary still owed, if any, and stops the timer; entries admitted afterwards are still limited.</summary>
    public void Dispose()
    {
        (int Count, LogLevel Level) owed;
        lock (_gate)
        {
            _disposed = true;
            owed = TakeLowered();
        }

        WriteSummary(owed);
    }

    private void OnWindowEnded()
    {
        (int Count, LogLevel Level) owed;
        lock (_gate)
        {
            owed = TakeLowered();
        }

        WriteSummary(owed);
    }

    /// <summary>Takes the count of lowered entries for a summary and resets it; called under the lock.</summary>
    private (int Count, LogLevel Level) TakeLowered()
    {
        var owed = (_lowered, _loweredLevel);
        _lowered = 0;
        _loweredLevel = LogLevel.Trace;
        _summary?.Dispose();
        _summary = null;
        return owed;
    }

    // Written outside the lock: a logger can be slow, and the entries it is summarizing must not wait for it.
    private void WriteSummary((int Count, LogLevel Level) owed)
    {
        if (owed.Count > 0)
        {
            SshLog.PeerTriggeredEntriesLowered(_logger, owed.Level, owed.Count, Burst);
        }
    }
}
