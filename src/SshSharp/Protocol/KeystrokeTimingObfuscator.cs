using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>
/// OpenSSH's <c>ObscureKeystrokeTiming</c> (9.5+) for a terminal session's input. While someone types, keystrokes leave only on a fixed
/// grid of intervals, and the intervals with nothing to send carry a chaff PING of the same size instead, so the timing of the packets no
/// longer gives away the timing of the keys. It starts with a keystroke, which goes at once, and keeps chaffing for a random 1 to 3
/// seconds after the last one. A write too large to be typing (a paste), a key re-exchange or the end of the session stops it, and the
/// next keystroke starts it again. Chaff is sent only to servers that answer pings (<c>ping@openssh.com</c>), as in OpenSSH.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001",
    Justification = "The gate's wait handle is never created, so it holds nothing to release; the chaff loop may still be using it when the session ends.")]
internal sealed class KeystrokeTimingObfuscator
{
    /// <summary>Writes smaller than this count as typing; OpenSSH's test is less than this much output waiting to be sent.</summary>
    internal const int InteractiveLimit = 256;

    // After the last keystroke, chaff goes on for 1024 ms plus up to 2048 ms more, chosen at random each time (OpenSSH's values).
    private const int ChaffMinimumMilliseconds = 1024;
    private const int ChaffRandomMilliseconds = 2048;

    private readonly SshChannel _channel;
    private readonly SshConnection _connection;
    private readonly TimeSpan _interval;
    private readonly TimeProvider _time;
    private readonly long _origin;

    // Held by a write from its arrival until it is sent, and by the chaff loop while it decides: writes stay in order, and a tick carries
    // either a keystroke or chaff, never both.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _active;
    private bool _chaffRunning;
    private TimeSpan _next; // the next tick, measured from _origin
    private TimeSpan _chaffUntil;
    private long _chaffSent;
    private volatile bool _stopped;

    public KeystrokeTimingObfuscator(SshChannel channel, SshConnection connection, TimeSpan interval)
    {
        _channel = channel;
        _connection = connection;
        _interval = interval;
        _time = connection.Time;
        _origin = _time.GetTimestamp();
    }

    /// <summary>Chaff packets sent so far, for tests.</summary>
    internal long ChaffSent => Interlocked.Read(ref _chaffSent);

    private TimeSpan Now => _time.GetElapsedTime(_origin);

    /// <summary>Sends <paramref name="data"/> on the channel: at once, or on the next tick while someone is typing.</summary>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = Now;
            if (_stopped || data.Length >= InteractiveLimit || _connection.IsRekeying)
            {
                // Not typing (or not any more): sent as it comes. The next keystroke starts over, and goes at once.
                _active = false;
                await _channel.SendDataAsync(data, cancellationToken).ConfigureAwait(false);
                return;
            }

            _chaffUntil = now + TimeSpan.FromMilliseconds(ChaffMinimumMilliseconds + RandomNumberGenerator.GetInt32(ChaffRandomMilliseconds));
            if (!_active)
            {
                _active = true;
                _next = now + _interval;
                if (!_chaffRunning)
                {
                    _chaffRunning = true;
                    _ = Task.Run(RunChaffAsync, CancellationToken.None);
                }

                await _channel.SendDataAsync(data, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (_next > now)
            {
                await Task.Delay(_next - now, _time, cancellationToken).ConfigureAwait(false);
            }

            await _channel.SendDataAsync(data, cancellationToken).ConfigureAwait(false);
            Advance(Now);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Stops for good (the input is closed or the session disposed); later writes are sent as they come.</summary>
    public void Stop() => _stopped = true;

    /// <summary>Moves the next tick past <paramref name="now"/>, skipping the ticks that went by unused.</summary>
    private void Advance(TimeSpan now)
    {
        if (now >= _next)
        {
            _next += _interval * (((now - _next).Ticks / _interval.Ticks) + 1);
        }
    }

    private async Task RunChaffAsync()
    {
        try
        {
            while (true)
            {
                TimeSpan wait;
                await _gate.WaitAsync(_connection.Closed).ConfigureAwait(false);
                try
                {
                    var now = Now;
                    if (_stopped || !_active || now >= _chaffUntil || _connection.IsRekeying || !_channel.IsOpenForSending)
                    {
                        _active = false;
                        _chaffRunning = false;
                        return;
                    }

                    if (now >= _next)
                    {
                        // Nothing was typed for this tick: send chaff in its place.
                        if (_connection.PostChaff())
                        {
                            Interlocked.Increment(ref _chaffSent);
                        }

                        Advance(now);
                    }

                    wait = _next - now;
                }
                finally
                {
                    _gate.Release();
                }

                await Task.Delay(wait, _time, _connection.Closed).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // The connection ended.
        }
    }
}
