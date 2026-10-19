using System.Globalization;

namespace SshSharp;

/// <summary>
/// The time limit on one connection attempt: <see cref="SshClientOptions.ConnectTimeout"/>, or ssh_config's <c>ConnectTimeout</c>. Its
/// <see cref="Token"/> ends at the deadline or with the caller's token; a deadline that passed becomes <see cref="Error"/>, while the
/// caller's own cancellation stays a cancellation.
/// </summary>
internal sealed class ConnectDeadline : IDisposable
{
    private readonly TimeSpan? _limit;
    private readonly CancellationToken _caller;
    private readonly CancellationTokenSource? _timeout;
    private readonly CancellationTokenSource? _linked;

    /// <summary>
    /// The longest delay a timer takes (2^32 - 2 ms, about 49.7 days). ssh_config allows longer times (up to 2^31 - 1 seconds), which
    /// are treated as no limit: a longer wait could not be timed, and would not end before the caller gave up anyway.
    /// </summary>
    internal static readonly TimeSpan MaxTimerDelay = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    /// <summary>Starts the clock: the deadline is <paramref name="limit"/> from now.</summary>
    /// <param name="limit">The limit; null, infinite or longer than <see cref="MaxTimerDelay"/> for none.</param>
    /// <param name="cancellationToken">The caller's token.</param>
    /// <param name="timeProvider">The clock, the same one that times the waits between connection attempts; the system clock by default.</param>
    public ConnectDeadline(TimeSpan? limit, CancellationToken cancellationToken, TimeProvider? timeProvider = null)
    {
        _limit = limit;
        _caller = cancellationToken;
        if (limit is { } span && span != Timeout.InfiniteTimeSpan && span <= MaxTimerDelay)
        {
            _timeout = new CancellationTokenSource(span, timeProvider ?? TimeProvider.System);
            _linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _timeout.Token);
        }
    }

    /// <summary>The token to connect with: cancelled at the deadline or by the caller.</summary>
    public CancellationToken Token => _linked?.Token ?? _caller;

    /// <summary>Whether the deadline, and not the caller, ended the attempt.</summary>
    public bool Expired => _timeout?.IsCancellationRequested == true && !_caller.IsCancellationRequested;

    /// <summary>
    /// What a passed deadline is reported as: <see cref="SshFailureReason.Timeout"/>, with a <see cref="TimeoutException"/> inside so that
    /// code wrapping a connection (the DI package) can tell it from other timeouts, such as a proxy's handshake.
    /// </summary>
    public SshException Error() => new(SshFailureReason.Timeout,
        $"Connecting took longer than ConnectTimeout ({_limit.GetValueOrDefault().TotalSeconds.ToString(CultureInfo.InvariantCulture)} s).",
        new TimeoutException());

    public void Dispose()
    {
        _linked?.Dispose();
        _timeout?.Dispose();
    }
}
