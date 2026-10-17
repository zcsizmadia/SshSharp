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

    /// <param name="limit">The limit; null or infinite for none.</param>
    /// <param name="cancellationToken">The caller's token.</param>
    public ConnectDeadline(TimeSpan? limit, CancellationToken cancellationToken)
    {
        _limit = limit;
        _caller = cancellationToken;
        if (limit is { } span && span != Timeout.InfiniteTimeSpan)
        {
            _timeout = new CancellationTokenSource(span);
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
