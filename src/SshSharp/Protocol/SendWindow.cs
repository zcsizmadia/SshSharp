namespace SshSharp.Protocol;

/// <summary>
/// The peer's receive window for one channel (RFC 4254 section 5.2): senders take bytes from it, wait when it is empty, and
/// <see cref="Add"/> is called when the peer sends <c>WINDOW_ADJUST</c>.
/// </summary>
internal sealed class SendWindow
{
    private readonly object _lock = new();
    private long _available;
    private Exception? _failure;
    private TaskCompletionSource? _waiter;

    public SendWindow(uint initial) => _available = initial;

    /// <summary>Takes between 1 and <paramref name="max"/> bytes from the window, waiting while it is empty.</summary>
    public async ValueTask<int> AcquireAsync(int max, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_lock)
            {
                if (_failure is not null)
                {
                    throw _failure;
                }

                if (_available > 0)
                {
                    var taken = (int)Math.Min(_available, max);
                    _available -= taken;
                    return taken;
                }

                _waiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _waiter.Task;
            }

            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Adds bytes to the window (the peer's <c>WINDOW_ADJUST</c>). The total is capped at the protocol maximum of 2^32 - 1.</summary>
    public void Add(uint bytes)
    {
        lock (_lock)
        {
            _available = Math.Min(_available + bytes, uint.MaxValue);
            Wake();
        }
    }

    /// <summary>Fails all current and future waiters (channel closed or connection lost).</summary>
    public void Fail(Exception exception)
    {
        lock (_lock)
        {
            _failure ??= exception;
            Wake();
        }
    }

    private void Wake()
    {
        var waiter = _waiter;
        _waiter = null;
        waiter?.TrySetResult();
    }
}