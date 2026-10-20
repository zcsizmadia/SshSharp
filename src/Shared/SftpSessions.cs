using SshSharp.Sftp;

// Shared by the adapter packages (SshSharp.FileProviders and SshSharp.IO.Abstractions): each compiles its own internal copy, linked
// from here, so the packages share the behavior without sharing an assembly.
namespace SshSharp.Adapters;

/// <summary>
/// The SFTP session an adapter works through. Either one session the caller owns, used as it is for the adapter's lifetime, or
/// sessions from a factory: one live session shared by every caller, opened when first needed and opened again after the connection
/// under it fails. The adapter owns the sessions its factory opens: a failed one is disposed when it is replaced, and the last one
/// with the adapter.
/// </summary>
/// <remarks>
/// Only a session that has ended is replaced (<see cref="SftpClient.IsConnected"/> false: its channel or the connection under it
/// closed or failed, for whatever reason, a missed keep-alive and a failed key exchange included). That is decided on the session's
/// state, not on the exception an operation threw: one request's failure, such as an error status from the server, a reply that timed
/// out or a reply too large to take, leaves a live session in use for the other callers. Concurrent callers that find no live session share one open, so a
/// dropped connection is followed by one reconnect, not one per caller; when that open fails, each of them gets the failure, and the
/// next call tries again (the factory decides how often that may connect).
/// </remarks>
internal sealed class SftpSessions : IAsyncDisposable
{
    private readonly SftpClient? _borrowed;
    private readonly Func<CancellationToken, Task<SftpClient>>? _factory;
    private readonly TimeSpan _openTimeout;
    private readonly TimeProvider _clock = TimeProvider.System;
    private readonly CancellationTokenSource _disposing = new();
    private readonly object _lock = new();

    // The shared session, or the open in progress; null before the first use and after the session failed. Guarded by _lock.
    private Task<SftpClient>? _current;

    // The disposals of failed sessions, awaited when the adapter is disposed. Guarded by _lock.
    private Task _retiring = Task.CompletedTask;
    private bool _disposed;

    /// <summary>Uses <paramref name="sftp"/> for the adapter's lifetime; it stays the caller's to dispose.</summary>
    public SftpSessions(SftpClient sftp) => _borrowed = sftp;

    /// <summary>
    /// Opens sessions with <paramref name="factory"/>, each open bounded by <paramref name="openTimeout"/> on <paramref name="clock"/>,
    /// and owns them.
    /// </summary>
    public SftpSessions(Func<CancellationToken, Task<SftpClient>> factory, TimeSpan openTimeout, TimeProvider clock)
    {
        _factory = factory;
        _openTimeout = openTimeout;
        _clock = clock;
    }

    /// <summary>The session to use now: the caller's, the shared one, or a new one when there is none.</summary>
    /// <exception cref="SshException">The session could not be opened (the factory's exception is the inner one).</exception>
    /// <exception cref="ObjectDisposedException">The adapter was disposed.</exception>
    public Task<SftpClient> GetAsync(CancellationToken cancellationToken)
    {
        if (_borrowed is not null)
        {
            return Task.FromResult(_borrowed);
        }

        Task<SftpClient> session;
        SftpClient? ended = null;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_current is { IsCompletedSuccessfully: true } open && !open.Result.IsConnected)
            {
                // The session ended since it was last used (the connection dropped while the adapter was idle): not worth a failed call.
                ended = open.Result;
                _current = null;
            }

            if (_current is null || _current.IsFaulted || _current.IsCanceled)
            {
                // Started on the thread pool, so the factory does not run under the lock.
                _current = Task.Run(OpenAsync, CancellationToken.None);
            }

            session = _current;
        }

        if (ended is not null)
        {
            DisposeRetired(ended);
        }

        return session.IsCompletedSuccessfully ? session : WaitForOpenAsync(session, cancellationToken);
    }

    /// <summary>
    /// Waits for a shared open. A failure becomes a new exception for each caller, with the factory's inside: rethrowing the one instance
    /// to every waiting caller would grow its stack trace with each of them, from several threads at once.
    /// </summary>
    private static async Task<SftpClient> WaitForOpenAsync(Task<SftpClient> open, CancellationToken cancellationToken)
    {
        try
        {
            return await open.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        // Not the caller's own cancellation: when its timeout and the open's pass together, the open may have faulted by the time this
        // filter runs, and the caller's OperationCanceledException (which the adapters report as a timeout) would be taken for the
        // open's failure and reported as ConnectFailed.
        catch (Exception ex) when (open.IsFaulted && ex is not ObjectDisposedException
            && !(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
        {
            throw new SshException(ex is SshException ssh ? ssh.Reason : SshFailureReason.ConnectFailed,
                "The SFTP session could not be opened: " + ex.Message, ex);
        }
    }

    private async Task<SftpClient> OpenAsync()
    {
        // Not a caller's token: the open is shared, so one caller giving up must not fail the others. It ends with the adapter, or
        // after the timeout.
        using var timeout = new CancellationTokenSource(_openTimeout, _clock);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(_disposing.Token, timeout.Token);
        SftpClient session;
        try
        {
            session = await _factory!(cancel.Token).ConfigureAwait(false)
                ?? throw new InvalidOperationException("The SFTP session factory returned null.");
        }
        catch (OperationCanceledException ex) when (cancel.IsCancellationRequested && !_disposing.IsCancellationRequested)
        {
            throw new SshException(SshFailureReason.Timeout, $"The SFTP session did not open within {_openTimeout.TotalSeconds:0.#} s.", ex);
        }

        lock (_lock)
        {
            if (!_disposed)
            {
                return session;
            }
        }

        // The adapter was disposed while the session opened: nobody else will dispose it.
        await session.DisposeAsync().ConfigureAwait(false);
        throw new ObjectDisposedException(nameof(SftpSessions));
    }

    /// <summary>
    /// Runs <paramref name="operation"/> on the session. When it fails and the session has ended (see <see cref="SftpClient.IsConnected"/>),
    /// the session is replaced, so the next call opens a new one; with <paramref name="retry"/> (only for operations that change nothing
    /// on the server), this call also tries once more on the new session, so a lookup right after a drop succeeds. A failure that left
    /// the session up (an error status, a timed-out reply, a reply too large) is this call's alone and changes nothing for the others.
    /// </summary>
    public async Task<T> RunAsync<T>(Func<SftpClient, CancellationToken, Task<T>> operation, bool retry, CancellationToken cancellationToken)
    {
        var session = await GetAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await operation(session, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (_factory is not null && !session.IsConnected)
        {
            Retire(session);
            if (!retry)
            {
                throw;
            }
        }

        session = await GetAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await operation(session, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!session.IsConnected)
        {
            Retire(session);
            throw;
        }
    }

    /// <summary>Stops sharing <paramref name="session"/> and disposes it, unless another caller already replaced it.</summary>
    private void Retire(SftpClient session)
    {
        lock (_lock)
        {
            if (_current is not { IsCompletedSuccessfully: true } current || !ReferenceEquals(current.Result, session))
            {
                return;
            }

            _current = null;
        }

        DisposeRetired(session);
    }

    /// <summary>Disposes a session no longer shared; the adapter's disposal waits for it.</summary>
    private void DisposeRetired(SftpClient session)
    {
        // Outside the lock: disposing closes the channel. Calls still running on the session fail, as they would have anyway.
        var disposal = DisposeQuietlyAsync(session);
        lock (_lock)
        {
            _retiring = Task.WhenAll(_retiring, disposal);
        }
    }

    private static async Task DisposeQuietlyAsync(SftpClient session)
    {
        try
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The session failed already; how its disposal goes changes nothing.
        }
    }

    /// <summary>Disposes the sessions the factory opened, after any open in progress ends; a session the caller passed stays open.</summary>
    public async ValueTask DisposeAsync()
    {
        Task<SftpClient>? current;
        Task retiring;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            current = _current;
            _current = null;
            retiring = _retiring;
        }

        if (_factory is null)
        {
            return;
        }

        await _disposing.CancelAsync().ConfigureAwait(false);
        if (current is not null)
        {
            SftpClient? session = null;
            try
            {
                session = await current.ConfigureAwait(false);
            }
            catch (Exception) when (!current.IsCompletedSuccessfully)
            {
                // The open failed, or was cancelled by this disposal (which then disposed what it opened): nothing to dispose here.
            }

            if (session is not null)
            {
                await DisposeQuietlyAsync(session).ConfigureAwait(false);
            }
        }

        await retiring.ConfigureAwait(false);
        _disposing.Dispose();
    }
}
