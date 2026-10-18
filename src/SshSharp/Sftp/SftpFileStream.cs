using System.Runtime.ExceptionServices;

namespace SshSharp.Sftp;

/// <summary>
/// An open remote file as a seekable stream (asynchronous only). Writes are split into requests of the server's write size. A stream
/// opened only for reading reads ahead while it is read sequentially: a window of reads in flight that grows from 2 to 16, so reading
/// through it approaches the speed of <see cref="SftpClient.DownloadAsync"/>; a seek starts over. A stream that also writes reads one
/// request at a time, so what it reads always includes its own writes. Disposing closes the remote handle. <see cref="Length"/> is the size
/// when the file was opened, kept up to date with this stream's own writes and <see cref="SetLength"/>; another writer's changes show in
/// <see cref="GetLengthAsync"/>.
/// </summary>
/// <remarks>
/// Writes are written behind: <see cref="WriteAsync(ReadOnlyMemory{byte}, CancellationToken)"/> sends its requests and returns without
/// waiting for their replies, keeping up to 16 in flight (it waits for the oldest when the window is full), so writing through the
/// stream approaches the speed of <see cref="SftpClient.UploadAsync"/>. A write that fails is never lost: the next call that finds it
/// (any call but the getters) throws its exception, and so does every call after it; <see cref="FlushAsync"/>, a read, a seek followed by
/// a write, <see cref="SetLength"/> and disposing wait for every write in flight first. Disposing still closes the handle after a failed
/// write, and throws the failure if no call reported it yet. A cancelled write leaves the stream faulted, since some of its data may have
/// been written.
/// </remarks>
internal sealed class SftpFileStream(SftpClient client, byte[] handle, string path, bool canRead, bool canWrite, long position, long? length) : Stream
{
    private const int MaxReadAhead = 16;

    /// <summary>The most writes in flight: as deep as the read-ahead, so at most 16 writes of the server's write size are held at once.</summary>
    internal const int MaxWriteBehind = 16;

    private readonly Queue<(long Offset, int Length, Task<SftpResponse> Reply)> _ahead = new();
    private readonly Queue<Task<SftpResponse>> _behind = new();
    private long? _length = length;
    private long _position = position;
    private long _aheadNext;
    private int _depth = 2;
    private ReadOnlyMemory<byte> _leftover;
    private SftpResponse? _leftoverReply;
    private long _leftoverOffset;
    private int _reading;
    private int _readsReleased;
    private long _behindEnd;
    private ExceptionDispatchInfo? _fault;
    private bool _faultReported;
    private int _disposed;

    public override bool CanRead => canRead && _disposed == 0;

    public override bool CanWrite => canWrite && _disposed == 0;

    /// <summary>
    /// Whether <see cref="Length"/> is known: callers that see a seekable stream read its length (<see cref="Stream.CopyToAsync(Stream)"/>
    /// does), so a file whose size the server did not report is not one. <see cref="Seek"/> from the start or the current position still works.
    /// </summary>
    public override bool CanSeek => _disposed == 0 && _length is not null;

    /// <summary>The file's size as this stream knows it, without a round trip (see the class remarks); it counts the writes in flight.</summary>
    /// <exception cref="NotSupportedException">The server did not report the file's size when it was opened.</exception>
    public override long Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return _length ?? throw new NotSupportedException("The SFTP server did not report the file's size.");
        }
    }

    /// <summary>
    /// The position. Setting it does not wait for the writes in flight (a write or read that follows does), but throws a write that
    /// already failed.
    /// </summary>
    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            ThrowIfWriteFailed();
            _position = value;
        }
    }

    public async Task<long> GetLengthAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        await WaitForWritesAsync(cancellationToken).ConfigureAwait(false);
        var size = (await client.GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size
            ?? throw new NotSupportedException("The SFTP server did not report the file's size.");
        _length = size;
        return size;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (!canRead)
        {
            throw new NotSupportedException("The file was not opened for reading.");
        }

        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (!canWrite)
        {
            return await ReadAheadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        // What is read includes this stream's own writes: they are acknowledged first.
        await WaitForWritesAsync(cancellationToken).ConfigureAwait(false);
        var length = Math.Min(buffer.Length, client.Limits.MaxReadLength);
        using var reply = await client.SendReadAsync(handle, _position, length, cancellationToken).ConfigureAwait(false);
        var data = SftpClient.ExpectData(reply, length, path); // copied out before the reply (its pooled buffer) is disposed
        data.CopyTo(buffer);
        _position += data.Length;
        return data.Length;
    }

    // Ownership of the read-ahead's pooled buffers (see SftpResponse): the replies of the reads in flight belong to _ahead until a read
    // dequeues one; the reply being read from is _leftoverReply, and _leftover is a slice of it, valid only until it is released. A read
    // releases it once the last byte is taken or when it moves elsewhere; DropAhead gives the replies still due to a continuation that
    // disposes them when they arrive. Disposing the stream releases all of it, unless a read is in progress: that read owns them until
    // it ends, and releases them then (the same handshake as SshChannelReadStream's).
    private async ValueTask<int> ReadAheadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _reading, 1) != 0)
        {
            throw new InvalidOperationException("Another read is already in progress on this stream.");
        }

        try
        {
            // Checked again now that the read is marked: a disposal from here on sees it and leaves the buffers to this read.
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return await ReadAheadCoreAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Exchange(ref _reading, 0);
            if (Volatile.Read(ref _disposed) != 0)
            {
                ReleaseReads(); // disposed during this read, which owned the buffers until now
            }
        }
    }

    private async ValueTask<int> ReadAheadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        // What is left of the last reply comes first, if the caller is still where it ended.
        if (!_leftover.IsEmpty && _leftoverOffset == _position)
        {
            return TakeLeftover(buffer);
        }

        ReleaseLeftover();
        if (_ahead.Count == 0 || _ahead.Peek().Offset != _position)
        {
            // Not where the reads in flight are (the first read, or after a seek or a short read): start over from here.
            DropAhead();
            _aheadNext = _position;
            _depth = 2;
        }

        // Read-ahead requests outlive this call, so they are not tied to its token; the wait for the next one is.
        var chunk = client.Limits.MaxReadLength;
        while (_ahead.Count < _depth)
        {
            _ahead.Enqueue((_aheadNext, chunk, client.SendReadAsync(handle, _aheadNext, chunk, CancellationToken.None)));
            _aheadNext += chunk;
        }

        _depth = Math.Min(_depth * 2, MaxReadAhead);
        var (offset, length, pending) = _ahead.Peek();
        var reply = await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
        _ahead.Dequeue(); // the reply is this read's now
        ReadOnlyMemory<byte> data;
        try
        {
            data = SftpClient.ExpectData(reply, length, path);
        }
        catch
        {
            reply.Dispose();
            throw;
        }

        if (data.IsEmpty)
        {
            reply.Dispose();
            DropAhead(); // the end of the file; the reads past it answer the same
            return 0;
        }

        if (data.Length < length)
        {
            DropAhead(); // a short read leaves a gap before the next read in flight: the next call starts over after this data
        }

        _leftoverReply = reply;
        _leftover = data;
        _leftoverOffset = offset;
        return TakeLeftover(buffer);
    }

    private int TakeLeftover(Memory<byte> buffer)
    {
        var count = Math.Min(buffer.Length, _leftover.Length);
        _leftover[..count].CopyTo(buffer);
        _leftover = _leftover[count..];
        _leftoverOffset += count;
        _position += count;
        if (_leftover.IsEmpty)
        {
            ReleaseLeftover(); // all of it taken: the buffer goes back now rather than at the next read
        }

        return count;
    }

    /// <summary>Forgets what is left of the last reply and returns its buffer; the slice must not be used after this.</summary>
    private void ReleaseLeftover()
    {
        _leftover = default;
        _leftoverReply?.Dispose();
        _leftoverReply = null;
    }

    /// <summary>
    /// Forgets the reads in flight; their replies are disposed when they arrive (they are nobody's now), and a failure (the session ended)
    /// is observed, not raised.
    /// </summary>
    private void DropAhead()
    {
        while (_ahead.TryDequeue(out var dropped))
        {
            _ = dropped.Reply.ContinueWith(static t =>
            {
                if (t.IsCompletedSuccessfully)
                {
                    t.Result.Dispose();
                }
                else
                {
                    _ = t.Exception;
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    /// <summary>
    /// On disposing, after <c>_disposed</c> is set: releases the read-ahead's buffers, or leaves them to a read in progress. Both sides
    /// write their flag before reading the other's (interlocked, so in that order): the read is seen here, or it sees the disposal when it
    /// ends and releases them itself.
    /// </summary>
    private void ReleaseReadsUnlessReading()
    {
        if (Volatile.Read(ref _reading) == 0)
        {
            ReleaseReads();
        }
    }

    /// <summary>On disposing: everything the read-ahead holds (once, by the disposal or by the read in progress that outlives it).</summary>
    private void ReleaseReads()
    {
        if (Interlocked.Exchange(ref _readsReleased, 1) == 0)
        {
            DropAhead();
            ReleaseLeftover();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>
    /// Sends <paramref name="buffer"/> in requests of the server's write size and returns once they are sent, not acknowledged (see the
    /// class remarks); the data is copied into the requests, so the buffer can be reused at once.
    /// </summary>
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (!canWrite)
        {
            throw new NotSupportedException("The file was not opened for writing.");
        }

        ThrowIfWriteFailed();
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (_behind.Count > 0 && _behindEnd != _position)
            {
                // After a seek, this write may overlap one in flight: those are acknowledged first, so the later bytes win.
                await WaitForWritesAsync(cancellationToken).ConfigureAwait(false);
            }

            while (!buffer.IsEmpty)
            {
                if (_behind.Count >= MaxWriteBehind)
                {
                    await AcknowledgeOldestAsync(cancellationToken).ConfigureAwait(false);
                }

                // The request is built (the data copied into a pooled buffer of its own, returned once the request is sent) before
                // SendWriteAsync returns. Like the read-ahead, it outlives this call, so it is not tied to its token; the wait for room is.
                var part = buffer[..Math.Min(buffer.Length, client.Limits.MaxWriteLength)];
                _behind.Enqueue(client.SendWriteAsync(handle, _position, part, CancellationToken.None));
                _position += part.Length;
                _behindEnd = _position;
                if (_length is { } known && _position > known)
                {
                    _length = _position;
                }

                buffer = buffer[part.Length..];
            }
        }
        catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested && _fault is null)
        {
            // Part of this write may be in flight and part not: the file's content is unknown, so the stream cannot go on.
            _fault = ExceptionDispatchInfo.Capture(ex);
            _faultReported = true;
            throw;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Moves the position. It does not wait for the writes in flight (a write or read that follows does), but throws a write that already failed.</summary>
    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));
        ThrowIfWriteFailed();
        return _position = target;
    }

    /// <summary>Waits for the writes in flight, then sets the file's size on the server.</summary>
    public override void SetLength(long value)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (!canWrite)
        {
            throw new NotSupportedException("The file was not opened for writing.");
        }

        // Stream has no asynchronous SetLength: the call blocks on the server, as it always has; the writes in flight come first, so a
        // write past the new end cannot land after it.
        SetLengthAsync(value).GetAwaiter().GetResult();
        _length = value;
    }

    private async Task SetLengthAsync(long value)
    {
        await WaitForWritesAsync(CancellationToken.None).ConfigureAwait(false);
        await client.SetHandleAttributesAsync(handle, path, new SftpFileAttributes { Size = value }, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for every write in flight, throwing the first that failed; then asks the server to write the file to disk
    /// (<c>fsync@openssh.com</c>), when it can.
    /// </summary>
    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (canWrite)
        {
            await WaitForWritesAsync(cancellationToken).ConfigureAwait(false);
            await client.SyncHandleAsync(handle, path, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Does not wait for the writes in flight (<see cref="FlushAsync"/> does), but throws a write that already failed.</summary>
    public override void Flush()
    {
        if (_disposed == 0)
        {
            ThrowIfWriteFailed();
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SFTP file streams are asynchronous; use ReadAsync.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SFTP file streams are asynchronous; use WriteAsync.");

    /// <summary>Forgets the writes acknowledged already, without waiting; throws if one failed, now or before.</summary>
    private void ThrowIfWriteFailed()
    {
        while (_behind.TryPeek(out var write) && write.IsCompleted)
        {
            Acknowledge(_behind.Dequeue());
        }

        if (_fault is { } fault)
        {
            _faultReported = true;
            fault.Throw();
        }
    }

    /// <summary>Waits for every write in flight; throws the first that failed. Cancelling the wait leaves the writes in flight.</summary>
    private async ValueTask WaitForWritesAsync(CancellationToken cancellationToken)
    {
        ThrowIfWriteFailed();
        while (_behind.Count > 0)
        {
            await AcknowledgeOldestAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask AcknowledgeOldestAsync(CancellationToken cancellationToken)
    {
        // As a plain Task: SuppressThrowing is not allowed on a Task<T>; the write's own outcome is read by Acknowledge.
        Task oldest = _behind.Peek();
        await oldest.WaitAsync(cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        cancellationToken.ThrowIfCancellationRequested(); // the write itself, if it is done, is acknowledged by the next call
        ThrowIfWriteFailed();
    }

    /// <summary>Records the outcome of a completed write: the first failure faults the stream, the others are observed.</summary>
    private void Acknowledge(Task<SftpResponse> write)
    {
        if (_fault is not null)
        {
            _ = write.Exception;
            return;
        }

        // Whatever the write failed with is kept and thrown later: a failure is never dropped.
        if (!write.IsCompletedSuccessfully)
        {
            _fault = write.IsCanceled
                ? ExceptionDispatchInfo.Capture(new TaskCanceledException(write))
                : ExceptionDispatchInfo.Capture(write.Exception!.InnerException ?? write.Exception);
            return;
        }

        try
        {
            SftpClient.ExpectWritten(write.Result, path); // completed: this does not block
        }
        catch (SshException ex)
        {
            _fault = ExceptionDispatchInfo.Capture(ex); // the server refused the write (an SftpException), or sent a malformed reply
        }
    }

    /// <summary>Waits for every write in flight without throwing, recording the first failure.</summary>
    private async Task SettleWritesAsync()
    {
        while (_behind.TryDequeue(out var write))
        {
            Task settled = write; // as a plain Task, for SuppressThrowing
            await settled.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            Acknowledge(write);
        }
    }

    /// <summary>On disposing: throws a write failure no call has reported yet.</summary>
    private void ThrowUnreportedFailure()
    {
        if (_fault is { } fault && !_faultReported)
        {
            _faultReported = true;
            fault.Throw();
        }
    }

    public override async ValueTask DisposeAsync()
    {
        var closing = Interlocked.Exchange(ref _disposed, 1) == 0;
        if (closing)
        {
            ReleaseReadsUnlessReading();
            await SettleWritesAsync().ConfigureAwait(false);
            await client.CloseHandleAsync(handle).ConfigureAwait(false); // closed even after a failed write
        }

        await base.DisposeAsync().ConfigureAwait(false);
        if (closing)
        {
            ThrowUnreportedFailure();
        }
    }

    protected override void Dispose(bool disposing)
    {
        var closing = disposing && Interlocked.Exchange(ref _disposed, 1) == 0;
        if (closing)
        {
            ReleaseReadsUnlessReading();
            if (_behind.Count > 0)
            {
                // Stream gives synchronous disposal no other way to report a write that fails: the writes in flight are waited for, as
                // SetLength waits for its request, rather than lost. Only a caller that wrote asynchronously and disposes synchronously
                // gets here.
                SettleWritesAsync().GetAwaiter().GetResult();
            }

            // The close is sent in the background, as before.
            _ = client.CloseHandleAsync(handle);
        }

        base.Dispose(disposing);
        if (closing)
        {
            ThrowUnreportedFailure();
        }
    }
}
