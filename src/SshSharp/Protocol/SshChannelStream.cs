namespace SshSharp.Protocol;

/// <summary>
/// A channel's data as a duplex <see cref="Stream"/> (asynchronous only): reads return channel data (extended data is dropped),
/// writes are sent as channel data, and disposing sends EOF and CLOSE. Used to run SSH over a <c>direct-tcpip</c> channel (ProxyJump)
/// and, later, for port forwarding. A read waits for the first chunk only, then also copies the chunks that have already arrived while
/// the caller's buffer has room.
/// </summary>
internal sealed class SshChannelStream(SshChannel channel) : Stream
{
    private ChannelData? _current;
    private int _offset;
    private bool _eof;
    private int _disposed;

    // 1 while a read is in progress, which owns _current then: as in SshChannelReadStream, disposal leaves the chunk to that read.
    private int _reading;

    public SshChannel Channel { get; } = channel;

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    // Pooled: completes asynchronously for nearly every packet, and would otherwise allocate a state machine box each time.
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (Interlocked.Exchange(ref _reading, 1) != 0)
        {
            throw new InvalidOperationException("Another read is already in progress on this stream.");
        }

        try
        {
            // Checked again now that the read is marked: a disposal from here on sees it and leaves the chunk to this read.
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            while (_current is null || _offset == _current.Data.Length)
            {
                ReleaseCurrent();
                if (_eof)
                {
                    return 0;
                }

                var next = await Channel.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (next is null)
                {
                    _eof = true;
                    return 0;
                }

                if (next.IsExtended)
                {
                    next.Dispose(); // stderr has no place in a byte stream
                    continue;
                }

                _current = next;
                _offset = 0;
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this); // disposed while this read waited
            }

            // Then the chunks that have already arrived, without waiting for more: one read returns as much as is there, rather than one
            // packet's worth (32 KiB at most) per call.
            var total = 0;
            while (true)
            {
                var available = _current.Data.Span[_offset..];
                var count = Math.Min(available.Length, buffer.Length - total);
                available[..count].CopyTo(buffer.Span[total..]);
                _offset += count;
                total += count;
                if (total == buffer.Length || Volatile.Read(ref _disposed) != 0 || !TryTakeQueued(out var next))
                {
                    return total; // a chunk used up last stays current until the next read, which releases it
                }

                // This chunk is used up: released (its window given back) as the next takes its place.
                ReleaseCurrent();
                _current = next;
            }
        }
        finally
        {
            Interlocked.Exchange(ref _reading, 0);
            if (Volatile.Read(ref _disposed) != 0)
            {
                ReleaseCurrent(); // disposed during this read, which owned the chunk until now
            }
        }
    }

    /// <summary>Takes the next chunk that has already arrived, without waiting; stderr is dropped, as when waiting for one.</summary>
    private bool TryTakeQueued([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ChannelData? next)
    {
        while (Channel.TryRead(out next))
        {
            if (!next.IsExtended)
            {
                return true;
            }

            next.Dispose(); // stderr has no place in a byte stream
        }

        return false;
    }

    /// <summary>Releases the current chunk on disposal, unless a read in progress owns it (that read releases it when it ends).</summary>
    private void ReleaseUnlessReading()
    {
        if (Volatile.Read(ref _reading) == 0)
        {
            ReleaseCurrent();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return Channel.SendDataAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Flush()
    {
        // Nothing is buffered: every write is sent as it is made.
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SSH channel streams are asynchronous; use ReadAsync.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SSH channel streams are asynchronous; use WriteAsync.");

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        ReleaseUnlessReading();
        try
        {
            await Channel.SendEofAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or ObjectDisposedException or IOException or InvalidOperationException)
        {
            // The channel or connection is already gone.
        }

        await Channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        Channel.DiscardUnread(); // data that arrived but was never read goes back to the buffer pool
        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            // Synchronous disposal cannot wait for the network; queue the CLOSE.
            ReleaseUnlessReading();
            _ = Channel.CloseAsync(CancellationToken.None).AsTask();
            Channel.DiscardUnread();
        }

        base.Dispose(disposing);
    }

    /// <summary>
    /// Takes the data received but not yet read (the rest of the last packet), so a caller that read a handshake through this stream can
    /// relay the channel directly afterwards without losing bytes the peer sent right after it. The stream must not be read again.
    /// </summary>
    public byte[] TakeBuffered()
    {
        var rest = _current is null ? [] : _current.Data.Span[_offset..].ToArray();
        ReleaseCurrent();
        return rest;
    }

    private void ReleaseCurrent()
    {
        // Taken atomically: disposal and a read that is ending can both release, and each chunk must be released exactly once.
        Interlocked.Exchange(ref _current, null)?.Dispose();
        _offset = 0;
    }
}
