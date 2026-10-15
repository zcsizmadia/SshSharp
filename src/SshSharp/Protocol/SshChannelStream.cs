namespace SshSharp.Protocol;

/// <summary>
/// A channel's data as a duplex <see cref="Stream"/> (asynchronous only): reads return channel data (extended data is dropped),
/// writes are sent as channel data, and disposing sends EOF and CLOSE. Used to run SSH over a <c>direct-tcpip</c> channel (ProxyJump)
/// and, later, for port forwarding.
/// </summary>
internal sealed class SshChannelStream(SshChannel channel) : Stream
{
    private ChannelData? _current;
    private int _offset;
    private bool _eof;
    private int _disposed;

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
            if (Volatile.Read(ref _disposed) != 0)
            {
                ReleaseCurrent(); // disposed while this read waited: the chunk would otherwise never be released
                throw new ObjectDisposedException(nameof(SshChannelStream));
            }
        }

        var available = _current.Data.Span[_offset..];
        var count = Math.Min(available.Length, buffer.Length);
        available[..count].CopyTo(buffer.Span);
        _offset += count;
        return count;
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

        ReleaseCurrent();
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
            ReleaseCurrent();
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
        // Taken atomically: disposal can race a read in progress, and each chunk must be released exactly once.
        Interlocked.Exchange(ref _current, null)?.Dispose();
        _offset = 0;
    }
}
