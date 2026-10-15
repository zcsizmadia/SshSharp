namespace SshSharp.Protocol;

/// <summary>
/// One direction of a session's output (stdout or stderr) as a read-only, asynchronous <see cref="Stream"/>. Reads hand out the received
/// packets' bytes without buffering them again; each packet is released, which lets the server send more, once it has been read.
/// </summary>
internal sealed class SshChannelReadStream(Func<CancellationToken, ValueTask<ChannelData?>> source, Action? disposed = null) : Stream
{
    private ChannelData? _current;
    private int _offset;
    private bool _eof;
    private int _disposed;

    public override bool CanRead => _disposed == 0;

    public override bool CanWrite => false;

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
            Release();
            if (_eof)
            {
                return 0;
            }

            _current = await source(cancellationToken).ConfigureAwait(false);
            if (_current is null)
            {
                _eof = true;
                return 0;
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                Release(); // disposed while this read waited: the chunk would otherwise never be released
                throw new ObjectDisposedException(nameof(SshChannelReadStream));
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

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SSH session streams are asynchronous; use ReadAsync.");

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Flush()
    {
        // Read-only.
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Release();
            disposed?.Invoke();
        }

        base.Dispose(disposing);
    }

    private void Release()
    {
        // Taken atomically: disposal can race a read in progress, and each chunk must be released exactly once.
        Interlocked.Exchange(ref _current, null)?.Dispose();
        _offset = 0;
    }
}

/// <summary>
/// A session's stdin as a write-only, asynchronous <see cref="Stream"/>: writes are sent as channel data; disposing sends EOF. With
/// <paramref name="obfuscator"/> (a terminal session with <see cref="SshClientOptions.ObscureKeystrokeTiming"/>), typing is sent on its grid.
/// </summary>
internal sealed class SshChannelWriteStream(SshChannel channel, KeystrokeTimingObfuscator? obfuscator = null) : Stream
{
    private int _closed;

    public override bool CanRead => false;

    public override bool CanWrite => _closed == 0;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_closed != 0, this);
        return obfuscator is null ? channel.SendDataAsync(buffer, cancellationToken) : obfuscator.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Flush()
    {
        // Nothing is buffered: every write is sent before it completes.
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SSH session streams are asynchronous; use WriteAsync.");

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Sends EOF (once): the remote program sees the end of its input.</summary>
    public async ValueTask CloseAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        obfuscator?.Stop();
        try
        {
            await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or ObjectDisposedException or IOException)
        {
            // The channel or connection is already gone; there is no input left to end.
        }
    }

    public override async ValueTask DisposeAsync()
    {
        await CloseAsync(CancellationToken.None).ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && _closed == 0)
        {
            // Synchronous disposal cannot wait for the network; queue the EOF.
            _ = CloseAsync(CancellationToken.None).AsTask();
        }

        base.Dispose(disposing);
    }
}
