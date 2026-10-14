namespace SshSharp.Sftp;

/// <summary>
/// An open remote file as a seekable stream (asynchronous only). Writes are split into requests of the server's write size. A stream
/// opened only for reading reads ahead while it is read sequentially: a window of reads in flight that grows from 2 to 16, so reading
/// through it approaches the speed of <see cref="SftpClient.DownloadAsync"/>; a seek starts over. A stream that also writes reads one
/// request at a time, so what it reads always includes its own writes. Disposing closes the remote handle. <see cref="Length"/> is the size
/// when the file was opened, kept up to date with this stream's own writes and <see cref="SetLength"/>; another writer's changes show in
/// <see cref="GetLengthAsync"/>.
/// </summary>
internal sealed class SftpFileStream(SftpClient client, byte[] handle, string path, bool canRead, bool canWrite, long position, long? length) : Stream
{
    private const int MaxReadAhead = 16;

    private readonly Queue<(long Offset, int Length, Task<SftpResponse> Reply)> _ahead = new();
    private long? _length = length;
    private long _position = position;
    private long _aheadNext;
    private int _depth = 2;
    private ReadOnlyMemory<byte> _leftover;
    private long _leftoverOffset;
    private int _disposed;

    public override bool CanRead => canRead && _disposed == 0;

    public override bool CanWrite => canWrite && _disposed == 0;

    public override bool CanSeek => _disposed == 0;

    /// <summary>The file's size as this stream knows it, without a round trip (see the class remarks).</summary>
    /// <exception cref="NotSupportedException">The server did not report the file's size when it was opened.</exception>
    public override long Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return _length ?? throw new NotSupportedException("The SFTP server did not report the file's size.");
        }
    }

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public async Task<long> GetLengthAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
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

        var length = Math.Min(buffer.Length, client.Limits.MaxReadLength);
        var reply = await client.SendReadAsync(handle, _position, length, cancellationToken).ConfigureAwait(false);
        var data = SftpClient.ExpectData(reply, length, path);
        data.CopyTo(buffer);
        _position += data.Length;
        return data.Length;
    }

    private async ValueTask<int> ReadAheadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        // What is left of the last reply comes first, if the caller is still where it ended.
        if (!_leftover.IsEmpty && _leftoverOffset == _position)
        {
            return TakeLeftover(buffer);
        }

        _leftover = default;
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
        _ahead.Dequeue();
        var data = SftpClient.ExpectData(reply, length, path);
        if (data.IsEmpty)
        {
            DropAhead(); // the end of the file; the reads past it answer the same
            return 0;
        }

        if (data.Length < length)
        {
            DropAhead(); // a short read leaves a gap before the next read in flight: the next call starts over after this data
        }

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
        return count;
    }

    /// <summary>Forgets the reads in flight; their replies are dropped, and a failure (the session ended) is observed, not raised.</summary>
    private void DropAhead()
    {
        while (_ahead.TryDequeue(out var dropped))
        {
            _ = dropped.Reply.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (!canWrite)
        {
            throw new NotSupportedException("The file was not opened for writing.");
        }

        while (!buffer.IsEmpty)
        {
            var part = buffer[..Math.Min(buffer.Length, client.Limits.MaxWriteLength)];
            SftpClient.ExpectWritten(await client.SendWriteAsync(handle, _position, part, cancellationToken).ConfigureAwait(false), path);
            _position += part.Length;
            if (_length is { } known && _position > known)
            {
                _length = _position;
            }

            buffer = buffer[part.Length..];
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

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
        return _position = target;
    }

    public override void SetLength(long value)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (!canWrite)
        {
            throw new NotSupportedException("The file was not opened for writing.");
        }

        client.SetHandleAttributesAsync(handle, path, new SftpFileAttributes { Size = value }, CancellationToken.None).GetAwaiter().GetResult();
        _length = value;
    }

    /// <summary>
    /// Every write is acknowledged when it returns; flushing also asks the server to write the file to disk (<c>fsync@openssh.com</c>),
    /// when it can.
    /// </summary>
    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (canWrite)
        {
            await client.SyncHandleAsync(handle, path, cancellationToken).ConfigureAwait(false);
        }
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SFTP file streams are asynchronous; use ReadAsync.");

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("SFTP file streams are asynchronous; use WriteAsync.");

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            DropAhead();
            await client.CloseHandleAsync(handle).ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            // Synchronous disposal cannot wait for the network; the close is sent in the background.
            DropAhead();
            _ = client.CloseHandleAsync(handle);
        }

        base.Dispose(disposing);
    }
}
