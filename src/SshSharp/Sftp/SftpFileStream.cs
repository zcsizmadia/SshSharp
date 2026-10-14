namespace SshSharp.Sftp;

/// <summary>
/// An open remote file as a seekable stream (asynchronous only). Each read is one request of up to the server's read size; writes are
/// split into requests of its write size. Disposing closes the remote handle.
/// </summary>
internal sealed class SftpFileStream(SftpClient client, byte[] handle, string path, bool canRead, bool canWrite, long position) : Stream
{
    private long _position = position;
    private int _disposed;

    public override bool CanRead => canRead && _disposed == 0;

    public override bool CanWrite => canWrite && _disposed == 0;

    public override bool CanSeek => _disposed == 0;

    /// <summary>The remote file's size now (asks the server; prefer <see cref="GetLengthAsync"/>).</summary>
    public override long Length => GetLengthAsync(CancellationToken.None).GetAwaiter().GetResult();

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
        return (await client.GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size
            ?? throw new NotSupportedException("The SFTP server did not report the file's size.");
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

        var length = Math.Min(buffer.Length, client.Limits.MaxReadLength);
        var reply = await client.SendReadAsync(handle, _position, length, cancellationToken).ConfigureAwait(false);
        var data = SftpClient.ExpectData(reply, length, path);
        data.CopyTo(buffer);
        _position += data.Length;
        return data.Length;
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
            await client.CloseHandleAsync(handle).ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            // Synchronous disposal cannot wait for the network; the close is sent in the background.
            _ = client.CloseHandleAsync(handle);
        }

        base.Dispose(disposing);
    }
}
