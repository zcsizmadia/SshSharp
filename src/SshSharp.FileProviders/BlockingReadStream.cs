namespace SshSharp.FileProviders;

/// <summary>
/// An SFTP read stream that also reads synchronously, as <see cref="Microsoft.Extensions.FileProviders.IFileInfo"/> consumers may: a
/// synchronous read waits for the asynchronous one (which never needs the caller's context), bounded by the provider's timeout.
/// </summary>
internal sealed class BlockingReadStream(Stream inner, long length, TimeSpan timeout) : Stream
{
    public override bool CanRead => inner.CanRead;

    public override bool CanSeek => inner.CanSeek;

    public override bool CanWrite => false;

    /// <summary>The size the server reported when the file was looked up (no round trip).</summary>
    public override long Length => length >= 0 ? length : inner.Length;

    public override long Position
    {
        get => inner.Position;
        set => inner.Position = value;
    }

    /// <summary>A synchronous read: a timeout is an <see cref="SshException"/> (<see cref="SshFailureReason.Timeout"/>), as for lookups.</summary>
    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        var memory = buffer.AsMemory(offset, count);
        return SftpFileProvider.Run(timeout, ct => inner.ReadAsync(memory, ct).AsTask());
    }

    public override int Read(Span<byte> buffer)
    {
        // The span cannot cross into the asynchronous read, so it goes through a pooled array.
        var length = buffer.Length;
        var rented = System.Buffers.ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var read = SftpFileProvider.Run(timeout, ct => inner.ReadAsync(rented.AsMemory(0, length), ct).AsTask());
            rented.AsSpan(0, read).CopyTo(buffer);
            return read;
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => origin == SeekOrigin.End && length >= 0
        ? inner.Seek(length + offset, SeekOrigin.Begin)
        : inner.Seek(offset, origin);

    public override void Flush()
    {
    }

    public override void SetLength(long value) => throw new NotSupportedException("The file provider is read-only.");

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("The file provider is read-only.");

    public override async ValueTask DisposeAsync()
    {
        await inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
