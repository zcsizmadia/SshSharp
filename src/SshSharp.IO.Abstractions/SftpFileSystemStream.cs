using System.IO.Abstractions;

namespace SshSharp.IO.Abstractions;

/// <summary>A remote file as the <see cref="FileSystemStream"/> the abstraction hands out: buffered, synchronous and asynchronous.</summary>
internal sealed class SftpFileSystemStream(Stream inner, string path) : FileSystemStream(inner, path, isAsync: true)
{
    /// <summary>
    /// Opens <paramref name="path"/> as a stream: the SFTP stream with synchronous reads and writes added, behind a buffer, so the many
    /// small writes of a <see cref="StreamWriter"/> become few requests.
    /// </summary>
    public static SftpFileSystemStream Open(SftpFileSystem fileSystem, string path, FileMode mode, FileAccess access, int bufferSize)
    {
        var full = fileSystem.Full(path);
        var remote = fileSystem.Run(full, mode is FileMode.Create or FileMode.CreateNew or FileMode.OpenOrCreate or FileMode.Append,
            ct => fileSystem.Sftp.OpenAsync(full, mode, access, ct));
        var blocking = new BlockingStream(remote, fileSystem.Options.OperationTimeout);
        return new SftpFileSystemStream(new BufferedStream(blocking, Math.Max(bufferSize, 64 * 1024)), full);
    }

    /// <summary>Synchronous calls on top of the asynchronous SFTP stream, each bounded by the timeout.</summary>
    private sealed class BlockingStream(Stream remote, TimeSpan timeout) : Stream
    {
        public override bool CanRead => remote.CanRead;

        public override bool CanSeek => remote.CanSeek;

        public override bool CanWrite => remote.CanWrite;

        public override long Length => Wait(ct => Task.FromResult(remote.Length));

        public override long Position
        {
            get => remote.Position;
            set => remote.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Wait(ct => remote.ReadAsync(buffer.AsMemory(offset, count), ct).AsTask());

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => remote.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            remote.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) =>
            Wait(async ct =>
            {
                await remote.WriteAsync(buffer.AsMemory(offset, count), ct).ConfigureAwait(false);
                return true;
            });

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => remote.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            remote.WriteAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => origin == SeekOrigin.End ? remote.Position = Length + offset : remote.Seek(offset, origin);

        public override void SetLength(long value) => Wait(ct => Task.Run(() =>
        {
            remote.SetLength(value);
            return true;
        }, ct));

        public override void Flush() => Wait(async ct =>
        {
            await remote.FlushAsync(ct).ConfigureAwait(false);
            return true;
        });

        public override Task FlushAsync(CancellationToken cancellationToken) => remote.FlushAsync(cancellationToken);

        public override async ValueTask DisposeAsync()
        {
            await remote.DisposeAsync().ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Wait(async _ =>
                {
                    await remote.DisposeAsync().ConfigureAwait(false); // closes the handle before returning, as a file stream does
                    return true;
                });
            }

            base.Dispose(disposing);
        }

        private T Wait<T>(Func<CancellationToken, Task<T>> operation)
        {
            using var cancel = new CancellationTokenSource(timeout);
            try
            {
                return Task.Run(() => operation(cancel.Token), CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, null, false, cancel.IsCancellationRequested) is { } translated)
            {
                throw translated;
            }
        }
    }
}
