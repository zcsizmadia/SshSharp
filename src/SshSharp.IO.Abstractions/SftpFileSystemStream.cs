using System.IO.Abstractions;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary>A remote file as the <see cref="FileSystemStream"/> the abstraction hands out: buffered, synchronous and asynchronous.</summary>
internal sealed class SftpFileSystemStream : FileSystemStream
{
    private SftpFileSystemStream(Stream inner, string path)
        : base(inner, path, isAsync: true)
    {
    }

    /// <summary>
    /// Opens <paramref name="path"/> as a stream: the SFTP stream with synchronous reads and writes added, behind a buffer, so the many
    /// small writes of a <see cref="StreamWriter"/> become few requests.
    /// </summary>
    public static SftpFileSystemStream Open(SftpFileSystem fileSystem, string path, FileMode mode, FileAccess access, int bufferSize)
    {
        var full = fileSystem.Full(path);
        // Opening to read changes nothing on the server, so after a dropped connection it is tried again on a new session.
        var (sftp, remote) = fileSystem.Run(full, mode is FileMode.Create or FileMode.CreateNew or FileMode.OpenOrCreate or FileMode.Append,
            async (sftp, ct) => (sftp, await sftp.OpenAsync(full, mode, access, ct).ConfigureAwait(false)),
            retry: mode == FileMode.Open && access == FileAccess.Read);
        return Wrap(fileSystem, sftp, remote, full, bufferSize);
    }

    /// <summary>
    /// An open SFTP stream as a file system stream: errors, synchronous or asynchronous, are <c>System.IO</c> exceptions. The stream
    /// stays on <paramref name="sftp"/>, the session that opened it.
    /// </summary>
    public static SftpFileSystemStream Wrap(SftpFileSystem fileSystem, SftpClient sftp, Stream remote, string full, int bufferSize) =>
        new(new BufferedStream(new IOStream(remote, full, sftp, fileSystem.Options.OperationTimeout, fileSystem.Options.Clock), Math.Max(bufferSize, 64 * 1024)), full);

    /// <summary>
    /// The SFTP stream with synchronous calls added (each bounded by the timeout) and every failure, synchronous or asynchronous,
    /// turned into the <c>System.IO</c> exception <see cref="SftpFileSystem.Translate"/> gives.
    /// </summary>
    private sealed class IOStream(Stream remote, string path, SftpClient sftp, TimeSpan timeout, TimeProvider clock) : Stream
    {
        public override bool CanRead => remote.CanRead;

        // Seekable while open, as a file stream is, even when the server did not report the size at open (the SFTP stream then says
        // it is not, so that its own copy does not ask for the length): the buffer in front needs it to seek at all.
        public override bool CanSeek => remote.CanRead || remote.CanWrite;

        public override bool CanWrite => remote.CanWrite;

        // The SFTP stream answers from what it knows; otherwise the server is asked, the wait bounded either way.
        public override long Length => remote.CanSeek
            ? remote.Length
            : Wait(async ct => (await sftp.GetAttributesAsync(path, cancellationToken: ct).ConfigureAwait(false)).Size
                ?? throw new NotSupportedException("The SFTP server did not report the file's size."));

        public override long Position
        {
            get => remote.Position;
            set => remote.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Wait(ct => remote.ReadAsync(buffer.AsMemory(offset, count), ct).AsTask());

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try
            {
                return await remote.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, path, false, timedOut: false) is { } translated)
            {
                throw translated;
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Write(byte[] buffer, int offset, int count) =>
            Wait(async ct =>
            {
                await remote.WriteAsync(buffer.AsMemory(offset, count), ct).ConfigureAwait(false);
                return true;
            });

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try
            {
                await remote.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, path, false, timedOut: false) is { } translated)
            {
                throw translated;
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

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

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            try
            {
                await remote.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, path, false, timedOut: false) is { } translated)
            {
                throw translated;
            }
        }

        public override async ValueTask DisposeAsync()
        {
            try
            {
                await remote.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, path, false, timedOut: false) is { } translated)
            {
                throw translated;
            }

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
            // The timeout starts when the work does (see SftpFileSystem.RunTransfer).
            CancellationTokenSource? cancel = null;
            try
            {
                return Task.Run(async () =>
                {
                    using var started = new CancellationTokenSource(timeout, clock);
                    cancel = started;
                    return await operation(started.Token).ConfigureAwait(false);
                }, CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (SftpFileSystem.Translate(ex, path, false, cancel?.IsCancellationRequested == true) is { } translated)
            {
                throw translated;
            }
        }
    }
}
