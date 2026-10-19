using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>
    /// <see cref="SftpTransferOptions.Segments"/> for an upload: the local file is split into ranges, the first written over this
    /// session and each other one over a sibling session of its own, all into the same remote file at their offsets. This session creates
    /// (or truncates) the file; each sibling opens it for writing without truncating it, and a server that refuses that second writer
    /// gets fewer sessions. The last range reads on to the end of the local file (it may have grown); a range that ends early means the
    /// file shrank, which fails the upload. The first failure cancels the rest and is the one reported, with one exception: a later
    /// range whose very first write is refused means the server takes writes in order only, and the rest of the file is then written in
    /// order over this session, from as far as the server holds it without a gap. A failed upload cuts the remote file to that unbroken
    /// start (deleting it where the server cannot cut it), so it never has a gap a resumed upload would keep.
    /// </summary>
    private async Task<long> UploadSegmentedAsync(string localPath, string remotePath, SftpTransferOptions options, CancellationToken cancellationToken)
    {
        using var local = File.OpenHandle(localPath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.Asynchronous);
        var size = RandomAccess.GetLength(local);
        var segments = (int)Math.Min(options.Segments, size / MinSegmentBytes);
        var (handle, _) = await OpenHandleAsync(remotePath, options.Overwrite ? FileMode.Create : FileMode.CreateNew, FileAccess.Write, cancellationToken)
            .ConfigureAwait(false);
        var siblings = new List<(SftpClient Client, byte[] Handle)>();
        try
        {
            // The sessions first, each with the file open: the server may allow fewer than asked (sshd's MaxSessions), or only one writer
            // of a file, and the ranges are split among those that have it open.
            for (var i = 1; i < segments; i++)
            {
                SftpClient sibling;
                try
                {
                    sibling = await OpenSibling!(cancellationToken).ConfigureAwait(false);
                }
                catch (SshException ex) when (ex.Reason is SshFailureReason.ChannelClosed or SshFailureReason.ProtocolError)
                {
                    break; // no more sessions: the ones open share the file
                }
                catch (NoMoreSessionsException)
                {
                    break; // the connection refuses new sessions (PreventNewSessionsAsync)
                }

                try
                {
                    sibling.OperationTimeout = OperationTimeout;
                    var (siblingHandle, _) = await sibling.OpenHandleAsync(remotePath, FileMode.Open, FileAccess.Write, cancellationToken).ConfigureAwait(false);
                    siblings.Add((sibling, siblingHandle));
                }
                catch (Exception ex)
                {
                    await sibling.DisposeAsync().ConfigureAwait(false);
                    if (ex is SftpException)
                    {
                        break; // the server will not open the file for a second writer: the sessions that have it share it
                    }

                    throw;
                }
            }

            return await WriteSegmentsAsync().ConfigureAwait(false);
        }
        finally
        {
            foreach (var (sibling, siblingHandle) in siblings)
            {
                await sibling.CloseHandleAsync(siblingHandle).ConfigureAwait(false);
                await sibling.DisposeAsync().ConfigureAwait(false);
            }

            await CloseHandleAsync(handle).ConfigureAwait(false);
        }

        async Task<long> WriteSegmentsAsync()
        {
            var count = 1 + siblings.Count;
            var part = size / count;
            var confirmed = new StrongBox<long>[count];
            for (var i = 0; i < count; i++)
            {
                confirmed[i] = new StrongBox<long>();
            }

            using var failed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            // Stopping a range stops its writes, but the replies to those already sent are still awaited (for up to 30 s): only then is it
            // known what the server holds, and only then can the file be cut without a write from another session landing after the cut.
            using var replies = new CancellationTokenSource();
            using var stopping = failed.Token.Register(() => replies.CancelAfter(TimeSpan.FromSeconds(30)));
            Exception? firstFailure = null;
            var outOfOrder = false;
            var progressLock = new object();
            long transferred = 0, reported = 0;
            var tasks = new Task<long>[count];
            for (var i = 0; i < count; i++)
            {
                tasks[i] = WriteSegmentAsync(i);
            }

            // As a plain Task: Task<T>'s own ConfigureAwait does not take SuppressThrowing.
            Task all = Task.WhenAll(tasks);
            await all.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

            long? fallbackStart = null;
            var fallbackConfirmed = new StrongBox<long>();
            try
            {
                if (Volatile.Read(ref firstFailure) is { } first)
                {
                    if (!outOfOrder)
                    {
                        // Report the failure that stopped the others, not what it caused in them (cancellations, or a session closing).
                        ExceptionDispatchInfo.Throw(first);
                    }

                    cancellationToken.ThrowIfCancellationRequested();

                    // The server takes writes in order only: the rest goes over this session, in order, from where the file is unbroken.
                    var start = UnbrokenLength();
                    fallbackStart = start;
                    long fallbackAcknowledged = 0;
                    var rest = await WriteRangeAsync(handle, remotePath, start, stop: null, ReadAsync, length =>
                    {
                        fallbackAcknowledged += length;
                        Report(start + fallbackAcknowledged);
                    }, fallbackConfirmed, options, cancellationToken).ConfigureAwait(false);
                    return start + rest;
                }

                await Task.WhenAll(tasks).ConfigureAwait(false); // any other outcome (the caller's cancellation) as it is
                return ((count - 1) * part) + tasks[^1].Result;
            }
            catch
            {
                await CutAsync(fallbackStart is { } start ? start + fallbackConfirmed.Value : UnbrokenLength()).ConfigureAwait(false);
                throw;
            }

            async Task<long> WriteSegmentAsync(int index)
            {
                var (client, segmentHandle) = index == 0 ? (this, handle) : siblings[index - 1];
                var start = index * part;
                long? stop = index == count - 1 ? null : start + part; // the last one reads to the end, wherever that now is
                try
                {
                    var written = await client.WriteRangeAsync(segmentHandle, remotePath, start, stop, ReadAsync, length =>
                    {
                        lock (progressLock)
                        {
                            transferred += length;
                            Report(transferred);
                        }
                    }, confirmed[index], options, failed.Token, replies.Token).ConfigureAwait(false);
                    if (stop is { } end && written != end - start)
                    {
                        throw new IOException($"'{localPath}' became shorter during the upload: its part from {start} ended early.");
                    }

                    return written;
                }
                catch (Exception ex)
                {
                    if (!failed.IsCancellationRequested && Interlocked.CompareExchange(ref firstFailure, ex, null) is null)
                    {
                        // A later range whose very first write the server refuses: it takes writes in order only (a server that stores
                        // files as objects, written from the start), not a failure of the file.
                        outOfOrder = index > 0 && ex is SftpException && confirmed[index].Value == 0;
                    }

                    await failed.CancelAsync().ConfigureAwait(false); // one part failed: stop the others
                    throw;
                }
            }

            // How far from the start the server holds the file without a gap: each range in turn, while the one before is complete.
            long UnbrokenLength()
            {
                long length = 0;
                for (var i = 0; i < count; i++)
                {
                    length = (i * part) + confirmed[i].Value;
                    if (i == count - 1 || confirmed[i].Value < part)
                    {
                        break;
                    }
                }

                return length;
            }

            // Progress only ever grows: a fallback starts again below what the ranges had reported.
            void Report(long value)
            {
                if (options.Progress is not { } progress)
                {
                    return;
                }

                lock (progressLock)
                {
                    if (value > reported)
                    {
                        reported = value;
                        progress.Report(new SftpTransferProgress(remotePath, value, size));
                    }
                }
            }
        }

        // Fills the buffer from the local file at the offset, as far as the file goes.
        async ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken token)
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await RandomAccess.ReadAsync(local, buffer[total..], offset + total, token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            return total;
        }

        // A failed upload keeps only its unbroken start, so a resumed one cannot keep a gap; the session may be gone, and then so be it.
        async Task CutAsync(long length)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                await SetHandleAttributesAsync(handle, remotePath, new SftpFileAttributes { Size = length }, timeout.Token).ConfigureAwait(false);
            }
            catch (SftpException)
            {
                // The server cannot cut a file: a file with gaps must not be taken for a partial upload, so it goes.
                try
                {
                    await DeleteFileAsync(remotePath, timeout.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SshException or OperationCanceledException)
                {
                    // Nothing more can be done.
                }
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException)
            {
                // The session ended.
            }
        }
    }
}
