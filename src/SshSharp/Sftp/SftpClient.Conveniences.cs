using System.Runtime.InteropServices;
using System.Text;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>How many REMOVE and RMDIR requests a recursive delete keeps in flight.</summary>
    internal const int DeleteRequestsInFlight = 64;

    /// <summary>How many directories a recursive delete works on at once: each holds a handle while it is listed.</summary>
    internal const int DeleteWalkers = 4;

    /// <summary>The largest buffer <see cref="ReadAllBytesAsync"/> sizes up front from the size the server reports; larger files grow it.</summary>
    internal const int MaxPresizedRead = 16 * 1024 * 1024;

    // ---- directories ----

    /// <summary>
    /// Creates a directory; with <paramref name="createParents"/>, also the directories above it that are missing, and an existing
    /// directory is not an error, as <c>mkdir -p</c> does. <paramref name="permissions"/>, if given, apply to <paramref name="path"/>
    /// itself; the parents it creates get the server's defaults (the server's umask applies to both).
    /// </summary>
    /// <remarks>
    /// With <paramref name="createParents"/>, the directory is created first, and only when that fails are the parents looked at, from
    /// <paramref name="path"/> upwards, as far as the first that exists: an existing tree costs one request, and a directory above it
    /// that is not writable (a chroot's top, say) is never touched. A directory created by someone else meanwhile is accepted. A link to
    /// a directory counts as a directory.
    /// </remarks>
    /// <exception cref="SftpException">A part of the path exists and is not a directory (<see cref="SftpStatusCode.Failure"/>), or the
    /// server refused to create one (for example <see cref="SftpStatusCode.PermissionDenied"/>).</exception>
    public async Task CreateDirectoryAsync(string path, bool createParents, UnixFileMode? permissions = null, CancellationToken cancellationToken = default)
    {
        if (!createParents)
        {
            await CreateDirectoryAsync(path, permissions, cancellationToken).ConfigureAwait(false);
            return;
        }

        CheckPath(path);

        // Upwards until a directory is created or found; the ones that could not be created yet, deepest first.
        var missing = new Stack<string>();
        var current = path;
        while (true)
        {
            try
            {
                await CreateDirectoryAsync(current, current == path ? permissions : null, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (SftpException)
            {
                // The status does not say why: OpenSSH answers Failure for a directory that exists, other servers NoSuchFile or
                // PermissionDenied for a missing parent. What is at the path does.
                switch (await DirectoryStateAsync(current, cancellationToken).ConfigureAwait(false))
                {
                    case DirectoryState.Directory:
                        break;
                    case DirectoryState.Other:
                        throw NotADirectory(current);
                    case DirectoryState.Missing when ParentOf(current) is { } parent:
                        missing.Push(current);
                        current = parent;
                        continue;
                    default:
                        throw; // missing with no parent to create (the top of a path), or the server will not say
                }

                break;
            }
        }

        while (missing.TryPop(out var directory))
        {
            await CreateOrFindDirectoryAsync(directory, directory == path ? permissions : null, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Deletes a directory; with <paramref name="recursive"/>, everything in it first, as <c>rm -r</c> does: files, symbolic links
    /// (the links themselves; what they point to is never followed or touched) and subdirectories, to any depth up to 64 levels.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The tree is deleted with many requests in flight (up to 64 removals, and up to 4 directories listed at once), so a large tree
    /// costs a few round trips per directory rather than one per file. Each directory is listed in full, then emptied, then removed.
    /// </para>
    /// <para>
    /// The first failure stops the deletion: no more requests are sent, those in flight are awaited, and that failure is thrown. What
    /// was deleted until then stays deleted, so the tree is left partly deleted; calling again carries on from where it stopped. An
    /// entry that is gone by the time it is deleted (deleted by someone else meanwhile) is not a failure; <paramref name="path"/>
    /// itself missing is (<see cref="SftpStatusCode.NoSuchFile"/>). Cancelling stops it the same way.
    /// </para>
    /// <para>
    /// When <paramref name="path"/> is itself a symbolic link, only the link is deleted, as <c>rm -r</c> and
    /// <see cref="Directory.Delete(string, bool)"/> do.
    /// </para>
    /// <para>
    /// Not following links relies on the server's state not changing under the delete. SFTP has no <c>O_NOFOLLOW</c> or <c>openat</c>:
    /// each request names a path the server resolves again, so a directory checked with <c>LSTAT</c> can be replaced by a link before
    /// the requests that follow. Someone else who can write inside the tree on the server can use that to make the delete remove
    /// files outside it, wherever this login may delete. Delete recursively only trees no one else can change while it runs.
    /// </para>
    /// </remarks>
    /// <exception cref="SftpException">The path does not exist, is not a directory, or the server refused to delete something in it
    /// (for example <see cref="SftpStatusCode.PermissionDenied"/>).</exception>
    /// <exception cref="SshException">The tree is deeper than 64 levels (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public async Task DeleteDirectoryAsync(string path, bool recursive, CancellationToken cancellationToken = default)
    {
        if (!recursive)
        {
            await DeleteDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
            return;
        }

        CheckPath(path);
        var attributes = await GetAttributesAsync(path, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
        if (attributes.IsSymbolicLink)
        {
            await DeleteFileAsync(path, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (attributes.FileType is SftpFileType.RegularFile or SftpFileType.Special)
        {
            await DeleteDirectoryAsync(path, cancellationToken).ConfigureAwait(false); // the server's own error for a file
            return;
        }

        // A server that limits open handles keeps one free for the caller's other work.
        var walkers = Limits.MaxOpenHandles is { } handles ? Math.Clamp(handles - 1, 1, DeleteWalkers) : DeleteWalkers;
        using var deletion = new TreeDeletion(walkers, cancellationToken);
        await deletion.RunAsync(token => DeleteTreeAsync(path, 0, deletion, token)).ConfigureAwait(false);
    }

    /// <summary>
    /// Empties and removes <paramref name="directory"/>: its files and links are removed with requests in flight together, and each
    /// subdirectory is handed to a walker of its own while one is free, or else deleted here and now, before going on. Taking a walker
    /// only when one is free means no walker ever waits for another, and at most <see cref="DeleteWalkers"/> listings are held at once.
    /// </summary>
    private async Task DeleteTreeAsync(string directory, int depth, TreeDeletion deletion, CancellationToken cancellationToken)
    {
        if (depth > MaxDepth)
        {
            throw new SshException(SshFailureReason.TransferFailed, $"The remote tree is deeper than {MaxDepth} levels.");
        }

        if (depth > 0)
        {
            // The listing said directory; LSTAT confirms it, since a server whose listing follows links (as it should not) would
            // otherwise lead the delete out of the tree, into whatever a link points to.
            SftpFileAttributes attributes;
            try
            {
                attributes = await GetAttributesAsync(directory, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
            }
            catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
            {
                return; // deleted by someone else meanwhile
            }

            if (!attributes.IsDirectory)
            {
                await DeleteFileAsync(directory, cancellationToken).ConfigureAwait(false);
                return;
            }
        }

        // Listed whole first: the listing's handle is closed before anything in the directory is deleted.
        var entries = new List<SftpFileInfo>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        await foreach (var entry in ListDirectoryAsync(directory, cancellationToken).ConfigureAwait(false))
        {
            if (seen.Add(entry.Name))
            {
                entries.Add(entry); // a name listed twice (a broken server) is deleted once
            }
        }

        var started = new List<Task>();
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Attributes.IsDirectory)
            {
                if (deletion.TryTakeWalker())
                {
                    started.Add(deletion.Start(async token =>
                    {
                        try
                        {
                            await DeleteTreeAsync(entry.FullPath, depth + 1, deletion, token).ConfigureAwait(false);
                        }
                        finally
                        {
                            deletion.ReleaseWalker();
                        }
                    }));
                }
                else
                {
                    await DeleteTreeAsync(entry.FullPath, depth + 1, deletion, cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                await deletion.Requests.WaitAsync(cancellationToken).ConfigureAwait(false);
                started.Add(deletion.Start(async token =>
                {
                    bool directoryAfterAll;
                    try
                    {
                        directoryAfterAll = await RemoveEntryAsync(entry, token).ConfigureAwait(false);
                    }
                    finally
                    {
                        deletion.Requests.Release(); // before going into a directory, whose own removals need slots
                    }

                    if (directoryAfterAll)
                    {
                        await DeleteTreeAsync(entry.FullPath, depth + 1, deletion, token).ConfigureAwait(false);
                    }
                }));
            }

            if (started.Count >= 2 * DeleteRequestsInFlight)
            {
                started.RemoveAll(task => task.IsCompleted);
            }
        }

        // The pieces never throw (TreeDeletion records a failure and cancels the token instead): a directory whose contents could not
        // all be deleted stops here rather than being removed.
        await Task.WhenAll(started).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        await deletion.Requests.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await DeleteDirectoryAsync(directory, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile && depth > 0)
        {
            // Deleted by someone else meanwhile.
        }
        finally
        {
            deletion.Requests.Release();
        }
    }

    /// <summary>
    /// Removes a file, link or special file found in a listing. Returns true when the entry turns out to be a directory after all: one
    /// whose type the listing did not say (no permissions in its attributes), which REMOVE refuses.
    /// </summary>
    private async Task<bool> RemoveEntryAsync(SftpFileInfo entry, CancellationToken cancellationToken)
    {
        try
        {
            await DeleteFileAsync(entry.FullPath, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
        {
            // Deleted by someone else meanwhile.
        }
        catch (SftpException) when (entry.Attributes.FileType == SftpFileType.Unknown)
        {
            var attributes = await GetAttributesAsync(entry.FullPath, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
            if (!attributes.IsDirectory)
            {
                throw;
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// The work of one recursive delete, which fails as a whole: the first failure cancels the rest and is the exception
    /// <see cref="RunAsync"/> throws, not the cancellations it caused. Holds the request slots and the walkers.
    /// </summary>
    private sealed class TreeDeletion : IDisposable
    {
        private readonly CancellationTokenSource _failed;
        private readonly SemaphoreSlim _walkers;
        private readonly TaskCompletionSource _idle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Exception? _firstFailure;
        private int _running;

        public TreeDeletion(int walkers, CancellationToken cancellationToken)
        {
            _failed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _walkers = new SemaphoreSlim(walkers - 1, walkers - 1); // the first walker is the caller's own
        }

        /// <summary>The REMOVE and RMDIR requests in flight.</summary>
        public SemaphoreSlim Requests { get; } = new(DeleteRequestsInFlight, DeleteRequestsInFlight);

        public bool TryTakeWalker() => _walkers.Wait(0);

        public void ReleaseWalker() => _walkers.Release();

        /// <summary>
        /// Runs the whole deletion and waits for every piece of it, including those still in flight when a failure stopped the rest,
        /// then throws its first failure, or the caller's cancellation.
        /// </summary>
        public async Task RunAsync(Func<CancellationToken, Task> work)
        {
            // The first failure is thrown below, rather than what it caused elsewhere. Work is started only by work that is running,
            // so once none is, none can start.
            _ = Start(work);
            await _idle.Task.ConfigureAwait(false);
            if (Volatile.Read(ref _firstFailure) is { } first)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(first);
            }

            _failed.Token.ThrowIfCancellationRequested(); // only the caller's token can have cancelled it without a failure
        }

        /// <summary>
        /// Starts <paramref name="work"/> as part of the deletion, with the deletion's token. The task returned never faults: a failure is
        /// recorded and cancels the token, which stops the rest.
        /// </summary>
        public Task Start(Func<CancellationToken, Task> work)
        {
            Interlocked.Increment(ref _running);
            return RunPieceAsync(work);
        }

        private async Task RunPieceAsync(Func<CancellationToken, Task> work)
        {
            try
            {
                await work(_failed.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (!_failed.IsCancellationRequested)
                {
                    Interlocked.CompareExchange(ref _firstFailure, ex, null);
                }

                // Recorded, not thrown: the token tells the rest to stop, and RunAsync throws the first failure once all have.
                await _failed.CancelAsync().ConfigureAwait(false);
            }
            finally
            {
                if (Interlocked.Decrement(ref _running) == 0)
                {
                    _idle.TrySetResult();
                }
            }
        }

        public void Dispose()
        {
            _failed.Dispose();
            _walkers.Dispose();
            Requests.Dispose();
        }
    }

    private enum DirectoryState
    {
        Missing,
        Directory,
        Other,
        Unknown,
    }

    /// <summary>What is at <paramref name="path"/>, following links; <see cref="DirectoryState.Unknown"/> when the server will not say.</summary>
    private async Task<DirectoryState> DirectoryStateAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var attributes = await GetAttributesAsync(path, followSymbolicLinks: true, cancellationToken).ConfigureAwait(false);
            return attributes.IsDirectory ? DirectoryState.Directory : DirectoryState.Other;
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
        {
            return DirectoryState.Missing;
        }
        catch (SftpException)
        {
            return DirectoryState.Unknown;
        }
    }

    /// <summary>Creates a directory whose parent exists now, or accepts one that someone else created meanwhile.</summary>
    private async Task CreateOrFindDirectoryAsync(string path, UnixFileMode? permissions, CancellationToken cancellationToken)
    {
        try
        {
            await CreateDirectoryAsync(path, permissions, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException)
        {
            switch (await DirectoryStateAsync(path, cancellationToken).ConfigureAwait(false))
            {
                case DirectoryState.Directory:
                    return;
                case DirectoryState.Other:
                    throw NotADirectory(path);
                default:
                    throw;
            }
        }
    }

    private static SftpException NotADirectory(string path) =>
        new(SftpStatusCode.Failure, $"Creating the directory '{path}' failed: it exists and is not a directory.", path);

    /// <summary>
    /// The directory above <paramref name="path"/>, or null when there is none to create: the root, or a single name (whose parent is
    /// the login directory, which exists).
    /// </summary>
    internal static string? ParentOf(string path)
    {
        var trimmed = path.TrimEnd('/');
        var slash = trimmed.LastIndexOf('/');
        if (slash <= 0)
        {
            return null;
        }

        var parent = trimmed[..slash].TrimEnd('/');
        return parent.Length == 0 ? null : parent;
    }

    // ---- whole files ----

    /// <summary>
    /// Reads a whole remote file into a byte array, as <see cref="File.ReadAllBytesAsync(string, CancellationToken)"/> does locally,
    /// with many reads in flight.
    /// </summary>
    /// <exception cref="SftpException">The file does not exist (<see cref="SftpStatusCode.NoSuchFile"/>), or another error.</exception>
    /// <exception cref="IOException">The file is larger than an array can hold (about 2 GiB).</exception>
    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        var (handle, _) = await OpenHandleAsync(path, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
        try
        {
            var size = (await GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size;
            if (size > Array.MaxLength)
            {
                throw new IOException($"'{path}' is too large to read into one array ({size} bytes).");
            }

            // Sized from what the server says, up to a bound: a server's word alone does not get a 2 GiB allocation.
            using var buffer = new MemoryStream((int)Math.Min(size ?? 0, MaxPresizedRead));
            await DownloadHandleAsync(handle, path, buffer, 0, size, new SftpTransferOptions(), cancellationToken).ConfigureAwait(false);
            return buffer.Length == buffer.Capacity ? buffer.GetBuffer() : buffer.ToArray();
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads a whole remote file as text, as <see cref="File.ReadAllTextAsync(string, Encoding, CancellationToken)"/> does locally: a
    /// byte order mark, if there is one, decides the encoding; otherwise <paramref name="encoding"/> (UTF-8 by default).
    /// </summary>
    /// <exception cref="SftpException">The file does not exist (<see cref="SftpStatusCode.NoSuchFile"/>), or another error.</exception>
    public async Task<string> ReadAllTextAsync(string path, Encoding? encoding = null, CancellationToken cancellationToken = default)
    {
        var bytes = await ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(new MemoryStream(bytes, writable: false), encoding ?? Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes <paramref name="bytes"/> to a remote file, creating it or replacing its contents, as
    /// <see cref="File.WriteAllBytesAsync(string, byte[], CancellationToken)"/> does locally, with many writes in flight.
    /// </summary>
    /// <remarks>
    /// The file is truncated first, so a failure part way leaves it partly written. Where readers must never see that, write to a
    /// temporary name and <see cref="RenameAsync"/> it over the file with <c>overwrite: true</c>.
    /// </remarks>
    public async Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
    {
        using var source = MemoryMarshal.TryGetArray(bytes, out var segment)
            ? new MemoryStream(segment.Array!, segment.Offset, segment.Count, writable: false)
            : new MemoryStream(bytes.ToArray(), writable: false);
        await UploadAsync(source, path, options: null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes <paramref name="contents"/> to a remote file, creating it or replacing its contents, as
    /// <see cref="File.WriteAllTextAsync(string, string, Encoding, CancellationToken)"/> does locally: UTF-8 without a byte order mark
    /// by default; a given <paramref name="encoding"/> writes its preamble (a byte order mark), if it has one.
    /// </summary>
    /// <remarks>As <see cref="WriteAllBytesAsync"/>: a failure part way leaves the file partly written.</remarks>
    public async Task WriteAllTextAsync(string path, string contents, Encoding? encoding = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(contents);
        byte[] bytes;
        if (encoding is null)
        {
            bytes = Encoding.UTF8.GetBytes(contents); // Encoding.UTF8.GetBytes writes no byte order mark
        }
        else
        {
            var preamble = encoding.Preamble;
            bytes = new byte[preamble.Length + encoding.GetByteCount(contents)];
            preamble.CopyTo(bytes);
            encoding.GetBytes(contents, bytes.AsSpan(preamble.Length));
        }

        await WriteAllBytesAsync(path, bytes, cancellationToken).ConfigureAwait(false);
    }
}
