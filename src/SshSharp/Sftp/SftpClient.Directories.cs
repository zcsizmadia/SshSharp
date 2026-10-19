using SshSharp.Scp;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>How deep a tree a directory transfer follows: a server cannot make it recurse without end.</summary>
    internal const int MaxDepth = 64;

    /// <summary>
    /// Downloads the directory <paramref name="remoteDirectory"/> and everything under it into <paramref name="localDirectory"/> (created
    /// if needed), file by file with <see cref="DownloadFileAsync"/> and the same <paramref name="options"/>. Symbolic links and special
    /// files are skipped, so a link cannot lead the download outside the tree. With <see cref="SftpTransferOptions.MaxConcurrentFiles"/>
    /// above 1, several files are downloaded at once. <see cref="SftpTransferOptions.Filter"/> chooses what is downloaded, and
    /// <see cref="SftpTransferOptions.SkipUnchanged"/> leaves local files that match the remote ones in size and modification time.
    /// </summary>
    /// <remarks>
    /// Every name the server lists is checked before it becomes a local path: names that cannot be a file name on this system (a
    /// separator, <c>.</c> or <c>..</c>, control characters, a name that is not valid UTF-8; on Windows also <c>\</c>, <c>:</c>, device
    /// names such as <c>CON</c> or <c>NUL</c>, and trailing dots) are skipped and counted in <see cref="SftpTransferSummary.Skipped"/>, and
    /// the resulting path must stay inside <paramref name="localDirectory"/>.
    /// </remarks>
    /// <exception cref="SshException">A path would end up outside the target (<see cref="SshFailureReason.TransferFailed"/>), or the tree is
    /// deeper than 64 levels.</exception>
    public async Task<SftpTransferSummary> DownloadDirectoryAsync(string remoteDirectory, string localDirectory, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        CheckPath(remoteDirectory);
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        options ??= new SftpTransferOptions();
        var root = Path.GetFullPath(localDirectory);
        Directory.CreateDirectory(root);
        var summary = new SummaryCounter();
        if (ConcurrentFiles(options) is var files && files > 1)
        {
            await DownloadTreeConcurrentlyAsync(remoteDirectory, root, files, options, summary, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await DownloadTreeAsync(remoteDirectory, root, root, string.Empty, 0, options, summary, cancellationToken).ConfigureAwait(false);
        }

        return summary.ToSummary();
    }

    /// <summary>
    /// Uploads the local directory <paramref name="localDirectory"/> and everything under it to <paramref name="remoteDirectory"/> (created
    /// if needed), file by file with <see cref="UploadFileAsync"/> and the same <paramref name="options"/>. Symbolic links, junctions and
    /// other reparse points are skipped, and so are special files on Unix (FIFOs, sockets, devices). With
    /// <see cref="SftpTransferOptions.MaxConcurrentFiles"/> above 1, several files are uploaded at once.
    /// <see cref="SftpTransferOptions.Filter"/> chooses what is uploaded, and <see cref="SftpTransferOptions.SkipUnchanged"/> leaves remote
    /// files that match the local ones in size and modification time.
    /// </summary>
    /// <exception cref="DirectoryNotFoundException"><paramref name="localDirectory"/> does not exist.</exception>
    public async Task<SftpTransferSummary> UploadDirectoryAsync(string localDirectory, string remoteDirectory, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        CheckPath(remoteDirectory);
        options ??= new SftpTransferOptions();
        var root = new DirectoryInfo(localDirectory);
        if (!root.Exists)
        {
            throw new DirectoryNotFoundException($"'{localDirectory}' does not exist.");
        }

        var summary = new SummaryCounter();
        if (ConcurrentFiles(options) is var files && files > 1)
        {
            await UploadTreeConcurrentlyAsync(root, remoteDirectory, files, options, summary, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await UploadTreeAsync(root, remoteDirectory, string.Empty, 0, options, summary, cancellationToken).ConfigureAwait(false);
        }

        return summary.ToSummary();
    }

    /// <summary>
    /// How many files a directory transfer moves at once: <see cref="SftpTransferOptions.MaxConcurrentFiles"/>, within the open handles
    /// the server allows, one kept for a listing.
    /// </summary>
    private int ConcurrentFiles(SftpTransferOptions options) =>
        Limits.MaxOpenHandles is { } handles ? Math.Clamp(handles - 1, 1, options.MaxConcurrentFiles) : options.MaxConcurrentFiles;

    private async Task DownloadTreeAsync(string remoteDirectory, string localDirectory, string root, string relative, int depth,
        SftpTransferOptions options, SummaryCounter summary, CancellationToken cancellationToken)
    {
        if (depth > MaxDepth)
        {
            throw new SshException(SshFailureReason.TransferFailed, $"The remote tree is deeper than {MaxDepth} levels.");
        }

        // The listing is read whole before anything is transferred, so its handle is closed before files and subdirectories are opened.
        var entries = new List<SftpFileInfo>();
        await foreach (var entry in ListDirectoryAsync(remoteDirectory, cancellationToken).ConfigureAwait(false))
        {
            entries.Add(entry);
        }

        // A name listed twice (a broken or hostile server) is fetched once: a directory's permissions are applied after its contents, so a
        // second copy would be written into a directory already made read-only.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (!seen.Add(entry.Name))
            {
                summary.Skip();
                continue;
            }

            if (LocalPathFor(localDirectory, entry.Name, root) is not { } local)
            {
                summary.Skip(); // a name this system cannot hold, or one that was not valid UTF-8
                continue;
            }

            var path = ChildPath(relative, entry.Name);
            if (DownloadAction(options, path, entry.Attributes, local) is var action && action != EntryAction.Transfer)
            {
                summary.Count(action);
                continue;
            }

            if (entry.Attributes.IsDirectory)
            {
                Directory.CreateDirectory(local);
                await DownloadTreeAsync(entry.FullPath, local, root, path, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.AddDirectory();
                if (options.Preserve)
                {
                    // After its contents, which would change its time (and which a mode without write permission could refuse).
                    if (entry.Attributes.LastWriteTime is { } modified)
                    {
                        Directory.SetLastWriteTimeUtc(local, modified.UtcDateTime);
                    }

                    SetLocalPermissions(local, entry.Attributes.Permissions);
                }
            }
            else if (entry.Attributes.IsRegularFile)
            {
                summary.AddFile(await DownloadFileAsync(entry.FullPath, local, options, cancellationToken).ConfigureAwait(false));
            }
            else
            {
                summary.Skip(); // a symbolic link, a device, or a type the server did not say
            }
        }
    }

    private async Task UploadTreeAsync(DirectoryInfo local, string remoteDirectory, string relative, int depth, SftpTransferOptions options,
        SummaryCounter summary, CancellationToken cancellationToken)
    {
        if (depth > MaxDepth)
        {
            throw new IOException($"The local tree is deeper than {MaxDepth} levels.");
        }

        var created = await EnsureRemoteDirectoryAsync(remoteDirectory, cancellationToken).ConfigureAwait(false);
        Dictionary<string, SftpFileAttributes>? remoteFiles = null;
        var prefix = remoteDirectory.EndsWith('/') ? remoteDirectory : remoteDirectory + "/";
        foreach (var entry in local.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                summary.Skip();
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            var remote = prefix + entry.Name;
            if (entry is FileInfo && !LocalFileType.IsRegularFile(entry.FullName))
            {
                summary.Skip(); // a FIFO (opening it would wait for a writer), a socket or a device
                continue;
            }

            var path = ChildPath(relative, entry.Name);
            if (!UploadIncludes(options, path, entry))
            {
                summary.Count(EntryAction.Excluded);
                continue;
            }

            if (entry is FileInfo file && options.SkipUnchanged && !created)
            {
                // What is in the remote directory, listed once (when the first file needs it) rather than looked up file by file.
                remoteFiles ??= await RemoteFilesAsync(remoteDirectory, cancellationToken).ConfigureAwait(false);
                if (RemoteFileUnchanged(file, remoteFiles))
                {
                    summary.Count(EntryAction.Unchanged);
                    continue;
                }
            }

            if (entry is DirectoryInfo directory)
            {
                await UploadTreeAsync(directory, remote, path, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.AddDirectory();
                if (options.Preserve)
                {
                    await SetAttributesAsync(remote, new SftpFileAttributes
                    {
                        LastWriteTime = directory.LastWriteTimeUtc,
                        LastAccessTime = directory.LastAccessTimeUtc,
                        Permissions = LocalPermissions(directory.FullName),
                    }, cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                summary.AddFile(await UploadFileAsync(entry.FullName, remote, options, cancellationToken).ConfigureAwait(false));
            }
        }
    }

    /// <summary>
    /// <see cref="DownloadDirectoryAsync"/> with <paramref name="concurrency"/> files at once: the tree is listed directory by directory,
    /// as the sequential walk does, and each file is handed to a download of its own once one of the <paramref name="concurrency"/> slots
    /// is free, so the walk never runs far ahead of the transfers. A directory is created locally before its listing is read, so before
    /// any file goes into it; its times and permissions (<see cref="SftpTransferOptions.Preserve"/>) are set once every file is in.
    /// </summary>
    private async Task DownloadTreeConcurrentlyAsync(string remoteDirectory, string root, int concurrency, SftpTransferOptions options,
        SummaryCounter summary, CancellationToken cancellationToken)
    {
        using var budget = new SemaphoreSlim(options.MaxRequestsInFlight, options.MaxRequestsInFlight);
        using var slots = new SemaphoreSlim(concurrency, concurrency);
        using var group = new TransferGroup(cancellationToken);
        var fileOptions = options.ForFilesOfDirectory(SerializedProgress.Wrap(options.Progress), budget);
        var claimed = new LocalPathClaims();
        var preserved = new List<(string Local, SftpFileAttributes Attributes, int Depth)>();

        _ = group.Run(token => WalkAsync(remoteDirectory, root, string.Empty, 0, token));
        await group.WhenAllAsync().ConfigureAwait(false);

        if (options.Preserve)
        {
            // After every file, the deepest first: a directory's contents would change its time, and a mode without write permission
            // could refuse them.
            foreach (var (local, attributes, _) in preserved.OrderByDescending(d => d.Depth))
            {
                if (attributes.LastWriteTime is { } modified)
                {
                    Directory.SetLastWriteTimeUtc(local, modified.UtcDateTime);
                }

                SetLocalPermissions(local, attributes.Permissions);
            }
        }

        async Task WalkAsync(string remote, string localDirectory, string relative, int depth, CancellationToken token)
        {
            if (depth > MaxDepth)
            {
                throw new SshException(SshFailureReason.TransferFailed, $"The remote tree is deeper than {MaxDepth} levels.");
            }

            var entries = new List<SftpFileInfo>();
            await foreach (var entry in ListDirectoryAsync(remote, token).ConfigureAwait(false))
            {
                entries.Add(entry);
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in entries)
            {
                if (!seen.Add(entry.Name))
                {
                    summary.Skip();
                    continue;
                }

                if (LocalPathFor(localDirectory, entry.Name, root) is not { } local)
                {
                    summary.Skip(); // a name this system cannot hold, or one that was not valid UTF-8
                    continue;
                }

                var path = ChildPath(relative, entry.Name);
                if (DownloadAction(options, path, entry.Attributes, local) is var action && action != EntryAction.Transfer)
                {
                    summary.Count(action);
                    continue;
                }

                if (entry.Attributes.IsDirectory)
                {
                    Directory.CreateDirectory(local);
                    await WalkAsync(entry.FullPath, local, path, depth + 1, token).ConfigureAwait(false);
                    summary.AddDirectory();
                    preserved.Add((local, entry.Attributes, depth));
                }
                else if (entry.Attributes.IsRegularFile)
                {
                    await slots.WaitAsync(token).ConfigureAwait(false);
                    var earlier = claimed.Claim(local, out var done);
                    _ = group.Run(async fileToken =>
                    {
                        try
                        {
                            // Two names this system takes for one file (they differ only in case): one after the other, the last
                            // listed winning, as one at a time.
                            await earlier.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
                            summary.AddFile(await DownloadFileAsync(entry.FullPath, local, fileOptions, fileToken).ConfigureAwait(false));
                        }
                        finally
                        {
                            done.TrySetResult();
                            slots.Release();
                        }
                    });
                }
                else
                {
                    summary.Skip(); // a symbolic link, a device, or a type the server did not say
                }
            }
        }
    }

    /// <summary>
    /// <see cref="UploadDirectoryAsync"/> with <paramref name="concurrency"/> files at once. The local tree is walked first; then every
    /// directory is created as soon as its parent exists, several at a time, and the files follow in the walk's order, each started once
    /// its directory exists and one of the <paramref name="concurrency"/> slots is free. With <see cref="SftpTransferOptions.Preserve"/>,
    /// the directories get their attributes at the end, the deepest first, a level at a time.
    /// </summary>
    private async Task UploadTreeConcurrentlyAsync(DirectoryInfo root, string remoteRoot, int concurrency, SftpTransferOptions options,
        SummaryCounter summary, CancellationToken cancellationToken)
    {
        var directories = new List<(DirectoryInfo Local, string Remote, string Relative, int Parent, int Depth)> { (root, remoteRoot, string.Empty, -1, 0) };
        var files = new List<(FileInfo Local, string Remote, int Directory)>();
        Walk(0);

        using var budget = new SemaphoreSlim(options.MaxRequestsInFlight, options.MaxRequestsInFlight);
        using var slots = new SemaphoreSlim(concurrency, concurrency);
        var fileOptions = options.ForFilesOfDirectory(SerializedProgress.Wrap(options.Progress), budget);
        using (var group = new TransferGroup(cancellationToken))
        {
            // Whether each directory was created by this transfer: one that was holds nothing to compare with (SkipUnchanged). Written
            // before its task in made completes, read after awaiting it.
            var created = new bool[directories.Count];
            var made = new Task[directories.Count];
            made[0] = group.Run(async token => created[0] = await EnsureRemoteDirectoryAsync(remoteRoot, token).ConfigureAwait(false));
            for (var i = 1; i < directories.Count; i++)
            {
                var (_, remote, _, parent, _) = directories[i];
                var parentMade = made[parent];
                var index = i;
                made[i] = group.Run(async token =>
                {
                    await parentMade.ConfigureAwait(false);
                    await HoldingSlotAsync(slots, async () => created[index] = await EnsureRemoteDirectoryAsync(remote, token).ConfigureAwait(false), token)
                        .ConfigureAwait(false);
                });
            }

            _ = group.Run(async token =>
            {
                var claimed = new LocalPathClaims();
                var remoteFiles = new Dictionary<int, Dictionary<string, SftpFileAttributes>>();
                foreach (var (local, remote, directory) in files)
                {
                    await made[directory].ConfigureAwait(false);
                    if (options.SkipUnchanged && !created[directory])
                    {
                        // The remote directory listed once, when its first file gets here, holding a slot for the handle.
                        if (!remoteFiles.TryGetValue(directory, out var there))
                        {
                            var remoteDirectory = directories[directory].Remote;
                            await HoldingSlotAsync(slots, async () => there = await RemoteFilesAsync(remoteDirectory, token).ConfigureAwait(false), token)
                                .ConfigureAwait(false);
                            remoteFiles[directory] = there!;
                        }

                        if (RemoteFileUnchanged(local, there!))
                        {
                            summary.Count(EntryAction.Unchanged);
                            continue;
                        }
                    }

                    await slots.WaitAsync(token).ConfigureAwait(false);
                    var earlier = claimed.Claim(remote, out var done);
                    _ = group.Run(async fileToken =>
                    {
                        try
                        {
                            // Names a server may take for one file (they differ only in case): one after the other, as one at a time.
                            await earlier.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
                            summary.AddFile(await UploadFileAsync(local.FullName, remote, fileOptions, fileToken).ConfigureAwait(false));
                        }
                        finally
                        {
                            done.TrySetResult();
                            slots.Release();
                        }
                    });
                }
            });

            await group.WhenAllAsync().ConfigureAwait(false);
        }

        if (!options.Preserve)
        {
            return;
        }

        // A level at a time, the deepest first: a directory made read-only (or unsearchable) before its subdirectories got theirs would
        // refuse them.
        foreach (var level in directories.Skip(1).GroupBy(d => d.Depth).OrderByDescending(level => level.Key))
        {
            using var group = new TransferGroup(cancellationToken);
            _ = group.Run(async token =>
            {
                foreach (var (local, remote, _, _, _) in level)
                {
                    await slots.WaitAsync(token).ConfigureAwait(false);
                    _ = group.Run(async setToken =>
                    {
                        try
                        {
                            await SetAttributesAsync(remote, new SftpFileAttributes
                            {
                                LastWriteTime = local.LastWriteTimeUtc,
                                LastAccessTime = local.LastAccessTimeUtc,
                                Permissions = LocalPermissions(local.FullName),
                            }, setToken).ConfigureAwait(false);
                        }
                        finally
                        {
                            slots.Release();
                        }
                    });
                }
            });

            await group.WhenAllAsync().ConfigureAwait(false);
        }

        void Walk(int index)
        {
            var (local, remoteDirectory, relative, _, depth) = directories[index];
            if (depth > MaxDepth)
            {
                throw new IOException($"The local tree is deeper than {MaxDepth} levels.");
            }

            var prefix = remoteDirectory.EndsWith('/') ? remoteDirectory : remoteDirectory + "/";
            foreach (var entry in local.EnumerateFileSystemInfos())
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    summary.Skip();
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();
                var remote = prefix + entry.Name;
                if (entry is FileInfo && !LocalFileType.IsRegularFile(entry.FullName))
                {
                    summary.Skip(); // a FIFO (opening it would wait for a writer), a socket or a device
                    continue;
                }

                var path = ChildPath(relative, entry.Name);
                if (!UploadIncludes(options, path, entry))
                {
                    summary.Count(EntryAction.Excluded);
                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    directories.Add((directory, remote, path, index, depth + 1));
                    Walk(directories.Count - 1);
                    summary.AddDirectory();
                }
                else
                {
                    files.Add(((FileInfo)entry, remote, index));
                }
            }
        }
    }

    /// <summary>Runs <paramref name="action"/> holding one of <paramref name="slots"/>.</summary>
    private static async Task HoldingSlotAsync(SemaphoreSlim slots, Func<Task> action, CancellationToken cancellationToken)
    {
        await slots.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await action().ConfigureAwait(false);
        }
        finally
        {
            slots.Release();
        }
    }

    /// <summary>
    /// The transfers of a directory transfer with several files at once, which fail together: the first failure cancels the others
    /// and is the exception <see cref="WhenAllAsync"/> throws, not the cancellations or closed sessions it caused in them.
    /// </summary>
    private sealed class TransferGroup : IDisposable
    {
        private readonly CancellationTokenSource _failed;
        private readonly List<Task> _tasks = [];
        private Exception? _firstFailure;

        public TransferGroup(CancellationToken cancellationToken) => _failed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        /// <summary>Cancelled by the caller, or once one of the transfers has failed.</summary>
        public CancellationToken Token => _failed.Token;

        /// <summary>Starts <paramref name="work"/> in the group.</summary>
        public Task Run(Func<CancellationToken, Task> work)
        {
            var task = RunAsync(work);
            lock (_tasks)
            {
                _tasks.Add(task);
            }

            return task;
        }

        private async Task RunAsync(Func<CancellationToken, Task> work)
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

                await _failed.CancelAsync().ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>Waits for every transfer, including those started meanwhile, then throws the first failure, or the caller's cancellation.</summary>
        public async Task WhenAllAsync()
        {
            Task[] all;
            while (true)
            {
                lock (_tasks)
                {
                    all = [.. _tasks];
                }

                // As a plain Task: Task<T>'s own ConfigureAwait does not take SuppressThrowing.
                await Task.WhenAll(all).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
                lock (_tasks)
                {
                    if (_tasks.Count == all.Length)
                    {
                        break; // nothing started while waiting: none can start now, as only running ones start others
                    }
                }
            }

            if (Volatile.Read(ref _firstFailure) is { } first)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(first);
            }

            await Task.WhenAll(all).ConfigureAwait(false); // any other outcome (the caller's cancellation) as it is
        }

        public void Dispose() => _failed.Dispose();
    }

    /// <summary>
    /// The destination paths a concurrent directory transfer has handed out, compared without case: two names that differ only in case
    /// may be one file on the receiving side (Windows, macOS), and two transfers into one file at once would collide, where one after the
    /// other the later one simply replaces it.
    /// </summary>
    private sealed class LocalPathClaims
    {
        private readonly Dictionary<string, Task> _claims = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Claims <paramref name="path"/>: returns what to wait for first (a transfer to the same path), and <paramref name="done"/> to complete when finished.</summary>
        public Task Claim(string path, out TaskCompletionSource done)
        {
            done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var earlier = _claims.GetValueOrDefault(path, Task.CompletedTask);
            _claims[path] = done.Task;
            return earlier;
        }
    }

    /// <summary>
    /// Reports progress one report at a time: the files of a concurrent directory transfer report from several threads, and a callback
    /// written for one transfer at a time need not be thread-safe.
    /// </summary>
    private sealed class SerializedProgress(IProgress<SftpTransferProgress> progress) : IProgress<SftpTransferProgress>
    {
        private readonly object _lock = new();

        public static SerializedProgress? Wrap(IProgress<SftpTransferProgress>? progress) =>
            progress is null ? null : new SerializedProgress(progress);

        public void Report(SftpTransferProgress value)
        {
            lock (_lock)
            {
                progress.Report(value);
            }
        }
    }

    /// <summary>The permission bits <see cref="SftpTransferOptions.Preserve"/> copies: read, write and execute for owner, group and others.</summary>
    private const UnixFileMode PreservedPermissions = (UnixFileMode)0x1FF; // 0777

    /// <summary>A local file's or directory's permissions to preserve, or null where this system has no Unix modes (Windows).</summary>
    private static UnixFileMode? LocalPermissions(string path) =>
        OperatingSystem.IsWindows() ? null : File.GetUnixFileMode(path) & PreservedPermissions;

    /// <summary>Gives a local file or directory the remote permissions, where this system has Unix modes and the server sent them.</summary>
    private static void SetLocalPermissions(string path, UnixFileMode? permissions)
    {
        if (!OperatingSystem.IsWindows() && permissions is { } mode)
        {
            File.SetUnixFileMode(path, mode & PreservedPermissions);
        }
    }

    /// <summary>Creates the remote directory, or accepts one that is there already; true when it was created (so it is empty).</summary>
    private async Task<bool> EnsureRemoteDirectoryAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await CreateDirectoryAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (SftpException ex) when (ex.Status is SftpStatusCode.Failure or SftpStatusCode.PermissionDenied)
        {
            // Probably there already (OpenSSH says "Failure" for an existing directory); anything else is the original error.
            SftpFileAttributes attributes;
            try
            {
                attributes = await GetAttributesAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (SftpException)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
                throw; // not reached
            }

            if (!attributes.IsDirectory)
            {
                throw;
            }

            return false;
        }
    }

    /// <summary>The path of <paramref name="name"/> relative to a directory transfer's root, from its directory's (<c>/</c>-separated).</summary>
    private static string ChildPath(string relative, string name) => relative.Length == 0 ? name : relative + "/" + name;

    /// <summary>
    /// What a directory download does with a remote entry: <see cref="SftpTransferOptions.Filter"/> and
    /// <see cref="SftpTransferOptions.SkipUnchanged"/> for a file or directory; anything else goes on to be skipped as before, unseen
    /// by the filter.
    /// </summary>
    private static EntryAction DownloadAction(SftpTransferOptions options, string path, SftpFileAttributes attributes, string local)
    {
        if (!attributes.IsDirectory && !attributes.IsRegularFile)
        {
            return EntryAction.Transfer;
        }

        if (options.Filter is { } filter && !filter(new SftpTransferEntry(path, attributes)))
        {
            return EntryAction.Excluded;
        }

        return options.SkipUnchanged && attributes.IsRegularFile && new FileInfo(local) is { Exists: true } file
            && IsUnchanged(attributes.Size, attributes.LastWriteTime, file.Length, file.LastWriteTimeUtc)
            ? EntryAction.Unchanged
            : EntryAction.Transfer;
    }

    /// <summary>Whether <see cref="SftpTransferOptions.Filter"/> takes a local file or directory of a directory upload.</summary>
    private static bool UploadIncludes(SftpTransferOptions options, string path, FileSystemInfo entry) =>
        options.Filter is not { } filter || filter(new SftpTransferEntry(path, new SftpFileAttributes
        {
            Size = entry is FileInfo file ? file.Length : null,
            Permissions = LocalPermissions(entry.FullName),
            FileType = entry is DirectoryInfo ? SftpFileType.Directory : SftpFileType.RegularFile,
            LastAccessTime = WholeSeconds(entry.LastAccessTimeUtc),
            LastWriteTime = WholeSeconds(entry.LastWriteTimeUtc),
        }));

    /// <summary>A local time as SFTP version 3 carries it: whole seconds, the fraction dropped.</summary>
    private static DateTimeOffset WholeSeconds(DateTime utc) => DateTimeOffset.FromUnixTimeSeconds(new DateTimeOffset(utc).ToUnixTimeSeconds());

    /// <summary>
    /// <see cref="SftpTransferOptions.SkipUnchanged"/>'s check: both sizes and both modification times known, the sizes equal and the
    /// times equal to the second (SFTP version 3 carries whole seconds, so the local time's fraction is dropped).
    /// </summary>
    internal static bool IsUnchanged(long? sourceSize, DateTimeOffset? sourceTime, long? destinationSize, DateTimeOffset? destinationTime) =>
        sourceSize is { } size && destinationSize == size
        && sourceTime is { } source && destinationTime is { } destination
        && source.ToUnixTimeSeconds() == destination.ToUnixTimeSeconds();

    /// <summary>Whether the remote copy of a local file, as its directory's listing describes it, is unchanged (<see cref="SftpTransferOptions.SkipUnchanged"/>).</summary>
    private static bool RemoteFileUnchanged(FileInfo local, Dictionary<string, SftpFileAttributes> remoteFiles) =>
        remoteFiles.TryGetValue(local.Name, out var remote)
        && remote.FileType is SftpFileType.RegularFile or SftpFileType.Unknown
        && IsUnchanged(local.Length, local.LastWriteTimeUtc, remote.Size, remote.LastWriteTime);

    /// <summary>The entries of a remote directory by name, for <see cref="SftpTransferOptions.SkipUnchanged"/>.</summary>
    private async Task<Dictionary<string, SftpFileAttributes>> RemoteFilesAsync(string directory, CancellationToken cancellationToken)
    {
        var entries = new Dictionary<string, SftpFileAttributes>(StringComparer.Ordinal);
        await foreach (var entry in ListDirectoryAsync(directory, cancellationToken).ConfigureAwait(false))
        {
            entries[entry.Name] = entry.Attributes;
        }

        return entries;
    }

    /// <summary>What a directory transfer does with an entry, past the checks every entry gets.</summary>
    private enum EntryAction
    {
        /// <summary>Transfer it (or skip it as a link or special file, as without a filter).</summary>
        Transfer,

        /// <summary>Leave it out: <see cref="SftpTransferOptions.Filter"/> declined it.</summary>
        Excluded,

        /// <summary>Leave it: <see cref="SftpTransferOptions.SkipUnchanged"/> found the destination the same.</summary>
        Unchanged,
    }

    /// <summary>
    /// The local path for a name from a remote listing, or null when the name cannot be a file name here (it is skipped): empty,
    /// <c>.</c>, <c>..</c>, a separator, NUL or another control character, or the replacement character a name that was not valid
    /// UTF-8 decodes to; on Windows also <c>\</c>, <c>:</c>, device names and trailing dots or spaces. A path that would still end up
    /// outside the root stops the download (<see cref="SshFailureReason.TransferFailed"/>).
    /// </summary>
    internal static string? LocalPathFor(string localDirectory, string name, string root, bool? windows = null)
    {
        if (!IsAcceptableName(name, windows ?? OperatingSystem.IsWindows()))
        {
            return null;
        }

        var path = Path.GetFullPath(Path.Join(localDirectory, name));
        var inside = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(inside, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new SshException(SshFailureReason.TransferFailed, $"'{name}' would be written outside the target directory.");
        }

        return path;
    }

    internal static bool IsAcceptableName(string name, bool windows)
    {
        if (name.Length == 0 || name is "." or ".." || name.Any(c => c is '/' or '�' || char.IsControl(c)))
        {
            return false;
        }

        if (!windows)
        {
            return true; // ':' and '\' are ordinary characters in POSIX names
        }

        try
        {
            SshScpExtensions.CheckName(name, windows: true);
            return true;
        }
        catch (SshException)
        {
            return false;
        }
    }

    /// <summary>What a directory transfer did so far; safe to update from the files of a concurrent transfer.</summary>
    private sealed class SummaryCounter
    {
        private int _files;
        private int _directories;
        private long _bytes;
        private int _skipped;
        private int _excluded;
        private int _unchanged;

        public void AddFile(long bytes)
        {
            Interlocked.Increment(ref _files);
            Interlocked.Add(ref _bytes, bytes);
        }

        public void AddDirectory() => Interlocked.Increment(ref _directories);

        public void Skip() => Interlocked.Increment(ref _skipped);

        /// <summary>Counts an entry that <see cref="SftpTransferOptions.Filter"/> or <see cref="SftpTransferOptions.SkipUnchanged"/> left out.</summary>
        public void Count(EntryAction action) => Interlocked.Increment(ref action == EntryAction.Excluded ? ref _excluded : ref _unchanged);

        public SftpTransferSummary ToSummary() =>
            new(Volatile.Read(ref _files), Volatile.Read(ref _directories), Interlocked.Read(ref _bytes), Volatile.Read(ref _skipped))
            {
                Excluded = Volatile.Read(ref _excluded),
                Unchanged = Volatile.Read(ref _unchanged),
            };
    }
}

/// <summary>What a directory transfer did.</summary>
/// <param name="Files">Files transferred.</param>
/// <param name="Directories">Directories created or entered below the top one.</param>
/// <param name="Bytes">Bytes transferred.</param>
/// <param name="Skipped">Entries left out: symbolic links, special files, reparse points, and names this system cannot hold.</param>
public sealed record SftpTransferSummary(int Files, int Directories, long Bytes, int Skipped)
{
    /// <summary>Files and directories that <see cref="SftpTransferOptions.Filter"/> left out (a directory counts once, not its contents).</summary>
    public int Excluded { get; init; }

    /// <summary>Files not transferred because <see cref="SftpTransferOptions.SkipUnchanged"/> found the destination the same.</summary>
    public int Unchanged { get; init; }
}

/// <summary>
/// A file or directory a directory transfer is about to transfer, as <see cref="SftpTransferOptions.Filter"/> sees it.
/// </summary>
/// <param name="RelativePath">
/// The entry's path below the transfer's top directory, with <c>/</c> between names whatever this system uses: <c>a.txt</c>, or
/// <c>logs/2026/app.log</c>.
/// </param>
/// <param name="Attributes">
/// The entry's attributes: the server's, from the listing, in a download; the local file's or directory's in an upload (its size, times
/// in whole seconds, its permissions where this system has Unix modes, and <see cref="SftpFileType.RegularFile"/> or
/// <see cref="SftpFileType.Directory"/>).
/// </param>
public sealed record SftpTransferEntry(string RelativePath, SftpFileAttributes Attributes)
{
    /// <summary>The entry's name: the last part of <see cref="RelativePath"/>.</summary>
    public string Name => RelativePath[(RelativePath.LastIndexOf('/') + 1)..];
}
