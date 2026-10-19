using System.IO.Abstractions;
using SshSharp.Adapters;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary>
/// An <see cref="IFileSystem"/> (System.IO.Abstractions) over SFTP: code written against <see cref="IFileSystem"/> instead of
/// <c>File</c>, <c>Directory</c> and <c>Path</c> reads and writes files on an SSH server. Nothing is mounted, so only this application
/// sees them.
/// </summary>
/// <remarks>
/// <para>
/// Paths are POSIX paths on the server, whatever OS this runs on: <see cref="Path"/> uses <c>/</c>, and relative paths are relative to
/// the current directory (<see cref="IDirectory.GetCurrentDirectory"/>), which starts as the login directory and is kept here, not on
/// the server. A <c>\</c> is an ordinary character in a POSIX file name.
/// </para>
/// <para>
/// The abstraction is synchronous at heart: each synchronous call waits for its SFTP round trips, on the thread pool and bounded by
/// <see cref="SftpFileSystemOptions.OperationTimeout"/>; the asynchronous methods (<c>ReadAllTextAsync</c> and so on) do not block.
/// Errors are the exceptions <c>System.IO</c> throws: <see cref="FileNotFoundException"/>, <see cref="DirectoryNotFoundException"/>,
/// <see cref="UnauthorizedAccessException"/> and <see cref="IOException"/> (also for a failed session or connection).
/// </para>
/// <para>
/// SFTP has no creation times (the creation time reads as the last write time, and setting it does nothing), no file system
/// notifications, drives, version information, encryption or handles: <see cref="FileSystemWatcher"/>, <see cref="DriveInfo"/>,
/// <see cref="FileVersionInfo"/>, <see cref="RandomAccess"/> and the <c>SafeFileHandle</c> overloads throw <see cref="NotSupportedException"/>.
/// </para>
/// <para>
/// Built from a session factory (<see cref="SftpFileSystem(Func{CancellationToken, Task{SftpClient}}, SftpFileSystemOptions?)"/>),
/// the file system follows a connection that drops and comes back: it keeps one session while it works, and opens a new one after the
/// session or its connection fails. Built from one <see cref="SftpClient"/>, it uses that session for its lifetime, and fails once it
/// fails.
/// </para>
/// </remarks>
public sealed class SftpFileSystem : IFileSystem, IDisposable, IAsyncDisposable
{
    private readonly SftpSessions _sessions;
    private string? _currentDirectory;

    /// <summary>A file system over <paramref name="sftp"/>.</summary>
    /// <param name="sftp">The SFTP session to use; it stays the caller's to dispose, after the file system is no longer used.</param>
    /// <param name="options">Timeouts.</param>
    public SftpFileSystem(SftpClient sftp, SftpFileSystemOptions? options = null)
        : this(new SftpSessions(sftp ?? throw new ArgumentNullException(nameof(sftp))), options)
    {
    }

    /// <summary>
    /// A file system over sessions from <paramref name="sessionFactory"/>: one is opened on the first call and shared by every call
    /// after it, and a new one is opened when the session or its connection fails. The file system owns the sessions it opens and
    /// disposes them (dispose the file system when it is no longer used).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only a session that has ended is replaced (<see cref="SftpClient.IsConnected"/> false: the connection dropped, a keep-alive
    /// declared it dead, and so on), and one found ended before a call is replaced before that call uses it; an SFTP error (a missing
    /// file, a denied request) or one request's timeout is not a failure of the session. Calls that
    /// find no session share one call to the factory, so a dropped connection is followed by one reconnect, not one per caller. The
    /// call that meets the dropped connection fails with an <see cref="IOException"/>, unless it only reads (an attribute lookup, a
    /// listing, a whole-file read, opening a file to read): those are tried once more on a new session. A call that writes is not, since
    /// the server may have done it before the connection dropped. If the factory fails, the call fails with an <see cref="IOException"/>
    /// and the next one calls the factory again. Opening a session counts against <see cref="SftpFileSystemOptions.OperationTimeout"/>.
    /// </para>
    /// <para>
    /// The factory opens a session on a connection it manages: the file system disposes the <see cref="SftpClient"/>, never the
    /// connection under it. With the dependency injection package, <c>ct =&gt; connections.OpenSftpAsync("name", ct)</c> opens it on the
    /// shared connection, which is itself opened again when it drops. Streams already open on a failed session fail; open them again.
    /// </para>
    /// </remarks>
    /// <param name="sessionFactory">Opens a new SFTP session; called on first use and after a failure, never concurrently.</param>
    /// <param name="options">Timeouts.</param>
    public SftpFileSystem(Func<CancellationToken, Task<SftpClient>> sessionFactory, SftpFileSystemOptions? options = null)
        : this(new SftpSessions(sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory)), (options ?? new SftpFileSystemOptions()).OperationTimeout), options)
    {
    }

    private SftpFileSystem(SftpSessions sessions, SftpFileSystemOptions? options)
    {
        _sessions = sessions;
        Options = options ?? new SftpFileSystemOptions();
        File = new SftpFile(this);
        Directory = new SftpDirectory(this);
        Path = new SftpPath(this);
        FileInfo = new SftpFileInfoFactory(this);
        DirectoryInfo = new SftpDirectoryInfoFactory(this);
        FileStream = new SftpFileStreamFactory(this);
        DriveInfo = new UnsupportedDriveInfoFactory(this);
        FileSystemWatcher = new UnsupportedFileSystemWatcherFactory(this);
        FileVersionInfo = new UnsupportedFileVersionInfoFactory(this);
        RandomAccess = new UnsupportedRandomAccess(this);
    }

    /// <inheritdoc/>
    public IDirectory Directory { get; }

    /// <inheritdoc/>
    public IDirectoryInfoFactory DirectoryInfo { get; }

    /// <summary>Not supported: SFTP has no drives (every factory method throws <see cref="NotSupportedException"/>).</summary>
    public IDriveInfoFactory DriveInfo { get; }

    /// <inheritdoc/>
    public IFile File { get; }

    /// <inheritdoc/>
    public IFileInfoFactory FileInfo { get; }

    /// <inheritdoc/>
    public IFileStreamFactory FileStream { get; }

    /// <summary>Not supported: SFTP has no change notifications.</summary>
    public IFileSystemWatcherFactory FileSystemWatcher { get; }

    /// <summary>Not supported: version resources would mean reading every file.</summary>
    public IFileVersionInfoFactory FileVersionInfo { get; }

    /// <summary>POSIX path operations (<c>/</c>), for the server's paths.</summary>
    public IPath Path { get; }

    /// <summary>Not supported: it works on OS file handles, which remote files do not have.</summary>
    public IRandomAccess RandomAccess { get; }

    internal SftpFileSystemOptions Options { get; }

    /// <summary>
    /// Disposes the SFTP sessions the file system opened from its session factory; later calls throw <see cref="ObjectDisposedException"/>.
    /// A file system built from one <see cref="SftpClient"/> leaves that session alone: it stays the caller's, and this does nothing.
    /// </summary>
    public ValueTask DisposeAsync() => _sessions.DisposeAsync();

    /// <summary>Disposes the file system as <see cref="DisposeAsync"/> does, waiting for it (on the thread pool, as synchronous calls do).</summary>
    public void Dispose() =>
        Task.Run(() => _sessions.DisposeAsync().AsTask(), CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>The directory relative paths start from: the login directory until <see cref="IDirectory.SetCurrentDirectory"/>.</summary>
    internal string CurrentDirectory
    {
        // Where the server resolves relative paths, as sftp starts. Not the home-directory extension: OpenSSH answers it with the
        // passwd home even in a ChrootDirectory session, where that path does not exist.
        get => _currentDirectory ??= Run(null, false, (sftp, ct) => sftp.GetFullPathAsync(".", ct), retry: true);
        set => _currentDirectory = value;
    }

    /// <summary>The absolute, normalized server path for <paramref name="path"/>.</summary>
    /// <exception cref="ArgumentException">The path is empty or contains NUL.</exception>
    internal string Full(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (path.Contains('\0'))
        {
            throw new ArgumentException("A path must not contain NUL.", nameof(path));
        }

        return RemotePath.Normalize(RemotePath.IsRooted(path) ? path : RemotePath.Join(CurrentDirectory, path));
    }

    /// <summary>The attributes of a path (following links unless <paramref name="follow"/> is false), or null when it does not exist.</summary>
    internal SftpFileAttributes? Stat(string fullPath, bool follow = true)
    {
        try
        {
            return Run(fullPath, false, (sftp, ct) => sftp.GetAttributesAsync(fullPath, follow, ct), retry: true);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <paramref name="path"/> exists (and is a directory, or not one, when <paramref name="directory"/> says so). Never throws,
    /// as <c>File.Exists</c> and <c>Directory.Exists</c> do not: an invalid path, a denied lookup or a failed session reads as false.
    /// </summary>
    internal bool Exists(string? path, bool? directory)
    {
        if (string.IsNullOrEmpty(path) || path.Contains('\0'))
        {
            return false;
        }

        try
        {
            return Stat(Full(path)) is { } attributes && (directory is not { } wanted || attributes.IsDirectory == wanted);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or SshException)
        {
            return false;
        }
    }

    /// <summary>
    /// Runs an SFTP operation to completion for a synchronous caller, on the thread pool (so a synchronization context cannot deadlock
    /// it), bounded by the timeout, with SFTP errors turned into <c>System.IO</c> exceptions about <paramref name="path"/>. The calling
    /// thread waits, so many concurrent synchronous calls hold as many threads; the asynchronous methods do not. The operation runs on
    /// the current session; <paramref name="retry"/> (only for operations that change nothing on the server) tries it once more on a new
    /// session when the connection dropped under it.
    /// </summary>
    internal T Run<T>(string? path, bool directory, Func<SftpClient, CancellationToken, Task<T>> operation, bool retry = false) =>
        RunTransfer(path, directory, (sftp, ct, _) => operation(sftp, ct), retry: retry);

    internal void Run(string? path, bool directory, Func<SftpClient, CancellationToken, Task> operation) =>
        Run<bool>(path, directory, async (sftp, ct) =>
        {
            await operation(sftp, ct).ConfigureAwait(false);
            return true;
        });

    /// <summary>
    /// Like <see cref="Run{T}"/> for a transfer of any length: the timeout limits how long it may go without progress (the operation
    /// reports progress to the <see cref="IProgress{T}"/> it is given), not how long it takes.
    /// </summary>
    internal T RunTransfer<T>(string? path, bool directory, Func<SftpClient, CancellationToken, IProgress<SftpTransferProgress>, Task<T>> operation,
        bool limited = true, bool retry = false)
    {
        // The deadline starts when the work does, on the thread pool: started before queueing it, a busy pool's delay would count
        // against the server, and the operation could find its time used up before it began.
        Deadline? deadline = null;
        try
        {
            return Task.Run(async () =>
            {
                using var started = new Deadline(limited ? Options.OperationTimeout : Timeout.InfiniteTimeSpan, CancellationToken.None);
                deadline = started;
                return await _sessions.RunAsync((sftp, ct) => operation(sftp, ct, started), retry, started.Token).ConfigureAwait(false);
            }, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (Translate(ex, path, directory, deadline?.TimedOut == true) is { } translated)
        {
            throw translated;
        }
    }

    internal void RunTransfer(string? path, bool directory, Func<SftpClient, CancellationToken, IProgress<SftpTransferProgress>, Task> operation, bool limited = true) =>
        RunTransfer<bool>(path, directory, async (sftp, ct, progress) =>
        {
            await operation(sftp, ct, progress).ConfigureAwait(false);
            return true;
        }, limited);

    /// <summary>Runs an asynchronous operation for an asynchronous caller, with the same exceptions as <see cref="Run{T}"/>.</summary>
    internal Task<T> RunAsync<T>(string? path, bool directory, Func<SftpClient, CancellationToken, Task<T>> operation, CancellationToken cancellationToken, bool retry = false) =>
        RunTransferAsync(path, directory, (sftp, ct, _) => operation(sftp, ct), cancellationToken, retry);

    /// <summary>The asynchronous <see cref="RunTransfer{T}"/>: the timeout limits time without progress.</summary>
    internal async Task<T> RunTransferAsync<T>(string? path, bool directory, Func<SftpClient, CancellationToken, IProgress<SftpTransferProgress>, Task<T>> operation,
        CancellationToken cancellationToken, bool retry = false)
    {
        using var deadline = new Deadline(Options.OperationTimeout, cancellationToken);
        try
        {
            return await _sessions.RunAsync((sftp, ct) => operation(sftp, ct, deadline), retry, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (Translate(ex, path, directory, deadline.TimedOut) is { } translated)
        {
            throw translated;
        }
    }

    internal Task RunTransferAsync(string? path, bool directory, Func<SftpClient, CancellationToken, IProgress<SftpTransferProgress>, Task> operation, CancellationToken cancellationToken) =>
        RunTransferAsync<bool>(path, directory, async (sftp, ct, progress) =>
        {
            await operation(sftp, ct, progress).ConfigureAwait(false);
            return true;
        }, cancellationToken);

    /// <summary>A timeout that each progress report restarts, linked to the caller's token; infinite when the timeout is.</summary>
    private sealed class Deadline : IProgress<SftpTransferProgress>, IDisposable
    {
        private readonly CancellationTokenSource _source;
        private readonly CancellationToken _caller;
        private readonly TimeSpan _timeout;

        public Deadline(TimeSpan timeout, CancellationToken caller)
        {
            _timeout = timeout;
            _caller = caller;
            _source = CancellationTokenSource.CreateLinkedTokenSource(caller);
            _source.CancelAfter(timeout);
        }

        public CancellationToken Token => _source.Token;

        /// <summary>Whether the timeout, not the caller, cancelled the operation (still answers once disposed).</summary>
        public bool TimedOut => _source.IsCancellationRequested && !_caller.IsCancellationRequested;

        public void Report(SftpTransferProgress value)
        {
            try
            {
                _source.CancelAfter(_timeout);
            }
            catch (ObjectDisposedException)
            {
                // A late report after the operation ended.
            }
        }

        public void Dispose() => _source.Dispose();
    }

    /// <summary>The <c>System.IO</c> exception for an SFTP or SSH failure; null for exceptions that pass through unchanged.</summary>
    internal static Exception? Translate(Exception ex, string? path, bool directory, bool timedOut) => ex switch
    {
        SftpException { Status: SftpStatusCode.NoSuchFile } sftp => directory
            ? new DirectoryNotFoundException($"Could not find a part of the path '{path ?? sftp.Path}'.", sftp)
            : new FileNotFoundException($"Could not find file '{path ?? sftp.Path}'.", path ?? sftp.Path, sftp),
        SftpException { Status: SftpStatusCode.PermissionDenied } sftp => new UnauthorizedAccessException($"Access to the path '{path ?? sftp.Path}' is denied.", sftp),
        SftpException sftp => new IOException(sftp.Message, sftp),
        OperationCanceledException when timedOut => new IOException("The SFTP server did not answer in time.", ex),
        SshException ssh => new IOException("The SFTP session failed: " + ssh.Message, ssh),
        _ => null,
    };
}

/// <summary>Options for <see cref="SftpFileSystem"/>.</summary>
public sealed class SftpFileSystemOptions
{
    /// <summary>
    /// How long the server may take to answer before the operation fails with an <see cref="IOException"/> (default 60 seconds;
    /// <see cref="Timeout.InfiniteTimeSpan"/> for no limit). For a request it bounds the answer; for a whole-file read, write, copy or
    /// append it bounds the time without progress, so a large file over a slow link is not cut off. A server-side copy
    /// (<c>copy-data</c>) reports no progress and has no limit.
    /// </summary>
    public TimeSpan OperationTimeout
    {
        get;
        init
        {
            if (value != Timeout.InfiniteTimeSpan)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value, TimeSpan.FromMilliseconds(int.MaxValue));
            }

            field = value;
        }
    } = TimeSpan.FromSeconds(60);
}
