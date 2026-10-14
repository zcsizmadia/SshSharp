using System.Diagnostics.CodeAnalysis;
using System.IO.Abstractions;
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
/// </remarks>
[Experimental(SftpClient.ExperimentalId)]
public sealed class SftpFileSystem : IFileSystem
{
    private string? _currentDirectory;

    /// <summary>A file system over <paramref name="sftp"/>.</summary>
    /// <param name="sftp">The SFTP session to use; it stays the caller's to dispose, after the file system is no longer used.</param>
    /// <param name="options">Timeouts.</param>
    public SftpFileSystem(SftpClient sftp, SftpFileSystemOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sftp);
        Sftp = sftp;
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

    internal SftpClient Sftp { get; }

    internal SftpFileSystemOptions Options { get; }

    /// <summary>The directory relative paths start from: the login directory until <see cref="IDirectory.SetCurrentDirectory"/>.</summary>
    internal string CurrentDirectory
    {
        // Where the server resolves relative paths, as sftp starts. Not the home-directory extension: OpenSSH answers it with the
        // passwd home even in a ChrootDirectory session, where that path does not exist.
        get => _currentDirectory ??= Run(null, false, ct => Sftp.GetFullPathAsync(".", ct));
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
            return Run(fullPath, false, ct => Sftp.GetAttributesAsync(fullPath, follow, ct));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Runs an SFTP operation to completion for a synchronous caller, on the thread pool (so a synchronization context cannot deadlock
    /// it), bounded by the timeout, with SFTP errors turned into <c>System.IO</c> exceptions about <paramref name="path"/>.
    /// </summary>
    internal T Run<T>(string? path, bool directory, Func<CancellationToken, Task<T>> operation)
    {
        using var timeout = new CancellationTokenSource(Options.OperationTimeout);
        try
        {
            return Task.Run(() => operation(timeout.Token), CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (Translate(ex, path, directory, timeout.IsCancellationRequested) is { } translated)
        {
            throw translated;
        }
    }

    internal void Run(string? path, bool directory, Func<CancellationToken, Task> operation) =>
        Run<bool>(path, directory, async ct =>
        {
            await operation(ct).ConfigureAwait(false);
            return true;
        });

    /// <summary>Runs an asynchronous operation for an asynchronous caller, with the same exceptions as <see cref="Run{T}"/>.</summary>
    internal async Task<T> RunAsync<T>(string? path, bool directory, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Options.OperationTimeout);
        try
        {
            return await operation(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (Translate(ex, path, directory, timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested) is { } translated)
        {
            throw translated;
        }
    }

    internal Task RunAsync(string? path, bool directory, Func<CancellationToken, Task> operation, CancellationToken cancellationToken) =>
        RunAsync<bool>(path, directory, async ct =>
        {
            await operation(ct).ConfigureAwait(false);
            return true;
        }, cancellationToken);

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
[Experimental(SftpClient.ExperimentalId)]
public sealed class SftpFileSystemOptions
{
    /// <summary>How long one operation may take before it fails with an <see cref="IOException"/> (default 60 seconds).</summary>
    public TimeSpan OperationTimeout
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            field = value;
        }
    } = TimeSpan.FromSeconds(60);
}
