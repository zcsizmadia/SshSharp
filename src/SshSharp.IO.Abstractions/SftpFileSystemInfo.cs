using System.IO.Abstractions;
using System.Runtime.ExceptionServices;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary>
/// What <see cref="IFileInfo"/> and <see cref="IDirectoryInfo"/> share. Attributes are read on first use and kept until
/// <see cref="Refresh"/>, as <c>FileSystemInfo</c> does; entries from an enumeration start with the listing's attributes.
/// </summary>
internal abstract class SftpFileSystemInfo : IFileSystemInfo
{
    private SftpFileAttributes? _own;
    private SftpFileAttributes? _attributes;
    private bool _loaded;
    private ExceptionDispatchInfo? _error;

    protected SftpFileSystemInfo(SftpFileSystem fileSystem, string path, KnownAttributes? known = null)
    {
        Fs = fileSystem;
        OriginalPath = path;
        FullName = fileSystem.Full(path);
        if (known is { } attributes)
        {
            _own = attributes.Own;
            _attributes = attributes.Current;
            _loaded = true;
        }
    }

    /// <summary>
    /// Attributes already known from a listing: the entry's own (a link's are the link's) and the current ones (what a link points to,
    /// null for a link that leads nowhere; the same as <see cref="Own"/> for anything else).
    /// </summary>
    internal readonly record struct KnownAttributes(SftpFileAttributes Own, SftpFileAttributes? Current);

    public IFileSystem FileSystem => Fs;

    public string FullName { get; protected set; }

    public string Name => FullName == "/" ? "/" : RemotePath.FileName(FullName).ToString();

    public string Extension => RemotePath.Extension(FullName).ToString();

    public abstract bool Exists { get; }

    /// <summary>The attributes; <c>-1</c> (all bits) when the path does not exist, as <c>FileSystemInfo.Attributes</c> reads then.</summary>
    public FileAttributes Attributes
    {
        get
        {
            Load();
            _error?.Throw();
            return _own is null ? (FileAttributes)(-1) : IO.Abstractions.Attributes.From(_own, Name, _own.IsSymbolicLink ? _attributes : null);
        }
        set
        {
            IO.Abstractions.Attributes.Set(Fs, FullName, value);
            Refresh();
        }
    }

    /// <summary>The last write time: SFTP has no creation times. Setting it does nothing.</summary>
    public DateTime CreationTime
    {
        get => LastWriteTime;
        set { }
    }

    /// <summary>The last write time: SFTP has no creation times. Setting it does nothing.</summary>
    public DateTime CreationTimeUtc
    {
        get => LastWriteTimeUtc;
        set { }
    }

    public DateTime LastAccessTime
    {
        get => LastAccessTimeUtc.ToLocalTime();
        set => LastAccessTimeUtc = value.ToUniversalTime();
    }

    public DateTime LastAccessTimeUtc
    {
        get => Current?.LastAccessTime?.UtcDateTime ?? Times.Missing;
        set
        {
            Times.Set(Fs, FullName, value, write: false);
            Refresh();
        }
    }

    public DateTime LastWriteTime
    {
        get => LastWriteTimeUtc.ToLocalTime();
        set => LastWriteTimeUtc = value.ToUniversalTime();
    }

    public DateTime LastWriteTimeUtc
    {
        get => Current?.LastWriteTime?.UtcDateTime ?? Times.Missing;
        set
        {
            Times.Set(Fs, FullName, value, write: true);
            Refresh();
        }
    }

    /// <summary>What a symbolic link points to, as stored; null when this is not a link.</summary>
    public string? LinkTarget
    {
        get
        {
            Load();
            _error?.Throw();
            return _own is { IsSymbolicLink: true } ? Fs.Run(FullName, false, (sftp, ct) => sftp.ReadSymbolicLinkAsync(FullName, ct), retry: true) : null;
        }
    }

    public UnixFileMode UnixFileMode
    {
        get => Current?.Permissions ?? (UnixFileMode)(-1);
        set
        {
            Fs.Run(FullName, false, (sftp, ct) => sftp.SetAttributesAsync(FullName, new SftpFileAttributes { Permissions = value }, ct));
            Refresh();
        }
    }

    protected SftpFileSystem Fs { get; }

    protected string OriginalPath { get; set; }

    /// <summary>The attributes (of what a link points to), or null when the path does not exist.</summary>
    /// <exception cref="IOException">The server could not be asked (the error is kept until <see cref="Refresh"/>).</exception>
    protected SftpFileAttributes? Current
    {
        get
        {
            Load();
            _error?.Throw();
            return _attributes;
        }
    }

    /// <summary>Like <see cref="Current"/>, but null instead of an error, for <see cref="Exists"/>, which never throws.</summary>
    protected SftpFileAttributes? CurrentOrNull
    {
        get
        {
            Load();
            return _error is null ? _attributes : null;
        }
    }

    public abstract void CreateAsSymbolicLink(string pathToTarget);

    public abstract void Delete();

    public void Refresh() => _loaded = false;

    public abstract IFileSystemInfo? ResolveLinkTarget(bool returnFinalTarget);

    public override string ToString() => OriginalPath;

    private void Load()
    {
        if (_loaded)
        {
            return;
        }

        // As FileSystemInfo does: an error is kept, Exists reads false, and the other members throw it.
        try
        {
            _own = Fs.Stat(FullName, follow: false);
            _attributes = _own is { IsSymbolicLink: true } ? Fs.Stat(FullName) : _own;
            _error = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _own = _attributes = null;
            _error = ExceptionDispatchInfo.Capture(ex);
        }

        _loaded = true;
    }
}
