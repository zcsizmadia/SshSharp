using System.IO.Abstractions;
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

    protected SftpFileSystemInfo(SftpFileSystem fileSystem, string path, SftpFileAttributes? known = null)
    {
        Fs = fileSystem;
        OriginalPath = path;
        FullName = fileSystem.Full(path);
        if (known is not null)
        {
            _own = _attributes = known;
            _loaded = true;
        }
    }

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
            return _own is { IsSymbolicLink: true } ? Fs.Run(FullName, false, ct => Fs.Sftp.ReadSymbolicLinkAsync(FullName, ct)) : null;
        }
    }

    public UnixFileMode UnixFileMode
    {
        get => Current?.Permissions ?? (UnixFileMode)(-1);
        set
        {
            Fs.Run(FullName, false, ct => Fs.Sftp.SetAttributesAsync(FullName, new SftpFileAttributes { Permissions = value }, ct));
            Refresh();
        }
    }

    protected SftpFileSystem Fs { get; }

    protected string OriginalPath { get; set; }

    /// <summary>The attributes (of what a link points to), or null when the path does not exist.</summary>
    protected SftpFileAttributes? Current
    {
        get
        {
            Load();
            return _attributes;
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

        _own = Fs.Stat(FullName, follow: false);
        _attributes = _own is { IsSymbolicLink: true } ? Fs.Stat(FullName) : _own;
        _loaded = true;
    }
}
