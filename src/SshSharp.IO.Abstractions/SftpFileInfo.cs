using System.IO.Abstractions;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary><see cref="IFileInfo"/> for a server path.</summary>
internal sealed class SftpFileInfoEntry(SftpFileSystem fileSystem, string path, SftpFileAttributes? known = null)
    : SftpFileSystemInfo(fileSystem, path, known), IFileInfo
{
    public override bool Exists => Current is { IsDirectory: false };

    public long Length => Current is { IsDirectory: false } attributes
        ? attributes.Size ?? 0
        : throw new FileNotFoundException($"Could not find file '{FullName}'.", FullName);

    public string? DirectoryName => Fs.Path.GetDirectoryName(FullName);

    public IDirectoryInfo? Directory => DirectoryName is { } directory ? Fs.DirectoryInfo.New(directory) : null;

    public bool IsReadOnly
    {
        get => (Attributes & FileAttributes.ReadOnly) != 0 && Exists;
        set => Attributes = value ? Attributes | FileAttributes.ReadOnly : Attributes & ~FileAttributes.ReadOnly;
    }

    public StreamWriter AppendText() => Fs.File.AppendText(FullName);

    public StreamWriter CreateText() => Fs.File.CreateText(FullName);

    public StreamReader OpenText() => Fs.File.OpenText(FullName);

    public FileSystemStream Create() => Fs.File.Create(FullName);

    public FileSystemStream Open(FileMode mode) => Fs.File.Open(FullName, mode);

    public FileSystemStream Open(FileMode mode, FileAccess access) => Fs.File.Open(FullName, mode, access);

    public FileSystemStream Open(FileMode mode, FileAccess access, FileShare share) => Fs.File.Open(FullName, mode, access, share);

    public FileSystemStream Open(FileStreamOptions options) => Fs.File.Open(FullName, options);

    public FileSystemStream OpenRead() => Fs.File.OpenRead(FullName);

    public FileSystemStream OpenWrite() => Fs.File.OpenWrite(FullName);

    public IFileInfo CopyTo(string destFileName) => CopyTo(destFileName, overwrite: false);

    public IFileInfo CopyTo(string destFileName, bool overwrite)
    {
        Fs.File.Copy(FullName, destFileName, overwrite);
        return Fs.FileInfo.New(destFileName);
    }

    public void MoveTo(string destFileName) => MoveTo(destFileName, overwrite: false);

    /// <summary>Moves the file; this object then describes it at its new path, as <c>FileInfo.MoveTo</c> does.</summary>
    public void MoveTo(string destFileName, bool overwrite)
    {
        Fs.File.Move(FullName, destFileName, overwrite);
        FullName = Fs.Full(destFileName);
        OriginalPath = destFileName;
        Refresh();
    }

    public IFileInfo Replace(string destinationFileName, string? destinationBackupFileName) => throw Unsupported.Replace();

    public IFileInfo Replace(string destinationFileName, string? destinationBackupFileName, bool ignoreMetadataErrors) => throw Unsupported.Replace();

    public void Decrypt() => throw Unsupported.Encryption();

    public void Encrypt() => throw Unsupported.Encryption();

    public override void CreateAsSymbolicLink(string pathToTarget)
    {
        Fs.File.CreateSymbolicLink(FullName, pathToTarget);
        Refresh();
    }

    public override void Delete()
    {
        Fs.File.Delete(FullName);
        Refresh();
    }

    public override IFileSystemInfo? ResolveLinkTarget(bool returnFinalTarget) => Fs.File.ResolveLinkTarget(FullName, returnFinalTarget);
}

/// <summary><see cref="IDirectoryInfo"/> for a server path.</summary>
internal sealed class SftpDirectoryInfoEntry(SftpFileSystem fileSystem, string path, SftpFileAttributes? known = null)
    : SftpFileSystemInfo(fileSystem, path, known), IDirectoryInfo
{
    public override bool Exists => Current is { IsDirectory: true };

    public IDirectoryInfo? Parent => Fs.Directory.GetParent(FullName);

    public IDirectoryInfo Root => Fs.DirectoryInfo.New("/");

    public void Create()
    {
        Fs.Directory.CreateDirectory(FullName);
        Refresh();
    }

    public IDirectoryInfo CreateSubdirectory(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (RemotePath.IsRooted(path))
        {
            throw new ArgumentException("The subdirectory must be a relative path.", nameof(path));
        }

        var full = Fs.Full(RemotePath.Join(FullName, path));
        if (!full.StartsWith(FullName == "/" ? "/" : FullName + "/", StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{path}' is not a subdirectory of '{FullName}'.", nameof(path));
        }

        return Fs.Directory.CreateDirectory(full);
    }

    public override void Delete() => Delete(recursive: false);

    public void Delete(bool recursive)
    {
        Fs.Directory.Delete(FullName, recursive);
        Refresh();
    }

    public void MoveTo(string destDirName)
    {
        Fs.Directory.Move(FullName, destDirName);
        FullName = Fs.Full(destDirName);
        OriginalPath = destDirName;
        Refresh();
    }

    public IEnumerable<IDirectoryInfo> EnumerateDirectories() => Directories("*", Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IDirectoryInfo> EnumerateDirectories(string searchPattern) => Directories(searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IDirectoryInfo> EnumerateDirectories(string searchPattern, SearchOption searchOption) => Directories(searchPattern, Search.Legacy(searchOption));

    public IEnumerable<IDirectoryInfo> EnumerateDirectories(string searchPattern, EnumerationOptions enumerationOptions) => Directories(searchPattern, enumerationOptions);

    public IEnumerable<IFileInfo> EnumerateFiles() => Files("*", Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IFileInfo> EnumerateFiles(string searchPattern) => Files(searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IFileInfo> EnumerateFiles(string searchPattern, SearchOption searchOption) => Files(searchPattern, Search.Legacy(searchOption));

    public IEnumerable<IFileInfo> EnumerateFiles(string searchPattern, EnumerationOptions enumerationOptions) => Files(searchPattern, enumerationOptions);

    public IEnumerable<IFileSystemInfo> EnumerateFileSystemInfos() => Infos("*", Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IFileSystemInfo> EnumerateFileSystemInfos(string searchPattern) => Infos(searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly));

    public IEnumerable<IFileSystemInfo> EnumerateFileSystemInfos(string searchPattern, SearchOption searchOption) => Infos(searchPattern, Search.Legacy(searchOption));

    public IEnumerable<IFileSystemInfo> EnumerateFileSystemInfos(string searchPattern, EnumerationOptions enumerationOptions) => Infos(searchPattern, enumerationOptions);

    public IDirectoryInfo[] GetDirectories() => [.. EnumerateDirectories()];

    public IDirectoryInfo[] GetDirectories(string searchPattern) => [.. EnumerateDirectories(searchPattern)];

    public IDirectoryInfo[] GetDirectories(string searchPattern, SearchOption searchOption) => [.. EnumerateDirectories(searchPattern, searchOption)];

    public IDirectoryInfo[] GetDirectories(string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateDirectories(searchPattern, enumerationOptions)];

    public IFileInfo[] GetFiles() => [.. EnumerateFiles()];

    public IFileInfo[] GetFiles(string searchPattern) => [.. EnumerateFiles(searchPattern)];

    public IFileInfo[] GetFiles(string searchPattern, SearchOption searchOption) => [.. EnumerateFiles(searchPattern, searchOption)];

    public IFileInfo[] GetFiles(string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateFiles(searchPattern, enumerationOptions)];

    public IFileSystemInfo[] GetFileSystemInfos() => [.. EnumerateFileSystemInfos()];

    public IFileSystemInfo[] GetFileSystemInfos(string searchPattern) => [.. EnumerateFileSystemInfos(searchPattern)];

    public IFileSystemInfo[] GetFileSystemInfos(string searchPattern, SearchOption searchOption) => [.. EnumerateFileSystemInfos(searchPattern, searchOption)];

    public IFileSystemInfo[] GetFileSystemInfos(string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateFileSystemInfos(searchPattern, enumerationOptions)];

    public override void CreateAsSymbolicLink(string pathToTarget)
    {
        Fs.Directory.CreateSymbolicLink(FullName, pathToTarget);
        Refresh();
    }

    public override IFileSystemInfo? ResolveLinkTarget(bool returnFinalTarget) => Fs.Directory.ResolveLinkTarget(FullName, returnFinalTarget);

    private IEnumerable<IDirectoryInfo> Directories(string pattern, EnumerationOptions options) =>
        Search.Entries(Fs, FullName, pattern, options, Search.Kind.Directories).Select(e => (IDirectoryInfo)new SftpDirectoryInfoEntry(Fs, e.FullPath, e.Attributes));

    private IEnumerable<IFileInfo> Files(string pattern, EnumerationOptions options) =>
        Search.Entries(Fs, FullName, pattern, options, Search.Kind.Files).Select(e => (IFileInfo)new SftpFileInfoEntry(Fs, e.FullPath, e.Attributes));

    private IEnumerable<IFileSystemInfo> Infos(string pattern, EnumerationOptions options) =>
        Search.Entries(Fs, FullName, pattern, options, Search.Kind.Both).Select(e => e.IsDirectory
            ? (IFileSystemInfo)new SftpDirectoryInfoEntry(Fs, e.FullPath, e.Attributes)
            : new SftpFileInfoEntry(Fs, e.FullPath, e.Attributes));
}
