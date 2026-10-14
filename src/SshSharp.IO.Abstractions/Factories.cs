using System.IO.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace SshSharp.IO.Abstractions;

internal sealed class SftpFileInfoFactory(SftpFileSystem fileSystem) : IFileInfoFactory
{
    public IFileSystem FileSystem => fileSystem;

    public IFileInfo New(string fileName) => new SftpFileInfoEntry(fileSystem, fileName);

    /// <summary>Not supported: a local <see cref="FileInfo"/> describes a file on this machine, not on the server.</summary>
    public IFileInfo? Wrap(FileInfo? fileInfo) => throw new NotSupportedException("A local FileInfo cannot describe a file on the SFTP server.");
}

internal sealed class SftpDirectoryInfoFactory(SftpFileSystem fileSystem) : IDirectoryInfoFactory
{
    public IFileSystem FileSystem => fileSystem;

    public IDirectoryInfo New(string path) => new SftpDirectoryInfoEntry(fileSystem, path);

    /// <summary>Not supported: a local <see cref="DirectoryInfo"/> describes a directory on this machine, not on the server.</summary>
    public IDirectoryInfo? Wrap(DirectoryInfo? directoryInfo) => throw new NotSupportedException("A local DirectoryInfo cannot describe a directory on the SFTP server.");
}

internal sealed class SftpFileStreamFactory(SftpFileSystem fileSystem) : IFileStreamFactory
{
    public IFileSystem FileSystem => fileSystem;

    public FileSystemStream New(string path, FileMode mode) => fileSystem.File.Open(path, mode);

    public FileSystemStream New(string path, FileMode mode, FileAccess access) => fileSystem.File.Open(path, mode, access);

    public FileSystemStream New(string path, FileMode mode, FileAccess access, FileShare share) => fileSystem.File.Open(path, mode, access);

    public FileSystemStream New(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize) =>
        SftpFileSystemStream.Open(fileSystem, path, mode, access, bufferSize);

    public FileSystemStream New(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync) =>
        SftpFileSystemStream.Open(fileSystem, path, mode, access, bufferSize);

    public FileSystemStream New(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, FileOptions options) =>
        SftpFileSystemStream.Open(fileSystem, path, mode, access, bufferSize);

    public FileSystemStream New(string path, FileStreamOptions options) => fileSystem.File.Open(path, options);

    public FileSystemStream New(SafeFileHandle handle, FileAccess access) => throw Unsupported.Handles();

    public FileSystemStream New(SafeFileHandle handle, FileAccess access, int bufferSize) => throw Unsupported.Handles();

    public FileSystemStream New(SafeFileHandle handle, FileAccess access, int bufferSize, bool isAsync) => throw Unsupported.Handles();

    /// <summary>Not supported: a local <see cref="FileStream"/> is a file on this machine, not on the server.</summary>
    public FileSystemStream Wrap(FileStream fileStream) => throw new NotSupportedException("A local FileStream cannot be a file on the SFTP server.");
}

internal sealed class UnsupportedDriveInfoFactory(SftpFileSystem fileSystem) : IDriveInfoFactory
{
    public IFileSystem FileSystem => fileSystem;

    public IDriveInfo[] GetDrives() => throw Drives();

    public IDriveInfo New(string driveName) => throw Drives();

    public IDriveInfo? Wrap(DriveInfo? driveInfo) => throw Drives();

    private static NotSupportedException Drives() => new("SFTP servers have no drives; use SftpClient.GetFileSystemInfoAsync for space.");
}

internal sealed class UnsupportedFileSystemWatcherFactory(SftpFileSystem fileSystem) : IFileSystemWatcherFactory
{
    public IFileSystem FileSystem => fileSystem;

    public IFileSystemWatcher New() => throw Watchers();

    public IFileSystemWatcher New(string path) => throw Watchers();

    public IFileSystemWatcher New(string path, string filter) => throw Watchers();

    public IFileSystemWatcher? Wrap(FileSystemWatcher? fileSystemWatcher) => throw Watchers();

    private static NotSupportedException Watchers() => new("SFTP has no change notifications.");
}

internal sealed class UnsupportedFileVersionInfoFactory(SftpFileSystem fileSystem) : IFileVersionInfoFactory
{
    public IFileSystem FileSystem => fileSystem;

    public IFileVersionInfo GetVersionInfo(string fileName) => throw new NotSupportedException("Version information is not read over SFTP.");
}

internal sealed class UnsupportedRandomAccess(SftpFileSystem fileSystem) : IRandomAccess
{
    public IFileSystem FileSystem => fileSystem;

    public void FlushToDisk(SafeFileHandle handle) => throw Unsupported.Handles();

    public long GetLength(SafeFileHandle handle) => throw Unsupported.Handles();

    public int Read(SafeFileHandle handle, Span<byte> buffer, long fileOffset) => throw Unsupported.Handles();

    public long Read(SafeFileHandle handle, IReadOnlyList<Memory<byte>> buffers, long fileOffset) => throw Unsupported.Handles();

    public ValueTask<int> ReadAsync(SafeFileHandle handle, Memory<byte> buffer, long fileOffset, CancellationToken cancellationToken = default) => throw Unsupported.Handles();

    public ValueTask<long> ReadAsync(SafeFileHandle handle, IReadOnlyList<Memory<byte>> buffers, long fileOffset, CancellationToken cancellationToken = default) =>
        throw Unsupported.Handles();

    public void SetLength(SafeFileHandle handle, long length) => throw Unsupported.Handles();

    public void Write(SafeFileHandle handle, ReadOnlySpan<byte> buffer, long fileOffset) => throw Unsupported.Handles();

    public void Write(SafeFileHandle handle, IReadOnlyList<ReadOnlyMemory<byte>> buffers, long fileOffset) => throw Unsupported.Handles();

    public ValueTask WriteAsync(SafeFileHandle handle, ReadOnlyMemory<byte> buffer, long fileOffset, CancellationToken cancellationToken = default) => throw Unsupported.Handles();

    public ValueTask WriteAsync(SafeFileHandle handle, IReadOnlyList<ReadOnlyMemory<byte>> buffers, long fileOffset, CancellationToken cancellationToken = default) =>
        throw Unsupported.Handles();
}
