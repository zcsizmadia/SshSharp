using Microsoft.Extensions.FileProviders;
using SshSharp.Sftp;

namespace SshSharp.FileProviders;

/// <summary>A file or directory that exists on the server, as <see cref="SftpFileProvider"/> serves it.</summary>
internal sealed class SftpProviderFileInfo(SftpFileProvider provider, string path, string name, SftpFileAttributes attributes) : IFileInfo
{
    public bool Exists => true;

    /// <summary>The size in bytes; -1 for a directory, as the contract asks.</summary>
    public long Length => IsDirectory ? -1 : attributes.Size ?? -1;

    /// <summary>Null: the file is on another machine.</summary>
    public string? PhysicalPath => null;

    public string Name { get; } = name;

    public DateTimeOffset LastModified => attributes.LastWriteTime ?? DateTimeOffset.MinValue;

    public bool IsDirectory => attributes.IsDirectory;

    /// <summary>The server path, for diagnostics.</summary>
    public string RemotePath => path;

    /// <exception cref="InvalidOperationException">This is a directory.</exception>
    public Stream CreateReadStream() => IsDirectory
        ? throw new InvalidOperationException($"'{path}' is a directory.")
        : provider.OpenRead(path, attributes.Size ?? -1);
}
