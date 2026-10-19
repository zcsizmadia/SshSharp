using System.IO.Abstractions;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary><see cref="IDirectory"/> over SFTP, with a client-side current directory.</summary>
internal sealed class SftpDirectory(SftpFileSystem fileSystem) : IDirectory
{
    public IFileSystem FileSystem => fileSystem;

    // ---- create, delete, move ----

    /// <summary>Creates the directory and any missing parents; an existing directory is fine, an existing file is an error.</summary>
    public IDirectoryInfo CreateDirectory(string path) => CreateDirectory(path, null);

    public IDirectoryInfo CreateDirectory(string path, UnixFileMode unixCreateMode) => CreateDirectory(path, (UnixFileMode?)unixCreateMode);

    private IDirectoryInfo CreateDirectory(string path, UnixFileMode? mode)
    {
        var full = fileSystem.Full(path);
        var current = string.Empty;
        foreach (var part in full.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            current += "/" + part;
            switch (fileSystem.Stat(current))
            {
                case { IsDirectory: true }:
                    continue;
                case { }:
                    throw new IOException($"'{current}' exists and is not a directory.");
                default:
                    var target = current;
                    try
                    {
                        fileSystem.Run(target, true, (sftp, ct) => sftp.CreateDirectoryAsync(target, mode, ct));
                    }
                    catch (IOException) when (fileSystem.Stat(target) is { IsDirectory: true })
                    {
                        // Created by someone else meanwhile.
                    }

                    break;
            }
        }

        return fileSystem.DirectoryInfo.New(path);
    }

    public IDirectoryInfo CreateTempSubdirectory(string? prefix = null)
    {
        var path = "/tmp/" + (prefix ?? string.Empty) + fileSystem.Path.GetRandomFileName().Replace(".", string.Empty, StringComparison.Ordinal);
        fileSystem.Run(path, true, (sftp, ct) => sftp.CreateDirectoryAsync(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, ct));
        return fileSystem.DirectoryInfo.New(path);
    }

    public void Delete(string path) => Delete(path, recursive: false);

    /// <summary>Deletes a directory; with <paramref name="recursive"/> everything in it first (links are removed, not followed).</summary>
    public void Delete(string path, bool recursive)
    {
        var full = fileSystem.Full(path);
        if (fileSystem.Stat(full, follow: false) is not { IsDirectory: true })
        {
            throw new DirectoryNotFoundException($"Could not find a part of the path '{path}'.");
        }

        if (recursive)
        {
            DeleteTree(full);
        }
        else
        {
            fileSystem.Run(full, true, (sftp, ct) => sftp.DeleteDirectoryAsync(full, ct));
        }
    }

    private void DeleteTree(string full)
    {
        var entries = fileSystem.Run(full, true, async (sftp, ct) =>
        {
            var list = new List<SftpFileInfo>();
            await foreach (var entry in sftp.ListDirectoryAsync(full, ct).ConfigureAwait(false))
            {
                list.Add(entry);
            }

            return list;
        }, retry: true);
        foreach (var entry in entries)
        {
            var child = RemotePath.Join(full, entry.Name);
            if (entry.Attributes.IsDirectory)
            {
                DeleteTree(child);
            }
            else
            {
                fileSystem.Run(child, false, (sftp, ct) => sftp.DeleteFileAsync(child, ct));
            }
        }

        fileSystem.Run(full, true, (sftp, ct) => sftp.DeleteDirectoryAsync(full, ct));
    }

    public void Move(string sourceDirName, string destDirName)
    {
        var source = fileSystem.Full(sourceDirName);
        var destination = fileSystem.Full(destDirName);
        if (fileSystem.Stat(source, follow: false) is null)
        {
            throw new DirectoryNotFoundException($"Could not find a part of the path '{sourceDirName}'.");
        }

        if (fileSystem.Stat(destination, follow: false) is not null)
        {
            throw new IOException($"Cannot create '{destDirName}' because a file or directory with the same name already exists.");
        }

        fileSystem.Run(destination, true, (sftp, ct) => sftp.RenameAsync(source, destination, overwrite: false, ct));
    }

    /// <summary>Whether a directory exists; never throws (an invalid path, a denied lookup or a failed session reads as false).</summary>
    public bool Exists(string? path) => fileSystem.Exists(path, directory: true);

    // ---- enumeration ----

    public IEnumerable<string> EnumerateDirectories(string path) => Enumerate(path, "*", Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Directories);

    public IEnumerable<string> EnumerateDirectories(string path, string searchPattern) => Enumerate(path, searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Directories);

    public IEnumerable<string> EnumerateDirectories(string path, string searchPattern, SearchOption searchOption) => Enumerate(path, searchPattern, Search.Legacy(searchOption), Search.Kind.Directories);

    public IEnumerable<string> EnumerateDirectories(string path, string searchPattern, EnumerationOptions enumerationOptions) => Enumerate(path, searchPattern, enumerationOptions, Search.Kind.Directories);

    public IEnumerable<string> EnumerateFiles(string path) => Enumerate(path, "*", Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Files);

    public IEnumerable<string> EnumerateFiles(string path, string searchPattern) => Enumerate(path, searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Files);

    public IEnumerable<string> EnumerateFiles(string path, string searchPattern, SearchOption searchOption) => Enumerate(path, searchPattern, Search.Legacy(searchOption), Search.Kind.Files);

    public IEnumerable<string> EnumerateFiles(string path, string searchPattern, EnumerationOptions enumerationOptions) => Enumerate(path, searchPattern, enumerationOptions, Search.Kind.Files);

    public IEnumerable<string> EnumerateFileSystemEntries(string path) => Enumerate(path, "*", Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Both);

    public IEnumerable<string> EnumerateFileSystemEntries(string path, string searchPattern) => Enumerate(path, searchPattern, Search.Legacy(SearchOption.TopDirectoryOnly), Search.Kind.Both);

    public IEnumerable<string> EnumerateFileSystemEntries(string path, string searchPattern, SearchOption searchOption) => Enumerate(path, searchPattern, Search.Legacy(searchOption), Search.Kind.Both);

    public IEnumerable<string> EnumerateFileSystemEntries(string path, string searchPattern, EnumerationOptions enumerationOptions) => Enumerate(path, searchPattern, enumerationOptions, Search.Kind.Both);

    public string[] GetDirectories(string path) => [.. EnumerateDirectories(path)];

    public string[] GetDirectories(string path, string searchPattern) => [.. EnumerateDirectories(path, searchPattern)];

    public string[] GetDirectories(string path, string searchPattern, SearchOption searchOption) => [.. EnumerateDirectories(path, searchPattern, searchOption)];

    public string[] GetDirectories(string path, string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateDirectories(path, searchPattern, enumerationOptions)];

    public string[] GetFiles(string path) => [.. EnumerateFiles(path)];

    public string[] GetFiles(string path, string searchPattern) => [.. EnumerateFiles(path, searchPattern)];

    public string[] GetFiles(string path, string searchPattern, SearchOption searchOption) => [.. EnumerateFiles(path, searchPattern, searchOption)];

    public string[] GetFiles(string path, string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateFiles(path, searchPattern, enumerationOptions)];

    public string[] GetFileSystemEntries(string path) => [.. EnumerateFileSystemEntries(path)];

    public string[] GetFileSystemEntries(string path, string searchPattern) => [.. EnumerateFileSystemEntries(path, searchPattern)];

    public string[] GetFileSystemEntries(string path, string searchPattern, SearchOption searchOption) => [.. EnumerateFileSystemEntries(path, searchPattern, searchOption)];

    public string[] GetFileSystemEntries(string path, string searchPattern, EnumerationOptions enumerationOptions) => [.. EnumerateFileSystemEntries(path, searchPattern, enumerationOptions)];

    /// <summary>The paths of the matching entries, each the given path joined with the entry's name, as <c>Directory.Enumerate*</c> returns them.</summary>
    private IEnumerable<string> Enumerate(string path, string searchPattern, EnumerationOptions options, Search.Kind kind) =>
        Search.Entries(fileSystem, path, searchPattern, options, kind).Select(e => e.Path);

    // ---- current directory and roots ----

    public string GetCurrentDirectory() => fileSystem.CurrentDirectory;

    /// <summary>Changes the directory relative paths start from (kept here; the server has no working directory for SFTP).</summary>
    public void SetCurrentDirectory(string path)
    {
        var full = fileSystem.Full(path);
        if (fileSystem.Stat(full) is not { IsDirectory: true })
        {
            throw new DirectoryNotFoundException($"Could not find a part of the path '{path}'.");
        }

        fileSystem.CurrentDirectory = full;
    }

    public string GetDirectoryRoot(string path)
    {
        fileSystem.Full(path);
        return "/";
    }

    public string[] GetLogicalDrives() => ["/"];

    public IDirectoryInfo? GetParent(string path)
    {
        var full = fileSystem.Full(path);
        var parent = RemotePath.DirectoryName(full, out var isRoot);
        return isRoot ? null : fileSystem.DirectoryInfo.New(parent.ToString());
    }

    // ---- times and links ----

    public DateTime GetCreationTime(string path) => GetLastWriteTime(path);

    public DateTime GetCreationTimeUtc(string path) => GetLastWriteTimeUtc(path);

    public DateTime GetLastAccessTime(string path) => Times.Get(fileSystem, path, write: false).ToLocalTime();

    public DateTime GetLastAccessTimeUtc(string path) => Times.Get(fileSystem, path, write: false);

    public DateTime GetLastWriteTime(string path) => Times.Get(fileSystem, path, write: true).ToLocalTime();

    public DateTime GetLastWriteTimeUtc(string path) => Times.Get(fileSystem, path, write: true);

    /// <summary>Does nothing: SFTP has no creation times.</summary>
    public void SetCreationTime(string path, DateTime creationTime) => fileSystem.Full(path);

    /// <summary>Does nothing: SFTP has no creation times.</summary>
    public void SetCreationTimeUtc(string path, DateTime creationTimeUtc) => fileSystem.Full(path);

    public void SetLastAccessTime(string path, DateTime lastAccessTime) => Times.Set(fileSystem, path, lastAccessTime.ToUniversalTime(), write: false);

    public void SetLastAccessTimeUtc(string path, DateTime lastAccessTimeUtc) => Times.Set(fileSystem, path, lastAccessTimeUtc, write: false);

    public void SetLastWriteTime(string path, DateTime lastWriteTime) => Times.Set(fileSystem, path, lastWriteTime.ToUniversalTime(), write: true);

    public void SetLastWriteTimeUtc(string path, DateTime lastWriteTimeUtc) => Times.Set(fileSystem, path, lastWriteTimeUtc, write: true);

    public IFileSystemInfo CreateSymbolicLink(string path, string pathToTarget)
    {
        ArgumentException.ThrowIfNullOrEmpty(pathToTarget);
        var full = fileSystem.Full(path);
        fileSystem.Run(full, true, (sftp, ct) => sftp.CreateSymbolicLinkAsync(full, pathToTarget, ct));
        return fileSystem.DirectoryInfo.New(path);
    }

    public IFileSystemInfo? ResolveLinkTarget(string linkPath, bool returnFinalTarget) => Links.Resolve(fileSystem, linkPath, returnFinalTarget, directory: true);
}
