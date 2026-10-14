using System.IO.Abstractions;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary><see cref="FileAttributes"/> from SFTP attributes, as .NET reports them on Unix.</summary>
internal static class Attributes
{
    private const UnixFileMode WriteBits = UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    /// <summary>The attributes of a path (a link itself, as <c>File.GetAttributes</c> does), or null when it does not exist.</summary>
    public static FileAttributes? Of(SftpFileSystem fileSystem, string path)
    {
        var full = fileSystem.Full(path);
        return fileSystem.Stat(full, follow: false) is { } own ? From(own, RemotePath.FileName(full), own.IsSymbolicLink ? fileSystem.Stat(full) : null) : null;
    }

    /// <summary>
    /// Directory or Normal; ReadOnly when the owner cannot write; Hidden for names starting with a dot; ReparsePoint for a symbolic link
    /// (and Directory when it points to one).
    /// </summary>
    public static FileAttributes From(SftpFileAttributes attributes, ReadOnlySpan<char> name, SftpFileAttributes? target = null)
    {
        FileAttributes result = 0;
        if (attributes.IsDirectory || target is { IsDirectory: true })
        {
            result |= FileAttributes.Directory;
        }

        if (attributes.IsSymbolicLink)
        {
            result |= FileAttributes.ReparsePoint;
        }

        if (attributes.Permissions is { } mode && (mode & UnixFileMode.UserWrite) == 0 && !attributes.IsSymbolicLink)
        {
            result |= FileAttributes.ReadOnly;
        }

        if (name.Length > 1 && name[0] == '.' && name is not "..")
        {
            result |= FileAttributes.Hidden;
        }

        return result == 0 ? FileAttributes.Normal : result;
    }

    /// <summary>Only ReadOnly can be changed: it removes or restores the owner's write permission (the others are ignored, as on Unix).</summary>
    public static void Set(SftpFileSystem fileSystem, string path, FileAttributes attributes)
    {
        var full = fileSystem.Full(path);
        var current = fileSystem.Stat(full) ?? throw new FileNotFoundException($"Could not find file '{path}'.", path);
        var mode = current.Permissions ?? UnixFileMode.None;
        var wanted = (attributes & FileAttributes.ReadOnly) != 0 ? mode & ~WriteBits : mode | UnixFileMode.UserWrite;
        if (wanted != mode)
        {
            fileSystem.Run(full, false, ct => fileSystem.Sftp.SetAttributesAsync(full, new SftpFileAttributes { Permissions = wanted }, ct));
        }
    }
}

/// <summary>Times as <c>File</c> and <c>Directory</c> report them: a path that does not exist reads as 1601-01-01 UTC.</summary>
internal static class Times
{
    public static readonly DateTime Missing = DateTime.FromFileTimeUtc(0);

    public static DateTime Get(SftpFileSystem fileSystem, string path, bool write)
    {
        var attributes = fileSystem.Stat(fileSystem.Full(path));
        var time = write ? attributes?.LastWriteTime : attributes?.LastAccessTime;
        return time?.UtcDateTime ?? Missing;
    }

    public static void Set(SftpFileSystem fileSystem, string path, DateTime utc, bool write)
    {
        var full = fileSystem.Full(path);
        var current = fileSystem.Stat(full) ?? throw new FileNotFoundException($"Could not find file '{path}'.", path);
        var time = new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc));
        var attributes = write
            ? new SftpFileAttributes { LastWriteTime = time, LastAccessTime = current.LastAccessTime ?? time }
            : new SftpFileAttributes { LastAccessTime = time, LastWriteTime = current.LastWriteTime ?? time };
        fileSystem.Run(full, false, ct => fileSystem.Sftp.SetAttributesAsync(full, attributes, ct));
    }
}

/// <summary>Symbolic link resolution for <c>ResolveLinkTarget</c>.</summary>
internal static class Links
{
    public static IFileSystemInfo? Resolve(SftpFileSystem fileSystem, string linkPath, bool returnFinalTarget, bool directory)
    {
        var full = fileSystem.Full(linkPath);
        var own = fileSystem.Stat(full, follow: false);
        if (own is null)
        {
            throw directory
                ? new DirectoryNotFoundException($"Could not find a part of the path '{linkPath}'.")
                : new FileNotFoundException($"Could not find file '{linkPath}'.", linkPath);
        }

        if (!own.IsSymbolicLink)
        {
            return null;
        }

        string target;
        if (returnFinalTarget)
        {
            // The server resolves every link in the chain.
            target = fileSystem.Run(full, directory, ct => fileSystem.Sftp.GetFullPathAsync(full, ct));
        }
        else
        {
            var stored = fileSystem.Run(full, directory, ct => fileSystem.Sftp.ReadSymbolicLinkAsync(full, ct));
            var parent = RemotePath.DirectoryName(full, out _).ToString();
            target = RemotePath.IsRooted(stored) ? stored : RemotePath.Normalize(RemotePath.Join(parent, stored));
        }

        return fileSystem.Stat(target) is { IsDirectory: true } ? fileSystem.DirectoryInfo.New(target) : fileSystem.FileInfo.New(target);
    }
}

/// <summary>The errors for what SFTP cannot do.</summary>
internal static class Unsupported
{
    public static NotSupportedException Handles() => new("SFTP files have no OS file handles; use the path overloads.");

    public static NotSupportedException Encryption() => new("SFTP has no file encryption.");

    public static NotSupportedException Replace() => new("SFTP cannot replace a file with a backup atomically; use Move with overwrite.");
}
