using System.IO.Abstractions;

namespace SshSharp.IO.Abstractions;

/// <summary>
/// <see cref="IPath"/> with POSIX semantics, for the server's paths: <c>/</c> separates and roots, <c>:</c> separates path lists, and
/// only NUL (and <c>/</c> in a file name) is invalid. Full paths are resolved against the file system's current directory.
/// </summary>
internal sealed class SftpPath(SftpFileSystem fileSystem) : IPath
{
    public IFileSystem FileSystem => fileSystem;

    public char AltDirectorySeparatorChar => RemotePath.Separator;

    public char DirectorySeparatorChar => RemotePath.Separator;

    public char PathSeparator => ':';

    public char VolumeSeparatorChar => RemotePath.Separator;

    public string? ChangeExtension(string? path, string? extension)
    {
        if (path is null)
        {
            return null;
        }

        var name = RemotePath.FileName(path);
        var dot = name.LastIndexOf('.');
        var stem = dot < 0 ? path : path[..(path.Length - name.Length + dot)];
        return extension is null ? stem : extension.Length == 0 || extension[0] == '.' ? stem + extension : stem + "." + extension;
    }

    public string Combine(string path1, string path2) => RemotePath.Combine([path1, path2]);

    public string Combine(string path1, string path2, string path3) => RemotePath.Combine([path1, path2, path3]);

    public string Combine(string path1, string path2, string path3, string path4) => RemotePath.Combine([path1, path2, path3, path4]);

    public string Combine(params string[] paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return RemotePath.Combine(paths);
    }

#if NET9_0_OR_GREATER
    public string Combine(ReadOnlySpan<string> paths) => RemotePath.Combine(paths.ToArray());
#endif

    public bool EndsInDirectorySeparator(ReadOnlySpan<char> path) => path.Length > 0 && path[^1] == RemotePath.Separator;

    public bool EndsInDirectorySeparator(string path) => EndsInDirectorySeparator(path.AsSpan());

    public bool Exists(string? path) => !string.IsNullOrEmpty(path) && !path.Contains('\0') && fileSystem.Stat(fileSystem.Full(path)) is not null;

    public ReadOnlySpan<char> GetDirectoryName(ReadOnlySpan<char> path) => RemotePath.DirectoryName(path, out _);

    public string? GetDirectoryName(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var directory = RemotePath.DirectoryName(path, out var isRoot);
        return isRoot ? null : directory.ToString();
    }

    public ReadOnlySpan<char> GetExtension(ReadOnlySpan<char> path) => RemotePath.Extension(path);

    public string? GetExtension(string? path) => path is null ? null : RemotePath.Extension(path).ToString();

    public ReadOnlySpan<char> GetFileName(ReadOnlySpan<char> path) => RemotePath.FileName(path);

    public string? GetFileName(string? path) => path is null ? null : RemotePath.FileName(path).ToString();

    public ReadOnlySpan<char> GetFileNameWithoutExtension(ReadOnlySpan<char> path) => RemotePath.FileNameWithoutExtension(path);

    public string? GetFileNameWithoutExtension(string? path) => path is null ? null : RemotePath.FileNameWithoutExtension(path).ToString();

    public string GetFullPath(string path) => fileSystem.Full(path);

    public string GetFullPath(string path, string basePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(basePath);
        if (!RemotePath.IsRooted(basePath))
        {
            throw new ArgumentException("The base path must be fully qualified.", nameof(basePath));
        }

        return RemotePath.Normalize(RemotePath.IsRooted(path) ? path : RemotePath.Join(basePath, path));
    }

    public char[] GetInvalidFileNameChars() => ['\0', RemotePath.Separator];

    public char[] GetInvalidPathChars() => ['\0'];

    public ReadOnlySpan<char> GetPathRoot(ReadOnlySpan<char> path) => RemotePath.IsRooted(path) ? "/" : ReadOnlySpan<char>.Empty;

    public string? GetPathRoot(string? path) => path is null ? null : GetPathRoot(path.AsSpan()).ToString();

    public string GetRandomFileName() => System.IO.Path.GetRandomFileName();

    public string GetRelativePath(string relativeTo, string path) => RemotePath.Relative(fileSystem.Full(relativeTo), fileSystem.Full(path));

    /// <summary>Creates an empty file with a unique name in <see cref="GetTempPath"/> on the server, and returns its path.</summary>
    public string GetTempFileName()
    {
        for (var attempt = 0; ; attempt++)
        {
            var path = GetTempPath() + "tmp" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4)) + ".tmp";
            try
            {
                using var created = fileSystem.FileStream.New(path, FileMode.CreateNew, FileAccess.Write);
                return path;
            }
            catch (IOException) when (attempt < 10 && fileSystem.File.Exists(path))
            {
                // Taken: try another name.
            }
        }
    }

    /// <summary><c>/tmp/</c>, the usual temporary directory on POSIX servers.</summary>
    public string GetTempPath() => "/tmp/";

    public bool HasExtension(ReadOnlySpan<char> path) => !RemotePath.Extension(path).IsEmpty;

    public bool HasExtension(string? path) => path is not null && HasExtension(path.AsSpan());

    public bool IsPathFullyQualified(ReadOnlySpan<char> path) => RemotePath.IsRooted(path);

    public bool IsPathFullyQualified(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return RemotePath.IsRooted(path);
    }

    public bool IsPathRooted(ReadOnlySpan<char> path) => RemotePath.IsRooted(path);

    public bool IsPathRooted(string? path) => path is not null && RemotePath.IsRooted(path);

    public string Join(ReadOnlySpan<char> path1, ReadOnlySpan<char> path2) => RemotePath.Join(path1, path2);

    public string Join(ReadOnlySpan<char> path1, ReadOnlySpan<char> path2, ReadOnlySpan<char> path3) => RemotePath.Join(RemotePath.Join(path1, path2), path3);

    public string Join(ReadOnlySpan<char> path1, ReadOnlySpan<char> path2, ReadOnlySpan<char> path3, ReadOnlySpan<char> path4) =>
        RemotePath.Join(RemotePath.Join(RemotePath.Join(path1, path2), path3), path4);

    public string Join(string? path1, string? path2) => Join(path1.AsSpan(), path2.AsSpan());

    public string Join(string? path1, string? path2, string? path3) => Join(path1.AsSpan(), path2.AsSpan(), path3.AsSpan());

    public string Join(string? path1, string? path2, string? path3, string? path4) => Join(path1.AsSpan(), path2.AsSpan(), path3.AsSpan(), path4.AsSpan());

    public string Join(params string?[] paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return paths.Aggregate(string.Empty, (joined, part) => RemotePath.Join(joined, part));
    }

#if NET9_0_OR_GREATER
    public string Join(ReadOnlySpan<string?> paths) => Join(paths.ToArray());
#endif

    public ReadOnlySpan<char> TrimEndingDirectorySeparator(ReadOnlySpan<char> path) =>
        path.Length > 1 && path[^1] == RemotePath.Separator ? path[..^1] : path;

    public string TrimEndingDirectorySeparator(string path) => TrimEndingDirectorySeparator(path.AsSpan()).ToString();

    public bool TryJoin(ReadOnlySpan<char> path1, ReadOnlySpan<char> path2, Span<char> destination, out int charsWritten) =>
        TryCopy(Join(path1, path2), destination, out charsWritten);

    public bool TryJoin(ReadOnlySpan<char> path1, ReadOnlySpan<char> path2, ReadOnlySpan<char> path3, Span<char> destination, out int charsWritten) =>
        TryCopy(Join(path1, path2, path3), destination, out charsWritten);

    private static bool TryCopy(string value, Span<char> destination, out int charsWritten)
    {
        if (value.TryCopyTo(destination))
        {
            charsWritten = value.Length;
            return true;
        }

        charsWritten = 0;
        return false;
    }
}
