using System.IO.Abstractions;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary><see cref="IFile"/> over SFTP: whole-file reads and writes use pipelined transfers; streams are buffered.</summary>
internal sealed class SftpFile(SftpFileSystem fileSystem) : IFile
{
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public IFileSystem FileSystem => fileSystem;

    // ---- whole files ----

    public byte[] ReadAllBytes(string path)
    {
        var full = fileSystem.Full(path);
        return fileSystem.Run(full, false, ct => DownloadAsync(full, ct));
    }

    public Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        var full = fileSystem.Full(path);
        return fileSystem.RunAsync(full, false, ct => DownloadAsync(full, ct), cancellationToken);
    }

    public string ReadAllText(string path) => Decode(ReadAllBytes(path), Encoding.UTF8);

    public string ReadAllText(string path, Encoding encoding) => Decode(ReadAllBytes(path), encoding);

    public async Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default) =>
        Decode(await ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false), Encoding.UTF8);

    public async Task<string> ReadAllTextAsync(string path, Encoding encoding, CancellationToken cancellationToken = default) =>
        Decode(await ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false), encoding);

    public string[] ReadAllLines(string path) => Lines(ReadAllText(path));

    public string[] ReadAllLines(string path, Encoding encoding) => Lines(ReadAllText(path, encoding));

    public async Task<string[]> ReadAllLinesAsync(string path, CancellationToken cancellationToken = default) =>
        Lines(await ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false));

    public async Task<string[]> ReadAllLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken = default) =>
        Lines(await ReadAllTextAsync(path, encoding, cancellationToken).ConfigureAwait(false));

    /// <summary>The lines, read as they are enumerated; a missing file fails here, not at the first line, as <c>File.ReadLines</c> does.</summary>
    public IEnumerable<string> ReadLines(string path) => ReadLines(path, Encoding.UTF8);

    public IEnumerable<string> ReadLines(string path, Encoding encoding)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        var reader = new StreamReader(OpenRead(path), encoding, detectEncodingFromByteOrderMarks: true);
        return Enumerate(reader);

        static IEnumerable<string> Enumerate(StreamReader reader)
        {
            using (reader)
            {
                while (reader.ReadLine() is { } line)
                {
                    yield return line;
                }
            }
        }
    }

    public IAsyncEnumerable<string> ReadLinesAsync(string path, CancellationToken cancellationToken = default) => ReadLinesAsync(path, Encoding.UTF8, cancellationToken);

    public async IAsyncEnumerable<string> ReadLinesAsync(string path, Encoding encoding, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        var full = fileSystem.Full(path);
        var stream = await fileSystem.RunAsync(full, false, ct => fileSystem.Sftp.OpenReadAsync(full, ct), cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true);
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            yield return line;
        }
    }

    public void WriteAllBytes(string path, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        Write(path, bytes, append: false);
    }

    public Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return WriteAsync(path, bytes, append: false, cancellationToken);
    }

    public void WriteAllText(string path, string? contents) => Write(path, Encode(contents, Utf8NoBom, preamble: true), append: false);

    public void WriteAllText(string path, string? contents, Encoding encoding) => Write(path, Encode(contents, encoding, preamble: true), append: false);

    public Task WriteAllTextAsync(string path, string? contents, CancellationToken cancellationToken = default) =>
        WriteAsync(path, Encode(contents, Utf8NoBom, preamble: true), append: false, cancellationToken);

    public Task WriteAllTextAsync(string path, string? contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        WriteAsync(path, Encode(contents, encoding, preamble: true), append: false, cancellationToken);

    public void WriteAllLines(string path, string[] contents) => WriteAllLines(path, (IEnumerable<string>)contents, Utf8NoBom);

    public void WriteAllLines(string path, IEnumerable<string> contents) => WriteAllLines(path, contents, Utf8NoBom);

    public void WriteAllLines(string path, string[] contents, Encoding encoding) => WriteAllLines(path, (IEnumerable<string>)contents, encoding);

    public void WriteAllLines(string path, IEnumerable<string> contents, Encoding encoding) => WriteAllText(path, JoinLines(contents), encoding);

    public Task WriteAllLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default) =>
        WriteAllTextAsync(path, JoinLines(contents), Utf8NoBom, cancellationToken);

    public Task WriteAllLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        WriteAllTextAsync(path, JoinLines(contents), encoding, cancellationToken);

    public void AppendAllText(string path, string? contents) => AppendText(path, contents, Utf8NoBom);

    public void AppendAllText(string path, string? contents, Encoding encoding) => AppendText(path, contents, encoding);

    public Task AppendAllTextAsync(string path, string? contents, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, contents, Utf8NoBom, cancellationToken);

    public Task AppendAllTextAsync(string path, string? contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, contents, encoding, cancellationToken);

    public void AppendAllLines(string path, IEnumerable<string> contents) => AppendText(path, JoinLines(contents), Utf8NoBom);

    public void AppendAllLines(string path, IEnumerable<string> contents, Encoding encoding) => AppendText(path, JoinLines(contents), encoding);

    public Task AppendAllLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, JoinLines(contents), Utf8NoBom, cancellationToken);

    public Task AppendAllLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, JoinLines(contents), encoding, cancellationToken);

#if NET9_0_OR_GREATER
    public void AppendAllBytes(string path, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        Write(path, bytes, append: true);
    }

    public void AppendAllBytes(string path, ReadOnlySpan<byte> bytes) => Write(path, bytes.ToArray(), append: true);

    public Task AppendAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return WriteAsync(path, bytes, append: true, cancellationToken);
    }

    public Task AppendAllBytesAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default) =>
        WriteAsync(path, bytes, append: true, cancellationToken);

    public void AppendAllText(string path, ReadOnlySpan<char> contents) => AppendText(path, contents.ToString(), Utf8NoBom);

    public void AppendAllText(string path, ReadOnlySpan<char> contents, Encoding encoding) => AppendText(path, contents.ToString(), encoding);

    public Task AppendAllTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, contents.ToString(), Utf8NoBom, cancellationToken);

    public Task AppendAllTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        AppendTextAsync(path, contents.ToString(), encoding, cancellationToken);

    public void WriteAllBytes(string path, ReadOnlySpan<byte> bytes) => Write(path, bytes.ToArray(), append: false);

    public Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default) =>
        WriteAsync(path, bytes, append: false, cancellationToken);

    public void WriteAllText(string path, ReadOnlySpan<char> contents) => WriteAllText(path, contents.ToString());

    public void WriteAllText(string path, ReadOnlySpan<char> contents, Encoding encoding) => WriteAllText(path, contents.ToString(), encoding);

    public Task WriteAllTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default) =>
        WriteAllTextAsync(path, contents.ToString(), cancellationToken);

    public Task WriteAllTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
        WriteAllTextAsync(path, contents.ToString(), encoding, cancellationToken);
#endif

    // ---- streams and text ----

    public FileSystemStream Create(string path) => Create(path, 4096);

    public FileSystemStream Create(string path, int bufferSize) => SftpFileSystemStream.Open(fileSystem, path, FileMode.Create, FileAccess.ReadWrite, bufferSize);

    public FileSystemStream Create(string path, int bufferSize, FileOptions options) => Create(path, bufferSize);

    public StreamWriter CreateText(string path) => new(SftpFileSystemStream.Open(fileSystem, path, FileMode.Create, FileAccess.Write, 4096), Utf8NoBom);

    public StreamWriter AppendText(string path) => new(SftpFileSystemStream.Open(fileSystem, path, FileMode.Append, FileAccess.Write, 4096), Utf8NoBom);

    public StreamReader OpenText(string path) => new(OpenRead(path), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

    public FileSystemStream Open(string path, FileMode mode) => Open(path, mode, mode == FileMode.Append ? FileAccess.Write : FileAccess.ReadWrite);

    public FileSystemStream Open(string path, FileMode mode, FileAccess access) => SftpFileSystemStream.Open(fileSystem, path, mode, access, 4096);

    public FileSystemStream Open(string path, FileMode mode, FileAccess access, FileShare share) => Open(path, mode, access);

    public FileSystemStream Open(string path, FileStreamOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var created = !Exists(path);
        var stream = SftpFileSystemStream.Open(fileSystem, path, options.Mode, options.Access, options.BufferSize);
        if (created && options.UnixCreateMode is { } mode && options.Mode != FileMode.Open)
        {
            SetUnixFileMode(path, mode);
        }

        return stream;
    }

    public FileSystemStream OpenRead(string path) => Open(path, FileMode.Open, FileAccess.Read);

    public FileSystemStream OpenWrite(string path) => Open(path, FileMode.OpenOrCreate, FileAccess.Write);

    // ---- names ----

    /// <summary>Whether a file (anything but a directory) exists; false for null, empty or invalid paths, as <c>File.Exists</c>.</summary>
    public bool Exists(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Contains('\0'))
        {
            return false;
        }

        return fileSystem.Stat(fileSystem.Full(path)) is { IsDirectory: false };
    }

    /// <summary>Copies on the server (<c>copy-data</c>) when it can, otherwise through this machine. Attributes are not copied.</summary>
    public void Copy(string sourceFileName, string destFileName) => Copy(sourceFileName, destFileName, overwrite: false);

    public void Copy(string sourceFileName, string destFileName, bool overwrite)
    {
        var source = fileSystem.Full(sourceFileName);
        var destination = fileSystem.Full(destFileName);
        if (fileSystem.Stat(source) is not { IsDirectory: false })
        {
            throw new FileNotFoundException($"Could not find file '{sourceFileName}'.", sourceFileName);
        }

        fileSystem.Run(destination, true, async ct =>
        {
            if (fileSystem.Sftp.Extensions.ContainsKey("copy-data"))
            {
                await fileSystem.Sftp.CopyFileAsync(source, destination, overwrite, ct).ConfigureAwait(false);
                return;
            }

            await using var reader = await fileSystem.Sftp.OpenReadAsync(source, ct).ConfigureAwait(false);
            await fileSystem.Sftp.UploadAsync(reader, destination, new SftpTransferOptions { Overwrite = overwrite }, ct).ConfigureAwait(false);
        });
    }

    public void Move(string sourceFileName, string destFileName) => Move(sourceFileName, destFileName, overwrite: false);

    public void Move(string sourceFileName, string destFileName, bool overwrite)
    {
        var source = fileSystem.Full(sourceFileName);
        var destination = fileSystem.Full(destFileName);
        if (fileSystem.Stat(source, follow: false) is null)
        {
            throw new FileNotFoundException($"Could not find file '{sourceFileName}'.", sourceFileName);
        }

        if (!overwrite && fileSystem.Stat(destination, follow: false) is not null)
        {
            throw new IOException($"The file '{destFileName}' already exists.");
        }

        fileSystem.Run(destination, true, ct => fileSystem.Sftp.RenameAsync(source, destination, overwrite, ct));
    }

    /// <summary>Deletes a file; a file that does not exist is not an error (but a missing directory is), as <c>File.Delete</c>.</summary>
    public void Delete(string path)
    {
        var full = fileSystem.Full(path);
        try
        {
            fileSystem.Run(full, false, ct => fileSystem.Sftp.DeleteFileAsync(full, ct));
        }
        catch (FileNotFoundException)
        {
            var parent = RemotePath.DirectoryName(full, out var isRoot);
            if (!isRoot && fileSystem.Stat(parent.ToString()) is not { IsDirectory: true })
            {
                throw new DirectoryNotFoundException($"Could not find a part of the path '{path}'.");
            }
        }
    }

    public IFileSystemInfo CreateSymbolicLink(string path, string pathToTarget)
    {
        ArgumentException.ThrowIfNullOrEmpty(pathToTarget);
        var full = fileSystem.Full(path);
        fileSystem.Run(full, true, ct => fileSystem.Sftp.CreateSymbolicLinkAsync(full, pathToTarget, ct));
        return fileSystem.FileInfo.New(path);
    }

    public IFileSystemInfo? ResolveLinkTarget(string linkPath, bool returnFinalTarget) => Links.Resolve(fileSystem, linkPath, returnFinalTarget, directory: false);

    // ---- attributes and times ----

    public FileAttributes GetAttributes(string path) => Attributes.Of(fileSystem, path) ?? throw new FileNotFoundException($"Could not find file '{path}'.", path);

    public void SetAttributes(string path, FileAttributes fileAttributes) => Attributes.Set(fileSystem, path, fileAttributes);

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

    public UnixFileMode GetUnixFileMode(string path)
    {
        var full = fileSystem.Full(path);
        return (fileSystem.Stat(full) ?? throw new FileNotFoundException($"Could not find file '{path}'.", path)).Permissions ?? UnixFileMode.None;
    }

    public void SetUnixFileMode(string path, UnixFileMode mode)
    {
        var full = fileSystem.Full(path);
        fileSystem.Run(full, false, ct => fileSystem.Sftp.SetAttributesAsync(full, new SftpFileAttributes { Permissions = mode }, ct));
    }

    // ---- not supported over SFTP ----

    public void Decrypt(string path) => throw Unsupported.Encryption();

    public void Encrypt(string path) => throw Unsupported.Encryption();

    public void Replace(string sourceFileName, string destinationFileName, string? destinationBackupFileName) => throw Unsupported.Replace();

    public void Replace(string sourceFileName, string destinationFileName, string? destinationBackupFileName, bool ignoreMetadataErrors) => throw Unsupported.Replace();

    public SafeFileHandle OpenHandle(string path, FileMode mode = FileMode.Open, FileAccess access = FileAccess.Read, FileShare share = FileShare.Read, FileOptions options = FileOptions.None, long preallocationSize = 0) =>
        throw Unsupported.Handles();

    public FileAttributes GetAttributes(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetCreationTime(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetCreationTimeUtc(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetLastAccessTime(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetLastAccessTimeUtc(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetLastWriteTime(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public DateTime GetLastWriteTimeUtc(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public UnixFileMode GetUnixFileMode(SafeFileHandle fileHandle) => throw Unsupported.Handles();

    public void SetAttributes(SafeFileHandle fileHandle, FileAttributes fileAttributes) => throw Unsupported.Handles();

    public void SetCreationTime(SafeFileHandle fileHandle, DateTime creationTime) => throw Unsupported.Handles();

    public void SetCreationTimeUtc(SafeFileHandle fileHandle, DateTime creationTimeUtc) => throw Unsupported.Handles();

    public void SetLastAccessTime(SafeFileHandle fileHandle, DateTime lastAccessTime) => throw Unsupported.Handles();

    public void SetLastAccessTimeUtc(SafeFileHandle fileHandle, DateTime lastAccessTimeUtc) => throw Unsupported.Handles();

    public void SetLastWriteTime(SafeFileHandle fileHandle, DateTime lastWriteTime) => throw Unsupported.Handles();

    public void SetLastWriteTimeUtc(SafeFileHandle fileHandle, DateTime lastWriteTimeUtc) => throw Unsupported.Handles();

    public void SetUnixFileMode(SafeFileHandle fileHandle, UnixFileMode mode) => throw Unsupported.Handles();

    // ---- helpers ----

    private async Task<byte[]> DownloadAsync(string full, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        await fileSystem.Sftp.DownloadAsync(full, buffer, null, cancellationToken).ConfigureAwait(false);
        return buffer.ToArray();
    }

    private void Write(string path, ReadOnlyMemory<byte> data, bool append)
    {
        var full = fileSystem.Full(path);
        fileSystem.Run(full, true, ct => WriteCoreAsync(full, data, append, ct));
    }

    private Task WriteAsync(string path, ReadOnlyMemory<byte> data, bool append, CancellationToken cancellationToken)
    {
        var full = fileSystem.Full(path);
        return fileSystem.RunAsync(full, true, ct => WriteCoreAsync(full, data, append, ct), cancellationToken);
    }

    private async Task WriteCoreAsync(string full, ReadOnlyMemory<byte> data, bool append, CancellationToken cancellationToken)
    {
        if (!append)
        {
            await fileSystem.Sftp.UploadAsync(new MemoryStream(data.ToArray(), writable: false), full, new SftpTransferOptions { Overwrite = true }, cancellationToken).ConfigureAwait(false);
            return;
        }

        await using var stream = await fileSystem.Sftp.OpenAsync(full, FileMode.Append, FileAccess.Write, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
    }

    private void AppendText(string path, string? contents, Encoding encoding) =>
        Write(path, Encode(contents, encoding, preamble: !(fileSystem.Stat(fileSystem.Full(path)) is { Size: > 0 })), append: true);

    private Task AppendTextAsync(string path, string? contents, Encoding encoding, CancellationToken cancellationToken) =>
        WriteAsync(path, Encode(contents, encoding, preamble: !(fileSystem.Stat(fileSystem.Full(path)) is { Size: > 0 })), append: true, cancellationToken);

    /// <summary>The text in <paramref name="encoding"/>, with its byte order mark first when <paramref name="preamble"/> (a new file).</summary>
    private static byte[] Encode(string? contents, Encoding encoding, bool preamble)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        var bom = preamble ? encoding.GetPreamble() : [];
        return [.. bom, .. encoding.GetBytes(contents ?? string.Empty)];
    }

    /// <summary>Decodes as <c>File.ReadAllText</c> does: a byte order mark, if there is one, overrides <paramref name="encoding"/>.</summary>
    private static string Decode(byte[] data, Encoding encoding)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        using var reader = new StreamReader(new MemoryStream(data), encoding, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static string[] Lines(string text)
    {
        var lines = new List<string>();
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } line)
        {
            lines.Add(line);
        }

        return [.. lines];
    }

    /// <summary>Each line followed by <see cref="Environment.NewLine"/>, as <c>File.WriteAllLines</c> writes them.</summary>
    private static string JoinLines(IEnumerable<string> contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        var text = new StringBuilder();
        foreach (var line in contents)
        {
            text.Append(line).Append(Environment.NewLine);
        }

        return text.ToString();
    }
}
