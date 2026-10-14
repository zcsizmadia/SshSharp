using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>
/// An SFTP session (version 3, as OpenSSH's sftp-server and <c>internal-sftp</c> speak it) over an <see cref="SshClient"/>: files,
/// directories, links and attributes, file streams, and pipelined uploads and downloads. Open one with
/// <see cref="SshSftpExtensions.OpenSftpAsync"/>; several can share a connection, and one may be used by several callers at once.
/// </summary>
/// <remarks>
/// Remote paths are passed to the server as they are: relative ones are relative to the login directory, and <c>/</c> is the
/// separator, whatever this machine uses. This API is experimental (diagnostic <c>SSHSHARP001</c>) until it settles; it may still
/// change between minor releases.
/// </remarks>
[Experimental(ExperimentalId)]
public sealed partial class SftpClient : IAsyncDisposable
{
    /// <summary>The diagnostic id of the experimental SFTP API.</summary>
    public const string ExperimentalId = "SSHSHARP001";

    private readonly SftpChannel _channel;

    private SftpClient(SftpChannel channel, SftpLimits limits)
    {
        _channel = channel;
        Limits = limits;
    }

    /// <summary>The protocol version the server speaks (3 for OpenSSH).</summary>
    public int ProtocolVersion => (int)_channel.Version;

    /// <summary>The protocol extensions the server announced, with their versions, for example <c>posix-rename@openssh.com</c> = <c>1</c>.</summary>
    public IReadOnlyDictionary<string, string> Extensions => _channel.Extensions;

    /// <summary>The server's limits (<c>limits@openssh.com</c>), or the defaults every server accepts when it announces none.</summary>
    public SftpLimits Limits { get; }

    internal static async Task<SftpClient> StartAsync(SshSession session, CancellationToken cancellationToken)
    {
        var channel = await SftpChannel.OpenAsync(session, cancellationToken).ConfigureAwait(false);
        try
        {
            var limits = new SftpLimits(SftpProtocol.DefaultChunk, SftpProtocol.DefaultChunk, null);
            if (channel.Extensions.ContainsKey(SftpProtocol.LimitsExtension))
            {
                var reply = await channel.RequestAsync(SftpProtocol.Extended, w => w.WriteString(SftpProtocol.LimitsExtension), cancellationToken).ConfigureAwait(false);
                if (reply.Type == SftpProtocol.ExtendedReply)
                {
                    var reader = reply.Body;
                    reader.ReadUInt64(); // max packet length: the read and write lengths below already fit it
                    var maxRead = reader.ReadUInt64();
                    var maxWrite = reader.ReadUInt64();
                    var maxHandles = reader.ReadUInt64();
                    limits = new SftpLimits(
                        Chunk(maxRead),
                        Chunk(maxWrite),
                        maxHandles is 0 or > int.MaxValue ? null : (int)maxHandles);
                }
            }

            return new SftpClient(channel, limits);
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        static int Chunk(ulong announced) => announced == 0 ? SftpProtocol.DefaultChunk : (int)Math.Min(announced, SftpProtocol.MaxChunk);
    }

    // ---- attributes ----

    /// <summary>The attributes of <paramref name="path"/>; of the link itself when <paramref name="followSymbolicLinks"/> is false.</summary>
    /// <exception cref="SftpException">The path does not exist (<see cref="SftpStatusCode.NoSuchFile"/>), or another error.</exception>
    public async Task<SftpFileAttributes> GetAttributesAsync(string path, bool followSymbolicLinks = true, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(followSymbolicLinks ? SftpProtocol.Stat : SftpProtocol.LStat, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        return ExpectAttributes(reply, "Stat", path);
    }

    /// <summary>Whether <paramref name="path"/> exists (following symbolic links: a dangling link does not).</summary>
    public async Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            await GetAttributesAsync(path, followSymbolicLinks: true, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
        {
            return false;
        }
    }

    /// <summary>Changes the attributes that are set in <paramref name="attributes"/> (size, owner, permissions, times).</summary>
    public async Task SetAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        ArgumentNullException.ThrowIfNull(attributes);
        var reply = await _channel.RequestAsync(SftpProtocol.SetStat, w =>
        {
            w.WriteString(path);
            attributes.Write(w);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Setting attributes", path);
    }

    // ---- directories ----

    /// <summary>
    /// Lists a directory, without <c>.</c> and <c>..</c>. Entries arrive in batches as the server sends them; names that cannot be
    /// file names in one directory (empty, or with a <c>/</c>) are left out.
    /// </summary>
    public async IAsyncEnumerable<SftpFileInfo> ListDirectoryAsync(string path, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var opened = await _channel.RequestAsync(SftpProtocol.OpenDir, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        var handle = ExpectHandle(opened, "Listing", path);
        try
        {
            var prefix = path.EndsWith('/') ? path : path + "/";
            while (true)
            {
                var reply = await _channel.RequestAsync(SftpProtocol.ReadDir, w => w.WriteString(handle), cancellationToken).ConfigureAwait(false);
                if (IsEndOfFile(reply))
                {
                    yield break;
                }

                foreach (var (name, longName, attributes) in ExpectNames(reply, "Listing", path))
                {
                    if (name is "." or ".." || name.Length == 0 || name.Contains('/') || name.Contains('\0'))
                    {
                        continue;
                    }

                    yield return new SftpFileInfo(name, prefix + name, longName, attributes);
                }
            }
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>Creates a directory, with <paramref name="permissions"/> if given (the server's umask applies).</summary>
    /// <exception cref="SftpException">It exists already, the parent does not exist, or another error.</exception>
    public async Task CreateDirectoryAsync(string path, UnixFileMode? permissions = null, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(SftpProtocol.MkDir, w =>
        {
            w.WriteString(path);
            new SftpFileAttributes { Permissions = permissions }.Write(w);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Creating the directory", path);
    }

    /// <summary>Deletes an empty directory.</summary>
    public async Task DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(SftpProtocol.RmDir, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Deleting the directory", path);
    }

    // ---- files and links ----

    /// <summary>Deletes a file (or a symbolic link, not its target).</summary>
    public async Task DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(SftpProtocol.Remove, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Deleting", path);
    }

    /// <summary>
    /// Renames or moves <paramref name="oldPath"/> to <paramref name="newPath"/>. Plain SFTP refuses when <paramref name="newPath"/> exists;
    /// with <paramref name="overwrite"/> it is replaced atomically, which needs the server's <c>posix-rename@openssh.com</c>.
    /// </summary>
    /// <exception cref="NotSupportedException"><paramref name="overwrite"/> and the server lacks <c>posix-rename@openssh.com</c>.</exception>
    public async Task RenameAsync(string oldPath, string newPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        CheckPath(oldPath);
        CheckPath(newPath);
        SftpResponse reply;
        if (overwrite)
        {
            if (!Extensions.ContainsKey(SftpProtocol.PosixRenameExtension))
            {
                throw new NotSupportedException("The server cannot replace a file in a rename (it lacks posix-rename@openssh.com).");
            }

            reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
            {
                w.WriteString(SftpProtocol.PosixRenameExtension);
                w.WriteString(oldPath);
                w.WriteString(newPath);
            }, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            reply = await _channel.RequestAsync(SftpProtocol.Rename, w =>
            {
                w.WriteString(oldPath);
                w.WriteString(newPath);
            }, cancellationToken).ConfigureAwait(false);
        }

        ExpectOk(reply, "Renaming", oldPath);
    }

    /// <summary>The canonical absolute form of <paramref name="path"/> (<c>.</c> is the login directory), as the server resolves it.</summary>
    public async Task<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(SftpProtocol.RealPath, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        return SingleName(reply, "Resolving", path);
    }

    /// <summary>The login directory: the server's <c>home-directory</c> extension when it has one, otherwise what <c>.</c> resolves to.</summary>
    public async Task<string> GetHomeDirectoryAsync(CancellationToken cancellationToken = default)
    {
        if (!Extensions.ContainsKey(SftpProtocol.HomeDirectoryExtension))
        {
            return await GetFullPathAsync(".", cancellationToken).ConfigureAwait(false);
        }

        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.HomeDirectoryExtension);
            w.WriteString(string.Empty); // the session's own user
        }, cancellationToken).ConfigureAwait(false);
        return SingleName(reply, "Finding the home directory", null);
    }

    /// <summary>The target of the symbolic link <paramref name="path"/>, as stored in the link.</summary>
    public async Task<string> ReadSymbolicLinkAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var reply = await _channel.RequestAsync(SftpProtocol.ReadLink, w => w.WriteString(path), cancellationToken).ConfigureAwait(false);
        return SingleName(reply, "Reading the link", path);
    }

    /// <summary>Creates the symbolic link <paramref name="linkPath"/> pointing to <paramref name="targetPath"/> (stored as given).</summary>
    public async Task CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        CheckPath(linkPath);
        CheckPath(targetPath);

        // OpenSSH's sftp-server takes the arguments in the reverse of the draft's order (PROTOCOL 4.1), and other servers follow it.
        var reply = await _channel.RequestAsync(SftpProtocol.Symlink, w =>
        {
            w.WriteString(targetPath);
            w.WriteString(linkPath);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Creating the link", linkPath);
    }

    /// <summary>Creates the hard link <paramref name="linkPath"/> to the file <paramref name="existingPath"/> (<c>hardlink@openssh.com</c>).</summary>
    /// <exception cref="NotSupportedException">The server lacks <c>hardlink@openssh.com</c>.</exception>
    public async Task CreateHardLinkAsync(string linkPath, string existingPath, CancellationToken cancellationToken = default)
    {
        CheckPath(linkPath);
        CheckPath(existingPath);
        if (!Extensions.ContainsKey(SftpProtocol.HardlinkExtension))
        {
            throw new NotSupportedException("The server does not create hard links (it lacks hardlink@openssh.com).");
        }

        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.HardlinkExtension);
            w.WriteString(existingPath);
            w.WriteString(linkPath);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Creating the hard link", linkPath);
    }

    // ---- streams ----

    /// <summary>
    /// Opens a remote file as a seekable <see cref="Stream"/> (asynchronous reads and writes only). <paramref name="mode"/> works as
    /// for <see cref="FileStream"/>: <see cref="FileMode.Create"/> creates or truncates, <see cref="FileMode.CreateNew"/> fails if the
    /// file exists, <see cref="FileMode.Append"/> starts at the end. Disposing the stream closes the remote file.
    /// </summary>
    public async Task<Stream> OpenAsync(string path, FileMode mode, FileAccess access, CancellationToken cancellationToken = default)
    {
        var (handle, flags) = await OpenHandleAsync(path, mode, access, cancellationToken).ConfigureAwait(false);
        long position = 0;
        if (mode == FileMode.Append)
        {
            try
            {
                position = (await GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size ?? 0;
            }
            catch
            {
                await CloseHandleAsync(handle).ConfigureAwait(false);
                throw;
            }
        }

        return new SftpFileStream(this, handle, path, (flags & SftpProtocol.OpenRead) != 0, (flags & SftpProtocol.OpenWrite) != 0, position);
    }

    /// <summary>Opens a remote file for reading, as <see cref="OpenAsync"/> with <see cref="FileMode.Open"/> and <see cref="FileAccess.Read"/>.</summary>
    public Task<Stream> OpenReadAsync(string path, CancellationToken cancellationToken = default) =>
        OpenAsync(path, FileMode.Open, FileAccess.Read, cancellationToken);

    /// <summary>Creates or truncates a remote file for writing, as <see cref="OpenAsync"/> with <see cref="FileMode.Create"/>.</summary>
    public Task<Stream> OpenWriteAsync(string path, CancellationToken cancellationToken = default) =>
        OpenAsync(path, FileMode.Create, FileAccess.Write, cancellationToken);

    // ---- transfers ----

    /// <summary>
    /// Downloads <paramref name="remotePath"/> into <paramref name="destination"/>, with several reads in flight (the window, by default
    /// 64 reads of up to <see cref="SftpLimits.MaxReadLength"/>), which is what makes SFTP fast on links with latency.
    /// </summary>
    /// <returns>The number of bytes downloaded.</returns>
    public async Task<long> DownloadAsync(string remotePath, Stream destination, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        options ??= new SftpTransferOptions();
        var (handle, _) = await OpenHandleAsync(remotePath, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
        try
        {
            return await DownloadHandleAsync(handle, remotePath, destination, 0, options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Downloads <paramref name="remotePath"/> to the local file <paramref name="localPath"/>. With <see cref="SftpTransferOptions.Overwrite"/>
    /// off, an existing local file is an error; with <see cref="SftpTransferOptions.PreserveTimes"/>, the local file gets the remote one's
    /// modification and access times. A failed download leaves no partial file behind.
    /// </summary>
    /// <returns>The number of bytes downloaded.</returns>
    public async Task<long> DownloadFileAsync(string remotePath, string localPath, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(localPath);
        options ??= new SftpTransferOptions();
        var (handle, _) = await OpenHandleAsync(remotePath, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
        try
        {
            var resumeFrom = options.Resume && File.Exists(localPath) ? new FileInfo(localPath).Length : 0;
            var attributes = options.PreserveTimes || resumeFrom > 0 ? await GetHandleAttributesAsync(handle, remotePath, cancellationToken).ConfigureAwait(false) : null;
            if (resumeFrom > 0 && attributes!.Size is { } remoteSize && resumeFrom > remoteSize)
            {
                throw new IOException($"The local file is larger than '{remotePath}' ({resumeFrom} > {remoteSize} bytes): it is not a partial download of it.");
            }

            long total;
            var created = false;
            try
            {
                var mode = resumeFrom > 0 ? FileMode.Append : options.Overwrite || options.Resume ? FileMode.Create : FileMode.CreateNew;
                await using (var file = new FileStream(localPath, mode, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true))
                {
                    created = resumeFrom == 0;
                    total = await DownloadHandleAsync(handle, remotePath, file, resumeFrom, options, cancellationToken).ConfigureAwait(false);
                }
            }
            catch when (created && !options.Resume)
            {
                // A fresh download that failed leaves nothing; with Resume, what arrived is kept for the next attempt.
                File.Delete(localPath);
                throw;
            }

            if (attributes is not null)
            {
                if (attributes.LastWriteTime is { } modified)
                {
                    File.SetLastWriteTimeUtc(localPath, modified.UtcDateTime);
                }

                if (attributes.LastAccessTime is { } accessed)
                {
                    File.SetLastAccessTimeUtc(localPath, accessed.UtcDateTime);
                }
            }

            return total;
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Uploads <paramref name="source"/> (read to its end) to <paramref name="remotePath"/>, with several writes in flight. The remote
    /// file is created or, with <see cref="SftpTransferOptions.Overwrite"/>, truncated.
    /// </summary>
    /// <returns>The number of bytes uploaded.</returns>
    public async Task<long> UploadAsync(Stream source, string remotePath, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        options ??= new SftpTransferOptions();
        var mode = options.Resume ? FileMode.OpenOrCreate : options.Overwrite ? FileMode.Create : FileMode.CreateNew;
        var (handle, _) = await OpenHandleAsync(remotePath, mode, FileAccess.Write, cancellationToken).ConfigureAwait(false);
        try
        {
            long start = 0;
            if (options.Resume)
            {
                // What the remote file already holds is taken as the source's first bytes, as sftp's reput does: those are skipped.
                start = (await GetHandleAttributesAsync(handle, remotePath, cancellationToken).ConfigureAwait(false)).Size ?? 0;
                await SkipAsync(source, start, remotePath, cancellationToken).ConfigureAwait(false);
            }

            return await UploadHandleAsync(handle, remotePath, source, start, options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Uploads the local file <paramref name="localPath"/> to <paramref name="remotePath"/>. With <see cref="SftpTransferOptions.PreserveTimes"/>,
    /// the remote file gets the local one's modification and access times.
    /// </summary>
    /// <returns>The number of bytes uploaded.</returns>
    public async Task<long> UploadFileAsync(string localPath, string remotePath, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(localPath);
        options ??= new SftpTransferOptions();
        long total;
        await using (var file = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true))
        {
            total = await UploadAsync(file, remotePath, options, cancellationToken).ConfigureAwait(false);
        }

        if (options.PreserveTimes)
        {
            await SetAttributesAsync(remotePath, new SftpFileAttributes
            {
                LastAccessTime = File.GetLastAccessTimeUtc(localPath),
                LastWriteTime = File.GetLastWriteTimeUtc(localPath),
            }, cancellationToken).ConfigureAwait(false);
        }

        return total;
    }

    /// <summary>Ends the SFTP session (the SSH connection stays up). Requests still waiting fail.</summary>
    public ValueTask DisposeAsync() => _channel.DisposeAsync();

    // ---- handle operations, also used by SftpFileStream ----

    internal async Task<(byte[] Handle, uint Flags)> OpenHandleAsync(string path, FileMode mode, FileAccess access, CancellationToken cancellationToken)
    {
        CheckPath(path);
        var flags = access switch
        {
            FileAccess.Read => SftpProtocol.OpenRead,
            FileAccess.Write => SftpProtocol.OpenWrite,
            FileAccess.ReadWrite => SftpProtocol.OpenRead | SftpProtocol.OpenWrite,
            _ => throw new ArgumentOutOfRangeException(nameof(access)),
        };
        flags |= mode switch
        {
            FileMode.Open => 0,
            FileMode.CreateNew => SftpProtocol.OpenCreate | SftpProtocol.OpenExclusive,
            FileMode.Create => SftpProtocol.OpenCreate | SftpProtocol.OpenTruncate,
            FileMode.OpenOrCreate => SftpProtocol.OpenCreate,
            FileMode.Truncate => SftpProtocol.OpenTruncate,
            FileMode.Append => SftpProtocol.OpenCreate | SftpProtocol.OpenAppend,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
        if (mode is FileMode.CreateNew or FileMode.Create or FileMode.Truncate or FileMode.Append && access == FileAccess.Read)
        {
            throw new ArgumentException($"FileMode.{mode} needs write access.", nameof(access));
        }

        var reply = await _channel.RequestAsync(SftpProtocol.Open, w =>
        {
            w.WriteString(path);
            w.WriteUInt32(flags);
            w.WriteUInt32(0); // no attributes: the server's defaults (0666 less its umask)
        }, cancellationToken).ConfigureAwait(false);
        return (ExpectHandle(reply, "Opening", path), flags);
    }

    internal async Task<SftpFileAttributes> GetHandleAttributesAsync(byte[] handle, string path, CancellationToken cancellationToken)
    {
        var reply = await _channel.RequestAsync(SftpProtocol.FStat, w => w.WriteString(handle), cancellationToken).ConfigureAwait(false);
        return ExpectAttributes(reply, "Stat", path);
    }

    internal async Task SetHandleAttributesAsync(byte[] handle, string path, SftpFileAttributes attributes, CancellationToken cancellationToken)
    {
        var reply = await _channel.RequestAsync(SftpProtocol.FSetStat, w =>
        {
            w.WriteString(handle);
            attributes.Write(w);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Setting attributes", path);
    }

    /// <summary>Sends one read; the reply is the data (possibly shorter than asked), or null at the end of the file.</summary>
    internal Task<SftpResponse> SendReadAsync(byte[] handle, long offset, int length, CancellationToken cancellationToken) =>
        _channel.RequestAsync(SftpProtocol.Read, w =>
        {
            w.WriteString(handle);
            w.WriteUInt64((ulong)offset);
            w.WriteUInt32((uint)length);
        }, cancellationToken);

    internal Task<SftpResponse> SendWriteAsync(byte[] handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        _channel.RequestAsync(SftpProtocol.Write, w =>
        {
            w.WriteString(handle);
            w.WriteUInt64((ulong)offset);
            w.WriteString(data.Span);
        }, cancellationToken);

    /// <summary>The data in a READ reply, or empty at the end of the file.</summary>
    internal static ReadOnlyMemory<byte> ExpectData(SftpResponse reply, int requested, string path)
    {
        if (IsEndOfFile(reply))
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        if (reply.Type != SftpProtocol.Data)
        {
            ThrowStatus(reply, "Reading", path);
        }

        // DATA: type, id, then string data; sliced out of the packet without a copy.
        var length = BinaryPrimitives.ReadUInt32BigEndian(reply.Packet.AsSpan(5));
        if (length > reply.Packet.Length - 9 || length > (uint)requested || length == 0)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server sent {length} bytes for a read of {requested}.");
        }

        return reply.Packet.AsMemory(9, (int)length);
    }

    internal static void ExpectWritten(SftpResponse reply, string path) => ExpectOk(reply, "Writing", path);

    internal async Task CloseHandleAsync(byte[] handle)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var reply = await _channel.RequestAsync(SftpProtocol.Close, w => w.WriteString(handle), timeout.Token).ConfigureAwait(false);
            ExpectOk(reply, "Closing", null);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The session ended (closing it closed the file), or the server refused: nothing more to do.
        }
    }

    private async Task<long> DownloadHandleAsync(byte[] handle, string path, Stream destination, long start, SftpTransferOptions options, CancellationToken cancellationToken)
    {
        // A window of reads in flight; replies are written in offset order. A short read (allowed by the draft, but not at the end of
        // the file) gets a follow-up read for the rest, at the front of the queue, so the output stays in order.
        var chunk = Limits.MaxReadLength;
        var inFlight = new LinkedList<(long Offset, int Length, Task<SftpResponse> Reply)>();
        var next = start;
        var end = false;
        long total = 0;
        try
        {
            while (true)
            {
                while (!end && inFlight.Count < options.MaxRequestsInFlight)
                {
                    inFlight.AddLast((next, chunk, SendReadAsync(handle, next, chunk, cancellationToken)));
                    next += chunk;
                }

                if (inFlight.Count == 0)
                {
                    return total;
                }

                var (offset, length, pending) = inFlight.First!.Value;
                inFlight.RemoveFirst();
                var data = ExpectData(await pending.ConfigureAwait(false), length, path);
                if (data.IsEmpty)
                {
                    end = true; // the later reads are past the end too; their replies are awaited (and dropped) below
                    continue;
                }

                if (!end)
                {
                    await destination.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                    total += data.Length;
                    options.Progress?.Report(total);
                    if (data.Length < length)
                    {
                        var rest = offset + data.Length;
                        inFlight.AddFirst((rest, length - data.Length, SendReadAsync(handle, rest, length - data.Length, cancellationToken)));
                    }
                }
            }
        }
        finally
        {
            // Replies still due are awaited, so none arrives after the handle is closed and the caller moves on.
            foreach (var (_, _, pending) in inFlight)
            {
                try
                {
                    await pending.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Already failing.
                }
            }
        }
    }

    /// <summary>Skips the first <paramref name="count"/> bytes of <paramref name="source"/>, which must have that many.</summary>
    private static async Task SkipAsync(Stream source, long count, string remotePath, CancellationToken cancellationToken)
    {
        if (count == 0)
        {
            return;
        }

        if (source.CanSeek)
        {
            if (source.Length - source.Position < count)
            {
                throw new IOException($"'{remotePath}' is larger than the source ({count} bytes): it is not a partial upload of it.");
            }

            source.Seek(count, SeekOrigin.Current);
            return;
        }

        var buffer = new byte[64 * 1024];
        while (count > 0)
        {
            var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, count)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException($"'{remotePath}' is larger than the source: it is not a partial upload of it.");
            }

            count -= read;
        }
    }

    /// <summary>Writes <paramref name="source"/> from its position to the remote file from <paramref name="start"/>; returns the bytes written.</summary>
    private async Task<long> UploadHandleAsync(byte[] handle, string path, Stream source, long start, SftpTransferOptions options, CancellationToken cancellationToken)
    {
        // A window of writes in flight; progress counts what the server has acknowledged.
        var chunk = Limits.MaxWriteLength;
        var inFlight = new Queue<(Task<SftpResponse> Reply, int Length)>();
        long offset = start, acknowledged = 0;
        try
        {
            while (true)
            {
                var buffer = new byte[chunk];
                var read = await source.ReadAtLeastAsync(buffer, chunk, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                inFlight.Enqueue((SendWriteAsync(handle, offset, buffer.AsMemory(0, read), cancellationToken), read));
                offset += read;
                if (inFlight.Count >= options.MaxRequestsInFlight)
                {
                    await AcknowledgeAsync().ConfigureAwait(false);
                }

                if (read < chunk)
                {
                    break;
                }
            }

            while (inFlight.Count > 0)
            {
                await AcknowledgeAsync().ConfigureAwait(false);
            }

            return offset - start;
        }
        finally
        {
            while (inFlight.Count > 0)
            {
                try
                {
                    await inFlight.Dequeue().Reply.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Already failing.
                }
            }
        }

        async Task AcknowledgeAsync()
        {
            var (reply, length) = inFlight.Dequeue();
            ExpectWritten(await reply.ConfigureAwait(false), path);
            acknowledged += length;
            options.Progress?.Report(acknowledged);
        }
    }

    // ---- replies ----

    private static void CheckPath(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (path.Contains('\0'))
        {
            throw new ArgumentException("A remote path must not contain NUL.", nameof(path));
        }
    }

    private static bool IsEndOfFile(SftpResponse reply) =>
        reply.Type == SftpProtocol.Status && reply.Body.ReadUInt32() == (uint)SftpStatusCode.EndOfFile;

    private static void ExpectOk(SftpResponse reply, string operation, string? path)
    {
        if (reply.Type != SftpProtocol.Status || reply.Body.ReadUInt32() != (uint)SftpStatusCode.Ok)
        {
            ThrowStatus(reply, operation, path);
        }
    }

    private static byte[] ExpectHandle(SftpResponse reply, string operation, string path)
    {
        if (reply.Type != SftpProtocol.Handle)
        {
            ThrowStatus(reply, operation, path);
        }

        var handle = Parse(reply, static (ref SshReader r) => r.ReadString().ToArray());
        return handle.Length is > 0 and <= 256 ? handle : throw new SshException(SshFailureReason.ProtocolError, "The SFTP server sent an invalid handle.");
    }

    private static SftpFileAttributes ExpectAttributes(SftpResponse reply, string operation, string path)
    {
        if (reply.Type != SftpProtocol.Attrs)
        {
            ThrowStatus(reply, operation, path);
        }

        return Parse(reply, static (ref SshReader r) => SftpFileAttributes.Read(ref r));
    }

    private static List<(string Name, string LongName, SftpFileAttributes Attributes)> ExpectNames(SftpResponse reply, string operation, string? path)
    {
        if (reply.Type != SftpProtocol.Name)
        {
            ThrowStatus(reply, operation, path);
        }

        return Parse(reply, static (ref SshReader r) =>
        {
            var count = r.ReadUInt32();
            var names = new List<(string, string, SftpFileAttributes)>((int)Math.Min(count, 1024));
            for (var i = 0; i < count; i++)
            {
                names.Add((r.ReadUtf8String(), r.ReadUtf8String(), SftpFileAttributes.Read(ref r)));
            }

            return names;
        });
    }

    private static string SingleName(SftpResponse reply, string operation, string? path)
    {
        var names = ExpectNames(reply, operation, path);
        return names.Count == 1 ? names[0].Name : throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server answered with {names.Count} names instead of one.");
    }

    private delegate T BodyParser<out T>(ref SshReader reader);

    private static T Parse<T>(SftpResponse reply, BodyParser<T> parse)
    {
        try
        {
            var reader = reply.Body;
            return parse(ref reader);
        }
        catch (SshProtocolException ex)
        {
            throw new SshException(SshFailureReason.ProtocolError, "The SFTP server sent a malformed reply.", ex);
        }
    }

    [DoesNotReturn]
    private static void ThrowStatus(SftpResponse reply, string operation, string? path)
    {
        if (reply.Type != SftpProtocol.Status)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server answered with message {reply.Type} where a status or result was expected.");
        }

        var (code, text) = Parse(reply, static (ref SshReader r) =>
        {
            var status = r.ReadUInt32();
            var message = r.IsEmpty ? string.Empty : r.ReadUtf8String(); // optional in some servers' replies
            return (status, message);
        });
        var status = (SftpStatusCode)code;
        var reason = SanitizedMessage(text) is { Length: > 0 } said ? said : status switch
        {
            SftpStatusCode.NoSuchFile => "No such file",
            SftpStatusCode.PermissionDenied => "Permission denied",
            SftpStatusCode.OperationUnsupported => "Operation unsupported",
            SftpStatusCode.EndOfFile => "End of file",
            _ => "Failure",
        };
        throw new SftpException(status, path is null ? $"{operation} failed: {reason}." : $"{operation} '{path}' failed: {reason}.", path);
    }

    /// <summary>The server's message, without control characters and at most 200 characters (it ends up in logs).</summary>
    private static string SanitizedMessage(string text)
    {
        var clean = new StringBuilder(Math.Min(text.Length, 200));
        foreach (var c in text)
        {
            if (clean.Length == 200)
            {
                break;
            }

            if (!char.IsControl(c))
            {
                clean.Append(c);
            }
        }

        return clean.ToString().Trim();
    }
}

/// <summary>The sizes an SFTP server accepts (<c>limits@openssh.com</c>), as used for reads and writes.</summary>
/// <param name="MaxReadLength">The largest read requested.</param>
/// <param name="MaxWriteLength">The largest write sent.</param>
/// <param name="MaxOpenHandles">How many files may be open at once, if the server says.</param>
[Experimental(SftpClient.ExperimentalId)]
public sealed record SftpLimits(int MaxReadLength, int MaxWriteLength, int? MaxOpenHandles);

/// <summary>A directory entry from <see cref="SftpClient.ListDirectoryAsync"/>.</summary>
/// <param name="Name">The entry's name.</param>
/// <param name="FullPath">The directory's path joined with the name.</param>
/// <param name="LongName">The server's <c>ls -l</c> style line for the entry (informational; its format is not standard).</param>
/// <param name="Attributes">The entry's attributes; a symbolic link is described itself, not its target.</param>
[Experimental(SftpClient.ExperimentalId)]
public sealed record SftpFileInfo(string Name, string FullPath, string LongName, SftpFileAttributes Attributes);

/// <summary>Options for <see cref="SftpClient"/>'s uploads and downloads.</summary>
[Experimental(SftpClient.ExperimentalId)]
public sealed class SftpTransferOptions
{
    /// <summary>Replace an existing destination file (default true, as <c>sftp put</c> and <c>get</c> do); otherwise it is an error.</summary>
    public bool Overwrite { get; init; } = true;

    /// <summary>Copy the source's modification and access times to the destination.</summary>
    public bool PreserveTimes { get; init; }

    /// <summary>
    /// Continue an interrupted transfer, as sftp's <c>reget</c> and <c>reput</c> do: the destination's existing bytes are taken as the
    /// source's first ones, and only the rest is sent; a destination larger than the source is an error. Nothing checks that the
    /// existing bytes match, so use it for the same file only. A failed download with this set keeps what arrived. Overrides
    /// <see cref="Overwrite"/> for an existing destination.
    /// </summary>
    public bool Resume { get; init; }

    /// <summary>Reports the bytes transferred so far.</summary>
    public IProgress<long>? Progress { get; init; }

    /// <summary>How many reads or writes may be in flight at once (default 64, as OpenSSH's sftp). More helps on links with latency.</summary>
    public int MaxRequestsInFlight
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 1024);
            field = value;
        }
    } = 64;
}
