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
/// separator, whatever this machine uses.
/// </remarks>
public sealed partial class SftpClient : IAsyncDisposable
{
    /// <summary>The most entries one directory listing returns before the server is taken to be looping.</summary>
    internal const long MaxListingEntries = 1_000_000;

    /// <summary>The most empty NAME replies in a row a listing accepts before the server is taken to be looping.</summary>
    internal const int MaxEmptyBatches = 1_000;

    private readonly SftpChannel _channel;

    private SftpClient(SftpChannel channel, SftpLimits limits, bool symlinkInDraftOrder)
    {
        _channel = channel;
        Limits = limits;
        _symlinkInDraftOrder = symlinkInDraftOrder;
    }

    // SSH_FXP_SYMLINK's argument order: the draft's (link, then target) for servers that follow it, otherwise OpenSSH's reversed one.
    private readonly bool _symlinkInDraftOrder;

    /// <summary>
    /// Whether the server takes SSH_FXP_SYMLINK in the draft's order (link path, then target). OpenSSH's sftp-server reverses it
    /// (PROTOCOL 4.1), and most servers follow OpenSSH (Dropbear runs OpenSSH's sftp-server; Go's pkg/sftp and Apache MINA SSHD take
    /// the same order). AsyncSSH keeps the draft's order with clients that are not OpenSSH or paramiko, which it knows to reverse, and
    /// Erlang/OTP's ssh_sftpd always keeps it, so both get the draft's order.
    /// </summary>
    /// <param name="serverSoftware">The software part of the server's identification (<c>AsyncSSH_2.21.0</c>, <c>Erlang/5.3.3</c>), as the transport parsed it.</param>
    internal static bool TakesSymlinkInDraftOrder(string? serverSoftware) =>
        serverSoftware is not null
        && (serverSoftware.StartsWith("AsyncSSH_", StringComparison.Ordinal) || serverSoftware.StartsWith("Erlang/", StringComparison.Ordinal));

    /// <summary>The protocol version the server speaks (3 for OpenSSH).</summary>
    public int ProtocolVersion => (int)_channel.Version;

    /// <summary>The protocol extensions the server announced, with their versions, for example <c>posix-rename@openssh.com</c> = <c>1</c>.</summary>
    public IReadOnlyDictionary<string, string> Extensions => _channel.Extensions;

    /// <summary>The server's limits (<c>limits@openssh.com</c>), or the defaults every server accepts when it announces none.</summary>
    public SftpLimits Limits { get; }

    /// <summary>
    /// How long a request may go unanswered while the server sends nothing at all, before it fails with an <see cref="SshException"/>
    /// (<see cref="SshFailureReason.Timeout"/>, with a <see cref="TimeoutException"/> inside). The default,
    /// <see cref="Timeout.InfiniteTimeSpan"/>, waits for as long as the session lasts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The limit is on the server's silence, not on how long an operation takes: while the server keeps answering other requests (a
    /// transfer's window of reads or writes on a slow link, or other callers on this session), a request waits on, so a large file is
    /// never cut off for its size. A server or link that has stopped answering fails every waiting request once this much time has
    /// passed without a reply. It applies to every request, those of transfers, streams and listings included; the
    /// <see cref="CancellationToken"/> each method takes still works alongside it, and cancelling is an
    /// <see cref="OperationCanceledException"/>, never a timeout.
    /// </para>
    /// <para>
    /// A request that timed out is abandoned, not undone: the server may still carry it out, and its late reply is dropped (a handle it
    /// opens is closed). The session stays usable. It can be changed at any time; requests already waiting keep the value they started
    /// with. A segmented download's extra sessions (<see cref="SftpTransferOptions.Segments"/>) take this session's value.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not positive and not <see cref="Timeout.InfiniteTimeSpan"/>, or longer than <see cref="int.MaxValue"/> milliseconds.</exception>
    public TimeSpan OperationTimeout
    {
        get => _channel.OperationTimeout;
        set
        {
            if (value != Timeout.InfiniteTimeSpan)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value, TimeSpan.FromMilliseconds(int.MaxValue));
            }

            _channel.OperationTimeout = value;
        }
    }

    /// <summary>Opens another SFTP session on the same connection (for <see cref="SftpTransferOptions.Segments"/>); null when unknown.</summary>
    internal Func<CancellationToken, Task<SftpClient>>? OpenSibling { get; set; }

    internal static async Task<SftpClient> StartAsync(SshSession session, string? serverSoftware, CancellationToken cancellationToken)
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
                    limits = ParseLimits(reply);
                }
            }

            return new SftpClient(channel, limits, TakesSymlinkInDraftOrder(serverSoftware));
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>The reply to <c>limits@openssh.com</c>: max packet, read and write lengths, and open handles (each 0 when unlimited).</summary>
    private static SftpLimits ParseLimits(SftpResponse reply)
    {
        var (maxRead, maxWrite, maxHandles) = Parse(reply, static (ref SshReader r) =>
        {
            r.ReadUInt64(); // max packet length: the read and write lengths already fit it
            return (r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64());
        });
        return new SftpLimits(Chunk(maxRead), Chunk(maxWrite), maxHandles is 0 or > int.MaxValue ? null : (int)maxHandles);

        static int Chunk(ulong announced) => announced == 0 ? SftpProtocol.DefaultChunk : (int)Math.Min(announced, SftpProtocol.MaxChunk);
    }

    /// <summary>
    /// Parses any reply packet (type, request id, body) the way the client would, for fuzzing: everything the server can send passes
    /// through one of these parsers. Rejects malformed input only with <see cref="SshException"/> (including <see cref="SftpException"/>).
    /// </summary>
    internal static void ParseAnyReply(byte[] packet)
    {
        if (packet.Length < 5)
        {
            return; // the packet reader rejects these before any parser sees them
        }

        var reply = new SftpResponse(packet[0], packet);
        switch (packet[0])
        {
            case SftpProtocol.VersionReply:
                SftpChannel.ParseVersion(packet);
                break;
            case SftpProtocol.ExtendedReply:
                ParseLimits(reply);
                ParseStatVfs(reply);
                break;
            case SftpProtocol.Attrs:
                ExpectAttributes(reply, "Fuzzing", "path");
                break;
            case SftpProtocol.Name:
                ExpectNames(reply, "Fuzzing", "path");
                break;
            case SftpProtocol.Handle:
                ExpectHandle(reply, "Fuzzing", "path");
                break;
            case SftpProtocol.Data:
                ExpectData(reply, SftpProtocol.MaxChunk, "path");
                break;
            default:
                ExpectOk(reply, "Fuzzing", "path"); // a status, or an unexpected type
                break;
        }
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
    public Task SetAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default) =>
        SetAttributesAsync(path, attributes, followSymbolicLinks: true, cancellationToken);

    /// <summary>
    /// Changes the attributes that are set in <paramref name="attributes"/>; of a symbolic link itself when
    /// <paramref name="followSymbolicLinks"/> is false (<c>lsetstat@openssh.com</c>, OpenSSH 8.0+: owner, permissions and times; a
    /// server may refuse a size).
    /// </summary>
    /// <exception cref="NotSupportedException">Not following links, and the server lacks <c>lsetstat@openssh.com</c>.</exception>
    public async Task SetAttributesAsync(string path, SftpFileAttributes attributes, bool followSymbolicLinks, CancellationToken cancellationToken = default)
    {
        if (!followSymbolicLinks)
        {
            await SetLinkAttributesAsync(path, attributes, cancellationToken).ConfigureAwait(false);
            return;
        }

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
    /// <remarks>
    /// Names are UTF-8 in SFTP version 3 as OpenSSH uses it; a name that is not valid UTF-8 (a legacy encoding on the server) is listed with
    /// U+FFFD in place of the bytes it cannot decode, so <see cref="SftpFileInfo.FullPath"/> cannot open it. A listing stops with an error
    /// (<see cref="SshFailureReason.ProtocolError"/>) after 1,000,000 entries or 1,000 empty batches in a row, so a hostile server cannot make it
    /// run forever.
    /// </remarks>
    public async IAsyncEnumerable<SftpFileInfo> ListDirectoryAsync(string path, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        var opened = await _channel.RequestAsync(SftpProtocol.OpenDir, w => w.WriteString(path), cancellationToken, CloseOrphanedHandle).ConfigureAwait(false);
        var handle = ExpectHandle(opened, "Listing", path);
        try
        {
            var prefix = path.EndsWith('/') ? path : path + "/";
            var total = 0L;
            var emptyBatches = 0;
            while (true)
            {
                var reply = await _channel.RequestAsync(SftpProtocol.ReadDir, w => w.WriteString(handle), cancellationToken).ConfigureAwait(false);
                if (IsEndOfFile(reply))
                {
                    yield break;
                }

                var names = ExpectNames(reply, "Listing", path);
                total += names.Count;
                emptyBatches = names.Count == 0 ? emptyBatches + 1 : 0;
                if (total > MaxListingEntries || emptyBatches > MaxEmptyBatches)
                {
                    throw new SshException(SshFailureReason.ProtocolError,
                        $"The SFTP server's listing of '{path}' does not end ({total} entries, {emptyBatches} empty batches in a row).");
                }

                foreach (var (name, longName, attributes) in names)
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

    /// <summary>
    /// Creates a directory, with <paramref name="permissions"/> if given (the server's umask applies). To create missing parents too,
    /// and accept an existing directory, use <see cref="CreateDirectoryAsync(string, bool, UnixFileMode?, CancellationToken)"/>.
    /// </summary>
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

    /// <summary>
    /// Deletes an empty directory. To delete one with everything in it, use
    /// <see cref="DeleteDirectoryAsync(string, bool, CancellationToken)"/>.
    /// </summary>
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

    /// <summary>
    /// The login directory: the server's <c>home-directory</c> extension when it has one, otherwise what <c>.</c> resolves to. In an
    /// OpenSSH <c>ChrootDirectory</c> session the extension answers the passwd home, outside the chroot; relative paths resolve from
    /// <see cref="GetFullPathAsync"/> of <c>.</c>.
    /// </summary>
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
        if (reply.Type == SftpProtocol.Status)
        {
            // PROTOCOL says an empty name means the session's user, but OpenSSH before 10.x answers Failure (it looks the empty name
            // up as a user); the login directory is where "." resolves, which every server answers.
            return await GetFullPathAsync(".", cancellationToken).ConfigureAwait(false);
        }

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

        // OpenSSH's sftp-server takes the arguments in the reverse of the draft's order (PROTOCOL 4.1), and most servers follow it; a
        // server that keeps the draft's order would otherwise create the link at the target's path (see TakesSymlinkInDraftOrder).
        var (first, second) = _symlinkInDraftOrder ? (linkPath, targetPath) : (targetPath, linkPath);
        var reply = await _channel.RequestAsync(SftpProtocol.Symlink, w =>
        {
            w.WriteString(first);
            w.WriteString(second);
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
    /// <remarks>
    /// A stream opened only for reading reads ahead (up to 16 reads in flight) while it is read in order, one read at a time: a read while
    /// another is in progress throws <see cref="InvalidOperationException"/>. Writes are written behind:
    /// <see cref="Stream.WriteAsync(ReadOnlyMemory{byte}, CancellationToken)"/> returns once its requests are sent, keeping up to 16 in
    /// flight, so a write the server refuses is thrown by a later call: the next write that finds it, or at the latest
    /// <see cref="Stream.FlushAsync(CancellationToken)"/> or <see cref="Stream.DisposeAsync"/>, which wait for every write in flight (as
    /// do reads and <see cref="Stream.SetLength"/>). The stream is then faulted: every later call throws the same exception, and
    /// disposing still closes the remote file. Cancelling a write also faults the stream.
    /// </remarks>
    public async Task<Stream> OpenAsync(string path, FileMode mode, FileAccess access, CancellationToken cancellationToken = default)
    {
        var (handle, flags) = await OpenHandleAsync(path, mode, access, cancellationToken).ConfigureAwait(false);

        // The size once, now: Length (which Stream.CopyToAsync reads) then needs no round trip, and Append starts at the end.
        long? length;
        try
        {
            length = (await GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size;
        }
        catch
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
            throw;
        }

        var position = mode == FileMode.Append ? length ?? 0 : 0;
        return new SftpFileStream(this, handle, path, (flags & SftpProtocol.OpenRead) != 0, (flags & SftpProtocol.OpenWrite) != 0, position, length);
    }

    /// <summary>Opens a remote file for reading, as <see cref="OpenAsync"/> with <see cref="FileMode.Open"/> and <see cref="FileAccess.Read"/>.</summary>
    public Task<Stream> OpenReadAsync(string path, CancellationToken cancellationToken = default) =>
        OpenAsync(path, FileMode.Open, FileAccess.Read, cancellationToken);

    /// <summary>
    /// Creates or truncates a remote file for writing, as <see cref="OpenAsync"/> with <see cref="FileMode.Create"/>. Writes are written
    /// behind (see <see cref="OpenAsync"/>): end with <see cref="Stream.FlushAsync(CancellationToken)"/> or dispose the stream
    /// asynchronously to see a failed write.
    /// </summary>
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
            var size = options.Progress is null ? null : (await GetHandleAttributesAsync(handle, remotePath, cancellationToken).ConfigureAwait(false)).Size;
            return await DownloadHandleAsync(handle, remotePath, destination, 0, size, options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Downloads <paramref name="remotePath"/> to the local file <paramref name="localPath"/>. With <see cref="SftpTransferOptions.Overwrite"/>
    /// off, an existing local file is an error; with <see cref="SftpTransferOptions.Preserve"/>, the local file gets the remote one's
    /// modification and access times, and its permissions where this system has Unix modes. A failed download leaves no partial file behind.
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
            var segmented = options.Segments > 1 && !options.Resume && OpenSibling is not null;
            var attributes = options.Preserve || options.Progress is not null || resumeFrom > 0 || segmented
                ? await GetHandleAttributesAsync(handle, remotePath, cancellationToken).ConfigureAwait(false)
                : null;
            if (resumeFrom > 0 && attributes!.Size is { } remoteSize && resumeFrom > remoteSize)
            {
                throw new IOException($"The local file is larger than '{remotePath}' ({resumeFrom} > {remoteSize} bytes): it is not a partial download of it.");
            }

            var created = false;
            var segments = segmented && attributes!.Size is { } size ? (int)Math.Min(options.Segments, size / MinSegmentBytes) : 1;
            var total = segments > 1
                ? await DownloadSegmentedAsync(handle, remotePath, localPath, attributes!, segments, options, cancellationToken).ConfigureAwait(false)
                : await DownloadSequentialAsync().ConfigureAwait(false);

            if (attributes is not null && options.Preserve)
            {
                if (attributes.LastWriteTime is { } modified)
                {
                    File.SetLastWriteTimeUtc(localPath, modified.UtcDateTime);
                }

                if (attributes.LastAccessTime is { } accessed)
                {
                    File.SetLastAccessTimeUtc(localPath, accessed.UtcDateTime);
                }

                SetLocalPermissions(localPath, attributes.Permissions);
            }

            return total;

            async Task<long> DownloadSequentialAsync()
            {
                try
                {
                    var mode = resumeFrom > 0 ? FileMode.Append : options.Overwrite || options.Resume ? FileMode.Create : FileMode.CreateNew;
                    await using var file = new FileStream(localPath, mode, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true);
                    created = resumeFrom == 0;
                    return await DownloadHandleAsync(handle, remotePath, file, resumeFrom, attributes?.Size, options, cancellationToken).ConfigureAwait(false);
                }
                catch when (created && !options.Resume)
                {
                    // A fresh download that failed leaves nothing; with Resume, what arrived is kept for the next attempt.
                    File.Delete(localPath);
                    throw;
                }
            }
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>The least a segment of a segmented download is given: smaller files use fewer segments.</summary>
    internal const long MinSegmentBytes = 1024 * 1024;

    /// <summary>
    /// <see cref="SftpTransferOptions.Segments"/>: the file is split into <paramref name="segments"/> ranges, the first fetched over
    /// <paramref name="handle"/> and each other one over a sibling session of its own, all written into the local file at their
    /// offsets. The last range reads on to the end of the file (it may have grown); a range that ends early means the file shrank
    /// meanwhile, which fails the download rather than leave a gap. Each other session opens the file by path again, so it must find
    /// the same size and modification time as <paramref name="attributes"/>: a file replaced or written to in between fails the download
    /// rather than mix two files. The first failure cancels the rest and is the one reported, and the local file is removed.
    /// </summary>
    private async Task<long> DownloadSegmentedAsync(byte[] handle, string remotePath, string localPath, SftpFileAttributes attributes, int segments,
        SftpTransferOptions options, CancellationToken cancellationToken)
    {
        var size = attributes.Size!.Value;

        // A file that is there already fails the download before any session is opened for it (CreateNew below still decides, should
        // one appear meanwhile).
        if (!options.Overwrite && File.Exists(localPath))
        {
            throw new IOException($"The file '{localPath}' already exists.");
        }

        // The sessions first: the server may allow fewer than asked (sshd's MaxSessions), and the ranges are split among those it opens.
        var siblings = new List<SftpClient>();
        try
        {
            for (var i = 1; i < segments; i++)
            {
                try
                {
                    var sibling = await OpenSibling!(cancellationToken).ConfigureAwait(false);
                    sibling.OperationTimeout = OperationTimeout;
                    siblings.Add(sibling);
                }
                catch (SshException ex) when (ex.Reason is SshFailureReason.ChannelClosed or SshFailureReason.ProtocolError)
                {
                    break; // no more sessions: the ones open share the file
                }
                catch (NoMoreSessionsException)
                {
                    break; // the connection refuses new sessions (PreventNewSessionsAsync): this session downloads alone
                }
            }

            SftpClient[] clients = [this, .. siblings];
            var mode = options.Overwrite ? FileMode.Create : FileMode.CreateNew;
            var created = false;
            try
            {
                using var file = File.OpenHandle(localPath, mode, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
                created = true;
                RandomAccess.SetLength(file, size);

                using var failed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                Exception? firstFailure = null;
                var progressLock = new object();
                long transferred = 0;
                var part = size / clients.Length;
                var tasks = new Task<long>[clients.Length];
                for (var i = 0; i < clients.Length; i++)
                {
                    var start = i * part;
                    long? stop = i == clients.Length - 1 ? null : start + part; // the last one reads to the end, wherever that now is
                    tasks[i] = DownloadSegmentAsync(clients[i], i == 0 ? handle : null, start, stop);
                }

                // As a plain Task: Task<T>'s own ConfigureAwait does not take SuppressThrowing.
                Task all = Task.WhenAll(tasks);
                await all.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
                if (Volatile.Read(ref firstFailure) is { } first)
                {
                    // Report the failure that stopped the others, not what it caused in them (cancellations, or a session closing).
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(first);
                }

                await Task.WhenAll(tasks).ConfigureAwait(false); // any other outcome (the caller's cancellation) as it is

                // The last range may have read past the size seen at the start (the file grew), or stopped short of it (it shrank).
                var length = (clients.Length - 1) * part + tasks[^1].Result;
                for (var i = 0; i < clients.Length - 1; i++)
                {
                    if (tasks[i].Result != part)
                    {
                        throw new IOException($"'{remotePath}' became shorter during the download: its part from {i * part} ended early.");
                    }
                }

                RandomAccess.SetLength(file, length);
                return length;

                async Task<long> DownloadSegmentAsync(SftpClient client, byte[]? openHandle, long start, long? stop)
                {
                    try
                    {
                        var segmentHandle = openHandle
                            ?? (await client.OpenHandleAsync(remotePath, FileMode.Open, FileAccess.Read, failed.Token).ConfigureAwait(false)).Handle;
                        try
                        {
                            if (openHandle is null &&
                                await client.GetHandleAttributesAsync(segmentHandle, remotePath, failed.Token).ConfigureAwait(false) is var seen &&
                                (seen.Size != attributes.Size || seen.LastWriteTime != attributes.LastWriteTime))
                            {
                                throw new IOException($"'{remotePath}' changed during the download (replaced or written to): download it again, or without Segments.");
                            }

                            return await client.DownloadRangeAsync(segmentHandle, remotePath, start, stop, async (offset, data, ct) =>
                            {
                                await RandomAccess.WriteAsync(file, data, offset, ct).ConfigureAwait(false);
                                if (options.Progress is { } progress)
                                {
                                    lock (progressLock)
                                    {
                                        transferred += data.Length;
                                        progress.Report(new SftpTransferProgress(remotePath, transferred, size));
                                    }
                                }
                            }, options, failed.Token).ConfigureAwait(false);
                        }
                        finally
                        {
                            if (openHandle is null)
                            {
                                await client.CloseHandleAsync(segmentHandle).ConfigureAwait(false);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!failed.IsCancellationRequested)
                        {
                            Interlocked.CompareExchange(ref firstFailure, ex, null);
                        }

                        await failed.CancelAsync().ConfigureAwait(false); // one part failed: stop the others
                        throw;
                    }
                }
            }
            catch when (created)
            {
                File.Delete(localPath);
                throw;
            }
        }
        finally
        {
            foreach (var sibling in siblings)
            {
                await sibling.DisposeAsync().ConfigureAwait(false);
            }
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
    /// Uploads the local file <paramref name="localPath"/> to <paramref name="remotePath"/>. With <see cref="SftpTransferOptions.Preserve"/>,
    /// the remote file gets the local one's modification and access times, and its permissions where this system has Unix modes.
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

        if (options.Preserve)
        {
            await SetAttributesAsync(remotePath, new SftpFileAttributes
            {
                LastAccessTime = File.GetLastAccessTimeUtc(localPath),
                LastWriteTime = File.GetLastWriteTimeUtc(localPath),
                Permissions = LocalPermissions(localPath),
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

        if (mode == FileMode.Append && access != FileAccess.Write)
        {
            // As FileStream: the server writes at the end whatever the offset, so reading and seeking would not match where writes land.
            throw new ArgumentException("FileMode.Append can only be used with FileAccess.Write.", nameof(access));
        }

        var reply = await _channel.RequestAsync(SftpProtocol.Open, w =>
        {
            w.WriteString(path);
            w.WriteUInt32(flags);
            w.WriteUInt32(0); // no attributes: the server's defaults (0666 less its umask)
        }, cancellationToken, CloseOrphanedHandle).ConfigureAwait(false);
        return (ExpectHandle(reply, "Opening", path), flags);
    }

    /// <summary>The reply to an OPEN or OPENDIR its caller stopped waiting for: a handle it holds is closed, so it does not stay open.</summary>
    private void CloseOrphanedHandle(SftpResponse reply)
    {
        if (reply.Type != SftpProtocol.Handle)
        {
            return;
        }

        try
        {
            _ = CloseHandleAsync(ExpectHandle(reply, "Opening", "(cancelled)"));
        }
        catch (SshException)
        {
            // A malformed handle: nothing to close.
        }
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

    /// <summary>Sends one write; <paramref name="data"/> is copied into the request before this returns, so the caller may reuse it at once.</summary>
    internal Task<SftpResponse> SendWriteAsync(byte[] handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        var frame = StartWrite(handle, offset, data.Length);
        data.Span.CopyTo(frame.GetSpan(data.Length));
        EndWrite(frame, handle, data.Length);
        return _channel.RequestAsync(frame, cancellationToken);
    }

    /// <summary>
    /// Starts a WRITE request with room for <paramref name="capacity"/> bytes of data, in one buffer of the size the whole request needs:
    /// the data goes straight into it (<see cref="SftpRequestFrame.GetMemory"/>), and <see cref="EndWrite"/> fills in its length. The
    /// caller owns the frame until it hands it to the channel.
    /// </summary>
    private static SftpRequestFrame StartWrite(byte[] handle, long offset, int capacity)
    {
        var frame = SftpRequestFrame.Start(SftpProtocol.Write, WriteHeaderLength(handle) + capacity);
        var writer = frame.Writer;
        writer.WriteString(handle);
        writer.WriteUInt64((ulong)offset);
        writer.WriteUInt32(0); // the data's length, filled in by EndWrite
        return frame;
    }

    /// <summary>Takes the <paramref name="count"/> bytes put after a <see cref="StartWrite"/> as the request's data.</summary>
    private static void EndWrite(SftpRequestFrame frame, byte[] handle, int count)
    {
        frame.Advance(count);
        frame.PatchUInt32(WriteHeaderLength(handle) - 4, (uint)count);
    }

    /// <summary>A WRITE request up to its data: length, type, id, handle, offset and data length.</summary>
    private static int WriteHeaderLength(byte[] handle) => SftpRequestFrame.HeaderLength + 4 + handle.Length + 8 + 4;

    /// <summary>
    /// The data in a READ reply, or empty at the end of the file. The data is a slice of <paramref name="reply"/>'s pooled buffer: it is
    /// valid until the reply is disposed, which the caller does once it has copied or written it out.
    /// </summary>
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
        var packet = reply.Packet;
        if (packet.Length < 9)
        {
            throw new SshException(SshFailureReason.ProtocolError, "The SFTP server sent a truncated data reply.");
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(packet.Span[5..]);
        if (length > packet.Length - 9 || length > (uint)requested || length == 0)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server sent {length} bytes for a read of {requested}.");
        }

        return packet.Slice(9, (int)length);
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

    private async Task<long> DownloadHandleAsync(byte[] handle, string path, Stream destination, long start, long? size, SftpTransferOptions options,
        CancellationToken cancellationToken)
    {
        long total = 0;
        return await DownloadRangeAsync(handle, path, start, stop: null, async (_, data, ct) =>
        {
            await destination.WriteAsync(data, ct).ConfigureAwait(false);
            total += data.Length;
            options.Progress?.Report(new SftpTransferProgress(path, start + total, size));
        }, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads <paramref name="handle"/> from <paramref name="start"/> up to <paramref name="stop"/> (or the end of the file), handing each
    /// piece with its file offset to <paramref name="write"/>, in offset order; returns the bytes read.
    /// </summary>
    private async Task<long> DownloadRangeAsync(byte[] handle, string path, long start, long? stop,
        Func<long, ReadOnlyMemory<byte>, CancellationToken, ValueTask> write, SftpTransferOptions options, CancellationToken cancellationToken)
    {
        // A window of reads in flight; replies are written in offset order. The window starts at 2 and doubles with each reply, up to
        // MaxRequestsInFlight, so a small file costs a few requests rather than a full window past its end. A short read (allowed by the
        // draft, but not at the end of the file) gets a follow-up read for the rest, at the front of the queue, so the output stays in order.
        //
        // In a directory transfer with several files at once, each read also takes a slot of the transfer's shared budget
        // (SftpTransferOptions.RequestBudget), held until its data is written out: the files together keep at most MaxRequestsInFlight
        // reads, and their data, in memory. A file that has reads in flight never waits for a slot; it takes the next one only as it
        // frees its own, so files waiting on each other cannot hold every slot.
        var chunk = Limits.MaxReadLength;
        var budget = options.RequestBudget;
        var window = Math.Min(2, options.MaxRequestsInFlight);
        var inFlight = new LinkedList<(long Offset, int Length, Task<SftpResponse> Reply)>();
        var next = start;
        var end = false;
        long total = 0;
        try
        {
            while (true)
            {
                while (!end && inFlight.Count < window && (stop is not { } limit || next < limit))
                {
                    if (budget is not null && !budget.Wait(0, cancellationToken))
                    {
                        if (inFlight.Count > 0)
                        {
                            break; // the replies due free slots of this file's own
                        }

                        await budget.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }

                    var requested = stop is { } last ? (int)Math.Min(chunk, last - next) : chunk;
                    inFlight.AddLast((next, requested, SendReadAsync(handle, next, requested, cancellationToken)));
                    next += requested;
                }

                if (inFlight.Count == 0)
                {
                    return total;
                }

                var (offset, length, pending) = inFlight.First!.Value;
                inFlight.RemoveFirst();
                var slotPassedOn = false;
                try
                {
                    // The data is a slice of the reply's pooled buffer: it is written out before the reply is disposed, and not used after.
                    using var reply = await pending.ConfigureAwait(false);
                    var data = ExpectData(reply, length, path);                    if (data.IsEmpty)
                    {
                        end = true; // the later reads are past the end too; their replies are awaited (and dropped) below
                        continue;
                    }

                    if (!end)
                    {
                        if (data.Length == length)
                        {
                            window = Math.Min(window * 2, options.MaxRequestsInFlight); // a full reply: more is likely to follow
                        }

                        await write(offset, data, cancellationToken).ConfigureAwait(false);
                        total += data.Length;
                        if (data.Length < length)
                        {
                            // The follow-up read takes over this read's slot: it must go out, and before anything else of this file.
                            var rest = offset + data.Length;
                            inFlight.AddFirst((rest, length - data.Length, SendReadAsync(handle, rest, length - data.Length, cancellationToken)));
                            slotPassedOn = true;
                        }
                    }
                }
                finally
                {
                    if (!slotPassedOn)
                    {
                        budget?.Release();
                    }
                }
            }
        }
        finally
        {
            // Replies still due are awaited, so none arrives after the handle is closed and the caller moves on; their buffers go back.
            foreach (var (_, _, pending) in inFlight)
            {
                try
                {
                    (await pending.ConfigureAwait(false)).Dispose();
                }
                catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
                {
                    // Already failing.
                }
                finally
                {
                    budget?.Release();
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
        // A window of writes in flight; progress counts what the server has acknowledged. In a directory transfer with several files at
        // once, each write (and its buffer) also holds a slot of the transfer's shared budget until it is acknowledged, taken as in
        // DownloadRangeAsync: a file with writes in flight frees its own rather than wait.
        var chunk = Limits.MaxWriteLength;
        var budget = options.RequestBudget;
        var inFlight = new Queue<(Task<SftpResponse> Reply, int Length)>();
        long offset = start, acknowledged = 0;
        long? size = options.Progress is not null && source.CanSeek ? source.Length : null;
        try
        {
            while (true)
            {
                if (budget is not null)
                {
                    await TakeSlotAsync(budget).ConfigureAwait(false);
                }

                // The request is built in one pooled buffer, and the source is read straight into its data: no buffer of its own, no copy.
                // This method owns the frame until RequestAsync takes it over, which returns it once it is sent.
                var frame = StartWrite(handle, offset, chunk);
                var handedOver = false;
                int read;
                try
                {
                    try
                    {
                        read = await source.ReadAtLeastAsync(frame.GetMemory(chunk)[..chunk], chunk, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        budget?.Release();
                        throw;
                    }

                    if (read == 0)
                    {
                        budget?.Release();
                        break;
                    }

                    EndWrite(frame, handle, read);
                    var request = _channel.RequestAsync(frame, cancellationToken); // takes the frame over, whatever happens
                    handedOver = true;
                    inFlight.Enqueue((request, read));
                }
                finally
                {
                    if (!handedOver)
                    {
                        frame.Dispose();
                    }
                }

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
                catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
                {
                    // Already failing.
                }
                finally
                {
                    budget?.Release();
                }
            }
        }

        async Task AcknowledgeAsync()
        {
            var (reply, length) = inFlight.Dequeue();
            try
            {
                ExpectWritten(await reply.ConfigureAwait(false), path);
            }
            finally
            {
                budget?.Release();
            }

            acknowledged += length;
            options.Progress?.Report(new SftpTransferProgress(path, start + acknowledged, size));
        }

        async Task TakeSlotAsync(SemaphoreSlim slots)
        {
            while (!slots.Wait(0, cancellationToken))
            {
                if (inFlight.Count == 0)
                {
                    await slots.WaitAsync(cancellationToken).ConfigureAwait(false);
                    return;
                }

                await AcknowledgeAsync().ConfigureAwait(false); // frees a slot of this file's own
            }
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
                // Lenient: one name in a legacy encoding must not fail the whole listing (it shows U+FFFD where bytes do not decode).
                var name = SftpChannel.Lenient(r.ReadString());
                var longName = SftpChannel.Lenient(r.ReadString());
                names.Add((name, longName, SftpFileAttributes.Read(ref r)));
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
            var message = r.IsEmpty ? string.Empty : SftpChannel.Lenient(r.ReadString()); // optional in some servers' replies
            return (status, message);
        });
        var status = (SftpStatusCode)code;
        if (status == SftpStatusCode.Ok)
        {
            // Success where a handle, data, attributes or names were expected is not an error this client can report as one.
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server answered OK where a result was expected ({operation}).");
        }

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
public sealed record SftpLimits(int MaxReadLength, int MaxWriteLength, int? MaxOpenHandles);

/// <summary>A directory entry from <see cref="SftpClient.ListDirectoryAsync"/>.</summary>
/// <param name="Name">The entry's name.</param>
/// <param name="FullPath">The directory's path joined with the name.</param>
/// <param name="LongName">The server's <c>ls -l</c> style line for the entry (informational; its format is not standard).</param>
/// <param name="Attributes">The entry's attributes; a symbolic link is described itself, not its target.</param>
public sealed record SftpFileInfo(string Name, string FullPath, string LongName, SftpFileAttributes Attributes);

/// <summary>The names of user and group ids, from <see cref="SftpClient.GetOwnerNamesAsync"/>.</summary>
/// <param name="UserNames">The user names by id; an id the server cannot name is left out.</param>
/// <param name="GroupNames">The group names by id; an id the server cannot name is left out.</param>
public sealed record SftpOwnerNames(IReadOnlyDictionary<uint, string> UserNames, IReadOnlyDictionary<uint, string> GroupNames);

/// <summary>The progress of one file in an SFTP transfer (<see cref="SftpTransferOptions.Progress"/>).</summary>
/// <param name="Path">The file's remote path.</param>
/// <param name="BytesTransferred">The file's bytes transferred so far, including what a resumed transfer found there already.</param>
/// <param name="TotalBytes">The file's size, or null when it is not known (an upload from a stream that cannot tell its length).</param>
public sealed record SftpTransferProgress(string Path, long BytesTransferred, long? TotalBytes);

/// <summary>Options for <see cref="SftpClient"/>'s uploads and downloads.</summary>
public sealed class SftpTransferOptions
{
    /// <summary>Replace an existing destination file (default true, as <c>sftp put</c> and <c>get</c> do); otherwise it is an error.</summary>
    public bool Overwrite { get; init; } = true;

    /// <summary>
    /// Copy the source's modification and access times, and its permission bits (read, write and execute for the owner, the group and
    /// others), to the destination, as <c>sftp -p</c> does. Permissions are copied only where the receiving side has Unix modes: a
    /// download to Windows keeps the times only, and an upload from Windows sends none. Unlike OpenSSH, setuid, setgid and the sticky bit
    /// are never copied, so a server cannot hand this machine a setuid file.
    /// </summary>
    public bool Preserve { get; init; }

    /// <summary>
    /// Continue an interrupted transfer, as sftp's <c>reget</c> and <c>reput</c> do: the destination's existing bytes are taken as the
    /// source's first ones, and only the rest is sent; a destination larger than the source is an error. Nothing checks that the
    /// existing bytes match, so use it for the same file only. A failed download with this set keeps what arrived. Overrides
    /// <see cref="Overwrite"/> for an existing destination.
    /// </summary>
    public bool Resume { get; init; }

    /// <summary>Reports each file's progress: its path, the bytes transferred so far and its size, when known.</summary>
    public IProgress<SftpTransferProgress>? Progress { get; init; }

    /// <summary>
    /// How many reads or writes may be in flight at once (default 64, as OpenSSH's sftp). More helps on links with latency. It bounds the
    /// whole transfer: one file's reads or writes, or in a directory transfer with <see cref="MaxConcurrentFiles"/> above 1 those of all
    /// its files together, so at most this many, each of up to <see cref="SftpLimits.MaxReadLength"/> or
    /// <see cref="SftpLimits.MaxWriteLength"/> bytes, are held in memory at once.
    /// </summary>
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

    /// <summary>
    /// How many parts of one file <see cref="SftpClient.DownloadFileAsync"/> fetches at once, each over its own SFTP session on the same
    /// connection (default 1: one session). Each session is an SSH channel with its own flow-control window, and on OpenSSH its own
    /// <c>sftp-server</c> process, so on a link with high latency several segments move more than one session can: one session carries at
    /// most its 2 MiB window per round trip. It does not help where the bandwidth, or the server's single connection, is the limit.
    /// Files smaller than 1 MiB per segment use fewer segments; the server may allow fewer sessions (sshd's <c>MaxSessions</c>, 10 by
    /// default), and then fewer are used. Ignored with <see cref="Resume"/> (only a sequential download leaves a prefix to resume from)
    /// and by <see cref="SftpClient.DownloadAsync"/>, which writes a stream in order. Each extra session opens the file by path, so a
    /// file whose size or modification time has changed by then (replaced, or still being written) fails the download.
    /// </summary>
    public int Segments
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 16);
            field = value;
        }
    } = 1;

    /// <summary>
    /// How many files <see cref="SftpClient.UploadDirectoryAsync"/> and <see cref="SftpClient.DownloadDirectoryAsync"/> transfer at once
    /// over the same SFTP session (default 1: one after another; at most 64). Each file costs round trips of its own (open, attributes,
    /// close), so on a link with latency a tree of many small files moves several times faster with 4 to 16. It does not speed up a few
    /// large files, which already keep <see cref="MaxRequestsInFlight"/> requests in flight (<see cref="Segments"/> is for those). The
    /// single-file methods ignore it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The files share the transfer's <see cref="MaxRequestsInFlight"/> reads or writes rather than take that many each, so the memory the
    /// transfer holds does not grow with this setting: at most <see cref="MaxRequestsInFlight"/> times the read or write length (64 ×
    /// 32 KiB by default, or 64 × 255 KiB with OpenSSH's limits, about 16 MiB), plus a 64 KiB local file buffer for each file in flight.
    /// Opening, closing and setting attributes add about one small request for each file in flight.
    /// </para>
    /// <para>
    /// A directory is created before any file goes into it, and directories are created several at a time. With <see cref="Preserve"/>,
    /// directories get their times and permissions once every file is in, the deepest first. When the server announces
    /// <see cref="SftpLimits.MaxOpenHandles"/>, fewer files are transferred at once if needed, keeping a handle free for listings.
    /// </para>
    /// <para>
    /// The first failure cancels the files still in flight and is the exception the transfer throws. A cancelled file is left as a failed
    /// single-file transfer leaves it: a download is deleted (unless <see cref="Resume"/> is set), an upload keeps what was written.
    /// <see cref="Progress"/> reports each file's progress as before, the files' reports interleaved but never made at the same time.
    /// </para>
    /// </remarks>
    public int MaxConcurrentFiles
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 64);
            field = value;
        }
    } = 1;

    /// <summary>
    /// The slots a directory transfer's files share for their reads and writes (<see cref="MaxRequestsInFlight"/> in all), or null in a
    /// transfer of one file: a read or write holds one until its data is written out or acknowledged.
    /// </summary>
    internal SemaphoreSlim? RequestBudget { get; init; }

    /// <summary>These options for the files of a directory transfer: reporting through <paramref name="progress"/>, sharing <paramref name="budget"/>.</summary>
    internal SftpTransferOptions ForFilesOfDirectory(IProgress<SftpTransferProgress>? progress, SemaphoreSlim budget) => new()
    {
        Overwrite = Overwrite,
        Preserve = Preserve,
        Resume = Resume,
        Progress = progress,
        MaxRequestsInFlight = MaxRequestsInFlight,
        Segments = Segments,
        MaxConcurrentFiles = MaxConcurrentFiles,
        RequestBudget = budget,
    };
}
