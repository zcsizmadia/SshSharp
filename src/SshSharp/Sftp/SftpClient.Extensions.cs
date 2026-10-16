using System.Diagnostics.CodeAnalysis;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>
    /// The size and free space of the file system that holds <paramref name="path"/>, as <c>df</c> shows them
    /// (<c>statvfs@openssh.com</c>).
    /// </summary>
    /// <exception cref="NotSupportedException">The server lacks <c>statvfs@openssh.com</c>.</exception>
    public async Task<SftpFileSystemInfo> GetFileSystemInfoAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        Require(SftpProtocol.StatVfsExtension, "report file system space");
        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.StatVfsExtension);
            w.WriteString(path);
        }, cancellationToken).ConfigureAwait(false);
        if (reply.Type != SftpProtocol.ExtendedReply)
        {
            ThrowStatus(reply, "Reading file system information for", path);
        }

        return ParseStatVfs(reply);
    }

    /// <summary>
    /// Copies <paramref name="sourcePath"/> to <paramref name="destinationPath"/> on the server (<c>copy-data</c>): the data never travels
    /// through this machine. The destination is created, or with <paramref name="overwrite"/> replaced.
    /// </summary>
    /// <returns>Nothing; the copy is complete when this returns.</returns>
    /// <exception cref="NotSupportedException">The server lacks <c>copy-data</c>; download and upload instead.</exception>
    /// <exception cref="SftpException">The destination is the source itself (<see cref="SftpStatusCode.Failure"/>), or another error.</exception>
    public async Task CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        CheckPath(sourcePath);
        CheckPath(destinationPath);
        Require(SftpProtocol.CopyDataExtension, "copy files on the server");

        // A copy onto itself is refused up front (as File.Copy does): the paths are compared as the server resolves them, links included.
        // A hard link to the source cannot be told apart, so the destination is never truncated before the copy (see below).
        if (await IsSameFileAsync(sourcePath, destinationPath, cancellationToken).ConfigureAwait(false))
        {
            throw new SftpException(SftpStatusCode.Failure, $"Copying '{sourcePath}' failed: the destination is the source file itself.", destinationPath);
        }

        var (source, _) = await OpenHandleAsync(sourcePath, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
        try
        {
            var size = (await GetHandleAttributesAsync(source, sourcePath, cancellationToken).ConfigureAwait(false)).Size;

            // Opened without truncating: the copy overwrites in place, then the size is set, so even the same file reached another way
            // keeps its data. Only when the server does not say the source's size is the destination emptied first.
            var (destination, _) = await OpenHandleAsync(destinationPath, overwrite ? FileMode.OpenOrCreate : FileMode.CreateNew, FileAccess.Write, cancellationToken).ConfigureAwait(false);
            try
            {
                if (overwrite && size is null)
                {
                    await SetHandleAttributesAsync(destination, destinationPath, new SftpFileAttributes { Size = 0 }, cancellationToken).ConfigureAwait(false);
                }

                var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
                {
                    w.WriteString(SftpProtocol.CopyDataExtension);
                    w.WriteString(source);
                    w.WriteUInt64(0); // from the start
                    w.WriteUInt64(0); // to the end of the file
                    w.WriteString(destination);
                    w.WriteUInt64(0);
                }, cancellationToken).ConfigureAwait(false);
                ExpectOk(reply, "Copying", sourcePath);
                if (overwrite && size is { } length)
                {
                    await SetHandleAttributesAsync(destination, destinationPath, new SftpFileAttributes { Size = length }, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                await CloseHandleAsync(destination).ConfigureAwait(false);
            }
        }
        finally
        {
            await CloseHandleAsync(source).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Whether two paths name the same file as the server resolves them (realpath, so <c>./a</c>, <c>a</c> and a link to it are one). A
    /// destination that cannot be resolved (it does not exist yet) is not the source.
    /// </summary>
    internal async Task<bool> IsSameFileAsync(string sourcePath, string destinationPath, CancellationToken cancellationToken)
    {
        if (sourcePath == destinationPath)
        {
            return true;
        }

        string destination;
        try
        {
            destination = await GetFullPathAsync(destinationPath, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException)
        {
            return false;
        }

        try
        {
            return await GetFullPathAsync(sourcePath, cancellationToken).ConfigureAwait(false) == destination;
        }
        catch (SftpException)
        {
            return false; // the open reports the missing source
        }
    }

    /// <summary>Asks the server to write an open file's data to disk (<c>fsync@openssh.com</c>); false when it cannot.</summary>
    internal async Task<bool> SyncHandleAsync(byte[] handle, string path, CancellationToken cancellationToken)
    {
        if (!Extensions.ContainsKey(SftpProtocol.FsyncExtension))
        {
            return false;
        }

        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.FsyncExtension);
            w.WriteString(handle);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Flushing", path);
        return true;
    }

    /// <summary>
    /// <paramref name="path"/> with a leading <c>~</c> or <c>~user</c> expanded and made canonical, as <c>sftp</c> does for
    /// <c>cd ~/dir</c> (<c>expand-path@openssh.com</c>, OpenSSH 8.7+). Without the extension, <c>~</c> and <c>~/...</c> start at
    /// <see cref="GetHomeDirectoryAsync"/>, and a path without a tilde resolves as <see cref="GetFullPathAsync"/> does.
    /// </summary>
    /// <exception cref="NotSupportedException">The path starts with <c>~user</c> and the server lacks <c>expand-path@openssh.com</c>.</exception>
    /// <exception cref="SftpException">The path cannot be resolved, or the user is unknown.</exception>
    public async Task<string> ExpandPathAsync(string path, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        if (Extensions.ContainsKey(SftpProtocol.ExpandPathExtension))
        {
            var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
            {
                w.WriteString(SftpProtocol.ExpandPathExtension);
                w.WriteString(path);
            }, cancellationToken).ConfigureAwait(false);
            return SingleName(reply, "Expanding", path);
        }

        if (!path.StartsWith('~'))
        {
            return await GetFullPathAsync(path, cancellationToken).ConfigureAwait(false);
        }

        if (path != "~" && !path.StartsWith("~/", StringComparison.Ordinal))
        {
            Require(SftpProtocol.ExpandPathExtension, "expand another user's home directory");
        }

        var home = await GetHomeDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return path.Length <= 2 ? home : await GetFullPathAsync(home.TrimEnd('/') + "/" + path[2..], cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The names of user and group ids, as <c>ls -l</c> shows them (<c>users-groups-by-id@openssh.com</c>, OpenSSH 9.1+).</summary>
    /// <returns>The names the server knows; an id it cannot name is left out.</returns>
    /// <exception cref="NotSupportedException">The server lacks <c>users-groups-by-id@openssh.com</c>.</exception>
    public async Task<(IReadOnlyDictionary<uint, string> UserNames, IReadOnlyDictionary<uint, string> GroupNames)> GetOwnerNamesAsync(
        IEnumerable<uint> userIds, IEnumerable<uint> groupIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userIds);
        ArgumentNullException.ThrowIfNull(groupIds);
        Require(SftpProtocol.UsersGroupsByIdExtension, "name user and group ids");
        var users = userIds.Distinct().ToArray();
        var groups = groupIds.Distinct().ToArray();
        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.UsersGroupsByIdExtension);
            WriteIds(w, users);
            WriteIds(w, groups);
        }, cancellationToken).ConfigureAwait(false);
        if (reply.Type != SftpProtocol.ExtendedReply)
        {
            ThrowStatus(reply, "Naming user and group ids", null);
        }

        return Parse(reply, (ref SshReader r) =>
        {
            var userNames = ReadNames(r.ReadString(), users);
            var groupNames = ReadNames(r.ReadString(), groups);
            return ((IReadOnlyDictionary<uint, string>)userNames, (IReadOnlyDictionary<uint, string>)groupNames);
        });
    }

    /// <summary>The ids as one string of uint32 values, as <c>users-groups-by-id@openssh.com</c> takes them.</summary>
    private static void WriteIds(SshWriter w, uint[] ids)
    {
        var bytes = new byte[ids.Length * 4];
        for (var i = 0; i < ids.Length; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(i * 4), ids[i]);
        }

        w.WriteString(bytes);
    }

    /// <summary>One name per id, in the request's order; an empty name (unknown id) is left out.</summary>
    private static Dictionary<uint, string> ReadNames(ReadOnlySpan<byte> names, uint[] ids)
    {
        var reader = new SshReader(names);
        var result = new Dictionary<uint, string>();
        foreach (var id in ids)
        {
            if (reader.ReadUtf8String() is { Length: > 0 } name)
            {
                result[id] = name;
            }
        }

        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("More names than ids in the users-groups-by-id@openssh.com reply.");
        }

        return result;
    }

    /// <summary>setstat on the link itself (<c>lsetstat@openssh.com</c>).</summary>
    private async Task SetLinkAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken)
    {
        CheckPath(path);
        ArgumentNullException.ThrowIfNull(attributes);
        Require(SftpProtocol.LSetStatExtension, "set the attributes of a symbolic link itself");
        var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(SftpProtocol.LSetStatExtension);
            w.WriteString(path);
            attributes.Write(w);
        }, cancellationToken).ConfigureAwait(false);
        ExpectOk(reply, "Setting the link's attributes", path);
    }

    private void Require(string extension, string what)
    {
        if (!Extensions.ContainsKey(extension))
        {
            throw new NotSupportedException($"The server cannot {what} (it lacks {extension}).");
        }
    }

    /// <summary>The reply to <c>statvfs@openssh.com</c>: eleven uint64 fields, as POSIX <c>statvfs</c> has them.</summary>
    private static SftpFileSystemInfo ParseStatVfs(SftpResponse reply) => Parse(reply, static (ref SshReader r) =>
    {
        var blockSize = r.ReadUInt64();
        var fragmentSize = r.ReadUInt64();
        var blocks = r.ReadUInt64();
        var free = r.ReadUInt64();
        var available = r.ReadUInt64();
        var files = r.ReadUInt64();
        var freeFiles = r.ReadUInt64();
        var availableFiles = r.ReadUInt64();
        r.ReadUInt64(); // file system id
        var flags = r.ReadUInt64();
        var maxName = r.ReadUInt64();
        var unit = fragmentSize != 0 ? fragmentSize : blockSize;
        return new SftpFileSystemInfo(
            Bytes(blocks, unit), Bytes(free, unit), Bytes(available, unit),
            Clamp(files), Clamp(freeFiles), Clamp(availableFiles),
            IsReadOnly: (flags & 1) != 0,
            MaxNameLength: (int)Math.Min(maxName, int.MaxValue));
    });

    private static long Bytes(ulong count, ulong unit) => count == 0 || unit == 0 ? 0 : count > (ulong)long.MaxValue / unit ? long.MaxValue : (long)(count * unit);

    private static long Clamp(ulong value) => (long)Math.Min(value, long.MaxValue);
}

/// <summary>A file system's size and free space, from <see cref="SftpClient.GetFileSystemInfoAsync"/>.</summary>
/// <param name="TotalBytes">The file system's size.</param>
/// <param name="FreeBytes">Free space, including what only the superuser may use.</param>
/// <param name="AvailableBytes">Free space the server's user may use.</param>
/// <param name="TotalFiles">The number of file entries (inodes).</param>
/// <param name="FreeFiles">Free file entries.</param>
/// <param name="AvailableFiles">Free file entries the server's user may use.</param>
/// <param name="IsReadOnly">Whether the file system is mounted read-only.</param>
/// <param name="MaxNameLength">The longest file name it accepts.</param>
[Experimental(SftpClient.ExperimentalId)]
public sealed record SftpFileSystemInfo(long TotalBytes, long FreeBytes, long AvailableBytes, long TotalFiles, long FreeFiles, long AvailableFiles,
    bool IsReadOnly, int MaxNameLength);
