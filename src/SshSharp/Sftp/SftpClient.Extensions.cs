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
