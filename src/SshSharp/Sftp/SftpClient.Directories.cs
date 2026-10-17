using System.Diagnostics.CodeAnalysis;
using SshSharp.Scp;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>How deep a tree a directory transfer follows: a server cannot make it recurse without end.</summary>
    internal const int MaxDepth = 64;

    /// <summary>
    /// Downloads the directory <paramref name="remoteDirectory"/> and everything under it into <paramref name="localDirectory"/> (created
    /// if needed), file by file with <see cref="DownloadFileAsync"/> and the same <paramref name="options"/>. Symbolic links and special
    /// files are skipped, so a link cannot lead the download outside the tree.
    /// </summary>
    /// <remarks>
    /// Every name the server lists is checked before it becomes a local path: names that cannot be a file name on this system (a
    /// separator, <c>.</c> or <c>..</c>, control characters, a name that is not valid UTF-8; on Windows also <c>\</c>, <c>:</c>, device
    /// names such as <c>CON</c> or <c>NUL</c>, and trailing dots) are skipped and counted in <see cref="SftpTransferSummary.Skipped"/>, and
    /// the resulting path must stay inside <paramref name="localDirectory"/>.
    /// </remarks>
    /// <exception cref="SshException">A path would end up outside the target (<see cref="SshFailureReason.TransferFailed"/>), or the tree is
    /// deeper than 64 levels.</exception>
    public async Task<SftpTransferSummary> DownloadDirectoryAsync(string remoteDirectory, string localDirectory, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        CheckPath(remoteDirectory);
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        options ??= new SftpTransferOptions();
        var root = Path.GetFullPath(localDirectory);
        Directory.CreateDirectory(root);
        var summary = new SummaryCounter();
        await DownloadTreeAsync(remoteDirectory, root, root, 0, options, summary, cancellationToken).ConfigureAwait(false);
        return summary.ToSummary();
    }

    /// <summary>
    /// Uploads the local directory <paramref name="localDirectory"/> and everything under it to <paramref name="remoteDirectory"/> (created
    /// if needed), file by file with <see cref="UploadFileAsync"/> and the same <paramref name="options"/>. Symbolic links, junctions and
    /// other reparse points are skipped, and so are special files on Unix (FIFOs, sockets, devices).
    /// </summary>
    /// <exception cref="DirectoryNotFoundException"><paramref name="localDirectory"/> does not exist.</exception>
    public async Task<SftpTransferSummary> UploadDirectoryAsync(string localDirectory, string remoteDirectory, SftpTransferOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        CheckPath(remoteDirectory);
        options ??= new SftpTransferOptions();
        var root = new DirectoryInfo(localDirectory);
        if (!root.Exists)
        {
            throw new DirectoryNotFoundException($"'{localDirectory}' does not exist.");
        }

        var summary = new SummaryCounter();
        await UploadTreeAsync(root, remoteDirectory, 0, options, summary, cancellationToken).ConfigureAwait(false);
        return summary.ToSummary();
    }

    private async Task DownloadTreeAsync(string remoteDirectory, string localDirectory, string root, int depth, SftpTransferOptions options,
        SummaryCounter summary, CancellationToken cancellationToken)
    {
        if (depth > MaxDepth)
        {
            throw new SshException(SshFailureReason.TransferFailed, $"The remote tree is deeper than {MaxDepth} levels.");
        }

        // The listing is read whole before anything is transferred, so its handle is closed before files and subdirectories are opened.
        var entries = new List<SftpFileInfo>();
        await foreach (var entry in ListDirectoryAsync(remoteDirectory, cancellationToken).ConfigureAwait(false))
        {
            entries.Add(entry);
        }

        foreach (var entry in entries)
        {
            if (LocalPathFor(localDirectory, entry.Name, root) is not { } local)
            {
                summary.Skipped++; // a name this system cannot hold, or one that was not valid UTF-8
                continue;
            }

            if (entry.Attributes.IsDirectory)
            {
                Directory.CreateDirectory(local);
                await DownloadTreeAsync(entry.FullPath, local, root, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.Directories++;
                if (options.Preserve)
                {
                    // After its contents, which would change its time (and which a mode without write permission could refuse).
                    if (entry.Attributes.LastWriteTime is { } modified)
                    {
                        Directory.SetLastWriteTimeUtc(local, modified.UtcDateTime);
                    }

                    SetLocalPermissions(local, entry.Attributes.Permissions);
                }
            }
            else if (entry.Attributes.IsRegularFile)
            {
                summary.Bytes += await DownloadFileAsync(entry.FullPath, local, options, cancellationToken).ConfigureAwait(false);
                summary.Files++;
            }
            else
            {
                summary.Skipped++; // a symbolic link, a device, or a type the server did not say
            }
        }
    }

    private async Task UploadTreeAsync(DirectoryInfo local, string remoteDirectory, int depth, SftpTransferOptions options, SummaryCounter summary,
        CancellationToken cancellationToken)
    {
        if (depth > MaxDepth)
        {
            throw new IOException($"The local tree is deeper than {MaxDepth} levels.");
        }

        await EnsureRemoteDirectoryAsync(remoteDirectory, cancellationToken).ConfigureAwait(false);
        var prefix = remoteDirectory.EndsWith('/') ? remoteDirectory : remoteDirectory + "/";
        foreach (var entry in local.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                summary.Skipped++;
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            var remote = prefix + entry.Name;
            if (entry is FileInfo && !LocalFileType.IsRegularFile(entry.FullName))
            {
                summary.Skipped++; // a FIFO (opening it would wait for a writer), a socket or a device
                continue;
            }

            if (entry is DirectoryInfo directory)
            {
                await UploadTreeAsync(directory, remote, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.Directories++;
                if (options.Preserve)
                {
                    await SetAttributesAsync(remote, new SftpFileAttributes
                    {
                        LastWriteTime = directory.LastWriteTimeUtc,
                        LastAccessTime = directory.LastAccessTimeUtc,
                        Permissions = LocalPermissions(directory.FullName),
                    }, cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                summary.Bytes += await UploadFileAsync(entry.FullName, remote, options, cancellationToken).ConfigureAwait(false);
                summary.Files++;
            }
        }
    }

    /// <summary>The permission bits <see cref="SftpTransferOptions.Preserve"/> copies: read, write and execute for owner, group and others.</summary>
    private const UnixFileMode PreservedPermissions = (UnixFileMode)0x1FF; // 0777

    /// <summary>A local file's or directory's permissions to preserve, or null where this system has no Unix modes (Windows).</summary>
    private static UnixFileMode? LocalPermissions(string path) =>
        OperatingSystem.IsWindows() ? null : File.GetUnixFileMode(path) & PreservedPermissions;

    /// <summary>Gives a local file or directory the remote permissions, where this system has Unix modes and the server sent them.</summary>
    private static void SetLocalPermissions(string path, UnixFileMode? permissions)
    {
        if (!OperatingSystem.IsWindows() && permissions is { } mode)
        {
            File.SetUnixFileMode(path, mode & PreservedPermissions);
        }
    }

    /// <summary>Creates the remote directory, or accepts one that is there already.</summary>
    private async Task EnsureRemoteDirectoryAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await CreateDirectoryAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException ex) when (ex.Status is SftpStatusCode.Failure or SftpStatusCode.PermissionDenied)
        {
            // Probably there already (OpenSSH says "Failure" for an existing directory); anything else is the original error.
            SftpFileAttributes attributes;
            try
            {
                attributes = await GetAttributesAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (SftpException)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
                throw; // not reached
            }

            if (!attributes.IsDirectory)
            {
                throw;
            }
        }
    }

    /// <summary>
    /// The local path for a name from a remote listing, or null when the name cannot be a file name here (it is skipped): empty,
    /// <c>.</c>, <c>..</c>, a separator, NUL or another control character, or the replacement character a name that was not valid
    /// UTF-8 decodes to; on Windows also <c>\</c>, <c>:</c>, device names and trailing dots or spaces. A path that would still end up
    /// outside the root stops the download (<see cref="SshFailureReason.TransferFailed"/>).
    /// </summary>
    internal static string? LocalPathFor(string localDirectory, string name, string root, bool? windows = null)
    {
        if (!IsAcceptableName(name, windows ?? OperatingSystem.IsWindows()))
        {
            return null;
        }

        var path = Path.GetFullPath(Path.Join(localDirectory, name));
        var inside = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(inside, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new SshException(SshFailureReason.TransferFailed, $"'{name}' would be written outside the target directory.");
        }

        return path;
    }

    internal static bool IsAcceptableName(string name, bool windows)
    {
        if (name.Length == 0 || name is "." or ".." || name.Any(c => c is '/' or '�' || char.IsControl(c)))
        {
            return false;
        }

        if (!windows)
        {
            return true; // ':' and '\' are ordinary characters in POSIX names
        }

        try
        {
            SshScpExtensions.CheckName(name, windows: true);
            return true;
        }
        catch (SshException)
        {
            return false;
        }
    }

    private sealed class SummaryCounter
    {
        public int Files { get; set; }

        public int Directories { get; set; }

        public long Bytes { get; set; }

        public int Skipped { get; set; }

        public SftpTransferSummary ToSummary() => new(Files, Directories, Bytes, Skipped);
    }
}

/// <summary>What a directory transfer did.</summary>
/// <param name="Files">Files transferred.</param>
/// <param name="Directories">Directories created or entered below the top one.</param>
/// <param name="Bytes">Bytes transferred.</param>
/// <param name="Skipped">Entries left out: symbolic links, special files, reparse points, and names this system cannot hold.</param>
[Experimental(SftpClient.ExperimentalId)]
public sealed record SftpTransferSummary(int Files, int Directories, long Bytes, int Skipped);
