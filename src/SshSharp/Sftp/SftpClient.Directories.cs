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
    /// Every name the server lists is checked before it becomes a local path, as for SCP downloads: no separators, <c>.</c> or
    /// <c>..</c>, and on Windows no device names (<c>CON</c>, <c>NUL</c>, ...) or trailing dots; and the resulting path must stay inside
    /// <paramref name="localDirectory"/>. A server that lists anything else is treated as hostile and the download stops.
    /// </remarks>
    /// <exception cref="SshException">The server listed an unacceptable name (<see cref="SshFailureReason.TransferFailed"/>), or the tree is
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
    /// other reparse points are skipped.
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
            var local = SafeLocalPath(localDirectory, entry.Name, root);
            if (entry.Attributes.IsDirectory)
            {
                Directory.CreateDirectory(local);
                await DownloadTreeAsync(entry.FullPath, local, root, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.Directories++;
                if (options.PreserveTimes && entry.Attributes.LastWriteTime is { } modified)
                {
                    Directory.SetLastWriteTimeUtc(local, modified.UtcDateTime); // after its contents, which would change it
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

            var remote = prefix + entry.Name;
            if (entry is DirectoryInfo directory)
            {
                await UploadTreeAsync(directory, remote, depth + 1, options, summary, cancellationToken).ConfigureAwait(false);
                summary.Directories++;
                if (options.PreserveTimes)
                {
                    await SetAttributesAsync(remote, new SftpFileAttributes { LastWriteTime = directory.LastWriteTimeUtc, LastAccessTime = directory.LastAccessTimeUtc },
                        cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                summary.Bytes += await UploadFileAsync(entry.FullName, remote, options, cancellationToken).ConfigureAwait(false);
                summary.Files++;
            }
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
    /// The local path for a name from a remote listing, checked: an acceptable file name (as SCP checks them), and inside the root.
    /// </summary>
    private static string SafeLocalPath(string localDirectory, string name, string root)
    {
        SshScpExtensions.CheckName(name);
        var path = Path.GetFullPath(Path.Join(localDirectory, name));
        var inside = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(inside, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new SshException(SshFailureReason.TransferFailed, $"'{name}' would be written outside the target directory.");
        }

        return path;
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
/// <param name="Skipped">Entries left out: symbolic links, special files, and reparse points.</param>
[Experimental(SftpClient.ExperimentalId)]
public sealed record SftpTransferSummary(int Files, int Directories, long Bytes, int Skipped);
