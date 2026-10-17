using SshSharp;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/file-sync.md.</summary>
internal static class FileSync
{
    // <sync>
    public sealed record SyncResult(int Uploaded, int Unchanged, int Deleted);

    /// <summary>
    /// Makes a remote directory match a local one: uploads new and changed files (by size and modification time), and with
    /// <paramref name="delete"/> removes remote files that no longer exist locally. Safe to run again after a failure.
    /// </summary>
    public static async Task<SyncResult> MirrorAsync(SftpClient sftp, string localRoot, string remoteRoot, bool delete,
        CancellationToken cancellationToken)
    {
        var remote = new Dictionary<string, SftpFileAttributes>(StringComparer.Ordinal);
        await ListRecursiveAsync(sftp, remoteRoot, "", remote, cancellationToken);

        int uploaded = 0, unchanged = 0, deleted = 0;
        var options = new SftpTransferOptions { Preserve = true };   // keeps the modification time, so the next run sees "unchanged"
        foreach (var path in Directory.EnumerateFiles(localRoot, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(localRoot, path).Replace('\\', '/');
            var local = new FileInfo(path);
            if (remote.Remove(relative, out var existing)
                && existing.Size == local.Length
                && existing.LastWriteTime is { } written
                && written.ToUnixTimeSeconds() == new DateTimeOffset(local.LastWriteTimeUtc).ToUnixTimeSeconds())   // SFTP v3 keeps whole seconds
            {
                unchanged++;
                continue;
            }

            var target = $"{remoteRoot}/{relative}";
            await EnsureDirectoryAsync(sftp, target[..target.LastIndexOf('/')], cancellationToken);

            // Upload beside the target, then rename over it: readers see the old file or the new one, never half of one.
            var temporary = $"{target}.sync-tmp";
            await sftp.UploadFileAsync(path, temporary, options, cancellationToken);
            await sftp.RenameAsync(temporary, target, overwrite: true, cancellationToken);
            uploaded++;
        }

        if (delete)
        {
            foreach (var extra in remote.Keys)   // what is left was not found locally
            {
                await sftp.DeleteFileAsync($"{remoteRoot}/{extra}", cancellationToken);
                deleted++;
            }
        }

        return new SyncResult(uploaded, unchanged, deleted);
    }

    private static async Task ListRecursiveAsync(SftpClient sftp, string root, string prefix, Dictionary<string, SftpFileAttributes> files,
        CancellationToken cancellationToken)
    {
        var directory = prefix.Length == 0 ? root : $"{root}/{prefix}";
        if (!await sftp.ExistsAsync(directory, cancellationToken))
        {
            return;
        }

        await foreach (var entry in sftp.ListDirectoryAsync(directory, cancellationToken))
        {
            var relative = prefix.Length == 0 ? entry.Name : $"{prefix}/{entry.Name}";
            if (entry.Attributes.IsDirectory)
            {
                await ListRecursiveAsync(sftp, root, relative, files, cancellationToken);
            }
            else if (entry.Attributes.IsRegularFile && !entry.Name.EndsWith(".sync-tmp", StringComparison.Ordinal))
            {
                files[relative] = entry.Attributes;
            }
        }
    }

    private static async Task EnsureDirectoryAsync(SftpClient sftp, string directory, CancellationToken cancellationToken)
    {
        if (directory.Length == 0 || await sftp.ExistsAsync(directory, cancellationToken))
        {
            return;
        }

        var slash = directory.LastIndexOf('/');
        if (slash > 0)
        {
            await EnsureDirectoryAsync(sftp, directory[..slash], cancellationToken);
        }

        await sftp.CreateDirectoryAsync(directory, cancellationToken: cancellationToken);
    }
    // </sync>

    public static async Task<int> MainAsync(string[] args)
    {
        // <sync-main>
        // sync <alias> <local directory> <remote directory>: retried on a dropped connection; each run skips what is done.
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await using var client = await SshClient.ConnectAsync(args[0]);
                await using var sftp = await client.OpenSftpAsync();
                var result = await MirrorAsync(sftp, args[1], args[2], delete: false, CancellationToken.None);
                Console.WriteLine($"{result.Uploaded} uploaded, {result.Unchanged} unchanged, {result.Deleted} deleted");
                return 0;
            }
            catch (SshException ex) when (attempt < 3 && ex.Reason is SshFailureReason.ConnectionClosed or SshFailureReason.ChannelClosed
                or SshFailureReason.Timeout or SshFailureReason.ConnectFailed)
            {
                Console.Error.WriteLine($"Attempt {attempt} failed ({ex.Reason}); trying again.");
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt));
            }
        }
        // </sync-main>
    }
}
