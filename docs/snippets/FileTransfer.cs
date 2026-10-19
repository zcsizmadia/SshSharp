using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SshSharp;
using SshSharp.Scp;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/transfer-files-sftp.md and docs/how-to/transfer-files-scp.md.</summary>
internal static class FileTransfer
{
    public static async Task OpenAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <sftp-open>
        await using var sftp = await client.OpenSftpAsync(cancellationToken); // one SFTP session; the connection stays shared
        Console.WriteLine($"SFTP v{sftp.ProtocolVersion}, home {await sftp.GetHomeDirectoryAsync(cancellationToken)}");
        // </sftp-open>
    }

    public static async Task UploadDownloadAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-upload-download>
        // Relative remote paths start at the login directory; '/' separates, whatever this machine uses.
        long sent = await sftp.UploadFileAsync("report.pdf", "incoming/report.pdf", cancellationToken: cancellationToken);
        long received = await sftp.DownloadFileAsync("outgoing/data.csv", "data.csv", cancellationToken: cancellationToken);

        // Streams work too: anything readable up, anything writable down.
        using var buffer = new MemoryStream();
        await sftp.DownloadAsync("/etc/os-release", buffer, cancellationToken: cancellationToken);
        Console.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
        // </sftp-upload-download>
        _ = (sent, received);
    }

    public static async Task ProgressAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-progress>
        var options = new SftpTransferOptions
        {
            Preserve = true,                 // keep times and permission bits, as sftp -p
            Overwrite = false,               // fail rather than replace an existing file
            Progress = new Progress<SftpTransferProgress>(p =>
                Console.Write($"\r{p.Path}: {p.BytesTransferred:N0} of {p.TotalBytes?.ToString("N0") ?? "?"} bytes")),
        };
        await sftp.UploadFileAsync("site.tar.gz", "/srv/releases/site.tar.gz", options, cancellationToken);
        // </sftp-progress>
    }

    public static async Task ResumeAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-resume>
        // Try, and on failure try again: each attempt sends only what the destination still lacks.
        var resume = new SftpTransferOptions { Resume = true };
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await sftp.DownloadFileAsync("backups/db.tar.zst", "db.tar.zst", resume, cancellationToken);
                break;
            }
            catch (SshException ex) when (attempt < 5 && ex.Reason is not SshFailureReason.SftpFailed)
            {
                // The session or connection broke. A real job reconnects and opens a new SftpClient here (see the file sync scenario).
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2), cancellationToken);
            }
        }
        // </sftp-resume>
    }

    public static async Task SegmentsAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-segments>
        // A large file over a high-latency link: four ranges in parallel, each over its own SFTP session.
        await sftp.DownloadFileAsync("images/vm.qcow2", "vm.qcow2", new SftpTransferOptions { Segments = 4 }, cancellationToken);
        // </sftp-segments>
    }

    public static async Task SegmentedUploadAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-segments-upload>
        // The other way: four ranges written in parallel into one remote file, each over its own SFTP session. A server that allows
        // one writer per file, or takes writes in order only, still gets the whole file (over fewer sessions, or in order).
        var options = new SftpTransferOptions { Segments = 4 };
        await sftp.UploadFileAsync("backups/db.tar.zst", "incoming/db.tar.zst", options, cancellationToken);
        // </sftp-segments-upload>
    }

    public static async Task SegmentedUploadRetryAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-segments-upload-cleanup>
        var options = new SftpTransferOptions { Segments = 4 };
        try
        {
            await sftp.UploadFileAsync("backups/db.tar.zst", "incoming/db.tar.zst", options, cancellationToken);
        }
        catch (SshException ex) when (ex.Reason is not SshFailureReason.ChannelClosed and not SshFailureReason.ConnectionClosed)
        {
            // Resume only a file whose cleanup finished: then it holds an unbroken start of the upload, and no gaps. Otherwise start
            // over (Resume off truncates the file).
            var mayHaveGaps = ex.Data[SftpClient.UploadCleanupIncompleteKey] is true;
            var retry = new SftpTransferOptions { Resume = !mayHaveGaps };
            await sftp.UploadFileAsync("backups/db.tar.zst", "incoming/db.tar.zst", retry, cancellationToken);
        }
        // </sftp-segments-upload-cleanup>
    }

    public static async Task VerifyWithHashAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-verify-hash>
        await sftp.UploadFileAsync("backups/db.tar.zst", "incoming/db.tar.zst", cancellationToken: cancellationToken);

        if (sftp.SupportsFileHash)
        {
            // The server hashes its copy where it is (check-file), so nothing is read back; ask for SHA-256 to compare it here.
            var remote = await sftp.GetFileHashAsync("incoming/db.tar.zst", ["sha256"], cancellationToken: cancellationToken);

            await using var local = File.OpenRead("backups/db.tar.zst");
            var expected = await SHA256.HashDataAsync(local, cancellationToken);
            if (!remote.Matches(expected))
            {
                throw new IOException("The uploaded file differs from the local one.");
            }
        }
        // </sftp-verify-hash>
    }

    public static async Task ExtendedRequestAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-extended-request>
        // A vendor extension this library has no method for: its fields after the name, encoded as the extension defines them.
        // Here one SSH string, a path (uint32 length, then the UTF-8 bytes).
        if (sftp.Extensions.ContainsKey("space-available"))
        {
            var path = Encoding.UTF8.GetBytes("/srv/data");
            var request = new byte[4 + path.Length];
            BinaryPrimitives.WriteInt32BigEndian(request, path.Length);
            path.CopyTo(request, 4);

            var reply = await sftp.SendExtendedRequestAsync("space-available", request, cancellationToken);
            reply.EnsureSuccess(); // a status other than OK throws SftpException
            if (reply.IsExtendedReply)
            {
                // The extension's reply fields: here four uint64 values and a uint32, the first the bytes on the device.
                var bytesOnDevice = BinaryPrimitives.ReadUInt64BigEndian(reply.Data.Span);
                Console.WriteLine($"{bytesOnDevice:N0} bytes on the device");
            }
        }
        // </sftp-extended-request>
    }

    public static async Task DirectoriesAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-directories>
        var options = new SftpTransferOptions { Preserve = true };
        var up = await sftp.UploadDirectoryAsync("publish", "/srv/www/app", options, cancellationToken);
        var down = await sftp.DownloadDirectoryAsync("/var/log/app", "logs", options, cancellationToken);
        Console.WriteLine($"up: {up.Files} files, {up.Bytes:N0} bytes; down: {down.Files} files, {down.Skipped} skipped");
        // </sftp-directories>
    }

    public static async Task ConcurrentFilesAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-concurrent-files>
        // A tree of many small files over a link with latency: eight files at a time over the same session. The eight share the
        // 64 requests in flight (and their memory) rather than take 64 each.
        var options = new SftpTransferOptions { MaxConcurrentFiles = 8, Preserve = true };
        var summary = await sftp.UploadDirectoryAsync("site", "/srv/www/site", options, cancellationToken);
        Console.WriteLine($"{summary.Files} files, {summary.Directories} directories, {summary.Bytes:N0} bytes");
        // </sftp-concurrent-files>
    }

    public static async Task BrowseAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-browse>
        await foreach (var entry in sftp.ListDirectoryAsync("/var/log", cancellationToken))
        {
            var a = entry.Attributes;
            var kind = a.IsDirectory ? "dir " : a.IsSymbolicLink ? "link" : "file";
            Console.WriteLine($"{kind} {a.Size,12:N0} {a.LastWriteTime:yyyy-MM-dd HH:mm} {entry.Name}");
        }

        if (!await sftp.ExistsAsync("archive", cancellationToken))
        {
            await sftp.CreateDirectoryAsync("archive", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, cancellationToken);
        }

        await sftp.RenameAsync("app.log.1", "archive/app.log.1", overwrite: true, cancellationToken);
        var disk = await sftp.GetFileSystemInfoAsync("/", cancellationToken);
        Console.WriteLine($"{disk.AvailableBytes:N0} bytes free");
        // </sftp-browse>
    }

    public static async Task WholeFilesAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-whole-files>
        // Small files in one call each, as File.ReadAllTextAsync and File.WriteAllBytesAsync do locally.
        var settings = await sftp.ReadAllTextAsync("/etc/myapp/settings.json", cancellationToken: cancellationToken);
        await sftp.WriteAllTextAsync("/etc/myapp/settings.json", settings.Replace("\"debug\": false", "\"debug\": true"), cancellationToken: cancellationToken);

        byte[] logo = await sftp.ReadAllBytesAsync("/srv/www/logo.png", cancellationToken);
        await sftp.WriteAllBytesAsync("/srv/www/logo-copy.png", logo, cancellationToken);
        // </sftp-whole-files>
    }

    public static async Task TreesAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-trees>
        // mkdir -p: creates what is missing, and an existing directory is fine.
        await sftp.CreateDirectoryAsync("/srv/releases/2026-10-18/assets", createParents: true, cancellationToken: cancellationToken);

        // rm -r: the directory and everything in it; symbolic links are removed, never followed.
        await sftp.DeleteDirectoryAsync("/srv/releases/2026-09-01", recursive: true, cancellationToken);
        // </sftp-trees>
    }

    public static async Task OperationTimeoutAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-operation-timeout>
        // Fail requests once the server has sent nothing for 30 seconds, rather than wait for as long as the connection lasts.
        // A long transfer is not cut off: while replies keep coming, the server is answering.
        sftp.OperationTimeout = TimeSpan.FromSeconds(30);
        try
        {
            await sftp.DownloadFileAsync("backups/db.tar.zst", "db.tar.zst", cancellationToken: cancellationToken);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.Timeout)
        {
            Console.WriteLine("The server stopped answering; reconnect and resume.");
        }
        // </sftp-operation-timeout>
    }

    public static async Task RandomAccessAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-stream>
        // Append a line to a remote file, in place.
        await using (var log = await sftp.OpenAsync("deploy.log", FileMode.Append, FileAccess.Write, cancellationToken))
        {
            await log.WriteAsync(Encoding.UTF8.GetBytes($"{DateTimeOffset.UtcNow:O} deployed\n"), cancellationToken);
            await log.FlushAsync(cancellationToken);  // fsync@openssh.com where the server has it
        }

        // Read the last 4 KiB of a large file without downloading the rest.
        await using var file = await sftp.OpenReadAsync("/var/log/app/app.log", cancellationToken);
        file.Seek(Math.Max(0, file.Length - 4096), SeekOrigin.Begin);
        var tail = new byte[4096];
        var read = await file.ReadAtLeastAsync(tail, tail.Length, throwOnEndOfStream: false, cancellationToken);
        Console.WriteLine(Encoding.UTF8.GetString(tail, 0, read));
        // </sftp-stream>
    }

    public static async Task StreamCopyAsync(SftpClient sftp, Stream source, CancellationToken cancellationToken)
    {
        // <sftp-stream-copy>
        // Copy any stream into a remote file. Writes are sent without waiting for each reply (up to 16 in flight), so a failure can
        // surface on a later call: FlushAsync waits for every write and throws it, and so does DisposeAsync.
        await using var remote = await sftp.OpenWriteAsync("incoming/export.csv", cancellationToken);
        await source.CopyToAsync(remote, cancellationToken);
        await remote.FlushAsync(cancellationToken);
        // </sftp-stream-copy>
    }

    public static async Task AtomicUploadAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-atomic>
        // Readers never see a half-written file: upload under a temporary name, then rename over the target.
        const string target = "/srv/app/config.json";
        var temporary = $"{target}.{Guid.NewGuid():N}.tmp";
        await sftp.UploadFileAsync("config.json", temporary, cancellationToken: cancellationToken);
        await sftp.RenameAsync(temporary, target, overwrite: true, cancellationToken); // posix-rename@openssh.com
        // </sftp-atomic>
    }

    public static async Task ErrorsAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-errors>
        try
        {
            await sftp.DownloadFileAsync("missing.txt", "missing.txt", cancellationToken: cancellationToken);
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
        {
            Console.WriteLine($"Not on the server: {ex.Path}");
        }
        catch (SftpException ex) when (ex.Status == SftpStatusCode.PermissionDenied)
        {
            Console.WriteLine($"No access to {ex.Path}");
        }
        // </sftp-errors>
    }

    public static async Task ScpAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <scp-files>
        // using SshSharp.Scp;
        await client.UploadFileAsync("report.csv", "/srv/reports/report.csv", cancellationToken: cancellationToken);
        await client.DownloadFileAsync("/var/log/app.log", "app.log", cancellationToken: cancellationToken);

        // An existing directory as the target keeps the other side's file name, as scp does.
        await client.UploadFileAsync("report.csv", "/srv/reports/", cancellationToken: cancellationToken);
        // </scp-files>
    }

    public static async Task ScpStreamsAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <scp-streams>
        var json = Encoding.UTF8.GetBytes("""{ "feature": true }""");
        using (var source = new MemoryStream(json))
        {
            await client.UploadAsync(source, "/etc/myapp/flags.json", cancellationToken: cancellationToken); // the length comes from the stream
        }

        using var destination = new MemoryStream();
        await client.DownloadAsync("/etc/hostname", destination, cancellationToken: cancellationToken);
        // </scp-streams>
    }

    public static async Task ScpDirectoryAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <scp-directory>
        var options = new SshScpOptions
        {
            Preserve = true,                                            // scp -p
            FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,  // 0600 for files whose mode is not preserved
            Progress = new Progress<SshScpProgress>(p => Console.Write($"\r{p.Path}: {p.BytesTransferred:N0}/{p.TotalBytes:N0}")),
        };
        await client.UploadDirectoryAsync("site", "/var/www/site", options, cancellationToken);   // scp -r
        await client.DownloadDirectoryAsync("/var/log/app", "logs", options, cancellationToken);
        // </scp-directory>
    }
}
