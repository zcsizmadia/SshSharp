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

    public static async Task DirectoriesAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp-directories>
        var options = new SftpTransferOptions { Preserve = true };
        var up = await sftp.UploadDirectoryAsync("publish", "/srv/www/app", options, cancellationToken);
        var down = await sftp.DownloadDirectoryAsync("/var/log/app", "logs", options, cancellationToken);
        Console.WriteLine($"up: {up.Files} files, {up.Bytes:N0} bytes; down: {down.Files} files, {down.Skipped} skipped");
        // </sftp-directories>
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
