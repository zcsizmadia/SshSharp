# File transfer (SCP)

`using SshSharp.Scp;` adds SCP transfers to `SshClient`. They run the server's `scp` program (as `scp -t` to receive, `scp -f`
to send), so they work wherever `scp` does, including servers without SFTP.

## Files

```csharp
using SshSharp.Scp;

await client.UploadFileAsync("report.csv", "/srv/reports/2024-05.csv");
await client.DownloadFileAsync("/var/log/app.log", "app.log");

// An existing directory as the target keeps the other side's file name.
await client.UploadFileAsync("report.csv", "/srv/reports/");
await client.DownloadFileAsync("/var/log/app.log", Path.GetTempPath());
```

## Streams

```csharp
await using var source = File.OpenRead("backup.tar");
await client.UploadAsync(source, "/backups/backup.tar");     // the length comes from the stream, or pass length: for one that cannot seek

using var memory = new MemoryStream();
await client.DownloadAsync("/etc/os-release", memory);
```

## Directories

```csharp
// Like scp -r: the directory becomes the target when that does not exist, or goes inside it when it does.
await client.UploadDirectoryAsync("site", "/var/www/site", new SshScpOptions { Preserve = true });
await client.DownloadDirectoryAsync("/var/log/app", "logs");
```

## Options and progress

```csharp
var options = new SshScpOptions
{
    Preserve = true,                                 // scp -p: modification and access times, and permission bits
    FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite, // 0600, for uploads whose mode is not preserved
    Progress = new Progress<SshScpProgress>(p => Console.Write($"\r{p.Path}: {p.BytesTransferred}/{p.TotalBytes}")),
};
await client.UploadFileAsync("secrets.env", "/etc/app/secrets.env", options, cancellationToken);
```

## Errors and safety

A failed transfer (a missing file, permission denied, a server without `scp`) throws an `SshException` with
`SshFailureReason.TransferFailed` and the server's own message.

Remote paths are passed to the server's shell as one single-quoted word, so spaces and special characters are safe with a POSIX shell (`sh`, `bash`); a Windows server whose default shell is `cmd.exe` or PowerShell does not read single quotes that way. When
downloading, every name the server sends must be a single path component (no `/`, `\`, `:`, `.`, `..` or control characters),
and a single-file download accepts exactly one file: a hostile server cannot write outside the target or slip in extra files
(CVE-2019-6111). Permission bits from the server are applied without set-id or sticky bits, and only with `Preserve`.
