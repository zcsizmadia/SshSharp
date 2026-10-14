# File transfer (SFTP)

SFTP is the file protocol of SSH: browse directories, read and write files in place, and transfer them, over the same connection
as your commands. SshSharp speaks SFTP version 3, the version OpenSSH's `sftp-server` and `internal-sftp` implement, with
OpenSSH's extensions.

> **Experimental.** The SFTP API is new and may still change between minor releases. Its types are marked
> `[Experimental("SSHSHARP001")]`, so the compiler warns where you use them; suppress the warning
> (`<NoWarn>$(NoWarn);SSHSHARP001</NoWarn>`) once you accept that.

```csharp
using SshSharp.Sftp;

await using var client = await SshClient.ConnectAsync("deploy@files.example.com");
await using var sftp = await client.OpenSftpAsync();

await sftp.UploadFileAsync("report.pdf", "incoming/report.pdf");
await sftp.DownloadFileAsync("outgoing/data.csv", "data.csv", new SftpTransferOptions { PreserveTimes = true });

await foreach (var entry in sftp.ListDirectoryAsync("incoming"))
{
    Console.WriteLine($"{entry.Name} {entry.Attributes.Size} {entry.Attributes.LastWriteTime}");
}
```

An `SftpClient` is one SFTP session. Several can share an `SshClient`, and one can be used by several tasks at once.
Disposing it ends the session; the connection stays up.

## Transfers

`UploadFileAsync`, `DownloadFileAsync`, `UploadAsync` (from any `Stream`) and `DownloadAsync` (into any `Stream`) keep many
reads or writes in flight at once (64 by default, as OpenSSH's `sftp` does), which is what makes SFTP fast over links with
latency. Each request is as large as the server allows (`limits@openssh.com`; 32 KiB when the server does not say).
`SftpTransferOptions` has:

| Option | Meaning |
|---|---|
| `Overwrite` (default true) | Replace an existing destination file; otherwise it is an error. |
| `PreserveTimes` | Copy the modification and access times. |
| `Progress` | An `IProgress<long>` with the bytes transferred so far. |
| `MaxRequestsInFlight` | The window of outstanding requests (1 to 1024). |

| `Resume` | Continue an interrupted transfer, as `reget` and `reput` do: only the part the destination lacks is sent. |

A failed download leaves no partial local file behind, unless `Resume` is set, in which case what arrived is kept for the
next attempt. A resume trusts that the destination's bytes are the start of the same file (nothing compares them), and a
destination larger than the source is an error.

### Directories

`UploadDirectoryAsync(localDirectory, remoteDirectory)` and `DownloadDirectoryAsync(remoteDirectory, localDirectory)` copy a
whole tree, creating directories as needed (an existing one is fine), with the same options for every file. They return an
`SftpTransferSummary` with the files, directories and bytes transferred and the entries skipped.

```csharp
var summary = await sftp.DownloadDirectoryAsync("releases/1.4", "out", new SftpTransferOptions { PreserveTimes = true });
Console.WriteLine($"{summary.Files} files, {summary.Bytes} bytes");
```

Symbolic links and special files are skipped in both directions, so a link cannot lead a transfer outside the tree. A download
treats the server as untrusted: every name it lists must be a plain file name (no separators, `.` or `..`, and on Windows no
device names such as `CON` or `NUL` and no trailing dot or space), the resulting path must stay inside the target directory, and
trees deeper than 64 levels are refused. A server that breaks these rules stops the download with an `SshException`
(`TransferFailed`).

## Files as streams

`OpenAsync(path, FileMode, FileAccess)` opens a remote file as a seekable `Stream`, with `FileMode` meaning what it does for
`FileStream`. `OpenReadAsync` and `OpenWriteAsync` are the common cases.

```csharp
await using var log = await sftp.OpenAsync("app.log", FileMode.Append, FileAccess.Write);
await log.WriteAsync(Encoding.UTF8.GetBytes("deployed\n"));
```

The stream is asynchronous only. `SetLength` truncates or extends the remote file. Each `ReadAsync` is one request; for whole
files, `DownloadAsync` is much faster.

## Files, directories and links

| Method | Does |
|---|---|
| `GetAttributesAsync(path, followSymbolicLinks)` | Size, owner, permissions, times, file type (`IsDirectory`, `IsRegularFile`, `IsSymbolicLink`). |
| `SetAttributesAsync(path, attributes)` | Changes the attributes that are set: `Size`, `Permissions`, `LastWriteTime`, ... |
| `ExistsAsync(path)` | Whether the path exists. |
| `ListDirectoryAsync(path)` | The entries, as `IAsyncEnumerable<SftpFileInfo>`, without `.` and `..`. |
| `CreateDirectoryAsync`, `DeleteDirectoryAsync` | One directory (deleting needs it empty). |
| `DeleteFileAsync` | A file, or a link itself. |
| `RenameAsync(old, new, overwrite)` | Rename or move; `overwrite` replaces the target atomically (`posix-rename@openssh.com`). |
| `CreateSymbolicLinkAsync`, `ReadSymbolicLinkAsync` | Symbolic links. |
| `CreateHardLinkAsync` | Hard links (`hardlink@openssh.com`). |
| `GetFullPathAsync`, `GetHomeDirectoryAsync` | Resolve a path; the login directory. |

Remote paths are passed to the server as they are: relative paths are relative to the login directory, and `/` is the
separator whatever this machine uses. `Extensions` lists what the server supports, and `Limits` the sizes it accepts.

## Errors

A request the server refuses throws `SftpException`, an `SshException` with `Reason = SftpFailed`, `Status` (the SFTP status
code, such as `NoSuchFile`, `PermissionDenied` or `Failure`) and the `Path` concerned. A broken SFTP session or connection is an
`SshException` with `ChannelClosed` or `ConnectionClosed`. An operation needing an extension the server lacks (an overwriting
rename, a hard link) throws `NotSupportedException`.

## SFTP or SCP?

Prefer SFTP. It can list, resume and change files, and OpenSSH 9.0 switched its own `scp` command to SFTP by default. SCP
(see [File transfer (SCP)](scp.md)) remains for servers that do not offer SFTP.
