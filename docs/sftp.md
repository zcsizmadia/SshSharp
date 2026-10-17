# File transfer (SFTP)

SFTP is the file protocol of SSH: browse directories, read and write files in place, and transfer them, over the same connection
as your commands. SshSharp speaks SFTP version 3, the version OpenSSH's `sftp-server` and `internal-sftp` implement, with
OpenSSH's extensions.

> **Experimental.** The SFTP API is new and may still change between minor releases. Its types are marked
> `[Experimental("SSHSHARP001")]`, so the compiler reports error SSHSHARP001 where you use them until you opt in, in the project
> file (`<NoWarn>$(NoWarn);SSHSHARP001</NoWarn>`) or around the code (`#pragma warning disable SSHSHARP001`).

```csharp
using SshSharp.Sftp;

await using var client = await SshClient.ConnectAsync("deploy@files.example.com");
await using var sftp = await client.OpenSftpAsync();

await sftp.UploadFileAsync("report.pdf", "incoming/report.pdf");
await sftp.DownloadFileAsync("outgoing/data.csv", "data.csv", new SftpTransferOptions { Preserve = true });

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
| `Preserve` | Copy the modification and access times, and the permission bits (`rwx` for owner, group and others), as `sftp -p` does. Permissions travel only where the receiving side has Unix modes, and setuid, setgid and the sticky bit are never copied. |
| `Progress` | An `IProgress<SftpTransferProgress>`: for each file, its remote `Path`, `BytesTransferred` so far (including what a resumed transfer found there) and `TotalBytes`, when known. |
| `MaxRequestsInFlight` | The window of outstanding requests (1 to 1024). |
| `Resume` | Continue an interrupted transfer, as `reget` and `reput` do: only the part the destination lacks is sent. |
| `Segments` (default 1) | Download one file in up to 16 parallel ranges, each over its own SFTP session (see below). |

A failed download leaves no partial local file behind, unless `Resume` is set, in which case what arrived is kept for the
next attempt. A resume trusts that the destination's bytes are the start of the same file (nothing compares them), and a
destination larger than the source is an error.

### Segmented downloads

One SFTP session is one SSH channel, and the data in flight on a channel is bounded by its flow-control window (2 MiB here), so
a single download moves at most about 2 MiB per round trip: some 20 MiB/s at 100 ms of latency, however many requests are in
flight. `Segments` splits a file into ranges and fetches each over its own session on the same connection, each with its own
window (and, on OpenSSH, its own `sftp-server` process), writing them into the local file at their offsets:

```csharp
await sftp.DownloadFileAsync("backups/db.tar.zst", "db.tar.zst", new SftpTransferOptions { Segments = 4 });
```

It helps on links with high latency, or where a single session's server process is the limit. It does not help where the
bandwidth is the limit (the sessions share one TCP connection), and it costs a few extra round trips to open the sessions, so
files smaller than 1 MiB per segment use fewer segments. The server may allow fewer sessions than asked (sshd's `MaxSessions`,
10 per connection by default); then the ranges are shared among the sessions it opens. `Progress` reports the file's total over all
segments. The first range that fails stops the others and the local file is removed. A file that grows during the download is
fetched to its new end; one that shrinks fails the download rather than leave a gap.

Only `DownloadFileAsync` (and `DownloadDirectoryAsync`, per file) uses segments; `DownloadAsync` writes a stream in order, and
`Resume` needs a sequential download (only that leaves a prefix to resume from), so with `Resume` set a file is fetched over one
session. Uploads use one session.

### Directories

`UploadDirectoryAsync(localDirectory, remoteDirectory)` and `DownloadDirectoryAsync(remoteDirectory, localDirectory)` copy a
whole tree, creating directories as needed (an existing one is fine), with the same options for every file. They return an
`SftpTransferSummary` with the files, directories and bytes transferred and the entries skipped.

```csharp
var summary = await sftp.DownloadDirectoryAsync("releases/1.4", "out", new SftpTransferOptions { Preserve = true });
Console.WriteLine($"{summary.Files} files, {summary.Bytes} bytes");
```

Symbolic links and special files (FIFOs, sockets, devices) are skipped in both directions, so a link cannot lead a transfer
outside the tree and an upload never waits on a FIFO. A download treats the server as untrusted: a name that cannot be a file
name here (a separator, `.` or `..`, control characters, a name that was not valid UTF-8; on Windows also `\`, `:`, device names
such as `CON` or `NUL`, and a trailing dot or space) is skipped and counted in `summary.Skipped`. A path that would still end up
outside the target directory, or a tree deeper than 64 levels, stops the download with an `SshException` (`TransferFailed`).

## Files as streams

`OpenAsync(path, FileMode, FileAccess)` opens a remote file as a seekable `Stream`, with `FileMode` meaning what it does for
`FileStream`. `OpenReadAsync` and `OpenWriteAsync` are the common cases.

```csharp
await using var log = await sftp.OpenAsync("app.log", FileMode.Append, FileAccess.Write);
await log.WriteAsync(Encoding.UTF8.GetBytes("deployed\n"));
```

The stream is asynchronous only. `SetLength` truncates or extends the remote file. Each `ReadAsync` is one request; for whole
files, `DownloadAsync` is much faster. `Length` is the size when the stream opened plus this stream's own writes and
`SetLength`, so it needs no round trip; to see another writer's changes, ask the server (`GetAttributesAsync`).

## Files, directories and links

| Method | Does |
|---|---|
| `GetAttributesAsync(path, followSymbolicLinks)` | Size, owner, permissions, times, file type (`IsDirectory`, `IsRegularFile`, `IsSymbolicLink`). |
| `SetAttributesAsync(path, attributes, followSymbolicLinks)` | Changes the attributes that are set: `Size`, `Permissions`, `LastWriteTime`, ... With `followSymbolicLinks: false`, those of a link itself (`lsetstat@openssh.com`; Linux keeps a link's permissions, but its times change). |
| `GetOwnerNamesAsync(userIds, groupIds)` | User and group names for owner ids, as `ls -l` shows them (`users-groups-by-id@openssh.com`), as an `SftpOwnerNames` (`UserNames`, `GroupNames`). |
| `ExistsAsync(path)` | Whether the path exists. |
| `ListDirectoryAsync(path)` | The entries, as `IAsyncEnumerable<SftpFileInfo>`, without `.` and `..`. A name that is not valid UTF-8 is listed with replacement characters (and cannot be opened by that name); a listing stops with an error after 1,000,000 entries. |
| `CreateDirectoryAsync`, `DeleteDirectoryAsync` | One directory (deleting needs it empty). |
| `DeleteFileAsync` | A file, or a link itself. |
| `RenameAsync(old, new, overwrite)` | Rename or move; `overwrite` replaces the target atomically (`posix-rename@openssh.com`). |
| `CreateSymbolicLinkAsync`, `ReadSymbolicLinkAsync` | Symbolic links. |
| `CreateHardLinkAsync` | Hard links (`hardlink@openssh.com`). |
| `GetFullPathAsync`, `GetHomeDirectoryAsync` | Resolve a path; the login directory. |
| `ExpandPathAsync(path)` | Resolve a path with `~`, `~/dir` or `~user/dir` in it, as `sftp` does (`expand-path@openssh.com`; without it, only your own `~`). |
| `CopyFileAsync(source, destination, overwrite)` | Copy on the server, without the data passing through this machine (`copy-data`). Copying a file onto itself is refused. |
| `GetFileSystemInfoAsync(path)` | Size and free space of the file system, as `df` shows them (`statvfs@openssh.com`). |

On a writable stream, `FlushAsync` asks the server to write the file to disk (`fsync@openssh.com`) when it can; every write is
acknowledged anyway.

Remote paths are passed to the server as they are: relative paths are relative to the login directory, and `/` is the
separator whatever this machine uses. `Extensions` lists what the server supports, and `Limits` the sizes it accepts.

## Serving files with `IFileProvider`

The `SshSharp.FileProviders` package (`dotnet add package SshSharp.FileProviders`) turns a directory on the server into an
`IFileProvider`. Anything that reads through `Microsoft.Extensions.FileProviders` can then use the server's files: ASP.NET Core
static files, Razor views, configuration. Nothing is mounted, so only your application sees them.

```csharp
using SshSharp.FileProviders;

var provider = new SftpFileProvider(sftp, "/srv/www");

app.UseStaticFiles(new StaticFileOptions { FileProvider = provider });   // ASP.NET Core
builder.Configuration.AddJsonFile(provider, "appsettings.json", optional: false, reloadOnChange: false);
```

- **Read-only.** Paths are relative to the root; `/` and `\` both separate, and a path with `..` does not exist, so nothing
  outside the root can be reached. Symbolic links are followed on the server; links that lead nowhere are left out of listings.
- **Synchronous by contract.** `IFileProvider` lookups are synchronous, so each waits for an SFTP round trip, bounded by
  `SftpFileProviderOptions.OperationTimeout` (30 s), and holds a thread-pool thread meanwhile. Attributes and listings are
  cached for `CacheDuration` (5 s; zero turns it off), at most `MaxCacheEntries` of them (10,000), and `ClearCache()` forgets
  them. Streams read ahead, and are fastest read asynchronously, as the static files middleware
  does.
- **No change notifications.** SFTP has none, so `Watch` returns a token that never fires (`reloadOnChange` has no effect).
- A missing file, or one the server will not let you read, has `Exists` false. A broken session or connection throws
  `SshException`.
- The provider does not own the `SftpClient`: dispose that after the provider is no longer used.

## Using `IFileSystem` (System.IO.Abstractions)

The `SshSharp.IO.Abstractions` package (`dotnet add package SshSharp.IO.Abstractions`) implements
[System.IO.Abstractions](https://github.com/TestableIO/System.IO.Abstractions)' `IFileSystem` over SFTP. Code written against
`IFileSystem` instead of `File`, `Directory` and `Path` then reads and writes files on the server, unchanged. Nothing is mounted,
so only your application sees them.

```csharp
using System.IO.Abstractions;
using SshSharp.IO.Abstractions;

IFileSystem fs = new SftpFileSystem(sftp);
fs.Directory.CreateDirectory("reports/2026");
fs.File.WriteAllText("reports/2026/summary.txt", "All green.");
var reports = fs.Directory.GetFiles("reports", "*.txt", SearchOption.AllDirectories);
```

| Area | Behaviour |
|---|---|
| Paths | POSIX paths on the server, on every client OS: `fs.Path` uses `/`, and `\` is an ordinary character. Relative paths start from the current directory, initially the login directory; `Directory.SetCurrentDirectory` changes it (client-side). |
| `File` | Reads and writes of bytes, text and lines (sync and async; UTF-8 without BOM by default, BOMs honoured when reading), streams, `Copy` (on the server with `copy-data`), `Move`, `Delete`, times, attributes, Unix modes, symbolic links. |
| `Directory` | `CreateDirectory` with parents, `Delete` (recursive removes links, never follows them), enumeration with `*` and `?` patterns, `SearchOption` and `EnumerationOptions` (recursion, case, hidden entries, special directories), `Move`, times. |
| `FileInfo`, `DirectoryInfo` | Attributes are read on first use and kept until `Refresh()`, as in `System.IO`; enumerations carry each entry's attributes, so no request per entry. |
| Streams | Buffered (64 KiB), sync and async, seekable; read-only streams read ahead. |
| Errors | The `System.IO` exceptions, from sync and async methods alike: `FileNotFoundException`, `DirectoryNotFoundException`, `UnauthorizedAccessException`, `IOException` (also a failed session or a timeout). `Exists` never throws: it is false when the answer cannot be had. `Copy` onto the same file is an `IOException`. |
| Timeouts | `SftpFileSystemOptions.OperationTimeout` (60 s; `Timeout.InfiniteTimeSpan` for none) bounds each request, and for whole-file reads, writes and copies the time without progress, so large files are not cut off. |
| Not supported | `FileSystemWatcher`, `DriveInfo`, `FileVersionInfo`, `RandomAccess`, `SafeFileHandle` overloads, encryption, `Replace`: they throw `NotSupportedException`. SFTP has no creation times: they read as the last write time, and setting one does nothing. |

The synchronous methods wait for SFTP round trips; the `...Async` ones do not block. `IFile`'s Unix-mode methods are marked
Unix-only for local files, but work over SFTP from any client OS (suppress CA1416 where you call them).

## Errors

A request the server refuses throws `SftpException`, an `SshException` with `Reason = SftpFailed`, `Status` (the SFTP status
code, such as `NoSuchFile`, `PermissionDenied` or `Failure`) and the `Path` concerned. A broken SFTP session or connection is an
`SshException` with `ChannelClosed` or `ConnectionClosed`. An operation needing an extension the server lacks (an overwriting
rename, a hard link) throws `NotSupportedException`.

## SFTP or SCP?

Prefer SFTP. It can list, resume and change files, and OpenSSH 9.0 switched its own `scp` command to SFTP by default. SCP
(see [File transfer (SCP)](scp.md)) remains for servers that do not offer SFTP.
