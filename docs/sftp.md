# File transfer (SFTP)

SFTP is the file protocol of SSH: browse directories, read and write files in place, and transfer them, over the same connection
as your commands. SshSharp speaks SFTP version 3, the version OpenSSH's `sftp-server` and `internal-sftp` implement, with
OpenSSH's extensions.

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
| `MaxRequestsInFlight` | The window of outstanding requests (1 to 1024), for the whole transfer: a directory transfer's files share it. |
| `Resume` | Continue an interrupted transfer, as `reget` and `reput` do: only the part the destination lacks is sent. |
| `Segments` (default 1) | Download one file in up to 16 parallel ranges, each over its own SFTP session (see below). |
| `MaxConcurrentFiles` (default 1) | Transfer up to 64 files of a directory at once over the same session (see [Several files at once](#several-files-at-once)). |

A failed download leaves no partial local file behind, unless `Resume` is set, in which case what arrived is kept for the
next attempt. A resume trusts that the destination's bytes are the start of the same file (nothing compares them), and a
destination larger than the source is an error.

### Memory

Transfers reuse their buffers instead of allocating new ones for each request, so moving a large file costs the garbage collector
little:

- **Uploads** read the source straight into the request that carries the data. The buffer comes from the shared pool
  (`ArrayPool<byte>.Shared`) and goes back as soon as the request is sent, before the server acknowledges it.
- **Downloads** receive each reply's data into a pooled buffer. It goes back once the data is written to the destination.
- **Other requests** (opening, listing, attributes) are built in pooled buffers too.

With OpenSSH's 255 KiB reads and writes, each buffer is a 256 KiB array. The pool keeps buffers for the next transfer, and the
runtime trims it when memory is short.

Both streams must follow the `Stream` contract. `UploadAsync` reads into a buffer that is sent and then reused, and `DownloadAsync`
writes from a buffer that is reused once `WriteAsync` completes. A stream that keeps the buffer it was given after the call returns
would see other data later. `MemoryStream`, `FileStream` and the BCL's other streams copy what they keep.

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

### Several files at once

By default a directory transfer moves one file after another. Each file costs round trips of its own however small it is
(opening it, closing it, and reading or setting its attributes), so over 50 to 100 ms of latency a tree of many
small files spends most of its time waiting. `MaxConcurrentFiles` (1 to 64) transfers that many files at once over the same
session:

```csharp
var options = new SftpTransferOptions { MaxConcurrentFiles = 8 };
var summary = await sftp.UploadDirectoryAsync("site", "/srv/www/site", options);
```

Use it for trees of many small or medium files on links with latency; 4 to 16 is a good range. Over 25 ms of added latency, a
tree of 60 small files and one of 700 KB uploaded about 4 times faster to OpenSSH with 16 than with 1, and downloaded about 3 times
faster. It does not speed up a few large files, which already keep the request window full; `Segments` is for those.

- **Requests in flight and memory.** `MaxRequestsInFlight` bounds the whole transfer, not each file: the files share its slots,
  each read or write holding one until its data is written out or acknowledged. So the memory a directory transfer holds does not
  grow with `MaxConcurrentFiles`: at most `MaxRequestsInFlight` times the request size (64 × 32 KiB = 2 MiB by default, 64 × 255 KiB
  ≈ 16 MiB with OpenSSH's `limits@openssh.com`), plus a 64 KiB local file buffer for each file in flight. Opening, closing and
  setting attributes add about one small request for each file in flight. A file that has requests in flight never waits for a
  slot (it reuses its own as replies come), so files cannot block each other.
- **Order.** A directory is created before any file goes into it. An upload walks the local tree first, then creates the remote
  directories several at a time (each as soon as its parent exists) while the files follow in the walk's order. A download lists
  the remote tree directory by directory, as before, and hands each file to a free slot. With `Preserve`, directories get their
  times and permissions once every file is in, the deepest first. Two names that differ only in case go one after the other, as
  they may be the same file on the receiving side.
- **Open handles.** When the server announces a limit on open files (`limits@openssh.com`), fewer files go at once if needed, one
  handle kept for listings.
- **Segments.** With `Segments` as well, each large file may open sessions of its own, so a download can ask for up to
  `MaxConcurrentFiles × (Segments − 1)` extra sessions; the server's `MaxSessions` (10 by default) caps them, and a file that gets
  none downloads over the main session. All their reads still share `MaxRequestsInFlight`.
- **Errors and cancellation.** The first failure cancels the files still in flight and is the exception the transfer throws (not an
  `AggregateException`). Each stopped file is left as a failed single-file transfer leaves it: a download is deleted (unless `Resume`
  is set), an upload keeps what was written. Cancelling the token stops every file.
- **Progress.** `Progress` still reports each file by its path; reports from different files interleave, but the callback is never
  called from two threads at once, so it needs no locking of its own. Sum the last report of each path for a total.

`MaxConcurrentFiles` applies to `UploadDirectoryAsync` and `DownloadDirectoryAsync` only. To transfer a list of files of your own
at once, call `UploadFileAsync` or `DownloadFileAsync` from several tasks on one `SftpClient`; each then has its own window.

## Files as streams

`OpenAsync(path, FileMode, FileAccess)` opens a remote file as a seekable `Stream`, with `FileMode` meaning what it does for
`FileStream`. `OpenReadAsync` and `OpenWriteAsync` are the common cases.

```csharp
await using var log = await sftp.OpenAsync("app.log", FileMode.Append, FileAccess.Write);
await log.WriteAsync(Encoding.UTF8.GetBytes("deployed\n"));
```

The stream is asynchronous only. `SetLength` truncates or extends the remote file. A stream opened only for reading reads ahead
(up to 16 reads in flight) while it is read in order; one that also writes reads one request at a time. Read-ahead replies are held in
pooled buffers (see [Memory](#memory)) until their data is read, so a read-only stream allows one `ReadAsync` at a time: a second
one while the first is still running throws `InvalidOperationException`. Disposing the stream during a read is safe. For whole files,
`DownloadAsync` is still faster. `Length` is the size when the stream opened plus this stream's own writes (including those still
in flight) and `SetLength`, so it needs no round trip; to see another writer's changes, ask the server (`GetAttributesAsync`).

### Writes in flight

`WriteAsync` does not wait for the server's reply. It splits the data into requests of the server's write size, sends them and
returns, keeping up to 16 writes in flight per stream; when 16 are outstanding it waits for the oldest. So `CopyToAsync` into
`OpenWriteAsync` keeps the link busy, as `UploadAsync` does, and memory stays bounded: at most 16 requests (16 × 32 KiB = 512 KiB
by default, about 4 MiB with OpenSSH's 255 KiB writes). The data is copied into the requests before `WriteAsync` returns, so
the caller's buffer can be reused at once. Nothing is held back to be combined: each `WriteAsync` sends its data, so many tiny
writes are many requests (put a `BufferedStream` in front, as the `IFileSystem` adapter does). Writes go out in offset order.

A write the server refuses is never lost. Which call reports it depends on when its reply comes:

| Call | Waits for the writes in flight? | Reports a failed write |
|---|---|---|
| `WriteAsync` | Only the oldest, when 16 are outstanding, and all of them after a seek. | Any that has failed by then. |
| `FlushAsync` | All of them, then asks the server to write the file to disk (`fsync@openssh.com`) when it can. | Any. |
| `ReadAsync` (read-write stream), `GetLengthAsync`, `SetLength` | All of them, so they see (or change) what was written. | Any. |
| `Seek`, `Position` set, `Flush` | No. | Any that has failed by then. |
| `DisposeAsync`, `Dispose` | All of them, then close the handle (also after a failure). | Any not reported yet. |

After a failure the stream is faulted: every later call throws the same exception, and disposing closes the handle without
throwing it again. Writes sent after the failed one may or may not have landed, so treat the file as incomplete. Cancelling a `WriteAsync` while it waits also faults the stream, since part of its data may have been sent.
Cancelling `FlushAsync` or a read only stops that wait: the writes stay in flight and the stream stays usable.

To get the errors where you handle them, end with `await stream.FlushAsync()` (or `await using`, whose `DisposeAsync` waits too).
A synchronous `Dispose` also waits for the writes in flight, blocking the thread, so dispose asynchronously when you can.

## Files, directories and links

| Method | Does |
|---|---|
| `GetAttributesAsync(path, followSymbolicLinks)` | Size, owner, permissions, times, file type (`IsDirectory`, `IsRegularFile`, `IsSymbolicLink`). |
| `SetAttributesAsync(path, attributes, followSymbolicLinks)` | Changes the attributes that are set: `Size`, `Permissions`, `LastWriteTime`, ... With `followSymbolicLinks: false`, those of a link itself (`lsetstat@openssh.com`; Linux keeps a link's permissions, but its times change). |
| `GetOwnerNamesAsync(userIds, groupIds)` | User and group names for owner ids, as `ls -l` shows them (`users-groups-by-id@openssh.com`), as an `SftpOwnerNames` (`UserNames`, `GroupNames`). |
| `ExistsAsync(path)` | Whether the path exists. |
| `ListDirectoryAsync(path)` | The entries, as `IAsyncEnumerable<SftpFileInfo>`, without `.` and `..`. A name that is not valid UTF-8 is listed with replacement characters (and cannot be opened by that name); a listing stops with an error after 1,000,000 entries. |
| `CreateDirectoryAsync`, `DeleteDirectoryAsync` | One directory (deleting needs it empty). |
| `CreateDirectoryAsync(path, createParents: true)` | As `mkdir -p`: the missing directories above it too, and an existing directory is not an error (a file in the path is). `permissions` apply to the last one. |
| `DeleteDirectoryAsync(path, recursive: true)` | As `rm -r`: the directory and everything in it, many requests at once; links are removed, never followed. The first failure stops it and is thrown, leaving the rest ([details](how-to/transfer-files-sftp.md#delete-recursively)). |
| `DeleteFileAsync` | A file, or a link itself. |
| `ReadAllBytesAsync`, `ReadAllTextAsync(path, encoding)` | A whole file into memory, with many reads in flight; text honours a byte order mark, else UTF-8 or `encoding`. |
| `WriteAllBytesAsync`, `WriteAllTextAsync(path, contents, encoding)` | Create or replace a file with these contents (UTF-8 without a byte order mark by default). A failure part way leaves it partly written. |
| `RenameAsync(old, new, overwrite)` | Rename or move; `overwrite` replaces the target atomically (`posix-rename@openssh.com`). |
| `CreateSymbolicLinkAsync`, `ReadSymbolicLinkAsync` | Symbolic links. |
| `CreateHardLinkAsync` | Hard links (`hardlink@openssh.com`). |
| `GetFullPathAsync`, `GetHomeDirectoryAsync` | Resolve a path; the login directory. |
| `ExpandPathAsync(path)` | Resolve a path with `~`, `~/dir` or `~user/dir` in it, as `sftp` does (`expand-path@openssh.com`; without it, only your own `~`). |
| `CopyFileAsync(source, destination, overwrite)` | Copy on the server, without the data passing through this machine (`copy-data`). Copying a file onto itself is refused. |
| `GetFileSystemInfoAsync(path)` | Size and free space of the file system, as `df` shows them (`statvfs@openssh.com`). |

On a writable stream, `FlushAsync` waits for the writes in flight, then asks the server to write the file to disk
(`fsync@openssh.com`) when it can (see [Writes in flight](#writes-in-flight)).

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
| Streams | Buffered (64 KiB), sync and async, seekable; read-only streams read ahead, and writes are written behind, so a failed write is thrown (as an `IOException`) by a later call, at the latest by `Flush` or `Dispose`. |
| Errors | The `System.IO` exceptions, from sync and async methods alike: `FileNotFoundException`, `DirectoryNotFoundException`, `UnauthorizedAccessException`, `IOException` (also a failed session or a timeout). `Exists` never throws: it is false when the answer cannot be had. `Copy` onto the same file is an `IOException`. |
| Timeouts | `SftpFileSystemOptions.OperationTimeout` (60 s; `Timeout.InfiniteTimeSpan` for none) bounds each request, and for whole-file reads, writes and copies the time without progress, so large files are not cut off. |
| Not supported | `FileSystemWatcher`, `DriveInfo`, `FileVersionInfo`, `RandomAccess`, `SafeFileHandle` overloads, encryption, `Replace`: they throw `NotSupportedException`. SFTP has no creation times: they read as the last write time, and setting one does nothing. |

The synchronous methods wait for SFTP round trips; the `...Async` ones do not block. `IFile`'s Unix-mode methods are marked
Unix-only for local files, but work over SFTP from any client OS (suppress CA1416 where you call them).

## Timeouts

Each method takes a `CancellationToken`, and `SftpClient.OperationTimeout` (off by default) fails a request once the server has sent
nothing at all for that long: `SshException` with `Reason = Timeout` and an inner `TimeoutException`. It limits the server's silence,
not how long an operation takes, so a transfer whose window of requests takes longer than the timeout to work through goes on as long
as replies keep coming. A request that timed out is abandoned (its late reply is dropped, a handle it opens is closed) and the session
stays usable. See [Fail when the server stops answering](how-to/transfer-files-sftp.md#fail-when-the-server-stops-answering).

The adapters above (`IFileProvider`, `IFileSystem`) have an `OperationTimeout` of their own, which they apply to each call with a
token and report their own way (`SshException` and `IOException`). They do not change the `SftpClient`'s; set that too if you want
both, and the adapters report its timeout as they report a failed session.

## Errors

A request the server refuses throws `SftpException`, an `SshException` with `Reason = SftpFailed`, `Status` (the SFTP status
code, such as `NoSuchFile`, `PermissionDenied` or `Failure`) and the `Path` concerned. A broken SFTP session or connection is an
`SshException` with `ChannelClosed` or `ConnectionClosed`, and a passed `OperationTimeout` one with `Timeout`. An operation needing
an extension the server lacks (an overwriting rename, a hard link) throws `NotSupportedException`.

## SFTP or SCP?

Prefer SFTP. It can list, resume and change files, and OpenSSH 9.0 switched its own `scp` command to SFTP by default. SCP
(see [File transfer (SCP)](scp.md)) remains for servers that do not offer SFTP.

The [sample tool](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples)'s `get`, `put` and `tree` commands show transfers
with `Preserve`, progress, segments and resuming, and `IFileSystem` over SFTP.

## See also

- How-to guides: [Transfer files with SFTP](how-to/transfer-files-sftp.md) (with a diagram of a pipelined transfer),
  [IFileSystem and IFileProvider](how-to/file-system-adapters.md)
- Scenarios: [A file sync job](scenarios/file-sync.md), [A background worker](scenarios/background-worker.md)
