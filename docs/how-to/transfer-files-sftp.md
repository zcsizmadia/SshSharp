# Transfer files with SFTP

SFTP is SSH's file protocol. `client.OpenSftpAsync()` opens an SFTP session over an existing connection; the `SftpClient` it returns
uploads and downloads files, streams and whole directories, and browses and changes the server's file system.

## When to use

- Copying files to or from a server: releases, backups, reports, logs.
- Working on remote files in place: appending to a log, reading the end of a large file, renaming, setting permissions.
- Prefer SFTP to [SCP](transfer-files-scp.md) whenever the server offers it (OpenSSH always does): it can list, resume and
  change files, and OpenSSH's own `scp` command uses SFTP by default since 9.0.

## Open a session

[!code-csharp[](../snippets/FileTransfer.cs#sftp-open)]

An `SftpClient` is one SFTP session (one SSH channel). Several can share an `SshClient`, and one can be used by several tasks at
once. Disposing it ends the session; the connection stays up.

## Upload and download

[!code-csharp[](../snippets/FileTransfer.cs#sftp-upload-download)]

## How a transfer runs

SFTP is a request-and-reply protocol, and on a link with latency, waiting for each reply before sending the next request would be
slow. The transfer methods keep many requests in flight at once (64 by default, as OpenSSH's `sftp` does), each as large as the
server allows (`limits@openssh.com`, or 32 KiB):

```mermaid
sequenceDiagram
    participant C as SftpClient.UploadFileAsync
    participant S as SFTP server
    C->>S: OPEN incoming/report.pdf (write, create, truncate)
    S-->>C: HANDLE
    par up to MaxRequestsInFlight requests outstanding
        C->>S: WRITE offset 0
        C->>S: WRITE offset 32768
        C->>S: WRITE offset 65536 ...
    and replies, in any order
        S-->>C: STATUS ok
        S-->>C: STATUS ok
    end
    Note over C,S: each reply frees a slot for the next WRITE
    C->>S: CLOSE handle
    S-->>C: STATUS ok
    opt Preserve = true
        C->>S: SETSTAT (times, permissions)
    end
```

Downloads work the same way with `READ`. A transfer is still bounded by the channel's flow-control window (2 MiB), which is where
segmented downloads help (below).

## Progress, overwrite and preserved attributes

[!code-csharp[](../snippets/FileTransfer.cs#sftp-progress)]

## Resume an interrupted transfer

With `Resume = true`, a transfer sends only the part the destination lacks, as `reget` and `reput` do; a failed download keeps what
arrived. Retry in a loop, with a new connection when the old one broke:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-resume)]

> [!WARNING]
> Resuming trusts that the bytes already at the destination are the start of the same file; nothing compares them. Resume only
> into a destination that nothing else writes.

## Download large files faster

One SFTP session moves at most about one window (2 MiB) per round trip: some 20 MiB/s at 100 ms of latency, however many requests
are in flight. `Segments` splits a download into ranges and fetches each over its own session on the same connection:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-segments)]

It helps on high-latency links and where one server process is the limit; it does not help where bandwidth is the limit. The
server may allow fewer sessions than asked (sshd's `MaxSessions`). Segments apply to `DownloadFileAsync` and
`DownloadDirectoryAsync` only, and not together with `Resume`.

A larger window does the same for one session, for every download (and for `Resume`): set `ChannelWindowSize` on the connection,
for example to 16 MiB. The two combine. See
[Tune and inspect a connection](tune-and-inspect-connections.md#move-more-data-per-round-trip-on-long-links).

## Copy whole directories

[!code-csharp[](../snippets/FileTransfer.cs#sftp-directories)]

Symbolic links and special files are skipped in both directions. A download treats the server as untrusted: a name that cannot be
a safe file name here is skipped and counted in `Skipped`, and a path that would land outside the target stops the download.

## Copy many small files faster

A directory transfer moves one file after another by default, and each file costs a few round trips (open, size, close) however
small it is. Over a link with latency, a tree of many small files spends most of its time waiting. `MaxConcurrentFiles` transfers
several files at once over the same session:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-concurrent-files)]

### When to use

- Many small or medium files (source trees, web sites, logs) over 20 ms or more of latency: start with 8. Over 25 ms of added
  latency, uploading 61 files to OpenSSH took 14.1 s one at a time and 3.3 s with 16 at once.
- Not for a few large files: one file already keeps `MaxRequestsInFlight` requests in flight. For those, use `Segments`.

### How it interacts with the other options

- **`MaxRequestsInFlight`** is the window of the whole transfer: the files share it. Memory stays at most `MaxRequestsInFlight`
  requests (2 MiB by default, about 16 MiB with OpenSSH's larger requests) plus 64 KiB per file in flight, whatever
  `MaxConcurrentFiles` is. Raise `MaxRequestsInFlight` if larger files in the tree should keep a full window while others run.
- **`Segments`** still splits each large file of a download over sessions of its own, so the sessions add up across files. The
  server's `MaxSessions` (10 by default) caps them; a file that gets no extra session downloads over the main one.
- **`Preserve`** sets directory times and permissions after every file is in, the deepest first.
- **`Progress`** reports each file by its path, interleaved, but never from two threads at once.

### Notes and pitfalls

- The first failure stops the other files and is the exception thrown; stopped downloads are deleted, stopped uploads keep what was
  written, as for a single file. Cancelling stops every file.
- A server that limits open files (`limits@openssh.com`) gets fewer files at once.
- The single-file methods ignore `MaxConcurrentFiles`. To transfer your own list of files at once, call `UploadFileAsync` or
  `DownloadFileAsync` from several tasks on one `SftpClient`, which is safe.

## Browse and change the remote file system

[!code-csharp[](../snippets/FileTransfer.cs#sftp-browse)]

## Read and write whole files

For a small file (a configuration, a manifest, a marker), `ReadAllBytesAsync`, `ReadAllTextAsync`, `WriteAllBytesAsync` and
`WriteAllTextAsync` do it in one call, as their `File` namesakes do locally:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-whole-files)]

- **Text** is UTF-8 by default. Reading honours a byte order mark when there is one; writing adds none unless you pass an
  `Encoding` that has one, as `File.WriteAllTextAsync` does.
- **Writing replaces the file**: it is created or truncated, then written with many writes in flight. A failure part way leaves it
  partly written; when readers must never see that, [replace it atomically](#replace-a-file-atomically) instead.
- **Reading holds the whole file in memory** (at most about 2 GiB, the largest array). For large files, use `DownloadFileAsync`
  or `DownloadAsync` into a stream.

## Create and delete directory trees

`CreateDirectoryAsync` and `DeleteDirectoryAsync` work on one directory. With `createParents: true` and `recursive: true` they work
on trees, as `mkdir -p` and `rm -r` do:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-trees)]

### Create with parents

- An existing directory is not an error; a file anywhere in the path is (`SftpException`, `Status = Failure`).
- The directory is created first, and only if that fails are the directories above it looked at, up to the first that exists. An
  existing tree costs one request, and a directory above that you may not write to (a chroot's top, for example) is never touched.
- `permissions` apply to the last directory only; the parents get the server's defaults, as `mkdir -p -m` does.

### Delete recursively

Each directory is listed, emptied and then removed, with many requests in flight: up to 64 removals at once, and up to 4
directories listed at once (fewer when the server limits open handles). A tree of thousands of files costs a few round trips per
directory, not one per file.

```mermaid
flowchart LR
    L["List the directory<br/>(whole, then close it)"] --> F["Remove its files and links<br/>(up to 64 REMOVE in flight)"]
    L --> D["Each subdirectory: LSTAT,<br/>then the same, on a free walker<br/>or right here"]
    F --> R["RMDIR the directory"]
    D --> R
```

- **Links are never followed.** A symbolic link in the tree is removed itself, even when it points to a directory; every
  subdirectory is checked with `LSTAT` before it is entered, so a server that describes a link as a directory in its listing
  cannot lead the delete out of the tree. A `path` that is itself a link removes only the link.
- **The first failure stops it.** No more requests are sent, the ones in flight finish, and that failure is thrown (for example
  `SftpException` with `PermissionDenied` and the `Path` it could not delete). What was deleted stays deleted; once the cause is
  fixed, calling again finishes the job. Cancelling stops it the same way.
- **Entries that vanish** meanwhile (deleted by someone else) are not an error, but a `path` that does not exist is
  (`NoSuchFile`).
- **Depth** is limited to 64 levels, as for directory downloads (`SshException`, `Reason = TransferFailed`).

## Fail when the server stops answering

By default, a request waits for its reply as long as the session lasts. A server that hangs (a stuck disk, a network path that
drops packets without closing the connection) then hangs your code too. Set `OperationTimeout`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-operation-timeout)]

- **It limits silence, not duration.** A request fails once the server has sent nothing at all for that long. While replies keep
  coming, a request waits on, so a large transfer over a slow link is never cut off for its size, even when a window of 64 requests
  takes longer than the timeout to work through.
- **What is thrown:** `SshException` with `Reason = Timeout`, and a `TimeoutException` as its inner exception. Your
  `CancellationToken` still works alongside it, and cancelling is an `OperationCanceledException`, never a timeout.
- **The session stays usable.** A request that timed out is abandoned, not undone: the server may still carry it out, and its
  late reply is dropped (a file it opens is closed again). A server that has really stopped answering fails the next requests too;
  reconnect, and resume transfers with `Resume = true`.
- It applies to every request of the `SftpClient`, including those of streams, listings and transfers, and to the extra sessions
  of a segmented download. Change it at any time.
- [Keep-alives](keepalive-and-reconnect.md) (`KeepAliveInterval`) detect a dead connection; `OperationTimeout` also catches a
  server that is connected but no longer answering SFTP requests.

## Replace a file atomically

Readers must never see a half-written configuration file. Upload under a temporary name and rename over the target; with
`overwrite: true` the rename is atomic (`posix-rename@openssh.com`):

[!code-csharp[](../snippets/FileTransfer.cs#sftp-atomic)]

## Work with remote files as streams

`OpenAsync`, `OpenReadAsync` and `OpenWriteAsync` return a seekable `Stream` over a remote file, with `FileMode` and `FileAccess`
meaning what they do for `FileStream`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-stream)]

### Copy a stream into a remote file

When the data comes from a stream (a response body, a compressor, a database export), copy it into `OpenWriteAsync`. The stream
writes behind: `WriteAsync` sends its requests and returns without waiting for the replies, keeping up to 16 in flight, so the copy
runs close to the speed of `UploadAsync`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-stream-copy)]

```mermaid
sequenceDiagram
    participant A as Your code
    participant F as SFTP file stream
    participant S as SFTP server
    A->>F: WriteAsync (returns once sent)
    F->>S: WRITE offset 0
    A->>F: WriteAsync
    F->>S: WRITE offset 32768 ... up to 16 in flight
    S-->>F: STATUS ok
    S-->>F: STATUS failure (disk full)
    A->>F: FlushAsync
    Note over F: waits for every write in flight
    F-->>A: throws SftpException (disk full)
    A->>F: DisposeAsync
    F->>S: CLOSE handle
```

Over 25 ms of latency (the fake server in the tests, 4 MiB in 32 KiB requests), the copy took 0.40 s with write-behind, against
4.27 s when each write waited for its reply, and `UploadAsync` 0.17 s (it keeps 64 requests in flight). Against OpenSSH on the same
machine, copying 64 MiB took 9.7 s, against 17.0 s before, the same as `UploadAsync`.

- **Where errors appear.** A write the server refuses is thrown by a later call: the next `WriteAsync` that finds it, `FlushAsync`,
  a read, `SetLength`, or at the latest `DisposeAsync`. It is never lost. After that, the stream is faulted: every call throws the
  same exception, and disposing still closes the remote file. The [SFTP guide](../sftp.md#writes-in-flight) lists what each call
  waits for.
- **End with `FlushAsync`** (or rely on `await using`) to see a failure where you handle it, and to have the server write the file
  to disk where it can (`fsync@openssh.com`).
- **Cancelling a write** leaves the stream faulted, since part of the data may already be on the server: open the file again.
- **Many tiny writes** are many requests; nothing is combined. Put a `BufferedStream` in front when writing a few bytes at a time.
- **Whole files** are still simplest with `UploadFileAsync` or `UploadAsync`, which keep a wider window (64 by default) and report
  progress.

## Handle errors

A request the server refuses throws `SftpException`, with the SFTP `Status` and the `Path`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-errors)]

## Notes and pitfalls

- **Paths.** Remote paths go to the server as they are: relative paths start at the login directory, and `/` is the separator
  whatever this machine uses. `GetFullPathAsync` and `ExpandPathAsync` resolve them.
- **Asynchronous streams.** SFTP file streams support only the asynchronous `Read`/`Write` methods; the synchronous ones throw
  `NotSupportedException`. For whole files, `DownloadAsync` is faster than reading a stream. Writes are written behind, so a failed
  write is thrown by a later call (at the latest by `FlushAsync` or `DisposeAsync`), usually not by the `WriteAsync` that sent it.
- **Times.** SFTP version 3 carries modification times in whole seconds.
- **Extensions.** An operation that needs an extension the server lacks (an overwriting rename, a hard link, a server-side copy)
  throws `NotSupportedException`; `sftp.Extensions` lists what the server has.
- **A broken session** or connection throws `SshException` (`ChannelClosed` or `ConnectionClosed`); open a new `SftpClient`.

## See also

- [File transfer (SFTP)](../sftp.md) (in-depth guide: every option and operation)
- [IFileSystem and IFileProvider](file-system-adapters.md)
- [A file sync job](../scenarios/file-sync.md)
- <xref:SshSharp.Sftp.SftpClient> and <xref:SshSharp.Sftp.SftpTransferOptions> in the API reference
