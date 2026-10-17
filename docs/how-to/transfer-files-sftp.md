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

## Copy whole directories

[!code-csharp[](../snippets/FileTransfer.cs#sftp-directories)]

Symbolic links and special files are skipped in both directions. A download treats the server as untrusted: a name that cannot be
a safe file name here is skipped and counted in `Skipped`, and a path that would land outside the target stops the download.

## Browse and change the remote file system

[!code-csharp[](../snippets/FileTransfer.cs#sftp-browse)]

## Replace a file atomically

Readers must never see a half-written configuration file. Upload under a temporary name and rename over the target; with
`overwrite: true` the rename is atomic (`posix-rename@openssh.com`):

[!code-csharp[](../snippets/FileTransfer.cs#sftp-atomic)]

## Work with remote files as streams

`OpenAsync`, `OpenReadAsync` and `OpenWriteAsync` return a seekable `Stream` over a remote file, with `FileMode` and `FileAccess`
meaning what they do for `FileStream`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-stream)]

## Handle errors

A request the server refuses throws `SftpException`, with the SFTP `Status` and the `Path`:

[!code-csharp[](../snippets/FileTransfer.cs#sftp-errors)]

## Notes and pitfalls

- **Paths.** Remote paths go to the server as they are: relative paths start at the login directory, and `/` is the separator
  whatever this machine uses. `GetFullPathAsync` and `ExpandPathAsync` resolve them.
- **Asynchronous streams.** SFTP file streams support only the asynchronous `Read`/`Write` methods; the synchronous ones throw
  `NotSupportedException`. For whole files, `DownloadAsync` is much faster than reading a stream.
- **Times.** SFTP version 3 carries modification times in whole seconds.
- **Extensions.** An operation that needs an extension the server lacks (an overwriting rename, a hard link, a server-side copy)
  throws `NotSupportedException`; `sftp.Extensions` lists what the server has.
- **A broken session** or connection throws `SshException` (`ChannelClosed` or `ConnectionClosed`); open a new `SftpClient`.

## See also

- [File transfer (SFTP)](../sftp.md) (in-depth guide: every option and operation)
- [IFileSystem and IFileProvider](file-system-adapters.md)
- [A file sync job](../scenarios/file-sync.md)
- <xref:SshSharp.Sftp.SftpClient> and <xref:SshSharp.Sftp.SftpTransferOptions> in the API reference
