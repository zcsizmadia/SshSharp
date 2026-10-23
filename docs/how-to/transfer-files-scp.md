# Transfer files with SCP

`using SshSharp.Scp;` adds SCP transfers to `SshClient` as extension methods. They run the server's `scp` program over an exec
channel (`scp -t` to receive, `scp -f` to send), as the classic `scp` command does.

## When to use

- The server has no SFTP subsystem: some embedded systems, appliances and restricted shells offer only `scp`.
- Otherwise prefer [SFTP](transfer-files-sftp.md): it can list, resume and change files, and does not depend on a program on the
  server.

## Files

[!code-csharp[](../snippets/FileTransfer.cs#scp-files)]

## Streams

[!code-csharp[](../snippets/FileTransfer.cs#scp-streams)]

`UploadAsync` takes the length from the stream; for a stream that cannot seek, pass `length:`. SCP sends the length before the
data, so it must be known in advance.

## Directories, permissions and progress

[!code-csharp[](../snippets/FileTransfer.cs#scp-directory)]

As with `scp -r`, the directory becomes the target when that does not exist, or goes inside it when it does.

## Notes and pitfalls

- **Errors.** A failed transfer (missing file, permission denied, no `scp` on the server) throws `SshException` with
  `SshFailureReason.TransferFailed` and the server's own message.
- **Quoting.** Remote paths are passed to the server's shell as one single-quoted word, which is safe with POSIX shells. A
  Windows server whose default shell is `cmd.exe` or PowerShell does not read single quotes that way.
- **Hostile servers.** Every name the server sends must be one path component, and a single-file download accepts exactly one file,
  so a server cannot write outside the target or add files (CVE-2019-6111). Set-id and sticky bits are never applied.
- **No resume, no listing.** SCP has neither; use SFTP for those.
- **`ScpCommand`.** `SshScpOptions.ScpCommand` names the program to run on the server, when `scp` is not on its `PATH`.
- **Tracing.** Each transfer is a span (`SshSharp.Scp.Upload`, `Download`, `UploadDirectory`, `DownloadDirectory`) with the bytes
  it moved, and `sshsharp.scp.bytes` counts the file data; no path is recorded. See
  [Tracing and metrics](../diagnostics.md#tracing-and-metrics).

## See also

- [File transfer (SCP)](../scp.md) (in-depth guide)
- [Transfer files with SFTP](transfer-files-sftp.md)
- <xref:SshSharp.Scp.SshScpExtensions> in the API reference
