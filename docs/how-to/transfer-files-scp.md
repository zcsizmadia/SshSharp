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

## Network devices and Windows servers

SCP runs `scp -t <path>` (or `scp -f <path>`) on the server, and by default writes the path as one single-quoted POSIX shell word:
`scp -t -- '/srv/in box/report.csv'`. That is safe for any path, but only a POSIX shell reads it that way.
`SshScpOptions.PathQuoting` (new in 1.3) writes it for servers that read the line differently:

| `PathQuoting` | The line | For |
|---|---|---|
| `Posix` (default) | `scp -t -- '/srv/in box/it'\''s.csv'` | Linux, BSD, macOS, and any server whose shell is `sh`, `bash` or `zsh` |
| `None` | `scp -t flash:/acl-update.txt` | Network devices whose SCP server reads the line itself, with no shell: Cisco IOS, MikroTik RouterOS and others. The quotes would become part of the file name there |
| `DoubleQuote` | `scp -t -- "C:\Reports\May 2024\report.csv"` | OpenSSH for Windows with its default shell, `cmd.exe`, which does not treat single quotes as quotes |

### Network devices

[!code-csharp[](../snippets/FileTransfer.cs#scp-device)]

`None` sends the path exactly as given, without `--` (which some devices would take for the path). So that nothing on the line can
be split, taken for an option or run, it allows only letters, digits and `/ . _ - : + @ , =`, and not `-` first; any other path
throws `ArgumentException` before anything is sent. That covers device paths such as `flash:/config.txt`, `nvram:startup-config`
or `disk0:/images/file.bin`. A path with a space cannot be sent this way.

### Windows servers

[!code-csharp[](../snippets/FileTransfer.cs#scp-windows)]

OpenSSH for Windows runs the line as `cmd.exe /c "<line>"`, and `scp.exe` then splits it by the C runtime's rules. Inside double
quotes, spaces, `&`, `^`, `(`, `)`, `;` and `'` are plain characters to both. `DoubleQuote` refuses, with `ArgumentException` and
before anything is sent, what they would still read:

- control characters (line breaks, tabs, escapes);
- `"`, which would end the word (no Windows name has one);
- `%`, which `cmd.exe` expands even inside double quotes (`%USERPROFILE%`), and `!`, which it expands there with delayed expansion;
- `$` and `` ` ``, which PowerShell expands inside double quotes, so that a server whose default shell is PowerShell cannot run
  anything either (the mode is meant and tested for `cmd.exe`);
- PowerShell's typographic double quotes (`“ ” „`), and `< > | * ?`, which Windows does not allow in names;
- a `\` at the end, which `scp.exe` would read, with the closing quote, as a literal `"`. Write `C:\Reports` or `C:/Reports/`.

CI runs the Windows mode against OpenSSH for Windows with `cmd.exe` as its shell.

### Only paths you control

`None` and `DoubleQuote` put the path on a command line that something other than a POSIX shell reads. The checks above refuse
what could split the path or run a command, but a path from user input can still name any file the account can reach (`..`,
another drive). Give these modes paths your application builds, and use [SFTP](transfer-files-sftp.md), which sends paths as data,
where the server offers it.

## Notes and pitfalls

- **Errors.** A failed transfer (missing file, permission denied, no `scp` on the server) throws `SshException` with
  `SshFailureReason.TransferFailed` and the server's own message.
- **Quoting.** By default, remote paths are passed to the server's shell as one single-quoted word, which is safe with POSIX shells.
  A Windows server whose default shell is `cmd.exe` or PowerShell does not read single quotes that way, and a network device reads
  them as part of the name: see [Network devices and Windows servers](#network-devices-and-windows-servers).
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
