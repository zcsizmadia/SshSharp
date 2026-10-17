# Interactive shells and SshExpect

`SshClient.StartShellAsync` starts the user's login shell, usually with a pseudo-terminal, as `ssh host` does. `SshExpect` scripts
such a session the way the `expect` tool does: wait for a prompt or other output, then send the next line.

## When to use

- The program only works interactively: `sudo` that asks for a password, an installer that asks questions, `passwd`.
- The server is a network device or appliance whose CLI is not a POSIX shell (routers, switches, storage arrays).
- You relay a terminal to a person, as a web terminal does.

When a plain command would do, prefer [`RunCommandAsync`](run-a-command.md): no prompt to wait for, no echo to skip, and you get
the exit status.

## A shell with a terminal

[!code-csharp[](../snippets/Shells.cs#shell-terminal)]

With a terminal, the server merges stderr into stdout and echoes your input. Resize it when the local window changes, and send
control characters as a user's keyboard would:

[!code-csharp[](../snippets/Shells.cs#shell-resize)]

## Answer a prompt with SshExpect

`ExpectAsync` waits until the output contains a text or matches a regular expression, and returns what came before it (`Before`),
the match (`Value`) and, for a regular expression, its groups (`Match`). Output after the match is kept for the next call.

[!code-csharp[](../snippets/Shells.cs#expect-sudo)]

## Read output line by line

`ReadLineAsync` reads from the same buffer, so lines and prompts mix. A prompt has no line feed after it, so wait for prompts with
`ExpectAsync` and use a marker line to find the end of a command's output:

[!code-csharp[](../snippets/Shells.cs#expect-lines)]

## Capture values with groups

[!code-csharp[](../snippets/Shells.cs#expect-groups)]

## Script a network device

[!code-csharp[](../snippets/Shells.cs#expect-device)]

## Start a subsystem

A subsystem is a protocol the server runs by name instead of a command, as `ssh -s` does: `netconf`, or anything configured with
sshd's `Subsystem`. The session's streams then carry that protocol byte for byte. (For SFTP use `client.OpenSftpAsync()`.)

[!code-csharp[](../snippets/Shells.cs#subsystem)]

## Notes and pitfalls

- **Timeouts are cancellation tokens.** Give the whole conversation one deadline (`CancelAfter`), as above. If the token is
  cancelled nothing is lost: `Pending` holds what has arrived.
- **The echo matches too.** With a terminal your input is echoed back, so a pattern can match the command you just sent. Wait for
  something the echo does not contain, such as the prompt that follows.
- **Anchor patterns.** Patterns are tried on output received so far: `\d+` could match the first digits of a number still
  arriving. Give regular expressions a match timeout, as above, when the output is not yours.
- **End of output.** If the session ends before a match, `ExpectAsync` throws `EndOfStreamException`.
- **One reader.** `SshExpect` reads `StandardOutput` itself. Do not also read it with a `StreamReader`; both buffer, so each would
  lose data the other read.
- **Secrets.** Prompts and output come from the server; strip control characters before showing them in a terminal, and never log
  what you send in answer to a password prompt.
- **Keystroke timing.** For applications that relay a person's typing, `SshClientOptions.ObscureKeystrokeTiming` hides the timing
  of keys from someone watching the traffic. See [Commands and shells](../sessions.md#hiding-keystroke-timing).

## See also

- [Commands and shells](../sessions.md) (in-depth guide, including terminal modes, signals and BREAK)
- [Migrate from SSH.NET: shells](../migrating-from-sshnet.md#shells)
- <xref:SshSharp.SshExpect> and <xref:SshSharp.SshTerminalOptions> in the API reference
