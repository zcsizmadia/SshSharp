# Run a command

`SshClient.RunCommandAsync` runs a command on the server, waits for it to finish, and returns its standard output, standard error and
exit status. It is the SSH equivalent of `Process.Start` with redirected streams, for commands whose output fits in memory.

## When to use

- The command finishes on its own and prints a bounded amount of output: `systemctl status`, `df`, `git rev-parse`, a script.
- You need the exit status to decide what happens next.

For output that is large, endless or needed while the command runs, use [`StartCommandAsync`](stream-output.md) instead. For a
program that asks questions (a password prompt, a device CLI), see [Interactive shells](interactive-shell.md).

## Read stdout, stderr and the exit status

[!code-csharp[](../snippets/Commands.cs#run-basic)]

stdout and stderr arrive separately, as they do from `ssh host command`. `StandardOutputText` and `StandardErrorText` decode them
as UTF-8; `StandardOutput` and `StandardError` are the raw bytes:

[!code-csharp[](../snippets/Commands.cs#run-bytes)]

## Act on the result

A command that fails on the server is a result, not an exception: check `ExitStatus`. When the program was killed by a signal
there is no exit status, and `ExitSignal` says which signal:

[!code-csharp[](../snippets/Commands.cs#run-checked)]

## Pass arguments safely

The command text is a shell command line, parsed by the user's login shell on the server, exactly as with `ssh host 'command'`.
Quote every value you did not write yourself:

[!code-csharp[](../snippets/Commands.cs#quote)]

[!code-csharp[](../snippets/Commands.cs#run-quoted)]

> [!WARNING]
> Never build a command line by concatenating unquoted input: a file name such as `x; rm -rf ~` runs as two commands. The quoting
> above is for POSIX shells (`sh`, `bash`, `zsh`). A Windows server whose default shell is `cmd.exe` or PowerShell parses
> differently.

## Run several commands at once

One connection carries many channels, so independent commands can run concurrently. Each `RunCommandAsync` is its own session on
the server:

[!code-csharp[](../snippets/Commands.cs#run-parallel)]

The server limits how many sessions one connection may have open (sshd's `MaxSessions`, 10 by default). Commands are independent:
a `cd` in one does not affect the next. Chain dependent steps in one command line (`cd /srv/app && ./deploy.sh`).

## Notes and pitfalls

- **Output limit.** Output is collected in memory up to `SshClientOptions.MaxCommandOutputBytes` (128 MiB). Beyond that,
  `RunCommandAsync` throws `InvalidOperationException`: stream such output with `StartCommandAsync`.
- **No terminal.** Commands run without a pseudo-terminal, so they do not prompt, colorize or page. Programs that insist on a
  terminal (`sudo` without `NOPASSWD`, `top`) need [`StartCommandAsync` with a terminal](interactive-shell.md).
- **Environment.** The server runs the command through the user's shell non-interactively (as `shell -c command`), so startup
  files that only interactive shells read do not run, and `PATH` may differ from what you see in a terminal. Use full paths in
  scripts.
- **Cancellation.** Cancelling the token closes the command's channel; the connection stays usable. See
  [Cancellation and timeouts](cancellation-and-timeouts.md) for stopping the program on the server too.
- **Errors.** `SshException` means the command could not be run at all (the server refused it, or the connection failed), not that
  the command failed.

## See also

- [Stream large output](stream-output.md)
- [Commands and shells](../sessions.md) (in-depth guide)
- <xref:SshSharp.SshClient.RunCommandAsync*> and <xref:SshSharp.SshCommandResult> in the API reference
