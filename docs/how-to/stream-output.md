# Stream large output

`SshClient.StartCommandAsync` starts a command and returns an `SshSession` whose `StandardInput`, `StandardOutput` and
`StandardError` are streams. You read output as it arrives and write input while the program runs, with nothing collected in memory.

## When to use

- The output is large (a database dump, a log archive) or endless (`tail -f`, `journalctl -f`).
- You want to show progress, or act on each line as it arrives.
- The program reads its standard input (`gzip -c`, `psql`, `tar -x`).

For a short command whose output fits in memory, [`RunCommandAsync`](run-a-command.md) is simpler.

## Read lines as they arrive

[!code-csharp[](../snippets/Commands.cs#stream-lines)]

## Read stdout and stderr together

Read both streams at the same time. SSH flow control gives each channel a window (2 MiB here); output that nobody reads fills it,
and then the server stops sending on **both** streams, so a program that writes a lot to stderr while you wait on stdout stalls.
This is the same rule as for redirected `Process` streams.

[!code-csharp[](../snippets/Commands.cs#stream-both)]

## Save output of any size to a file

[!code-csharp[](../snippets/Commands.cs#stream-to-file)]

`ExitStatus` is known once `WaitForExitAsync` returns. Check it: a dump that failed halfway still produced a file.

## Send input

Write to `StandardInput`, then call `CloseInputAsync` to send end-of-file, as closing a pipe does. Programs that read until
end-of-file (`gzip`, `sort`, `tar -x`) finish only then.

[!code-csharp[](../snippets/Commands.cs#stream-input)]

## Stop early

[!code-csharp[](../snippets/Commands.cs#stream-stop)]

Disposing `StandardOutput` while the program still runs tells an OpenSSH server to stop sending output (`eow@openssh.com`), so it
is not sent only to be dropped; the program may then get `SIGPIPE` on its next write, as `yes | head` does.

## Notes and pitfalls

- **Read what you start.** An unread stderr is the most common cause of a stalled command. If you do not need it, drain it:
  `_ = session.StandardError.CopyToAsync(Stream.Null)`.
- **Exit status.** `ExitStatus` and `ExitSignal` are set when the program ends; `WaitForExitAsync` waits for that.
- **Disposing.** Disposing the session closes the channel. A program still running then loses its input and output (with a
  terminal, it gets a hangup).
- **Text encoding.** The streams carry bytes. `StreamReader` decodes UTF-8 by default; pass another `Encoding` if the program
  prints something else.
- **Lines that never end.** A progress bar that redraws with `\r` never completes a line; read raw bytes for such output.

## See also

- [Run a command](run-a-command.md)
- [Interactive shells and SshExpect](interactive-shell.md)
- [Channels and flow control](../concepts/channels.md)
- <xref:SshSharp.SshSession> in the API reference
