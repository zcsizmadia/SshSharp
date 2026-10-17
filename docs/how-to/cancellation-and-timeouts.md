# Cancellation and timeouts

Every network operation in SshSharp is asynchronous and takes a `CancellationToken`. There are no separate timeout properties to
learn: a timeout is a token that cancels itself.

## When to use

Always, for anything that talks to the network. A server that accepts the TCP connection and then says nothing would otherwise be
waited for until the operating system gives up, which can take minutes.

## Bound connecting

[!code-csharp[](../snippets/Resilience.cs#connect-timeout)]

One token covers the TCP connection, the key exchange and authentication. With `ssh_config`, `ConnectTimeout` applies when
connecting by alias, per hop, and fails with `SshException` (`Reason = Timeout`) instead of `OperationCanceledException`.

## Bound a command

[!code-csharp[](../snippets/Resilience.cs#command-timeout)]

## Stop the program when you give up

Cancelling closes the command's channel on this side; the connection stays usable. Without a terminal, OpenSSH does not signal the
program, which runs on until it next writes output (and gets `SIGPIPE`) or finishes. To stop it, send a signal before the channel
closes:

[!code-csharp[](../snippets/Resilience.cs#stop-on-cancel)]

## Stop when the connection ends

Link your token with `client.ConnectionClosed`, so waits end when either side gives up:

[!code-csharp[](../snippets/Resilience.cs#linked)]

## What is thrown

| What happened | Exception |
|---|---|
| Your token was cancelled | `OperationCanceledException` (or `TaskCanceledException`, a subclass) |
| `ConnectTimeout` from `ssh_config` passed | `SshException`, `Reason = Timeout` |
| The server missed `KeepAliveCountMax` keep-alives | `SshException`, `Reason = Timeout` |
| The connection ended during the operation | `SshException`, `Reason = ConnectionClosed` |
| The DI factory's `ConnectTimeout` passed | `TimeoutException` |

## Notes and pitfalls

- **Distinguish your timeout from the caller's cancellation**: catch `OperationCanceledException` `when` the caller's token is not
  cancelled, as in the first example.
- **Dispose `CancellationTokenSource`s** with `using`; a linked source keeps a registration on its parents until disposed.
- **Ping has no timeout of its own.** `PingAsync` waits for an answer until the connection ends; give it a token with a limit.
- **Disposal is not cancellation.** `DisposeAsync` on a client ends every operation on it, which then fail with `SshException` or
  `ObjectDisposedException`. Cancel first when you want a clean `OperationCanceledException`.

## See also

- [Keep-alive and reconnecting](keepalive-and-reconnect.md)
- [Errors and failure reasons](../reference/errors.md)
