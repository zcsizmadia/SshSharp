# Cancellation and timeouts

Every network operation in SshSharp is asynchronous and takes a `CancellationToken`. Apart from connecting, which has
`SshClientOptions.ConnectTimeout`, and SFTP, whose `SftpClient.OperationTimeout` catches a server that stops answering, there are
no separate timeout properties to learn: a timeout is a token that cancels itself.

## When to use

Always, for anything that talks to the network. A server that accepts the TCP connection and then says nothing would otherwise be
waited for until the operating system gives up, which can take minutes.

## Bound connecting

Set `ConnectTimeout`, as `ssh -o ConnectTimeout=15` does:

[!code-csharp[](../snippets/Resilience.cs#connect-timeout)]

It covers the whole attempt: resolving the name, the TCP connection (or the connection through `Proxy`), the key exchange, host key
verification and authentication, including the time your callbacks take (a host key prompt, `KeyboardInteractive`). Over a stream
you opened (`SshClient.ConnectAsync(stream, ...)`) it covers the key exchange and authentication. It ends with the connection:
commands and transfers are bounded by their own tokens.

When it passes, the attempt fails with `SshException` (`Reason = Timeout`, with a `TimeoutException` as its inner exception). Your
token still works alongside it, and cancelling it is an `OperationCanceledException`, never a timeout, so the two are easy to tell
apart. `null` (the default) sets no limit.

With `ssh_config`, `ConnectTimeout` applies when connecting by alias, per hop, and fails the same way. There it starts before the
identity files are loaded and covers the `ProxyJump` hops before the host, as `ssh`'s does. `SshConfigConnectOptions.ConnectTimeout`,
when set, replaces the configured value for every host (`Timeout.InfiniteTimeSpan` for no limit).

`ConnectionAttempts` (in `ssh_config`, or `SshConfigConnectOptions.ConnectionAttempts`) tries a server that could not be reached
again, one second later, for a host that may be restarting. Only failures to reach it count (refused, unreachable, timed out), and
the attempts share the one `ConnectTimeout`: with `ConnectTimeout 10` and `ConnectionAttempts 30`, connecting still gives up
after ten seconds.

With `SshClientOptions.JumpHosts`, the destination's `ConnectTimeout` bounds the whole chain (every hop, every tunnel, and the
destination's handshake and login), and a hop's own `ConnectTimeout` bounds that hop within it. Either fails the same way.

A token gives the same bound without the option, with an exception of your choosing:

[!code-csharp[](../snippets/Resilience.cs#connect-timeout-token)]

### Notes

- **One limit for all of the server's addresses.** A host name with several addresses (IPv6 and IPv4) is tried address by address
  within the same `ConnectTimeout`, so an address that does not answer can use it up before the next is tried. Where the IPv6 route
  is known to be broken, set `AddressFamily = SshAddressFamily.Inet` (see [Connecting](../connecting.md#ipv4-or-ipv6-only)).
- **The DI package** maps its endpoint's `ConnectTimeout` onto this option and reports it as a `TimeoutException`; see
  [ASP.NET Core and dependency injection](aspnetcore-and-di.md).

## Bound a command

[!code-csharp[](../snippets/Resilience.cs#command-timeout)]

## Bound SFTP requests

A token bounds one call, however long it should take. For SFTP, where a large transfer may rightly take hours, set
`OperationTimeout` instead: it fails a request only once the server has sent nothing at all for that long, so slow transfers go on
while a hung server is caught. See [Fail when the server stops answering](transfer-files-sftp.md#fail-when-the-server-stops-answering).

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
| `SshClientOptions.ConnectTimeout`, or `ConnectTimeout` from `ssh_config`, passed | `SshException`, `Reason = Timeout` (inner `TimeoutException`) |
| The server missed `KeepAliveCountMax` keep-alives | `SshException`, `Reason = Timeout` |
| An SFTP server sent nothing for `SftpClient.OperationTimeout` | `SshException`, `Reason = Timeout` (inner `TimeoutException`) |
| The connection ended during the operation | `SshException`, `Reason = ConnectionClosed` |
| The DI factory's `ConnectTimeout` passed | `TimeoutException` |

## Notes and pitfalls

- **Distinguish your timeout from the caller's cancellation**: with `ConnectTimeout` they are different exceptions already; with a
  token of your own, catch `OperationCanceledException` `when` the caller's token is not cancelled, as in the token example.
- **Dispose `CancellationTokenSource`s** with `using`; a linked source keeps a registration on its parents until disposed.
- **Ping has no timeout of its own.** `PingAsync` waits for an answer until the connection ends; give it a token with a limit.
- **Disposal is not cancellation.** `DisposeAsync` on a client ends every operation on it, which then fail with `SshException` or
  `ObjectDisposedException`. Cancel first when you want a clean `OperationCanceledException`.

## See also

- [Keep-alive and reconnecting](keepalive-and-reconnect.md)
- [Errors and failure reasons](../reference/errors.md)
