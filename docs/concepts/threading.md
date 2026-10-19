# Threading and concurrency

SshSharp is asynchronous throughout, with no synchronous network calls and no hidden threads blocked on I/O. This page says what
may be used from several tasks at once, and what may not.

## What is safe to share

| Object | Concurrent use |
|---|---|
| `SshClient` | Yes. Commands, sessions, SFTP clients, tunnels and forwarders can be started from many tasks at once; each is its own channel. This is what the shared connection of `ISshConnectionProvider` relies on. |
| `SftpClient` | Yes. Requests from several tasks are pipelined on the one SFTP session, and replies are matched to their requests. |
| `SshSession` | One reader per stream, one writer for `StandardInput`. Reading `StandardOutput` and `StandardError` from two tasks at the same time is expected (and needed, see [flow control](channels.md#flow-control)). |
| `SshExpect` | One caller at a time. It reads `StandardOutput` itself; nothing else may read it. |
| Tunnel streams | As for any `Stream`: one reader and one writer at a time, which may run concurrently. |
| SFTP file streams (`OpenAsync`) | One call at a time, as for `FileStream`. Writes in flight are answered in the background, but the stream looks at their replies only during your calls, so nothing races with you. |
| `SftpFileSystem`, `SftpFileProvider` | Yes, through their shared `SftpClient`. Built from a session factory, concurrent callers share one session and one reopen after a drop. |
| `SshClientOptions`, `SshConfigConnectOptions`, `SshConfig` | Immutable once built; one instance can serve many connections. |
| `ISshClientFactory`, `ISshConnectionProvider` | Yes; singletons in the container. |

Running commands in parallel on one connection:

[!code-csharp[](../snippets/Commands.cs#run-parallel)]

### What must not be shared

- **Two readers of one stream**, or two writers: `StandardOutput` read from two tasks at once, two tasks writing `StandardInput` or one
  tunnel stream. Bytes would interleave unpredictably. Give each stream one reader and one writer, or serialize them yourself.
- **One SFTP file stream from two tasks.** Concurrent calls on one `Stream` are not supported, as for `FileStream`. Open the file
  twice, or use `SftpClient`'s methods, which are safe to call concurrently.
- **`SshExpect` from two tasks**, or alongside your own reads of `StandardOutput`.
- **A disposed object.** Disposing while another task is using an object is allowed and makes that call fail (see below), but no
  call may start after `DisposeAsync`.

## Lifetime: who disposes what

Every object a method returns is the caller's to dispose, with `await using`. Disposing one closes what it owns, never what it was
made from:

| Object | Owned by | Disposing it | When its owner goes away |
|---|---|---|---|
| `SshClient` | The caller of `ConnectAsync` (the shared connection of `ISshConnectionProvider` belongs to the provider: never dispose it). | Disconnects, stops the forwardings started from `ssh_config`, closes the connection and every `ProxyJump` or `JumpHosts` hop, and the stream unless `leaveOpen` was given. | - |
| `SshSession` | The caller of `StartCommandAsync`, `StartShellAsync`, `StartSubsystemAsync`. | Closes the channel; a program still running gets a hangup from the server. The connection stays up. | Calls waiting on it fail with `SshException` (`ConnectionClosed`). |
| `SftpClient` | The caller of `OpenSftpAsync` (or of `ISshConnectionProvider.OpenSftpAsync`). | Ends the SFTP session; requests still waiting fail. The connection stays up. | Its requests fail. |
| SFTP file streams | The caller of `OpenAsync`, `OpenReadAsync`, `OpenWriteAsync`. | Waits for writes in flight and closes the handle. Dispose them before their `SftpClient`. | Later calls fail, and writes not yet answered may not have reached the file. |
| Tunnel streams (`OpenTcpTunnelAsync`, `OpenUnixSocketTunnelAsync`) | The caller. | Closes the channel. | Reads end and writes fail. |
| Forwarders (`SshLocalPortForwarder`, `SshLocalSocketForwarder`, `SshDynamicPortForwarder`, `SshRemotePortForwarder`, `SshRemoteSocketForwarder`) | The caller of the `Forward...Async` method. | Stops listening (a remote one cancels the forwarding on the server), closes the forwarded connections, and removes a local socket file. | A local one stops listening and removes its socket file; its connections close. Dispose it anyway. |
| `SshPrivateKey` (in `PrivateKeys`) | Whoever loaded it. | Clears the key material. | The client does not dispose the keys you pass in options: dispose them after connecting. |
| `SftpFileSystem`, `SftpFileProvider` | The caller. | Built from an `SftpClient`, leaves it to you; built from a session factory, disposes the sessions it opened (never the connection). | - |
| `ISshClientFactory.ConnectAsync`'s client | The caller. | As `SshClient`. | - |

`DisposeAsync` is safe to call more than once and from several tasks: the first call does the work. A call in progress on another
task fails with `SshException` (`ConnectionClosed` or `ChannelClosed`) or `ObjectDisposedException`, rather than hanging.

## Callbacks

Callbacks you supply (host key verifiers, `AskHostKey`, `KeyboardInteractive`, `PassphraseProvider`, `AuthenticationBanner`,
`SshKeySigner.SignAsync`, `allowDestination` filters) run on thread-pool threads, during connecting or while forwarding:

- They may run concurrently when several connections are made at once, so share state in them safely.
- They are asynchronous (`ValueTask`): await I/O in them rather than blocking.
- A callback that prompts a person delays the connection until it answers; bound the prompt with the token it receives.

## Synchronization contexts

The library does not capture a `SynchronizationContext` (it uses `ConfigureAwait(false)` internally), so awaiting it from a UI
thread or a legacy ASP.NET request context does not deadlock as long as you await. Blocking on a task (`.Result`, `.Wait()`)
is still a bad idea: it holds a thread for a network round trip.

## Synchronous APIs

Two adapters are synchronous by contract: `IFileProvider` and many `IFileSystem` members. Each such call blocks a thread for an SFTP
round trip, bounded by the adapter's `OperationTimeout`. Under load, prefer `IFileSystem`'s `...Async` methods and keep
`SftpFileProvider`'s cache on.

An SFTP file stream is asynchronous, but two `Stream` members have no asynchronous form: `SetLength`, and a synchronous `Dispose`
of a stream with writes in flight, block until the server answers (a failed write must not be lost). Dispose with `await using`.

## See also

- [Channels and flow control](channels.md)
- [IFileSystem and IFileProvider](../how-to/file-system-adapters.md)
- [ASP.NET Core and dependency injection](../how-to/aspnetcore-and-di.md)
