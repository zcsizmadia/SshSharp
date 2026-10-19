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
