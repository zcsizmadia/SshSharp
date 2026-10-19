# Errors and failure reasons

Every SSH-level failure is an `SshException`, and its `Reason` (an `SshFailureReason`) says what kind of failure it is. Five
reasons have their own exception types with extra information. Everything else follows .NET's usual conventions.

## The exception types

```
Exception
├── SshException                  Reason: SshFailureReason
│   ├── SshHostKeyException       HostKey: the key the server presented
│   ├── SshAuthenticationException AllowedMethods: what the server would accept; Attempts: what was tried
│   ├── SshProtocolException      the server violated the protocol
│   ├── SftpException             Status: SftpStatusCode, Path
│   └── SshCommandException       ExitStatus, ExitSignal, StandardError (last 4 KiB): from EnsureSuccess()
├── OperationCanceledException    your CancellationToken was cancelled
├── ArgumentException             invalid arguments
├── InvalidOperationException     RunCommandAsync output over MaxCommandOutputBytes
└── NotSupportedException         an SFTP operation the server lacks an extension for; synchronous reads on SFTP streams
```

## SshFailureReason

| Reason | Meaning | Type | What to do |
|---|---|---|---|
| `ConnectFailed` | The TCP connection, a proxy (a custom one's connector included, with its exception inside), a `ProxyJump` or `JumpHosts` hop or a `ProxyCommand` could not be established. | `SshException` | Check name, port, firewall and proxy; retry with backoff. |
| `HostKeyRejected` | The host key verifier refused the server's key: unknown, changed or revoked. | `SshHostKeyException` | Do not retry with a looser policy. Confirm the key out of band. |
| `AuthenticationFailed` | No credential was accepted. | `SshAuthenticationException` | Compare `AllowedMethods` with the credentials you gave; `Attempts` lists each key (by fingerprint) and method tried, and what became of it. |
| `KeyExchangeFailed` | No common algorithms, or the key exchange failed. | `SshException` | The server needs a modern algorithm; see [Algorithms](algorithms.md). |
| `ProtocolError` | The server sent something that violates the protocol. | `SshProtocolException` | Report it with a `Debug` log; usually a server bug or interference on the path. |
| `ConnectionClosed` | The connection was lost, or the server or the client closed it. | `SshException` | Reconnect; decide whether interrupted work is safe to repeat. |
| `ChannelClosed` | A channel was refused or closed: a command, terminal, subsystem or tunnel the server refused, or a session that ended. | `SshException` | Check server policy (`AllowTcpForwarding`, `Subsystem`, `MaxSessions`). The connection is still usable. |
| `Timeout` | `SshClientOptions.ConnectTimeout` or `ConnectTimeout` from `ssh_config` passed (the inner exception is a `TimeoutException`), a proxy did not finish its handshake, the server missed `KeepAliveCountMax` keep-alives, or an SFTP server sent nothing for `SftpClient.OperationTimeout` (inner `TimeoutException`; the SFTP session stays usable). | `SshException` | Reconnect; check the network path. |
| `AgentFailed` | The SSH agent could not be reached, or refused a request. | `SshException` | Check `SSH_AUTH_SOCK` or the agent service; a locked agent refuses, and an in-process agent (`SshAgent.FromKeys`) refuses to add, remove or lock keys. |
| `TransferFailed` | An SCP transfer failed on the server's side, or a directory download met a name it will not write. | `SshException` | The message has the server's words. |
| `SftpFailed` | An SFTP request failed. | `SftpException` | `Status` (`NoSuchFile`, `PermissionDenied`, `Failure`, ...) and `Path` say what and where. |
| `CommandFailed` | `SshCommandResult.EnsureSuccess()` found that the command did not succeed: a non-zero exit status, a signal, or neither reported. | `SshCommandException` | `ExitStatus` or `ExitSignal` says how it ended; `StandardErrorText` (the last 4 KiB of stderr) usually says why. The connection is fine. |
| `Unknown` | Not otherwise classified. | `SshException` | Look at `InnerException`. |

## Handling them

[!code-csharp[](../snippets/Diagnostics.cs#errors)]

## Exceptions that are not SSH failures

| Exception | When |
|---|---|
| `OperationCanceledException` | Your token was cancelled. Not an error of the connection. |
| `TimeoutException` | The dependency injection factory's `ConnectTimeout` passed. |
| `InvalidOperationException` | `RunCommandAsync` output exceeded `SshClientOptions.MaxCommandOutputBytes`: stream with `StartCommandAsync` instead. |
| `NotSupportedException` | An SFTP operation needs an extension the server lacks (an overwriting rename, a hard link); a synchronous read or write on an SFTP stream; `Resolve` on a configuration that needs `ResolveAsync`. |
| `CryptographicException` | A custom `SshKeySigner` returned a signature that does not verify against its public key. |
| `ObjectDisposedException` | A method was called on a disposed client or session. |
| `FileNotFoundException`, `UnauthorizedAccessException`, `IOException` | From `SftpFileSystem`, which reports SFTP failures as `System.IO` exceptions. |

## Messages

Exception messages never contain passwords, keys, command text, user names or host names, so they are safe to log. Some carry
text from the server (an SFTP error, an SCP message); treat that as untrusted before showing it to end users. `SshCommandException`
keeps the command's stderr out of its message, in `StandardError` and `StandardErrorText`: it is the remote program's own output,
which may contain anything, so decide whether it is safe to log, and strip control characters before showing it in a terminal.

## See also

- [Troubleshooting](troubleshooting.md)
- [Errors and diagnostics](../diagnostics.md)
- <xref:SshSharp.SshFailureReason> in the API reference
