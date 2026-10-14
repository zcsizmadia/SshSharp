# Errors and diagnostics

## Exceptions

Everything SshSharp raises for SSH-level problems is an `SshException` with a `Reason`:

| `SshFailureReason` | Meaning | Type |
|---|---|---|
| `ConnectFailed` | The TCP connection (or ProxyJump hop, or ProxyCommand) could not be established | `SshException` |
| `HostKeyRejected` | The host key verifier refused the server's key; `HostKey` has the key | `SshHostKeyException` |
| `AuthenticationFailed` | No credential was accepted; `AllowedMethods` lists what the server takes | `SshAuthenticationException` |
| `KeyExchangeFailed` | No common algorithms, or the key exchange failed | `SshException` |
| `ProtocolError` | The server sent something that violates the protocol | `SshProtocolException` |
| `ConnectionClosed` | The connection was lost or the server disconnected | `SshException` |
| `ChannelClosed` | A channel was refused or closed (for example the server refused a command or a terminal) | `SshException` |
| `Timeout` | `ConnectTimeout` passed, or the server missed `KeepAliveCountMax` keep-alives | `SshException` |
| `AgentFailed` | The SSH agent could not be reached or refused a request | `SshException` |
| `TransferFailed` | An SCP transfer failed on the server's side (a missing file, no permission); the message has the server's words | `SshException` |

```csharp
try
{
    await using var client = await SshClient.ConnectAsync("prod-db");
}
catch (SshHostKeyException ex)
{
    Console.Error.WriteLine($"Host key not trusted: {ex.HostKey?.Fingerprint}: {ex.Message}");
}
catch (SshAuthenticationException ex)
{
    Console.Error.WriteLine($"Login failed; the server accepts {string.Join(", ", ex.AllowedMethods)}.");
}
catch (SshException ex) when (ex.Reason is SshFailureReason.ConnectFailed or SshFailureReason.Timeout)
{
    Console.Error.WriteLine($"Unreachable: {ex.Message}");
}
```

Cancellation is reported as `OperationCanceledException`, and invalid arguments as `ArgumentException`, as usual in .NET.
`RunCommandAsync` throws `InvalidOperationException` when a command's output exceeds `SshClientOptions.MaxCommandOutputBytes`
(a safety limit, not a connection problem): stream such output with `StartCommandAsync` instead.

## Logging

Pass an `ILogger` (`Microsoft.Extensions.Logging`) in `SshClientOptions.Logger` or `SshConfigConnectOptions.Logger`:

```csharp
using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
var options = new SshClientOptions
{
    UserName = "deploy",
    Password = password,
    HostKeyVerifier = verifier,
    Logger = loggerFactory.CreateLogger("SshSharp"),
};
```

Information: connected (algorithms and host key fingerprint), authenticated (method), identity files and agent keys that
were skipped, host keys recorded by `UpdateHostKeys`. Debug: key exchanges, rekeys, channels, sessions, authentication
attempts. Logs never contain passwords, private keys, command text or user names.

## Tracing and metrics

SshSharp publishes an `ActivitySource` and a `Meter` named `SshTelemetry.SourceName` (`"SshSharp"`). With OpenTelemetry:

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddSource(SshTelemetry.SourceName))
    .WithMetrics(metrics => metrics.AddMeter(SshTelemetry.SourceName));
```

| Activity | Tags |
|---|---|
| `SshSharp.Connect` | `ssh.kex`, `ssh.kex.post_quantum`, `ssh.cipher`, `ssh.host_key.type` |
| `SshSharp.Command` | `ssh.command.exit_status` |

| Instrument | Unit | Description |
|---|---|---|
| `sshsharp.connections` | `{connection}` | Open connections |
| `sshsharp.connect.duration` | `s` | Time to connect, exchange keys and authenticate; tagged `ssh.kex.post_quantum` |
| `sshsharp.bytes.sent` / `sshsharp.bytes.received` | `By` | Message payload bytes |
| `sshsharp.key_exchanges` | `{exchange}` | Completed key exchanges |
| `sshsharp.channels` | `{channel}` | Open channels |
| `sshsharp.commands` | `{command}` | Commands run, tagged by outcome |

Nothing is recorded unless something listens.
