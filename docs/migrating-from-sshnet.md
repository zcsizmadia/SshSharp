# Migrating from SSH.NET

This guide maps [SSH.NET](https://github.com/sshnet/SSH.NET) code to SshSharp. Before you start, check that SshSharp covers what you
need (see "Why not SSH.NET?" in the README): it targets .NET 8 and later only, has no SFTP yet, and does not speak legacy algorithms
(CBC ciphers, SHA-1 MACs, `ssh-rsa` signatures, DH group 1).

The main differences:

- **Async only.** Every operation is `async` and takes a `CancellationToken`. Clients, sessions and forwarders are
  `IAsyncDisposable`, so use `await using`.
- **Connecting is one call.** `SshClient.ConnectAsync` returns a client that is already connected and authenticated. There is no
  separate constructor, `Connect` or `Disconnect`; disposing the client disconnects.
- **Options are immutable.** `SshClientOptions` uses `init` properties, set once. It replaces `ConnectionInfo`, the
  authentication method objects and the client properties.
- **Host keys are always verified.** `HostKeyVerifier` is required. There is no "accept anything" default and no event to forget
  to handle.
- **One connection for everything.** Commands, shells, port forwarding and SCP all run over the same `SshClient`. SSH.NET's
  `ScpClient` opens its own connection.

## Connecting

SSH.NET:

```csharp
using var client = new SshClient("example.com", 22, "deploy", password);
client.HostKeyReceived += (_, e) => e.CanTrust = e.FingerPrintSHA256 == expectedFingerprint;
client.Connect();
```

SshSharp:

```csharp
await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    Password = password,
    HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:" + expectedFingerprint),
});
```

`FingerPrintSHA256` in SSH.NET is the base64 hash without a prefix. SshSharp fingerprints are written as `ssh-keygen -l` prints
them, with the `SHA256:` prefix.

Or connect the way `ssh` does, with `~/.ssh/config`, `known_hosts`, the user's keys and the agent:

```csharp
await using var client = await SshClient.ConnectAsync("deploy@example.com");
```

See [Connecting](connecting.md) for streams, jump hosts and timeouts.

### Connection settings

| SSH.NET | SshSharp |
|---|---|
| `new SshClient(host, port, user, password)` | `SshClient.ConnectAsync(host, port, new SshClientOptions { UserName, Password, HostKeyVerifier })` |
| `new SshClient(host, user, keyFiles)` | `SshClientOptions.PrivateKeys` (see [Keys](#keys)) |
| `new SshClient(connectionInfo)` | `SshClientOptions`; or `ssh_config` with `SshClient.ConnectAsync(destination)` |
| `client.Connect()`, `ConnectAsync(ct)` | `SshClient.ConnectAsync(...)`: returns a connected client |
| `client.Disconnect()`, `Dispose()` | `await client.DisposeAsync()` |
| `ConnectionInfo.Timeout` | a `CancellationToken` (for example `new CancellationTokenSource(TimeSpan.FromSeconds(10))`), or `ConnectTimeout` in `ssh_config` |
| `client.KeepAliveInterval` | `SshClientOptions.KeepAliveInterval` and `KeepAliveCountMax` (`ServerAliveInterval` in `ssh_config`) |
| `ConnectionInfo.Encryptions` / `KeyExchangeAlgorithms` / `HostKeyAlgorithms` (removing entries) | `SshClientOptions.AlgorithmPreferences`, or `Ciphers`, `KexAlgorithms`, `HostKeyAlgorithms` in `ssh_config` |
| `ConnectionInfo.ProxyType` (SOCKS, HTTP) | not supported; use `ProxyJump`, `ProxyCommand`, or `SshClient.ConnectAsync(Stream, ...)` over a stream you open yourself |
| `client.IsConnected` | `client.IsConnected`; `client.ConnectionClosed` (a `CancellationToken`) fires when the connection drops |
| `client.ErrorOccurred` event | `client.ConnectionClosed` and `client.ConnectionError` |
| `client.ConnectionInfo.ServerVersion` | `client.ServerIdentification` |

## Host keys

| SSH.NET | SshSharp |
|---|---|
| `HostKeyReceived` with `e.CanTrust = e.FingerPrintSHA256 == ...` | `SshHostKeyVerifier.Pinned("SHA256:...")` |
| `HostKeyReceived` with your own logic | `SshHostKeyVerifier.FromDelegate((context, ct) => ...)`; `context.HostKey` has the key, type and fingerprint |
| (no handler: every key is accepted) | no equivalent: a verifier is required |
| (no `known_hosts` support) | `KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes)` |

A rejected key throws `SshHostKeyException`, which carries the key the server presented. See [Host keys](host-keys.md).

## Authentication

| SSH.NET | SshSharp |
|---|---|
| `PasswordAuthenticationMethod(user, password)` | `SshClientOptions.Password` |
| `PrivateKeyAuthenticationMethod(user, keyFiles)` | `SshClientOptions.PrivateKeys` |
| `KeyboardInteractiveAuthenticationMethod` and its `AuthenticationPrompt` event | `SshClientOptions.KeyboardInteractive`, a callback that returns the answers |
| several methods in `ConnectionInfo` | set several options: the client tries public keys, keyboard-interactive, then password, as `ssh` does, and follows the server's multi-factor chains |
| (no agent support) | `SshAgent.FromEnvironment()` and `GetKeysAsync()`; `ForwardAgent` for agent forwarding |
| `SshAuthenticationException` | `SshAuthenticationException`, with `AllowedMethods` listing what the server would accept |

When the server takes passwords only through keyboard-interactive (PAM with `PasswordAuthentication no`), `Password` answers that
prompt, so you need no handler for it.

### Keys

| SSH.NET | SshSharp |
|---|---|
| `new PrivateKeyFile(path)`, `new PrivateKeyFile(path, passphrase)` | `await SshPrivateKey.LoadFileAsync(path, passphrase)` |
| `new PrivateKeyFile(stream)` | `SshPrivateKey.Parse(text, passphrase)` |
| OpenSSH, PKCS#1, PKCS#8, PuTTY `.ppk` | the same, plus SEC1; ssh.com keys are not read (convert them with `ssh-keygen -i`) |
| `ssh-rsa` (SHA-1) signatures | RSA keys sign with `rsa-sha2-256` or `rsa-sha2-512` only |

`SshPrivateKey` is `IDisposable`: disposing it clears the key material.

## Commands

SSH.NET:

```csharp
var command = client.RunCommand("df -h /");
Console.WriteLine($"exit {command.ExitStatus}: {command.Result}");
```

SshSharp:

```csharp
var result = await client.RunCommandAsync("df -h /");
Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
```

| SSH.NET | SshSharp |
|---|---|
| `client.RunCommand(text)`, `command.ExecuteAsync(ct)` | `await client.RunCommandAsync(text, ct)` |
| `command.Result`, `command.Error` | `result.StandardOutputText`, `result.StandardErrorText` (or the raw bytes: `StandardOutput`, `StandardError`) |
| `command.ExitStatus`, `command.ExitSignal` | `result.ExitStatus`, `result.ExitSignal` |
| `command.OutputStream`, `ExtendedOutputStream`, `CreateInputStream()` | `await client.StartCommandAsync(text)`, then `session.StandardOutput`, `StandardError`, `StandardInput` |
| `command.CancelAsync()` | cancel the token, or `session.SendSignalAsync("TERM")` |
| `command.CommandTimeout` | a `CancellationToken` |

`RunCommandAsync` collects all output in memory, up to `SshClientOptions.MaxCommandOutputBytes` (a safety limit). For large or
endless output, stream it:

```csharp
await using var session = await client.StartCommandAsync("tail -f /var/log/syslog");
using var reader = new StreamReader(session.StandardOutput);
while (await reader.ReadLineAsync(cancellationToken) is { } line)
{
    Console.WriteLine(line);
}
```

## Shells

SSH.NET:

```csharp
using var shell = client.CreateShellStream("xterm", 80, 24, 0, 0, 4096);
shell.WriteLine("uptime");
var line = shell.ReadLine();
```

SshSharp:

```csharp
await using var shell = await client.StartShellAsync(new SshSessionOptions
{
    Terminal = new SshTerminalOptions { TerminalType = "xterm", Columns = 80, Rows = 24 },
});
var input = new StreamWriter(shell.StandardInput) { AutoFlush = true };
var output = new StreamReader(shell.StandardOutput);
await input.WriteLineAsync("uptime");
var line = await output.ReadLineAsync();
```

`ShellStream.Expect` has no equivalent: read the output stream and match what you need. Resize with
`shell.ResizeTerminalAsync(columns, rows)`. See [Commands and shells](sessions.md).

## Port forwarding

SSH.NET:

```csharp
var forward = new ForwardedPortLocal("127.0.0.1", 15432, "db.internal", 5432);
client.AddForwardedPort(forward);
forward.Start();
```

SshSharp:

```csharp
await using var forward = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 15432), "db.internal", 5432);
```

| SSH.NET | SshSharp |
|---|---|
| `ForwardedPortLocal` (`ssh -L`) | `client.ForwardLocalPortAsync(localEndPoint, remoteHost, remotePort)` |
| `ForwardedPortRemote` (`ssh -R`) | `client.ForwardRemotePortAsync(bindAddress, remotePort, localHost, localPort)` |
| `ForwardedPortDynamic` (`ssh -D`) | `client.ForwardDynamicPortAsync(localEndPoint)` |
| `forward.Start()`, `Stop()` | started when returned; stopped by `DisposeAsync` |
| `client.ForwardedPorts` | `client.LocalForwardings`, `RemoteForwardings`, `DynamicForwardings` (the ones started from `ssh_config`) |
| (none) | `client.OpenTcpTunnelAsync(host, port)` and `OpenUnixSocketTunnelAsync(path)`: a `Stream` to the far end, without a local listener |

With `ssh_config`, `LocalForward`, `RemoteForward` and `DynamicForward` start with the connection when
`SshConfigConnectOptions.StartForwardings` is set.

## SCP

SSH.NET:

```csharp
using var scp = new ScpClient("example.com", "deploy", password);
scp.Connect();
scp.Upload(new FileInfo("site.tar.gz"), "/tmp/site.tar.gz");
```

SshSharp:

```csharp
using SshSharp.Scp;

await client.UploadFileAsync("site.tar.gz", "/tmp/site.tar.gz");
```

| SSH.NET | SshSharp (`using SshSharp.Scp;`) |
|---|---|
| `scp.Upload(Stream, path)` | `client.UploadAsync(stream, remotePath)` |
| `scp.Upload(FileInfo, path)` | `client.UploadFileAsync(localPath, remotePath)` |
| `scp.Upload(DirectoryInfo, path)` | `client.UploadDirectoryAsync(localDirectory, remotePath)` |
| `scp.Download(path, Stream)` | `client.DownloadAsync(remotePath, stream)` |
| `scp.Download(path, FileInfo)` / `DirectoryInfo` | `client.DownloadFileAsync(...)` / `DownloadDirectoryAsync(...)` |
| `Uploading` / `Downloading` events | `SshScpOptions.Progress` |
| `RemotePathTransformation` | not needed: remote paths are always quoted as one word for the server's shell |

See [File transfer (SCP)](scp.md).

## Errors

| SSH.NET | SshSharp |
|---|---|
| `SshConnectionException` | `SshException` with `Reason` (`ConnectFailed`, `ConnectionClosed`, `ProtocolError`, `KeyExchangeFailed`, ...) |
| `SshAuthenticationException` | `SshAuthenticationException` (a subclass of `SshException`) |
| `SshOperationTimeoutException` | `OperationCanceledException` when your token was cancelled; `SshException` with `Reason = Timeout` for `ConnectTimeout` |
| `ProxyException` | not applicable |
| `ScpException` | `SshException` with `Reason = TransferFailed` |

See [Errors and diagnostics](diagnostics.md) for logging (`SshClientOptions.Logger`), tracing and metrics.
