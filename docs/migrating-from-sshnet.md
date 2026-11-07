# Migrating from SSH.NET

This guide maps [SSH.NET](https://github.com/sshnet/SSH.NET) code to SshSharp. Before you start, check that SshSharp covers what you
need (see "Why not SSH.NET?" in the README): it targets .NET 8 and later only, and it does not speak legacy algorithms
(CBC ciphers, SHA-1 MACs, `ssh-rsa` signatures, DH group 1).

The main differences:

- **Async only.** Every network operation is `async` and takes a `CancellationToken`. Clients, sessions and forwarders are
  `IAsyncDisposable`, so use `await using`.
- **Connecting is one call.** `SshClient.ConnectAsync` returns a client that is already connected and authenticated. There is no
  separate constructor, `Connect` or `Disconnect`; disposing the client disconnects.
- **Options are immutable.** `SshClientOptions` uses `init` properties, set once. It replaces `ConnectionInfo`, the
  authentication method objects and the client properties.
- **Host keys are always verified.** `HostKeyVerifier` is required. There is no "accept anything" default and no event to forget
  to handle.
- **One connection for everything.** Commands, shells, port forwarding and SCP all run over the same `SshClient`. SSH.NET's
  `ScpClient` opens its own connection.

## What you gain

Features that SSH.NET users have asked for in its issue tracker, and that SshSharp has:

| Request | SshSharp |
|---|---|
| Verify host keys against `known_hosts` | `KnownHostsVerifier`, with hashed hosts, `@cert-authority`, `@revoked` and `StrictHostKeyChecking` (see [Host keys](host-keys.md)) |
| Jump hosts / bastions | `SshClientOptions.JumpHosts`, one `SshJumpHost` per hop with its own credentials and host key check; `ProxyJump` chains and `ProxyCommand` from `ssh_config`; or by hand: `OpenTcpTunnelAsync` to the next host and `SshClient.ConnectAsync(stream, ...)` over it (see [Jump hosts](how-to/jump-hosts.md)) |
| Connect through your own transport (a cloud tunnel, a WebSocket) | `SshProxy.FromConnector((host, port, ct) => ...)` returns the stream; it works wherever a proxy does, including the first jump host (see [Jump hosts](how-to/jump-hosts.md)) |
| Keys held by your application or a KMS, offered through an agent | `SshAgent.FromKeys(...)`, an in-process agent for any keys SshSharp holds, including keys behind an `SshKeySigner` (a KMS or HSM); `SshClientOptions.ForwardAgentFilter` decides each request a forwarded agent gets (see [Keys and the SSH agent](how-to/agent-and-keys.md)) |
| Directory trees over SFTP | `UploadDirectoryAsync` and `DownloadDirectoryAsync` with several files at once, a `Filter` and `SkipUnchanged`; recursive `ListDirectoryAsync` with a `Pattern`; `DeleteDirectoryAsync(path, recursive: true)` (see [Transfer files with SFTP](how-to/transfer-files-sftp.md)) |
| Check a transfer with a hash the server computes | `sftp.GetFileHashAsync(path)` (`check-file` or `md5-hash`, when the server offers one); `SendExtendedRequestAsync` for other vendor extensions (see [SFTP](sftp.md)) |
| A SOCKS proxy with a password | `client.ForwardDynamicPortAsync(localEndPoint, new NetworkCredential(user, password))` (SOCKS 5, RFC 1929) |
| Forward to a Unix socket on the server from a local port or socket (`ssh -L port:/remote.sock`) | `client.ForwardLocalPortAsync(localEndPoint, remoteSocketPath)` and `ForwardLocalUnixSocketAsync(localSocketPath, ...)` (see [Port forwarding](how-to/port-forwarding.md)) |
| Remote forwarding without a local listener | `client.ForwardRemotePortAsync(bindAddress, port, handler)`: each connection reaches your code as a `Stream` |
| Named SSH connections in ASP.NET Core | `SshSharp.Extensions.DependencyInjection`: endpoints from configuration, a shared connection that reconnects, keyed `ISshEndpoint` services, `UseSshTunnel` for `HttpClient`, and a health check (see [Dependency injection](dependency-injection.md)) |
| Use the keys in `ssh-agent`; agent forwarding | `SshAgent` and `ForwardAgent`, on Unix sockets, the Windows OpenSSH agent and PuTTY's Pageant (`SshAgent.FromPageant()`) |
| Add, remove and lock agent keys (`ssh-add`) | `agent.AddKeyAsync(key, constraints)` (lifetime, confirmation), `RemoveKeyAsync`, `RemoveAllKeysAsync`, `LockAsync` and `UnlockAsync`; `AddKeysToAgent` in `ssh_config` (see [Authentication](authentication.md)) |
| A subsystem other than `sftp` | `client.StartSubsystemAsync(name)` |
| A terminal for a single command (`ssh -t host cmd`) | `StartCommandAsync(command, new SshSessionOptions { Terminal = ... })` |
| Send a signal to a command | `session.SendSignalAsync("TERM")` |
| Forward to a Unix socket | `client.OpenUnixSocketTunnelAsync(path)`; the other way, the server's socket to this machine, with `client.ForwardRemoteUnixSocketAsync(remotePath, ...)` |
| A SOCKS proxy on the server's side (`ssh -R port`) | `client.ForwardRemoteDynamicPortAsync(bindAddress, port, allowDestination)` |
| `HttpClient` through the connection | `client.CreateHttpConnectCallback()` for `SocketsHttpHandler.ConnectCallback` |
| Fetch host keys without logging in (`ssh-keyscan`) | `SshClient.ScanHostKeysAsync(host, port)` |
| Generate keys (`ssh-keygen -t`) | `SshPrivateKey.Generate(type)` and `SaveAsync(path, passphrase)` |
| Sign and verify files or git commits (`ssh-keygen -Y`) | `SshSignature` and `SshAllowedSigners` (see [Signing](signing.md)) |
| Issue and check OpenSSH certificates (`ssh-keygen -s`, `-L`) | `SshCertificateBuilder` signs user and host certificates with any key, an agent's or a KMS's too; `SshCertificate.IsValidFor` checks one (see [Certificates](how-to/certificates.md#act-as-a-certificate-authority)) |
| Connect from a chosen local address or interface | `SshClientOptions.LocalEndPoint`, `BindAddress` and `BindInterface` in `ssh_config` |
| Agent keys limited to some hosts (`ssh-add -h`) | adding them: `SshAgentKeyConstraints.Destinations` (`restrict-destination-v00@openssh.com`); using them: session binding and `publickey-hostbound`, automatically |
| Send a BREAK to a serial console | `session.SendBreakAsync()` (RFC 4335, as OpenSSH's `~B`) |
| Revoked host keys | `KnownHostsVerifier.RevokedHostKeys` (`RevokedHostKeys` in `ssh_config`): OpenSSH KRLs from `ssh-keygen -k`, or key lists |
| Measure the round trip | `client.PingAsync()` (`ping@openssh.com`, or a `keepalive@openssh.com` request on older servers) |
| Close idle channels | `SshClientOptions.ChannelTimeouts` (`ChannelTimeout` in `ssh_config`, as OpenSSH 9.2+) |
| Faster SFTP downloads and uploads over high-latency links | `SftpTransferOptions.Segments`: one file in parallel ranges, each over its own SFTP session (see [SFTP](sftp.md)) |
| Kerberos / Active Directory sign-in (GSSAPI) | `SshClientOptions.Gssapi`, or `GSSAPIAuthentication yes` in `ssh_config` (.NET 10 and later; see [Authentication](authentication.md)) |
| Remote files as an `IFileSystem` or `IFileProvider` | the `SshSharp.IO.Abstractions` and `SshSharp.FileProviders` packages |
| Detect a stalled connection, also while a write is blocked | keep-alive (`KeepAliveInterval`, `KeepAliveCountMax`): the probes don't wait for pending writes, so a server that stops reading is still detected |
| RSA SHA-2 signatures with servers that announce them | `server-sig-algs` (RFC 8308) is used to pick `rsa-sha2-512` or `rsa-sha2-256` |
| FIPS-approved algorithms only | `SshClientOptions.FipsMode`, including post-quantum key exchange on .NET 10 and later |
| Cancellation everywhere | a `CancellationToken` on every network operation |

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
| `ConnectionInfo.Timeout` | `SshClientOptions.ConnectTimeout` (`ConnectTimeout` in `ssh_config`); it covers the TCP connection, key exchange and authentication. A `CancellationToken` works too |
| `client.KeepAliveInterval` | `SshClientOptions.KeepAliveInterval` and `KeepAliveCountMax` (`ServerAliveInterval` in `ssh_config`) |
| `ConnectionInfo.Encryptions` / `KeyExchangeAlgorithms` / `HostKeyAlgorithms` / `HmacAlgorithms` (removing or reordering entries) | `SshClientOptions.Ciphers`, `KexAlgorithms`, `HostKeyAlgorithms` and `Macs`, for example `Ciphers = SshAlgorithmList.Remove("aes*-ctr")`; or the same directives in `ssh_config` (the defaults are modern only; `SshClientOptions.FipsMode` restricts them to FIPS algorithms; see [Choose algorithms](how-to/algorithms-and-authentication-order.md)) |
| `ConnectionInfo.CompressionAlgorithms` (moving `zlib@openssh.com` before `none`) | `SshClientOptions.Compression = true` (`Compression yes` in `ssh_config`); off by default, as in `ssh` |
| `ConnectionInfo.CurrentClientEncryption`, `CurrentServerCompressionAlgorithm` and the other `Current*` properties | `client.Algorithms` (`EncryptionClientToServer`, `CompressionServerToClient`, ...) |
| `ConnectionInfo.ProxyType`, `ProxyHost`, `ProxyPort`, `ProxyUsername`, `ProxyPassword` | `SshClientOptions.Proxy = SshProxy.Http(host, port, credentials)` (or `Socks5`, `Socks4`, or `SshProxy.FromUri(new Uri("socks5://proxy:1080"))`) |
| `client.IsConnected` | `client.IsConnected`; `client.ConnectionClosed` (a `CancellationToken`) fires when the connection drops |
| `client.ErrorOccurred` event | `client.ConnectionClosed` and `client.ConnectionError` |
| `client.ConnectionInfo.ServerVersion` | `client.ServerIdentification` |

## Host keys

| SSH.NET | SshSharp |
|---|---|
| `HostKeyReceived` with `e.CanTrust = e.FingerPrintSHA256 == ...` | `SshHostKeyVerifier.Pinned("SHA256:...")` |
| `HostKeyReceived` with your own logic | `SshHostKeyVerifier.FromDelegate((context, ct) => ...)`; `context.HostKey` has the key, type and fingerprint |
| `HostKeyReceived` comparing `e.HostKey` with a key you hold | `SshHostKeyVerifier.Pinned(SshPublicKey.Parse(pubLine))` |
| `e.HostKey` (the key bytes), `e.HostKeyName`, `e.KeyLength` | `context.HostKey.PublicKey`, `KeyType`, `KeySizeBits`; `context.HostKey.GetPublicKey()` as an `SshPublicKey` |
| `e.FingerPrintSHA256` | `context.HostKey.Fingerprint`, with the `SHA256:` prefix |
| `e.FingerPrintMD5` (`aa:bb:...`) | `context.HostKey.GetPublicKey().GetFingerprint(HashAlgorithmName.MD5)`, written `MD5:aa:bb:...` as `ssh-keygen -E md5` prints it |
| (no handler: every key is accepted) | no equivalent: a verifier is required |
| (no `known_hosts` support) | `KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes)` |

A rejected key throws `SshHostKeyException`, which carries the key the server presented. See [Host keys](host-keys.md).

## Authentication

| SSH.NET | SshSharp |
|---|---|
| `PasswordAuthenticationMethod(user, password)` | `SshClientOptions.Password`; or `PasswordProvider`, which asks only when a password is needed |
| `PasswordAuthenticationMethod.PasswordExpired`, setting `e.NewPassword` | `SshClientOptions.ChangePassword`, a callback that returns the new password (see [Passwords](how-to/passwords.md)) |
| `PrivateKeyAuthenticationMethod(user, keyFiles)` | `SshClientOptions.PrivateKeys` |
| `KeyboardInteractiveAuthenticationMethod` and its `AuthenticationPrompt` event | `SshClientOptions.KeyboardInteractive`, a callback that returns the answers |
| several methods in `ConnectionInfo` | set several options: the client tries public keys, keyboard-interactive, then password, as `ssh` does, and follows the server's multi-factor chains |
| (no agent support) | `SshAgent.FromEnvironment()` and `GetKeysAsync()`; `ForwardAgent` for agent forwarding |
| `SshAuthenticationException` | `SshAuthenticationException`, with `AllowedMethods` listing what the server would accept and `Attempts` listing each method tried and its outcome |

When the server takes passwords only through keyboard-interactive (PAM with `PasswordAuthentication no`), `Password` answers that
prompt, so you need no handler for it.

### Keys

| SSH.NET | SshSharp |
|---|---|
| `new PrivateKeyFile(path)`, `new PrivateKeyFile(path, passphrase)` | `await SshPrivateKey.LoadAsync(path, passphrase)` |
| `new PrivateKeyFile(stream)` | `SshPrivateKey.Parse(text, passphrase)` |
| OpenSSH, PKCS#1, PKCS#8, PuTTY `.ppk` | the same, plus SEC1; ssh.com keys are not read (convert them with `ssh-keygen -i`) |
| encrypted traditional PEM (`Proc-Type: 4,ENCRYPTED`) with AES-CBC or DES-EDE3-CBC | AES-128/192/256-CBC only: a 3DES-encrypted key throws a `FormatException` naming the cipher; re-encrypt it once with `ssh-keygen -p -f <file>` (see [Encrypted key files](how-to/agent-and-keys.md#encrypted-key-files)) |
| OpenSSH keys encrypted with `aes*-ctr`, `aes*-cbc`, `aes*-gcm@openssh.com`, `chacha20-poly1305@openssh.com` | the same |
| `ssh-rsa` (SHA-1) signatures | RSA keys sign with `rsa-sha2-256` or `rsa-sha2-512` only |
| (no key generation) | `SshPrivateKey.Generate(SshKeyType.Ed25519)`, then `SaveAsync(path, passphrase)` (see [Authentication](authentication.md#generating-keys)) |
| a `PrivateKeyFile`'s public key | `key.GetPublicKey()`: an `SshPublicKey` with `KeyType`, `Fingerprint` and `ToAuthorizedKeysLine()` |
| (no public key type: `.pub` files and `authorized_keys` lines read by hand) | `SshPublicKey.Parse(line)` and `FromBlob(bytes)`, equal by key bytes, with `VerifySignature` (see [Read a public key](how-to/agent-and-keys.md#read-a-public-key-and-its-fingerprint)) |

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
| `client.CreateCommand(text)`, then `command.Execute()` | `await client.RunCommandAsync(text, ct)`: one call, and each call is its own session |
| `command.Result`, `command.Error` | `result.StandardOutputText`, `result.StandardErrorText` (or the raw bytes: `StandardOutput`, `StandardError`) |
| `command.ExitStatus`, `command.ExitSignal` | `result.ExitStatus`, `result.ExitSignal?.Name` |
| `if (command.ExitStatus != 0) throw new Exception(command.Error)` | `result.EnsureSuccess()`: throws `SshCommandException` with `ExitStatus`, `ExitSignal` and the last 4 KiB of stderr |
| `command.CreateInputStream()`, write, then dispose it, for input known up front | `await client.RunCommandAsync(text, null, SshCommandInput.FromText(input), ct)` (or `FromBytes`, `FromStream`): written, then end-of-file |
| `command.OutputStream`, `ExtendedOutputStream`, `CreateInputStream()` while the command runs | `await client.StartCommandAsync(text)`, then `session.StandardOutput`, `StandardError`, `StandardInput` |
| Environment variables or a terminal for a command (SSH.NET's `SshCommand` has neither) | `RunCommandAsync(text, new SshSessionOptions { Environment = ..., Terminal = ... }, null, ct)` |
| `command.CancelAsync()` | cancel the token, or `session.SendSignalAsync("TERM")` |
| `command.CommandTimeout` | a `CancellationToken` |

A command that fails is a result in both libraries. Where SSH.NET code checks `ExitStatus` and throws, chain `EnsureSuccess()`:

```csharp
// SSH.NET
var command = client.RunCommand("make -C /srv/app build");
if (command.ExitStatus != 0)
{
    throw new InvalidOperationException(command.Error);
}

// SshSharp
var result = (await client.RunCommandAsync("make -C /srv/app build")).EnsureSuccess();
```

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

SshSharp offers three ways, depending on what the shell is for.

**Option 1: one command, no shell.** Often the shell only runs a command and reads its output. A command needs no terminal, so
there is no echo or prompt to skip, and you get the exit status too:

```csharp
var result = await client.RunCommandAsync("uptime");
var line = result.StandardOutputText.TrimEnd('\n');
```

**Option 2: an interactive shell, line by line, with `SshExpect`.** It decodes the output and keeps a buffer, so lines, prompts and
partial reads mix safely:

```csharp
await using var shell = await client.StartShellAsync(new SshSessionOptions
{
    Terminal = new SshTerminalOptions { TerminalType = "xterm", Columns = 80, Rows = 24 },
});
var io = new SshExpect(shell);
await io.SendLineAsync("uptime");
var echo = await io.ReadLineAsync(); // the terminal echoes the command first, as with ShellStream
var line = await io.ReadLineAsync();
```

A prompt ends without a line feed, so wait for it with `ExpectAsync` (below) rather than `ReadLineAsync`, which would wait for the
line to end.

**Option 3: the session's streams, for full control.** `StandardInput` and `StandardOutput` are plain streams, for your own reader and
writer, or to copy to a file or the console:

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

Use one way per session: `SshExpect` and a `StreamReader` both buffer what they read, so reading the same output with both loses
data.

For `ShellStream.Expect`, wrap the session in `SshExpect`:

| SSH.NET | SshSharp |
|---|---|
| `shell.Expect("$ ", timeout)` | `await expect.ExpectAsync("$ ", token)`: returns `Before` and `Value`; throws `EndOfStreamException` when the output ends first |
| `shell.Expect(new ExpectAction(regex, action))` | `var match = await expect.ExpectAsync(regex, token)`, then act on `match.Match.Groups` |
| `shell.WriteLine(text)` | `await expect.SendLineAsync(text, token)` |

Create it with `var expect = new SshExpect(shell)`. Resize with `shell.ResizeTerminalAsync(columns, rows)`. See
[Commands and shells](sessions.md#scripting-a-shell-expect).

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
| `ForwardedPortRemote` (`ssh -R`) | `client.ForwardRemotePortAsync(bindAddress, remotePort, localHost, localPort)`, or with a handler that gets each connection as a `Stream` |
| (no remote dynamic forwarding) | `client.ForwardRemoteDynamicPortAsync(bindAddress, remotePort, allowDestination)` (`ssh -R port`) |
| `ForwardedPortDynamic` (`ssh -D`) | `client.ForwardDynamicPortAsync(localEndPoint)`; with `credentials`, a SOCKS 5 proxy that asks for a user name and password |
| (no local Unix-socket forwarding) | `client.ForwardLocalPortAsync(localEndPoint, remoteSocketPath)` (`ssh -L port:/remote.sock`) and `ForwardLocalUnixSocketAsync(localSocketPath, ...)` (`ssh -L /local.sock:...`) |
| `forward.Start()`, `Stop()` | started when returned; stopped by `DisposeAsync` |
| (no remote Unix-socket forwarding) | `client.ForwardRemoteUnixSocketAsync(remoteSocketPath, localHost, localPort)` or `(remoteSocketPath, localSocketPath)` (`ssh -R /socket:target`) |
| `client.ForwardedPorts` | `client.LocalForwardings`, `RemoteForwardings`, `RemoteSocketForwardings`, `DynamicForwardings` (the ones started from `ssh_config`) |
| (none) | `client.OpenTcpTunnelAsync(host, port)` and `OpenUnixSocketTunnelAsync(path)`: a `Stream` to the far end, without a local listener |

With `ssh_config`, `LocalForward`, `RemoteForward` and `DynamicForward` start with the connection when
`SshConfigConnectOptions.StartForwardings` is set.

## SFTP

SSH.NET:

```csharp
using var sftp = new SftpClient("files.example.com", "deploy", password);
sftp.Connect();
using var file = File.OpenRead("report.pdf");
sftp.UploadFile(file, "incoming/report.pdf");
```

SshSharp (see [File transfer (SFTP)](sftp.md)):

```csharp
using SshSharp.Sftp;

await using var sftp = await client.OpenSftpAsync();
await sftp.UploadFileAsync("report.pdf", "incoming/report.pdf");
```

| SSH.NET | SshSharp (`using SshSharp.Sftp;`) |
|---|---|
| `new SftpClient(...)`, `Connect()` | `await client.OpenSftpAsync()` on a connected `SshClient` (one connection for SFTP, commands and forwarding) |
| `UploadFile(stream, path)`, `UploadFileAsync` | `UploadAsync(stream, path)`, or `UploadFileAsync(localPath, path)` |
| `DownloadFile(path, stream)`, `DownloadFileAsync` | `DownloadAsync(path, stream)`, or `DownloadFileAsync(path, localPath)` |
| `ListDirectory(path)`, `ListDirectoryAsync` | `ListDirectoryAsync(path)`: `IAsyncEnumerable<SftpFileInfo>`, without `.` and `..`; with `SftpListOptions`, a name `Pattern` and `Recursive` listings |
| `SynchronizeDirectories(source, destination, searchPattern)` | `UploadDirectoryAsync(source, destination, new SftpTransferOptions { Preserve = true, SkipUnchanged = true, Filter = ... })`: new and changed files by size and modification time, a whole tree; `DownloadDirectoryAsync` the other way |
| `Exists`, `Get`, `GetAttributes` | `ExistsAsync`, `GetAttributesAsync` |
| `CreateDirectory`, `DeleteDirectory`, `DeleteFile`, `Delete` | `CreateDirectoryAsync`, `DeleteDirectoryAsync`, `DeleteFileAsync`; also `CreateDirectoryAsync(path, createParents: true)` (`mkdir -p`) and `DeleteDirectoryAsync(path, recursive: true)` (`rm -r`) |
| `ReadAllBytes`, `ReadAllText`, `WriteAllBytes`, `WriteAllText` | `ReadAllBytesAsync`, `ReadAllTextAsync`, `WriteAllBytesAsync`, `WriteAllTextAsync` |
| `OperationTimeout` | `SftpClient.OperationTimeout` (off by default; it limits how long the server may stay silent, so long transfers are not cut off) |
| `RenameFile(old, new, isPosix)` | `RenameAsync(old, new, overwrite)` |
| `Open`, `OpenRead`, `OpenWrite`, `Create`, `AppendText` | `OpenAsync(path, FileMode, FileAccess)`, `OpenReadAsync`, `OpenWriteAsync` |
| `ChangePermissions`, `SetLastWriteTime`, `SetAttributes` | `SetAttributesAsync(path, new SftpFileAttributes { Permissions = ..., LastWriteTime = ... })` |
| `SymbolicLink`, `ReadLink`-style calls | `CreateSymbolicLinkAsync`, `ReadSymbolicLinkAsync`; also `CreateHardLinkAsync` |
| `WorkingDirectory`, `ChangeDirectory` | none: pass full paths, or paths relative to the login directory (`GetHomeDirectoryAsync`) |
| `SftpPathNotFoundException`, `SftpPermissionDeniedException` | `SftpException` with `Status` `NoSuchFile`, `PermissionDenied` (and `Path`) |
| upload/download callbacks | `SftpTransferOptions.Progress` |
| `BufferSize`, `MaxPendingReads` | taken from the server's limits; `SftpTransferOptions.MaxRequestsInFlight` |

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
| `SshOperationTimeoutException` | `OperationCanceledException` when your token was cancelled; `SshException` with `Reason = Timeout` for `SshClientOptions.ConnectTimeout` (or `ConnectTimeout` in `ssh_config`) and `SftpClient.OperationTimeout` |
| `ProxyException` | `SshException` with `Reason = ConnectFailed`, saying what the proxy answered |
| `ScpException` | `SshException` with `Reason = TransferFailed` |

See [Errors and diagnostics](diagnostics.md) for logging (`SshClientOptions.Logger`), tracing and metrics.

## See also

- [Getting started](getting-started.md) and the [how-to guides](how-to/index.md)
- [FAQ](reference/faq.md)
- [Unit-test code that uses SshSharp](how-to/unit-testing.md): SshSharp has no interfaces to mock, by design
