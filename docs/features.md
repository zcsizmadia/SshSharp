# Features

Everything SshSharp does, one row per feature, with the API or `ssh_config` directive to use and the page that shows how.
<span class="badge text-bg-primary">1.1</span> marks a feature added in 1.1.

The four packages share one version: `SshSharp` (the client), `SshSharp.Extensions.DependencyInjection`,
`SshSharp.IO.Abstractions` and `SshSharp.FileProviders`. All target .NET 8 and .NET 10 and have no native dependencies.

## Connecting and configuration

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| Connect by alias | Resolves a destination as `ssh -G` does: host name, port, user, keys, agent, jump hosts and host key policy | `SshClient.ConnectAsync("alias")`; `~/.ssh/config` | [ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md) |
| `ssh_config` | `Host`, `Match` (`localnetwork`, `sessiontype`, `command`, `tagged`, and `exec` when you allow it), `Include`, tokens and environment variables | `SshConfig.Load`, `SshConfigConnectOptions`, `SshConfigResolveOptions` | [Directives](reference/ssh-config.md) |
| Typed options in code | Connect without `ssh_config`: host, credentials, host key policy and every setting as a typed property | <xref:SshSharp.SshClientOptions> | [Getting started](getting-started.md) |
| Override the configuration | Change the port, timeouts, attempts, address family, keep-alives or compression of an alias in code <span class="badge text-bg-primary">1.1</span> | `SshConfigConnectOptions.Port`, `ConnectTimeout`, `ConnectionAttempts`, ... | [ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md) |
| Host name canonicalization | `CanonicalizeHostname` with a DNS resolver built in, or your own <span class="badge text-bg-primary">1.1</span> | `SshConfigResolveOptions.UseDnsCanonicalizer`, `HostCanonicalizer` | [Configuration files](config-files.md) |
| Jump hosts from `ssh_config` | `ProxyJump` chains of any length, each hop with its own configuration | `ProxyJump` | [Jump hosts](how-to/jump-hosts.md) |
| Jump hosts in code | One `SshJumpHost` per hop, each with its own credentials and host key check; the destination's credentials never reach a hop <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.JumpHosts` | [Jump hosts](how-to/jump-hosts.md) |
| `ProxyCommand` | Runs a local command and speaks SSH over its standard input and output (an opt-in) | `ProxyCommand`; `SshConfigConnectOptions.AllowProxyCommand` | [Connecting](connecting.md) |
| HTTP and SOCKS proxies | Reach the server through an HTTP `CONNECT`, SOCKS 4/4a or SOCKS 5 proxy, with credentials | `SshProxy.Http`, `Socks5`, `Socks4`, `FromUri` | [Connecting](connecting.md) |
| Your own transport | A function that returns a connected stream (a cloud tunnel, a WebSocket, a named pipe), usable wherever a proxy is <span class="badge text-bg-primary">1.1</span> | `SshProxy.FromConnector` | [Jump hosts](how-to/jump-hosts.md) |
| Connect over a stream | Run SSH over any `Stream` you already have | `SshClient.ConnectAsync(stream, ...)` | [Connecting](connecting.md) |
| Timeouts | One limit for the TCP connection, key exchange and authentication together <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.ConnectTimeout`; `ConnectTimeout` | [Cancellation and timeouts](how-to/cancellation-and-timeouts.md) |
| Connection attempts | Retries a server that cannot be reached, one second apart, within `ConnectTimeout` <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.ConnectionAttempts`; `ConnectionAttempts` | [Cancellation and timeouts](how-to/cancellation-and-timeouts.md) |
| Address family and local address | IPv4 or IPv6 only <span class="badge text-bg-primary">1.1</span>; connect from a chosen address or interface | `AddressFamily`, `LocalEndPoint`; `AddressFamily`, `BindAddress`, `BindInterface` | [Connecting](connecting.md) |
| Socket options | Set options on each TCP socket before it connects; `TCPKeepAlive` and `IPQoS` applied <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.ConfigureSocket`; `TCPKeepAlive`, `IPQoS` | [Tune and inspect a connection](how-to/tune-and-inspect-connections.md) |
| Channel window and packet size | Larger windows for long, fast links (default 2 MiB window, 32 KiB packets) <span class="badge text-bg-primary">1.1</span> | `ChannelWindowSize`, `ChannelMaxPacketSize` | [Tune for throughput](how-to/performance-tuning.md) |
| Identification comment | Adds a comment to the client's identification line <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.VersionAddendum` | [Tune and inspect a connection](how-to/tune-and-inspect-connections.md) |
| Connection details | Endpoints, connect time, session ID, bytes sent and received, the negotiated algorithms <span class="badge text-bg-primary">1.1</span> | `RemoteEndPoint`, `LocalEndPoint`, `ConnectedAt`, `SessionId`, `BytesSent`, `BytesReceived`, `Algorithms` | [Tune and inspect a connection](how-to/tune-and-inspect-connections.md) |
| Re-keying | Automatic by data and time, or on demand <span class="badge text-bg-primary">1.1</span> | `RekeyAfterBytes`, `RekeyAfterTime`, `SshClient.RekeyAsync` | [Tune and inspect a connection](how-to/tune-and-inspect-connections.md) |
| Keep-alive | Detects a dead or stalled server, also while a write is blocked | `KeepAliveInterval`, `KeepAliveCountMax`; `ServerAliveInterval`, `ServerAliveCountMax` | [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md) |
| Round-trip ping | Measures the round trip on an open connection | `SshClient.PingAsync` | [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md) |
| Connection state | Learn when the connection drops, and why | `IsConnected`, `ConnectionClosed`, `ConnectionError` | [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md) |

## Host verification

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| `known_hosts` | Hashed hosts, `@cert-authority`, `@revoked`, and the `StrictHostKeyChecking` policies; new keys recorded as `ssh` records them | <xref:SshSharp.KnownHostsVerifier>; `UserKnownHostsFile`, `StrictHostKeyChecking`, `HashKnownHosts` | [Verify host keys](how-to/verify-host-keys.md) |
| Pinned keys | Accept only the fingerprints or public keys you name | `SshHostKeyVerifier.Pinned` (fingerprints, or `SshPublicKey` <span class="badge text-bg-primary">1.1</span>) | [Verify host keys](how-to/verify-host-keys.md) |
| Your own rule | Decide each host key in code | `SshHostKeyVerifier.FromDelegate` | [Verify host keys](how-to/verify-host-keys.md) |
| Host certificates | Trust host keys signed by a certificate authority | `@cert-authority` lines | [Host keys](host-keys.md) |
| Revoked host keys | OpenSSH KRLs and key lists | `KnownHostsVerifier.RevokedHostKeys`; `RevokedHostKeys` | [Host keys](host-keys.md) |
| Host key rotation | Learns the server's other host keys (`hostkeys-00@openssh.com`) | `KnownHostsVerifier.UpdateHostKeys`; `UpdateHostKeys` | [Host keys](host-keys.md) |
| `KnownHostsCommand` | Gets known hosts from a command (an opt-in) | `KnownHostsCommand`; `AllowKnownHostsCommand` | [Directives](reference/ssh-config.md) |
| Host key scanning | Fetches a server's host keys without logging in, as `ssh-keyscan` | `SshClient.ScanHostKeysAsync` | [Verify host keys](how-to/verify-host-keys.md) |

## Authentication and keys

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| Public keys | Ed25519, ECDSA and RSA (SHA-2 signatures), encrypted or not; certificates paired with their keys | `SshClientOptions.PrivateKeys`, `SshPrivateKey.LoadAsync`; `IdentityFile`, `CertificateFile` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Key formats | Reads OpenSSH, PKCS#1, PKCS#8, SEC1 and PuTTY `.ppk`, each also encrypted (traditional `Proc-Type: 4,ENCRYPTED` PEM with AES; OpenSSH keys with every `ssh-keygen -Z` cipher) | `SshPrivateKey.Parse`, `LoadAsync` | [Encrypted key files](how-to/agent-and-keys.md#encrypted-key-files) |
| Key generation | Ed25519, ECDSA and RSA keys, saved as `ssh-keygen` saves them | `SshPrivateKey.Generate`, `SaveAsync` | [Authentication](authentication.md) |
| Key export | PKCS#8 and PuTTY `.ppk` v3, and OpenSSH with your own bcrypt rounds <span class="badge text-bg-primary">1.1</span> | `ToPkcs8PrivateKey`, `ToPuttyPrivateKey`, `SaveAsync(path, SshPrivateKeyFormat, ...)` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Public keys as a type | Parse `.pub` and `authorized_keys` lines, take fingerprints, verify signatures <span class="badge text-bg-primary">1.1</span> | <xref:SshSharp.SshPublicKey> | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Keys you cannot export | Sign with a key in a KMS, an HSM, a TPM or the Windows key store | `SshKeySigner`, `SshPrivateKey.FromSigner` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Passwords | A given password, or a callback asked only when one is needed, up to `NumberOfPasswordPrompts` times <span class="badge text-bg-primary">1.1</span> | `Password`, `PasswordProvider` <span class="badge text-bg-primary">1.1</span>; `NumberOfPasswordPrompts` | [Passwords, prompts and expiry](how-to/passwords.md) |
| Expired passwords | Answers the server's request to change an expired password (RFC 4252 section 8) <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.ChangePassword` | [Passwords, prompts and expiry](how-to/passwords.md) |
| Keyboard-interactive and multi-factor | One-time codes and PAM prompts; the server's multi-factor chains followed | `SshClientOptions.KeyboardInteractive` | [Authentication](authentication.md) |
| What was tried | Each method tried, with its key fingerprint and outcome, when nothing logs in <span class="badge text-bg-primary">1.1</span> | `SshAuthenticationException.Attempts` | [Passwords, prompts and expiry](how-to/passwords.md) |
| Method order and key types | The authentication order, the RSA size floor and the key algorithms offered <span class="badge text-bg-primary">1.1</span> | `PreferredAuthentications`, `RequiredRsaSize`, `PubkeyAcceptedAlgorithms` | [Choose algorithms and authentication](how-to/algorithms-and-authentication-order.md) |
| SSH agent | `ssh-agent`, the Windows OpenSSH agent and PuTTY's Pageant; FIDO security keys held by the agent | `SshAgent.FromEnvironment`, `FromPageant`; `IdentityAgent` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Agent key management | Add with a lifetime, confirmation or destination limits, remove, lock; `AddKeysToAgent` (with `ask` <span class="badge text-bg-primary">1.1</span>) | `AddKeyAsync`, `SshAgentKeyConstraints`, `RemoveKeyAsync`, `LockAsync`; `AddKeysToAgent` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Agent forwarding | Lets programs on the server use your agent | `SshClientOptions.ForwardAgent`; `ForwardAgent` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| In-process agent | An agent in your process from any keys SshSharp holds, KMS signers included, to log in with and to forward <span class="badge text-bg-primary">1.1</span> | `SshAgent.FromKeys` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| Forwarded-agent filter | Decides each request a forwarded agent gets: which keys are listed, what may be signed <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.ForwardAgentFilter` | [Keys and the SSH agent](how-to/agent-and-keys.md) |
| User certificates | Log in with an OpenSSH certificate | `SshPrivateKey.WithCertificate`; `CertificateFile` | [Certificates](how-to/certificates.md) |
| Issue certificates | Sign user and host certificates as a CA, with the CA key in a file, an agent or a KMS <span class="badge text-bg-primary">1.1</span> | <xref:SshSharp.SshCertificateBuilder> | [Certificates](how-to/certificates.md) |
| Check certificates | Signature, validity period, principal and authority, as `sshd` checks them <span class="badge text-bg-primary">1.1</span> | `SshCertificate.VerifySignature`, `IsValidAt`, `IsValidFor` | [Certificates](how-to/certificates.md) |
| Revocation lists | Checks keys and certificates against an OpenSSH KRL or a key list, as `ssh-keygen -Q` <span class="badge text-bg-primary">1.1</span> | <xref:SshSharp.SshKeyRevocationList> | [Certificates](how-to/certificates.md) |
| Kerberos | `gssapi-with-mic` with the current user's ticket or given credentials (.NET 10) | `SshClientOptions.Gssapi`; `GSSAPIAuthentication`, `GSSAPIDelegateCredentials` | [Kerberos](how-to/kerberos.md) |
| SSH signatures | Sign and verify files and git commits, with allowed-signers files, as `ssh-keygen -Y` | `SshSignature`, `SshAllowedSigners` | [Signing files and commits](signing.md) |

## Sessions and commands

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| Run a command | Collects the output and exit status; `EnsureSuccess` throws on failure <span class="badge text-bg-primary">1.1</span> | `RunCommandAsync`, `SshCommandResult.EnsureSuccess` | [Run a command](how-to/run-a-command.md) |
| Input and options for a command | Standard input from bytes, text or a stream, with session options <span class="badge text-bg-primary">1.1</span> | `RunCommandAsync(command, options, SshCommandInput, ...)` | [Run a command](how-to/run-a-command.md) |
| Stream a command | Standard input, output and error as streams, for large or endless output | `StartCommandAsync`, `SshSession` | [Stream large output](how-to/stream-output.md) |
| Shells and terminals | An interactive shell with a pseudo-terminal, window resizing and terminal modes | `StartShellAsync`, `SshTerminalOptions`, `ResizeTerminalAsync` | [Interactive shells](how-to/interactive-shell.md) |
| `expect`-style scripting | Wait for prompts and patterns, send lines | <xref:SshSharp.SshExpect> | [Interactive shells](how-to/interactive-shell.md) |
| Environment variables | `env` requests for a session | `SshSessionOptions.Environment`; `SetEnv`, `SendEnv` | [Commands and shells](sessions.md) |
| Signals and BREAK | Any signal, including extension signals; BREAK for serial consoles (RFC 4335) | `SendSignalAsync`, `SendBreakAsync` | [Commands and shells](sessions.md) |
| Subsystems | Any subsystem, as `ssh -s` (for example `netconf`) | `StartSubsystemAsync` | [Commands and shells](sessions.md) |
| Channel idle timeouts | Closes idle channels by type, as OpenSSH 9.2+ | `ChannelTimeouts`; `ChannelTimeout` | [Directives](reference/ssh-config.md) |
| Keystroke timing | Hides keystroke timing in terminal sessions, as OpenSSH 9.5+ | `ObscureKeystrokeTiming` | [Directives](reference/ssh-config.md) |
| No more sessions | Refuses further sessions on a connection (`no-more-sessions@openssh.com`) | `SshClient.PreventNewSessionsAsync` | [Commands and shells](sessions.md) |

## SFTP

| Feature | What it does | API | Docs |
|---|---|---|---|
| File transfers | Pipelined uploads and downloads (64 requests in flight by default), with progress, kept times and permissions, and resume | `UploadFileAsync`, `DownloadFileAsync`, `UploadAsync`, `DownloadAsync`; `SftpTransferOptions` | [Transfer files with SFTP](how-to/transfer-files-sftp.md) |
| Segmented transfers | One large file in parallel ranges over several sessions, downloads and (since 1.1) uploads <span class="badge text-bg-primary">1.1</span> | `SftpTransferOptions.Segments` | [SFTP](sftp.md) |
| Directory trees | Whole trees either way, several files at once <span class="badge text-bg-primary">1.1</span> | `UploadDirectoryAsync`, `DownloadDirectoryAsync`; `MaxConcurrentFiles` | [Transfer files with SFTP](how-to/transfer-files-sftp.md) |
| Filters and skipping unchanged files | Choose what a directory transfer includes; skip files whose size and time match, as rsync does <span class="badge text-bg-primary">1.1</span> | `SftpTransferOptions.Filter`, `SkipUnchanged` | [Transfer files with SFTP](how-to/transfer-files-sftp.md) |
| Listings | Pipelined directory reads; name patterns and recursion <span class="badge text-bg-primary">1.1</span> | `ListDirectoryAsync`, `SftpListOptions` | [Transfer files with SFTP](how-to/transfer-files-sftp.md) |
| Conveniences | `mkdir -p`, `rm -r` (never following links), whole-file reads and writes <span class="badge text-bg-primary">1.1</span> | `CreateDirectoryAsync(path, createParents: true)`, `DeleteDirectoryAsync(path, recursive: true)`, `ReadAllTextAsync`, `WriteAllBytesAsync`, ... | [Transfer files with SFTP](how-to/transfer-files-sftp.md) |
| Files and links | Attributes, rename (with an atomic overwrite), symbolic and hard links, server-side copies, file system statistics | `GetAttributesAsync`, `RenameAsync`, `CreateSymbolicLinkAsync`, `CreateHardLinkAsync`, `CopyFileAsync`, `GetFileSystemInfoAsync` | [SFTP](sftp.md) |
| Remote file streams | Seekable streams; writes behind (up to 16 in flight), errors never lost <span class="badge text-bg-primary">1.1</span>; `fsync` on flush | `OpenAsync`, `OpenReadAsync`, `OpenWriteAsync` | [SFTP](sftp.md) |
| Server-side hashes | Check a transfer with a hash the server computes (`check-file`, `md5-hash`) <span class="badge text-bg-primary">1.1</span> | `GetFileHashAsync`, `SupportsFileHash` | [SFTP](sftp.md) |
| Vendor extensions | Send any extended request and read its reply <span class="badge text-bg-primary">1.1</span> | `SendExtendedRequestAsync` | [SFTP](sftp.md) |
| Timeouts | Fails requests once the server has been silent too long (off by default) <span class="badge text-bg-primary">1.1</span> | `SftpClient.OperationTimeout`, `IsConnected` | [Cancellation and timeouts](how-to/cancellation-and-timeouts.md) |

## SCP

| Feature | What it does | API | Docs |
|---|---|---|---|
| Files, streams and directories | Uploads and downloads with progress and kept times, for servers without SFTP | `UploadFileAsync`, `DownloadFileAsync`, `UploadDirectoryAsync`, `DownloadDirectoryAsync` (`SshSharp.Scp`), `SshScpOptions` | [Transfer files with SCP](how-to/transfer-files-scp.md) |
| Hostile-server checks | A server cannot write outside the target or slip in extra files | built in | [File transfer (SCP)](scp.md) |

## Forwarding and tunnels

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| Local forwarding | `ssh -L`: a local port to a host and port the server reaches | `ForwardLocalPortAsync`; `LocalForward` | [Port forwarding](how-to/port-forwarding.md) |
| Remote forwarding | `ssh -R`: a port on the server to a host and port here | `ForwardRemotePortAsync`; `RemoteForward` | [Port forwarding](how-to/port-forwarding.md) |
| Remote forwarding to a handler | Each connection to the server's port reaches your code as a `Stream`, with half-close and a shutdown grace period <span class="badge text-bg-primary">1.1</span> | `ForwardRemotePortAsync(bindAddress, port, handler)`, `HandlerShutdownTimeout` | [Port forwarding](how-to/port-forwarding.md) |
| Dynamic forwarding | `ssh -D`: a SOCKS 4/5 proxy here | `ForwardDynamicPortAsync`; `DynamicForward` | [Port forwarding](how-to/port-forwarding.md) |
| SOCKS 5 with a password | A dynamic forward that asks for a user name and password (RFC 1929), so it can serve other machines <span class="badge text-bg-primary">1.1</span> | `ForwardDynamicPortAsync(localEndPoint, credentials)` | [Port forwarding](how-to/port-forwarding.md) |
| Remote dynamic forwarding | `ssh -R port`: a SOCKS proxy on the server's side, with a destination filter | `ForwardRemoteDynamicPortAsync`; `RemoteForward`, `PermitRemoteOpen` <span class="badge text-bg-primary">1.1</span> | [Port forwarding](how-to/port-forwarding.md) |
| Unix sockets in local forwarding | `-L port:/remote.sock`, `-L /local.sock:host:port`, `-L /local.sock:/remote.sock`; owner-only socket files <span class="badge text-bg-primary">1.1</span> | `ForwardLocalPortAsync(endPoint, remoteSocketPath)`, `ForwardLocalUnixSocketAsync`; `StreamLocalBindMask`, `StreamLocalBindUnlink` | [Port forwarding](how-to/port-forwarding.md) |
| Remote Unix-socket forwarding | `ssh -R /remote.sock:target`, for example gpg-agent forwarding | `ForwardRemoteUnixSocketAsync` | [Port forwarding](how-to/port-forwarding.md) |
| Tunnels without a listener | A `Stream` to a host and port, or a Unix socket, on the server's side | `OpenTcpTunnelAsync`, `OpenUnixSocketTunnelAsync` | [Port forwarding](how-to/port-forwarding.md) |
| `HttpClient` through SSH | HTTP requests that connect through the SSH connection | `CreateHttpConnectCallback`; `UseSshTunnel` <span class="badge text-bg-primary">1.1</span> | [Port forwarding](how-to/port-forwarding.md) |
| Forwardings from `ssh_config` | `LocalForward`, `RemoteForward` and `DynamicForward` started with the connection | `SshConfigConnectOptions.StartForwardings` | [ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md) |

## Cryptography

| Feature | What it does | API / `ssh_config` | Docs |
|---|---|---|---|
| Post-quantum key exchange | `mlkem768x25519-sha256` (.NET 10 with platform ML-KEM) and `sntrup761x25519-sha512` (managed, everywhere) | defaults | [Algorithms](reference/algorithms.md) |
| Modern algorithms only | Curve25519, ECDH, SHA-2 finite-field DH (group exchange and group 18 <span class="badge text-bg-primary">1.1</span>); ChaCha20-Poly1305, AES-GCM, AES-CTR with HMAC-SHA2 (plain `hmac-sha2-*` <span class="badge text-bg-primary">1.1</span>); Ed25519, ECDSA, RSA with SHA-2. No CBC, SHA-1 or `ssh-rsa` | defaults | [Algorithms](reference/algorithms.md) |
| Algorithm choices in code | Key exchange, host key, cipher and MAC lists with `ssh_config`'s `+`, `-` and `^` forms; unknown names fail when set <span class="badge text-bg-primary">1.1</span> | `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `Macs` (<xref:SshSharp.SshAlgorithmList>) | [Choose algorithms](how-to/algorithms-and-authentication-order.md) |
| Strict key exchange | The Terrapin countermeasure, always on | built in | [Algorithms](reference/algorithms.md) |
| FIPS mode | FIPS-approved algorithms only, including post-quantum `mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384` on .NET 10 | `SshClientOptions.FipsMode` | [FIPS mode](how-to/fips-mode.md) |
| Delayed compression | `zlib@openssh.com`, started after authentication, off by default as in `ssh` <span class="badge text-bg-primary">1.1</span> | `SshClientOptions.Compression`; `Compression` | [Tune and inspect a connection](how-to/tune-and-inspect-connections.md) |

## .NET integration

| Feature | What it does | API | Docs |
|---|---|---|---|
| Dependency injection | Named endpoints from configuration, a factory for new connections, a shared connection that reconnects, and a health check | `AddSshClient`, `ISshClientFactory`, `ISshConnectionProvider`; `AddSsh` on `IHealthChecksBuilder` | [Dependency injection](dependency-injection.md) |
| Endpoint settings | Pinned host keys, private keys as values, a proxy URI, jump hosts, the agent, address family and compression from configuration <span class="badge text-bg-primary">1.1</span> | `SshEndpointOptions` | [Dependency injection](dependency-injection.md) |
| Keyed endpoints | Inject one endpoint by name <span class="badge text-bg-primary">1.1</span> | `[FromKeyedServices("name")] ISshEndpoint` | [ASP.NET Core and DI](how-to/aspnetcore-and-di.md) |
| `HttpClient` through an endpoint | A named `HttpClient` that connects through a named SSH connection <span class="badge text-bg-primary">1.1</span> | `IHttpClientBuilder.UseSshTunnel` | [ASP.NET Core and DI](how-to/aspnetcore-and-di.md) |
| Connection events | Connected, Disconnected and Reconnected, as a stream <span class="badge text-bg-primary">1.1</span> | `ISshConnectionProvider.WatchAsync` | [Dependency injection](dependency-injection.md) |
| `IFileSystem` over SFTP | System.IO.Abstractions' `File`, `Directory`, `Path` and streams on the server; follows a reconnecting connection <span class="badge text-bg-primary">1.1</span> | `SftpFileSystem` (`SshSharp.IO.Abstractions`) | [IFileSystem and IFileProvider](how-to/file-system-adapters.md) |
| `IFileProvider` over SFTP | A remote directory for ASP.NET Core static files, Razor views and configuration; follows a reconnecting connection <span class="badge text-bg-primary">1.1</span> | `SftpFileProvider` (`SshSharp.FileProviders`) | [IFileSystem and IFileProvider](how-to/file-system-adapters.md) |
| Native AOT and trimming | AOT-compatible, with an AOT-compiled smoke test against a real server in CI | `IsAotCompatible` | [Native AOT](how-to/native-aot.md) |
| Async and cancellation | Every network operation is async and takes a `CancellationToken` | throughout | [Cancellation and timeouts](how-to/cancellation-and-timeouts.md) |
| Testable code | A small interface of your own in front of SshSharp, so your logic is tested without a server | your own seam | [Unit-test code that uses SshSharp](how-to/unit-testing.md) |

## Observability

| Feature | What it does | API | Docs |
|---|---|---|---|
| Logging | `ILogger` events; never host names, user names, passwords or key material | `SshClientOptions.Logger` | [Logging and diagnostics](how-to/logging-and-diagnostics.md) |
| Traces | `ActivitySource` spans for connecting (`SshSharp.Connect`) and running commands (`SshSharp.Command`), following OpenTelemetry's conventions | `SshTelemetry.SourceName` (`"SshSharp"`) | [Errors and diagnostics](diagnostics.md) |
| Metrics | `Meter` instruments: open connections and channels, connect duration, bytes sent and received, key exchanges, commands | `SshTelemetry.SourceName` | [Errors and diagnostics](diagnostics.md) |
| Errors | One exception type with a machine-readable reason | `SshException.Reason` (<xref:SshSharp.SshFailureReason>) | [Errors and failure reasons](reference/errors.md) |
