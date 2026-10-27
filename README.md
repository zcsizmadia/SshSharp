<img src="https://raw.githubusercontent.com/zcsizmadia/SshSharp/main/assets/logo/sshsharp-512.png" alt="SshSharp logo" width="96">

# SshSharp

[![CI](https://github.com/zcsizmadia/SshSharp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zcsizmadia/SshSharp/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/SshSharp?logo=nuget&label=NuGet)](https://www.nuget.org/packages/SshSharp)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/download/dotnet)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/zcsizmadia/SshSharp/blob/main/LICENSE)

A managed, async-first SSH client library for .NET, with OpenSSH `ssh_config` and `known_hosts` support. Connect to a host
by its `ssh_config` alias and get the same host name, user, keys, agent, jump hosts and host key policy that `ssh` would use.

```csharp
await using var client = await SshClient.ConnectAsync("prod-db");   // an alias from ~/.ssh/config
var result = await client.RunCommandAsync("uptime");
Console.WriteLine(result.StandardOutputText);
```

> **Status:** 1.x: the public API follows semantic versioning, so breaking changes wait for a major version. The managed
> cryptography has had an internal constant-time review but not yet an outside one. See [SECURITY.md](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md).

## Features

- **Platform:** pure managed C#, no native dependencies; .NET 8, .NET 10 and .NET 11 on Windows, Linux and macOS; trimming and Native AOT.
  Async all the way, with a `CancellationToken` on every network operation.
- **Connecting:** `ssh_config` aliases (`Host`, `Match`, `Include`), ProxyJump chains (from `ssh_config` or in code),
  ProxyCommand, HTTP and SOCKS proxies or your own transport, typed options for algorithms and timeouts, keep-alive.
- **Host verification:** `known_hosts` with OpenSSH's policies, host certificates, revocation lists, `UpdateHostKeys`, pinning
  or your own verifier; no "accept anything" default.
- **Authentication and keys:** passwords (prompted and changed when expired), keys in OpenSSH, PKCS#1/#8, SEC1 and PuTTY
  formats, key generation and export, ssh-agent and Pageant, an in-process agent, agent forwarding with a filter, FIDO keys,
  KMS and HSM signers, certificates (also issued as a CA), revocation lists, keyboard-interactive, Kerberos, `ssh-keygen -Y`
  signatures.
- **Commands and shells:** run or stream commands, shells with a terminal, `expect`-style scripting, signals, subsystems.
- **SFTP and SCP:** pipelined and segmented transfers, directory trees with filters and skipping of unchanged files, recursive
  listings, server-side hashes, remote file streams, SCP for servers without SFTP.
- **Forwarding:** local, remote and dynamic (SOCKS 5 with a password if you like), Unix sockets on either end, remote
  forwarding to a handler in your code, `HttpClient` through the connection.
- **Cryptography:** post-quantum key exchange, ChaCha20-Poly1305 and AES-GCM, strict key exchange, a FIPS mode, delayed
  compression; no legacy algorithms.
- **.NET integration:** dependency injection (named and keyed endpoints, a shared reconnecting connection, health checks),
  SFTP as `IFileSystem` or `IFileProvider`.
- **Observability:** `ILogger`, `ActivitySource` traces and `Meter` metrics, with no secrets recorded.

Every feature, with its API and the page that shows how:
**[Features](https://github.com/zcsizmadia/SshSharp/blob/main/docs/features.md)**.

## Why not SSH.NET?

[SSH.NET](https://github.com/sshnet/SSH.NET) is the established .NET SSH library, and for some projects it is the better choice
(see below). SshSharp is for applications that should behave like OpenSSH's `ssh`: connect by `ssh_config` alias, trust what
`known_hosts` says, sign with the user's agent, hop through jump hosts, and do all of it asynchronously.

| | SshSharp | SSH.NET 2026.0 |
|---|---|---|
| Target frameworks | .NET 8, .NET 10, .NET 11 | .NET Framework 4.6.2+, .NET Standard 2.0, .NET 8+ |
| API | Async-only network API; `CancellationToken` on every network operation | Mostly synchronous; async connect, commands and SFTP |
| Faster on the same server with the same algorithms: 8 parallel commands in half the time, SFTP stream writes 3x faster, downloads and streaming 20-40% faster | ✅ ([benchmarks](https://github.com/zcsizmadia/SshSharp/blob/main/docs/benchmarks.md#a-second-machine-windows-and-wsl)) | ❌ |
| Fewer allocations: 3-7x less memory allocated per transfer (SCP, SFTP, command output), no large-object-heap garbage per SFTP request | ✅ ([benchmarks](https://github.com/zcsizmadia/SshSharp/blob/main/docs/benchmarks.md#a-second-machine-windows-and-wsl)) | ❌ |
| `ssh_config` (`Host`, `Match` with `localnetwork`, `sessiontype` and `command`, `Include`; connect by alias; `KnownHostsCommand`, `RefuseConnection`) | ✅ | ❌ |
| `known_hosts` verification (hashed hosts, `@cert-authority`, `@revoked`, `StrictHostKeyChecking`) | ✅ | ❌ (verify in a `HostKeyReceived` handler) |
| Revoked host keys (`RevokedHostKeys`: OpenSSH KRLs from `ssh-keygen -k`, or key lists) | ✅ | ❌ |
| `UpdateHostKeys` (key rotation) | ✅ | ❌ |
| Host key scanning (`ssh-keyscan`) | ✅ | ❌ |
| ProxyJump chains (ssh_config or in code), ProxyCommand | ✅ | ❌ |
| HTTP and SOCKS 4/5 proxies | ✅ | ✅ |
| Connect over any `Stream` (WebSocket, named pipe, your own tunnel) | ✅ | ❌ |
| Connect from a chosen local address or interface (`BindAddress`, `BindInterface`) | ✅ | ❌ |
| Keep-alive that detects a dead server (`ServerAliveCountMax`) | ✅ | ❌ (keep-alives get no reply) |
| Round-trip ping (`client.PingAsync`, OpenSSH's `ping@openssh.com`) | ✅ | ❌ |
| Channel idle timeouts by channel type (`ChannelTimeout`, OpenSSH 9.2+) | ✅ | ❌ |
| Hide keystroke timing in terminal sessions (`ObscureKeystrokeTiming`, OpenSSH 9.5+) | ✅ | ❌ |
| Stop a program's output early without killing it (`eow@openssh.com`), refuse further sessions on a connection (`no-more-sessions@openssh.com`) | ✅ | ❌ |
| SSH agent (`ssh-agent`, Windows OpenSSH agent, PuTTY's Pageant) | ✅ | ❌ |
| Agent forwarding | ✅ | ❌ |
| An in-process agent from your keys and KMS/HSM signers, and a filter or confirmation for each forwarded agent request | ✅ | ❌ |
| FIDO security keys through the agent (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`, and their certificates) | ✅ | ❌ |
| Agent key management (`ssh-add`: add with lifetime, confirmation or destination constraints (`-h`), remove, lock; `AddKeysToAgent`), and signing with destination-constrained keys | ✅ | ❌ |
| Password, public key, keyboard-interactive, multi-factor | ✅ | ✅ |
| Kerberos (GSSAPI, `gssapi-with-mic`; .NET 10) | ✅ | ❌ |
| OpenSSH certificates | User and host; issuing them as a CA; checking them against a KRL | User (authentication) |
| Private key formats | OpenSSH, PKCS#1/#8, SEC1, PuTTY `.ppk` | OpenSSH, PKCS#1/#8, PuTTY `.ppk`, ssh.com |
| Key generation (Ed25519, ECDSA, RSA) and export (OpenSSH, PKCS#8, PuTTY `.ppk`) | ✅ | ❌ |
| Signing and verifying files and git commits (`ssh-keygen -Y`, SSHSIG, allowed-signers files) | ✅ | ❌ |
| Post-quantum key exchange `sntrup761x25519-sha512` (OpenSSH 8.5+, also as `@openssh.com`) | ✅ (managed: every platform, .NET 8 too) | ✅ |
| Post-quantum key exchange `mlkem768x25519-sha256` (OpenSSH 9.9+) | ✅ (.NET 10+ with platform ML-KEM) | ✅ |
| FIPS-compatible post-quantum key exchange (`mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384`) | ✅ (.NET 10+ with platform ML-KEM) | ❌ |
| Strict key exchange (Terrapin fix) | ✅ | ✅ |
| Legacy algorithms (CBC, 3DES, SHA-1, `ssh-rsa`, DH group 1, pre-authentication `zlib`) | — (by design) | ✅ (plain `zlib` only when you add it to `CompressionAlgorithms`) |
| Commands, shells with a terminal, `expect`-style scripting | ✅ | ✅ |
| Environment variables for a session (`env` requests, as ssh's `SetEnv` and `SendEnv`) | ✅ | ❌ |
| Any signal to a running session, including extension signals (`INFO@openssh.com`) | ✅ | ❌ (TERM or KILL, when cancelling a command) |
| BREAK (RFC 4335, for serial consoles) | ✅ | ❌ |
| Any subsystem (`ssh -s`) | ✅ | ❌ (SFTP and NETCONF only) |
| Local, remote and dynamic port forwarding | ✅ (also started from `ssh_config`) | ✅ |
| A SOCKS proxy (`ssh -D`) that asks for a user name and password (SOCKS 5, RFC 1929), so it can listen beyond loopback | ✅ | ❌ (SOCKS 4 and 5 without authentication only) |
| Remote dynamic forwarding (`ssh -R port`, a SOCKS proxy on the client side) | ✅ | ❌ |
| Unix-socket tunnels (Docker or database sockets on the server) | ✅ | ❌ |
| Remote Unix-socket forwarding (`ssh -R /remote.sock:target`, for example gpg-agent forwarding) | ✅ | ❌ |
| Local Unix-socket forwarding (`ssh -L /local.sock:/remote.sock`, `-L port:/remote.sock`, for example a remote Docker daemon) | ✅ | ❌ |
| Remote forwarding to an in-process handler (each connection as a `Stream`, no local port) | ✅ | ❌ |
| `HttpClient` through the SSH connection (`SocketsHttpHandler.ConnectCallback`) | ✅ | ❌ |
| FIPS mode (FIPS-approved algorithms only) | ✅ | ❌ |
| SCP | ✅ | ✅ |
| SFTP | ✅ (version 3 with OpenSSH extensions, pipelined transfers) | ✅ |
| SFTP directory trees: recursive uploads and downloads (several files at once, a filter, skipping unchanged files), recursive listings with patterns, `rm -r` and `mkdir -p` | ✅ | ❌ (`SynchronizeDirectories` uploads the files of one local directory, without its subdirectories) |
| Segmented SFTP downloads and uploads (one file in parallel ranges over several sessions) | ✅ | ❌ |
| SFTP file hashes computed by the server (`check-file`, to verify a transfer) and raw extended requests | ✅ | ❌ |
| SFTP `fsync@openssh.com` (durable uploads), `hardlink@openssh.com` and `limits@openssh.com` | ✅ | ❌ |
| Remote files as an `IFileSystem` (System.IO.Abstractions: `File`, `Directory`, `Path`, streams) | ✅ (`SshSharp.IO.Abstractions`) | ❌ |
| Remote files as an `IFileProvider` (ASP.NET Core static files, Razor, configuration) | ✅ (`SshSharp.FileProviders`) | ❌ |
| Dependency injection: named endpoints from configuration, a shared connection that reconnects, health checks, `HttpClient` through an endpoint | ✅ (`SshSharp.Extensions.DependencyInjection`) | ❌ |
| Native AOT | ✅ (an AOT-compiled binary connects to a real server in CI) | ✅ (AOT-compatible; an AOT publish is checked in CI) |
| Diagnostics | `ILogger`, `ActivitySource` tracing, `Meter` metrics (OpenTelemetry semantic conventions) | `ILogger` |
| Fuzzing | ✅ (coverage-guided, nightly; every parser in each test run) | ❌ |
| Fault-injection tests against real servers (cuts at any byte, either way; silent or one-way stalled networks; latency, tiny segments, low bandwidth; sessions killed on the server) | ✅ | Partial (sessions killed on the server) |
| Mutation testing | ✅ (Stryker.NET, weekly) | ❌ |
| Maturity | New (1.0 in October 2026); managed crypto awaiting an outside review | More than a decade of production use |

**Use SSH.NET instead** when you need .NET Framework or .NET Standard, servers that only speak legacy algorithms,
or a long track record. Moving from SSH.NET? See the
[migration guide](https://github.com/zcsizmadia/SshSharp/blob/main/docs/migrating-from-sshnet.md).

## Compared with Tmds.Ssh

[Tmds.Ssh](https://github.com/tmds/Tmds.Ssh) is another async-first .NET SSH client, MIT-licensed, that implements modern algorithms
only. The table lists differences we verified in its source.

Checked on 2026-10-19 against Tmds.Ssh 0.26.0 ([NuGet](https://www.nuget.org/packages/Tmds.Ssh), published 2026-10-10) and its
`main` branch at commit [`e186178`](https://github.com/tmds/Tmds.Ssh/tree/e1861789d90067c3382c6917b7ae821d1d0ffeb4/src/Tmds.Ssh)
(2026-10-14), by reading the source files at that commit. Tmds.Ssh is pre-1.0 and changes quickly, so check its current source and
[documentation](https://tmds.github.io/Tmds.Ssh/); corrections are welcome.

| | SshSharp | Tmds.Ssh 0.26.0 |
|---|---|---|
| Version | 1.x (stable public API) | 0.x (pre-1.0) |
| Target frameworks | .NET 8, .NET 10, .NET 11 | .NET 8, 9, 10 and 11 |
| Cryptography | The platform's (BCL), plus managed code where the platform has none | The platform's (BCL) and BouncyCastle (a package dependency) |
| Async API with `CancellationToken` | ✅ | ✅ |
| Native AOT | ✅ (an AOT-compiled binary connects to a real server in CI) | `IsAotCompatible` is set in the project |
| `ssh_config` | Most client directives, `Match` (including `exec` and `tagged`), `ProxyCommand`, forwardings ([list](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/ssh-config.md)) | A subset. `ProxyCommand`, `KnownHostsCommand`, `RevokedHostKeys` and other unsupported keywords throw; `Match exec` and `Match tagged` throw; forwarding directives are read and ignored |
| Jump hosts | ✅ (`ProxyJump`, or `JumpHosts` in code) | ✅ (`ProxyJump`, or `SshProxy` and `Proxy.Chain` in code) |
| HTTP and SOCKS proxies for the connection | ✅ | ❌ (`SshProxy` is the only proxy type; `Proxy`'s connect member is internal, so other types cannot be added from outside the library) |
| Password, public key, Kerberos (`gssapi-with-mic`) | ✅ | ✅ |
| Keyboard-interactive | ✅ | ❌ (the method name is defined, but no credential type uses it) |
| OpenSSH user certificates | ✅ (and issuing them as a CA) | ✅ |
| SSH agent | `ssh-agent`, Windows OpenSSH agent, Pageant | `SSH_AUTH_SOCK`, Windows OpenSSH agent |
| Agent forwarding | ✅ | ✅ |
| X11 forwarding | ❌ | ✅ |
| Private key formats | OpenSSH, PKCS#1/#8, SEC1, PuTTY `.ppk` | OpenSSH (`openssh-key-v1`) |
| Transport ciphers | AES-GCM, ChaCha20-Poly1305, AES-CTR with HMAC-SHA2 | AES-GCM, ChaCha20-Poly1305 (AES-CTR and AES-CBC only decrypt private key files) |
| Key exchange | `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, Curve25519, NIST ECDH, SHA-2 finite-field DH | `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, Curve25519, NIST ECDH |
| Compression (`zlib@openssh.com`) | ✅ (off by default; on .NET 8 only what the server sends) | ✅ (off by default) |
| Local, remote and dynamic forwarding; Unix-socket channels and listeners | ✅ | ✅ |
| SFTP, including directory transfers | ✅ | ✅ |
| SCP | ✅ | ❌ (the repository's `ssh-cp` tool copies over SFTP) |
| Logging | `ILogger`; never records user names or host names | `ILogger`; logs the host name and user name when authenticating (at `Information`) |
| Tracing and metrics (`ActivitySource`, `Meter`) | ✅ | ❌ |
| Dependency injection package, file system adapters | ✅ | ❌ |

Tmds.Ssh has X11 forwarding and .NET 9 and .NET 11 builds, which SshSharp does not.

## Install

```
dotnet add package SshSharp
dotnet add package SshSharp.IO.Abstractions # optional: an IFileSystem over SFTP
dotnet add package SshSharp.FileProviders   # optional: an IFileProvider over SFTP
dotnet add package SshSharp.Extensions.DependencyInjection # optional: named endpoints, a shared connection, health checks
```

## Examples

Connect with a key and verify the host against `~/.ssh/known_hosts`:

```csharp
using SshSharp;
using SshSharp.Config;

using var key = await SshPrivateKey.LoadAsync("/home/me/.ssh/id_ed25519");
await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key],
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
});

var result = await client.RunCommandAsync("df -h /");
Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
```

Stream a long-running command:

```csharp
await using var session = await client.StartCommandAsync("tail -f /var/log/syslog");
using var reader = new StreamReader(session.StandardOutput);
while (await reader.ReadLineAsync() is { } line)
{
    Console.WriteLine(line);
}
```

Use the keys in `ssh-agent`:

```csharp
var agent = SshAgent.FromEnvironment();
var keys = agent is null ? [] : await agent.GetKeysAsync();
```

## Documentation

**[zcsizmadia.github.io/SshSharp](https://zcsizmadia.github.io/SshSharp/)**: the guides below and the full API reference, for the
latest release.

- [Getting started](https://github.com/zcsizmadia/SshSharp/blob/main/docs/getting-started.md) and a
  [tutorial](https://github.com/zcsizmadia/SshSharp/blob/main/docs/tutorial.md)
- On the documentation site: task-oriented [how-to guides](https://github.com/zcsizmadia/SshSharp/blob/main/docs/how-to/index.md),
  complete [scenarios](https://github.com/zcsizmadia/SshSharp/blob/main/docs/scenarios/index.md) (a deployment script, a fleet
  health check, a file sync job, a database through a jump host, a webhook receiver behind NAT, a background worker,
  short-lived certificates for CI jobs, a KMS-held key forwarded through a bastion), concept pages
  ([architecture](https://github.com/zcsizmadia/SshSharp/blob/main/docs/concepts/architecture.md),
  [security model](https://github.com/zcsizmadia/SshSharp/blob/main/docs/concepts/security-model.md)), and reference pages
  ([ssh_config directives](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/ssh-config.md),
  [algorithms](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/algorithms.md),
  [errors](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/errors.md),
  [FAQ](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/faq.md),
  [troubleshooting](https://github.com/zcsizmadia/SshSharp/blob/main/docs/reference/troubleshooting.md))
- [Connecting](https://github.com/zcsizmadia/SshSharp/blob/main/docs/connecting.md): TCP, streams, `ssh_config` aliases,
  ProxyJump, keep-alive, algorithms
- [Authentication](https://github.com/zcsizmadia/SshSharp/blob/main/docs/authentication.md): passwords, keys,
  certificates, the agent, keyboard-interactive
- [Host keys](https://github.com/zcsizmadia/SshSharp/blob/main/docs/host-keys.md): `known_hosts`, policies, pinning
- [Commands and shells](https://github.com/zcsizmadia/SshSharp/blob/main/docs/sessions.md)
- [File transfer (SFTP)](https://github.com/zcsizmadia/SshSharp/blob/main/docs/sftp.md)
- [File transfer (SCP)](https://github.com/zcsizmadia/SshSharp/blob/main/docs/scp.md)
- [Signing files and commits](https://github.com/zcsizmadia/SshSharp/blob/main/docs/signing.md): SSH signatures
  (`ssh-keygen -Y`) and allowed-signers files
- [Configuration files](https://github.com/zcsizmadia/SshSharp/blob/main/docs/config-files.md)
- [Dependency injection](https://github.com/zcsizmadia/SshSharp/blob/main/docs/dependency-injection.md): named endpoints,
  a shared reconnecting connection, health checks
- [Errors and diagnostics](https://github.com/zcsizmadia/SshSharp/blob/main/docs/diagnostics.md): exceptions, logging,
  tracing, metrics
- [Migrating from SSH.NET](https://github.com/zcsizmadia/SshSharp/blob/main/docs/migrating-from-sshnet.md): the same tasks,
  side by side
- [Samples](https://github.com/zcsizmadia/SshSharp/tree/main/samples): an `ssh`-like tool (commands, streaming, shell, port
  forwarding, SOCKS, SCP, SFTP, `IFileSystem`, a Windows CNG key), ASP.NET Core with dependency injection, static files and a health
  check, a worker service that survives dropped connections, OpenTelemetry traces and metrics, a raw-mode terminal that follows
  the window's size, a jump host in code with a short-lived issued certificate, and a Native AOT tool
- [API reference](https://zcsizmadia.github.io/SshSharp/api/SshSharp.html): generated from the XML documentation with DocFX
  (to build it locally: `dotnet tool restore`, then `dotnet docfx docs/docfx.json --serve`); every public member is documented,
  and IntelliSense shows the same text.
- [Design notes](https://github.com/zcsizmadia/SshSharp/blob/main/docs/design.md),
  [testing and validation](https://github.com/zcsizmadia/SshSharp/blob/main/docs/testing.md),
  [threat model](https://github.com/zcsizmadia/SshSharp/blob/main/docs/threat-model.md),
  [cryptography review](https://github.com/zcsizmadia/SshSharp/blob/main/docs/crypto-review.md),
  [benchmarks](https://github.com/zcsizmadia/SshSharp/blob/main/docs/benchmarks.md)

## Testing

Every pull request runs about 1,300 unit tests on Linux, Windows and macOS (x64 and Arm64), each on .NET 8, .NET 10 and .NET 11, and the
interop tests against real servers: OpenSSH old and new on Linux and Windows, Dropbear, AsyncSSH, Apache MINA SSHD, Erlang/OTP,
and SFTP-only servers. The cryptography is checked against reference vectors and about 6,400 Project Wycheproof edge cases. A
fault-injection proxy cuts, stalls and slows connections at any point, the parsers are fuzzed nightly, and stress runs loop the
whole suite with an instrumented build that catches buffer misuse.
[Testing and validation](https://github.com/zcsizmadia/SshSharp/blob/main/docs/testing.md) has the details, what the testing
found, and what is not covered yet.

## Building

- .NET SDK 10.0.401 or later (see `global.json`).
- Build: `dotnet build -c Release`
- Test (TUnit): `dotnet test --project tests/SshSharp.Tests -c Release`. Tests against real servers run when
  `SSHSHARP_TEST_SSHD` and related variables are set; CI sets them up on Linux, and `. ./scripts/test-server.ps1` starts the
  same server in Docker locally (`-Server dropbear` for Dropbear, `-Stop` to remove it).
- Coverage report: `./scripts/coverage.ps1` (target 95%+, not enforced in CI).
- Mutation testing (Stryker.NET, weekly in CI): `dotnet tool restore`, then in `tests/SshSharp.Tests`:
  `dotnet stryker --test-runner mtp --project SshSharp.csproj --target-framework net10.0 -m "**/Crypto/X25519.cs"`.
- Releases: pushing a `v*` tag on `main` publishes to nuget.org (`.github/workflows/publish.yml`).
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md). Every new feature ships with its documentation (how-to, reference,
  compiled examples) in the same pull request.

## License

[MIT](https://github.com/zcsizmadia/SshSharp/blob/main/LICENSE)
