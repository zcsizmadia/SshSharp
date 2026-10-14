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

> **Status:** pre-1.0 (0.x releases). The API may still change before 1.0, and the managed cryptography
> has had an internal constant-time review but not yet an outside one. See [SECURITY.md](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md).

## Features

- **Pure managed C#**, no native dependencies; .NET 8 and .NET 10, tested on Windows and Linux (x64 and Arm64) and macOS
  (Arm64); trimming- and Native AOT-compatible, with an AOT-compiled smoke test against a real server in CI.
- **Async all the way:** `CancellationToken` on every network operation, `IAsyncDisposable`, `System.IO.Pipelines` I/O with zero-copy
  packet handling.
- **OpenSSH configuration:** `ssh_config` (`Host`, `Match`, `Include`, tokens) and `known_hosts` (hashed hosts,
  `@cert-authority`, `@revoked`), resolved like `ssh -G`.
- **Authentication:** password, public keys (OpenSSH, PKCS#8, PKCS#1/SEC1 and PuTTY `.ppk` formats, encrypted too),
  OpenSSH user certificates, ssh-agent (Unix sockets and the Windows OpenSSH agent) and agent forwarding,
  keyboard-interactive (one-time codes, PAM), and multi-factor chains. Key generation, saved as `ssh-keygen` does.
- **Host verification:** `StrictHostKeyChecking` policies, host certificates, `UpdateHostKeys`, key pinning, or your own
  verifier. There is no "accept anything" default. Host key scanning, as `ssh-keyscan` does it.
- **Connections:** ProxyJump chains, ProxyCommand, HTTP and SOCKS proxies, connect over any `Stream` or from a chosen local
  address (`BindAddress`, `BindInterface`), keep-alive and
  dead-connection detection; `HttpClient` through the SSH connection;
  TCP and Unix-socket tunnels; local, remote and dynamic (SOCKS) port forwarding (`ssh -L`, `-R`, `-D`) and remote dynamic forwarding (`-R port`), also
  started from `ssh_config`.
- **Sessions:** run commands, stream stdin/stdout/stderr, interactive shells with a pseudo-terminal, environment variables,
  signals and window resizing; subsystems (`ssh -s`) such as `netconf`; `expect`-style scripting of shells.
- **Modern algorithms:** post-quantum `mlkem768x25519-sha256`, and the FIPS-compatible `mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384` (on .NET 10 where the platform has ML-KEM), `curve25519-sha256`,
  ECDH and DH group 14/16 key exchange; ChaCha20-Poly1305, AES-GCM and
  AES-CTR with HMAC-SHA2 ETM; Ed25519, ECDSA and RSA (SHA-2) keys; strict key exchange (Terrapin) always on; a FIPS mode.
- **File transfer:** SFTP (version 3 with OpenSSH's extensions: pipelined uploads and downloads, seekable remote file
  streams, directories, links and attributes; the API is experimental for now), and SCP uploads and downloads of files,
  streams and directories, with progress, kept times, and checks that stop a hostile server from writing outside the target.
- **Observability:** `ILogger` logging, `ActivitySource` tracing and `Meter` metrics, with no secrets recorded.

## Why not SSH.NET?

[SSH.NET](https://github.com/sshnet/SSH.NET) is the established .NET SSH library, and for some projects it is the better choice
(see below). SshSharp is for applications that should behave like OpenSSH's `ssh`: connect by `ssh_config` alias, trust what
`known_hosts` says, sign with the user's agent, hop through jump hosts, and do all of it asynchronously.

| | SshSharp | SSH.NET 2026.0 |
|---|---|---|
| Target frameworks | .NET 8, .NET 10 | .NET Framework 4.6.2+, .NET Standard 2.0, .NET 8+ |
| API | Async-only network API; `CancellationToken` on every network operation | Mostly synchronous; async connect, commands and SFTP |
| `ssh_config` (`Host`, `Match`, `Include`; connect by alias) | ✅ | ❌ |
| `known_hosts` verification (hashed hosts, `@cert-authority`, `@revoked`, `StrictHostKeyChecking`) | ✅ | ❌ (verify in a `HostKeyReceived` handler) |
| `UpdateHostKeys` (key rotation) | ✅ | ❌ |
| Host key scanning (`ssh-keyscan`) | ✅ | ❌ |
| ProxyJump chains, ProxyCommand | ✅ | ❌ |
| HTTP and SOCKS 4/5 proxies | ✅ | ✅ |
| Connect over any `Stream` (WebSocket, named pipe, your own tunnel) | ✅ | ❌ |
| Connect from a chosen local address or interface (`BindAddress`, `BindInterface`) | ✅ | ❌ |
| Keep-alive that detects a dead server (`ServerAliveCountMax`) | ✅ | ❌ (keep-alives get no reply) |
| SSH agent (`ssh-agent`, Windows OpenSSH agent), including destination-constrained keys (`ssh-add -h`) | ✅ | ❌ |
| Agent forwarding | ✅ | ❌ |
| Password, public key, keyboard-interactive, multi-factor | ✅ | ✅ |
| OpenSSH certificates | User and host | User (authentication) |
| Private key formats | OpenSSH, PKCS#1/#8, SEC1, PuTTY `.ppk` | OpenSSH, PKCS#1/#8, PuTTY `.ppk`, ssh.com |
| Key generation (Ed25519, ECDSA, RSA; saved in the OpenSSH format) | ✅ | ❌ |
| Post-quantum key exchange | `mlkem768x25519-sha256`, and FIPS-compatible `mlkem768nistp256-sha256` / `mlkem1024nistp384-sha384` (.NET 10 with platform ML-KEM) | `mlkem768x25519-sha256`, `sntrup761x25519-sha512` |
| Strict key exchange (Terrapin fix) | ✅ | ✅ |
| Legacy algorithms (CBC, 3DES, SHA-1, `ssh-rsa`, DH group 1, zlib) | — (by design) | ✅ |
| Commands, shells with a terminal, `expect`-style scripting | ✅ | ✅ |
| Signals to a running command | ✅ | ❌ |
| Any subsystem (`ssh -s`) | ✅ | ❌ (SFTP and NETCONF only) |
| Local, remote and dynamic port forwarding | ✅ (also started from `ssh_config`) | ✅ |
| Remote dynamic forwarding (`ssh -R port`, a SOCKS proxy on the client side) | ✅ | ❌ |
| Unix-socket tunnels (Docker or database sockets on the server) | ✅ | ❌ |
| `HttpClient` through the SSH connection (`SocketsHttpHandler.ConnectCallback`) | ✅ | ❌ |
| FIPS mode (FIPS-approved algorithms only) | ✅ | ❌ |
| SCP | ✅ | ✅ |
| SFTP | ✅ (version 3 with OpenSSH extensions, pipelined transfers; experimental API) | ✅ |
| Native AOT | ✅ (an AOT-compiled binary connects to a real server in CI) | ✅ (AOT-compatible; an AOT publish is checked in CI) |
| Diagnostics | `ILogger`, `ActivitySource` tracing, `Meter` metrics | `ILogger` |
| Fuzzing | ✅ (coverage-guided, nightly; every parser in each test run) | ❌ |
| Mutation testing | ✅ (Stryker.NET, weekly) | ❌ |
| Maturity | New, pre-1.0; managed crypto awaiting an outside review | More than a decade of production use |

**Use SSH.NET instead** when you need .NET Framework or .NET Standard, a settled (non-experimental) SFTP API, servers that only speak legacy algorithms,
or a long track record. Moving from SSH.NET? See the
[migration guide](https://github.com/zcsizmadia/SshSharp/blob/main/docs/migrating-from-sshnet.md).

## Install

```
dotnet add package SshSharp
```

## Examples

Connect with a key and verify the host against `~/.ssh/known_hosts`:

```csharp
using SshSharp;
using SshSharp.Config;

using var key = await SshPrivateKey.LoadFileAsync("/home/me/.ssh/id_ed25519");
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

- [Getting started](https://github.com/zcsizmadia/SshSharp/blob/main/docs/getting-started.md)
- [Connecting](https://github.com/zcsizmadia/SshSharp/blob/main/docs/connecting.md): TCP, streams, `ssh_config` aliases,
  ProxyJump, keep-alive, algorithms
- [Authentication](https://github.com/zcsizmadia/SshSharp/blob/main/docs/authentication.md): passwords, keys,
  certificates, the agent, keyboard-interactive
- [Host keys](https://github.com/zcsizmadia/SshSharp/blob/main/docs/host-keys.md): `known_hosts`, policies, pinning
- [Commands and shells](https://github.com/zcsizmadia/SshSharp/blob/main/docs/sessions.md)
- [File transfer (SFTP)](https://github.com/zcsizmadia/SshSharp/blob/main/docs/sftp.md)
- [File transfer (SCP)](https://github.com/zcsizmadia/SshSharp/blob/main/docs/scp.md)
- [Configuration files](https://github.com/zcsizmadia/SshSharp/blob/main/docs/config-files.md)
- [Errors and diagnostics](https://github.com/zcsizmadia/SshSharp/blob/main/docs/diagnostics.md): exceptions, logging,
  tracing, metrics
- [Migrating from SSH.NET](https://github.com/zcsizmadia/SshSharp/blob/main/docs/migrating-from-sshnet.md): the same tasks,
  side by side
- [Samples](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples): a small `ssh`-like tool (commands,
  streaming, shell, port forwarding, SOCKS, SCP)
- [API reference](https://zcsizmadia.github.io/SshSharp/api/SshSharp.html): generated from the XML documentation with DocFX
  (to build it locally: `dotnet tool restore`, then `dotnet docfx docs/docfx.json --serve`); every public member is documented,
  and IntelliSense shows the same text.
- [Design notes](https://github.com/zcsizmadia/SshSharp/blob/main/docs/design.md),
  [threat model](https://github.com/zcsizmadia/SshSharp/blob/main/docs/threat-model.md),
  [cryptography review](https://github.com/zcsizmadia/SshSharp/blob/main/docs/crypto-review.md)

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

## License

[MIT](https://github.com/zcsizmadia/SshSharp/blob/main/LICENSE)
