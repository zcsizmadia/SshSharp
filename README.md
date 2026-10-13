# SshSharp

[![CI](https://github.com/zcsizmadia/SshSharp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zcsizmadia/SshSharp/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/SshSharp?logo=nuget&label=NuGet)](https://www.nuget.org/packages/SshSharp)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/download/dotnet)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/zcsizmadia/SshSharp/blob/main/LICENSE)

A managed, async-first SSH client library for .NET, with OpenSSH `ssh_config` and `known_hosts` support. Connect to a host
by its `ssh_config` alias and get the same host name, user, keys, agent, jump hosts and host key policy that `ssh` would use.

```csharp
await using var client = await SshClient.ConnectAsync("prod-db");   // an alias from ~/.ssh/config
var result = await client.RunCommandAsync("uptime");
Console.WriteLine(result.StandardOutputText);
```

> **Status:** in development, prerelease packages only. The API may still change before 1.0, and the managed cryptography
> has had an internal constant-time review but not yet an outside one. See [SECURITY.md](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md).

## Features

- **Pure managed C#**, no native dependencies; .NET 8 and .NET 10, tested on Windows and Linux (x64 and Arm64) and macOS
  (Arm64); marked trimming- and AOT-compatible (analyzer-checked).
- **Async all the way:** `CancellationToken` on every operation, `IAsyncDisposable`, `System.IO.Pipelines` I/O with zero-copy
  packet handling.
- **OpenSSH configuration:** `ssh_config` (`Host`, `Match`, `Include`, tokens) and `known_hosts` (hashed hosts,
  `@cert-authority`, `@revoked`), resolved like `ssh -G`.
- **Authentication:** password, public keys (OpenSSH, PKCS#8, PKCS#1/SEC1 and PuTTY `.ppk` formats, encrypted too),
  OpenSSH user certificates, ssh-agent (Unix sockets and the Windows OpenSSH agent) and agent forwarding,
  keyboard-interactive (one-time codes, PAM), and multi-factor chains.
- **Host verification:** `StrictHostKeyChecking` policies, host certificates, `UpdateHostKeys`, key pinning, or your own
  verifier. There is no "accept anything" default.
- **Connections:** ProxyJump chains, ProxyCommand, connect over any `Stream`, keep-alive and dead-connection detection;
  TCP and Unix-socket tunnels; local, remote and dynamic (SOCKS) port forwarding (`ssh -L`, `-R`, `-D`), also
  started from `ssh_config`.
- **Sessions:** run commands, stream stdin/stdout/stderr, interactive shells with a pseudo-terminal, environment variables,
  signals and window resizing.
- **Modern algorithms:** `curve25519-sha256`, ECDH and DH group 14/16 key exchange; ChaCha20-Poly1305, AES-GCM and
  AES-CTR with HMAC-SHA2 ETM; Ed25519, ECDSA and RSA (SHA-2) keys; strict key exchange (Terrapin) always on; a FIPS mode.
- **File transfer:** SCP uploads and downloads of files, streams and directories, with progress, kept times, and checks
  that stop a hostile server from writing outside the target.
- **Observability:** `ILogger` logging, `ActivitySource` tracing and `Meter` metrics, with no secrets recorded.

Coming next: SFTP, as a separate package.

## Install

```
dotnet add package SshSharp --prerelease
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

- [Getting started](https://github.com/zcsizmadia/SshSharp/blob/main/docs/getting-started.md)
- [Connecting](https://github.com/zcsizmadia/SshSharp/blob/main/docs/connecting.md): TCP, streams, `ssh_config` aliases,
  ProxyJump, keep-alive, algorithms
- [Authentication](https://github.com/zcsizmadia/SshSharp/blob/main/docs/authentication.md): passwords, keys,
  certificates, the agent, keyboard-interactive
- [Host keys](https://github.com/zcsizmadia/SshSharp/blob/main/docs/host-keys.md): `known_hosts`, policies, pinning
- [Commands and shells](https://github.com/zcsizmadia/SshSharp/blob/main/docs/sessions.md)
- [File transfer (SCP)](https://github.com/zcsizmadia/SshSharp/blob/main/docs/scp.md)
- [Configuration files](https://github.com/zcsizmadia/SshSharp/blob/main/docs/config-files.md)
- [Errors and diagnostics](https://github.com/zcsizmadia/SshSharp/blob/main/docs/diagnostics.md): exceptions, logging,
  tracing, metrics
- API reference: generated from the XML documentation with DocFX (`dotnet tool restore`, then
  `dotnet docfx docs/docfx.json --serve`); every public member is documented, and IntelliSense shows the same text.
- [Design notes](https://github.com/zcsizmadia/SshSharp/blob/main/docs/design.md),
  [threat model](https://github.com/zcsizmadia/SshSharp/blob/main/docs/threat-model.md),
  [cryptography review](https://github.com/zcsizmadia/SshSharp/blob/main/docs/crypto-review.md)

## Building

- .NET SDK 10.0.401 or later (see `global.json`).
- Build: `dotnet build -c Release`
- Test (TUnit): `dotnet test --project tests/SshSharp.Tests -c Release`. Tests against real servers run when
  `SSHSHARP_TEST_SSHD` and related variables are set; CI sets them up on Linux.
- Coverage report: `./scripts/coverage.ps1` (target 95%+, not enforced in CI).
- Releases: pushing a `v*` tag on `main` publishes to nuget.org (`.github/workflows/publish.yml`).

## License

[MIT](https://github.com/zcsizmadia/SshSharp/blob/main/LICENSE)
