# SshSharp: Implementation Plan

Managed-only, async-first SSH client library for .NET with OpenSSH `known_hosts` and `ssh_config` support.

## Decisions

| Topic | Decision |
|---|---|
| Target frameworks | `net8.0` and `net10.0` only |
| Test framework | TUnit (Microsoft.Testing.Platform); no xunit/NUnit |
| Coverage | Target 95%+ line and branch; reported by CI, **not a gate**; reviewed locally from time to time |
| Protocol | Pure managed C#, no native dependencies |
| API style | Async-first, `CancellationToken` everywhere, `IAsyncDisposable` |
| License | MIT |
| Repo | github.com/zcsizmadia/SshSharp (private until M5), commit email `zcsizmadia@gmail.com` |

## Engineering principles

**Modern C# (C# 12/14 on net8.0/net10.0)**
- `readonly record struct` for small value types, `required`/`init` members, primary constructors, collection expressions,
  file-scoped namespaces, pattern matching and `switch` expressions, `ref struct` parsers.
- `[GeneratedRegex]`, `SearchValues<T>`, `FrozenDictionary` for the algorithm registry, `TimeProvider`, `Lock` (net9+ type
  on net10; `object` fallback on net8), `ValueTask` on hot paths, `IAsyncEnumerable<T>` for streaming output.
- Nullable reference types on, warnings as errors, analyzers on, AOT/trim-compatible (`IsAotCompatible`): no reflection,
  no runtime codegen.

**Async and zero copy**
- I/O is built on `System.IO.Pipelines` over the socket. Packets are parsed from `ReadOnlySequence<byte>`
  and written through `IBufferWriter<byte>`; no intermediate `byte[]` per packet.
- `Span<byte>`/`Memory<byte>` everywhere in the packet, crypto and channel APIs. `ArrayPool<byte>` or `MemoryPool<byte>`
  for anything that must outlive a call, `stackalloc` for small fixed sizes.
- Decrypt in place and verify MACs/AEAD tags over the same buffer. Channel data is handed to the caller as `ReadOnlyMemory<byte>`
  slices of the pipe buffer (consumed explicitly) with a `Stream` adapter on top for convenience.
- Backpressure comes from the SSH channel window, mapped onto the pipe's pause/resume thresholds.
- Secrets (keys, passwords) live in pooled buffers that are zeroed on release (`CryptographicOperations.ZeroMemory`).
- Allocation budgets are tested: BenchmarkDotNet plus allocation-assert tests on the hot path (encrypt, send, receive).
- No blocking calls and no sync-over-async. Cancellation and timeouts are honored at every await.

## Scope

In: transport, modern algorithms, password/publickey/keyboard-interactive auth, agents, exec/shell/PTY channels,
port forwarding (local, remote, SOCKS5), agent forwarding, SCP, ProxyJump, `known_hosts`, `ssh_config`, config-driven
connect, connect over any `Stream`, typed exceptions, keep-alive, FIPS mode, logging/tracing/metrics.
Later (M6, after the M5 release): SFTP, as the separate `SshSharp.Sftp` package. Out: server-side SSH, `ControlMaster` multiplexing, GSSAPI, X11 forwarding.

## Packages

| Package | Contents |
|---|---|
| `SshSharp` | Transport, crypto, auth, channels, agent, forwarding, `known_hosts`, `ssh_config`, ProxyJump, SCP (`SshSharp.Scp` namespace) |
| `SshSharp.Sftp` | SFTP client (M6); depends on `SshSharp`, exposed as extension methods on `SshClient` |

- SCP is small (a text protocol over one exec channel), so it stays in the core; trimming removes it when unused.
- SFTP is a large, fast-changing API, so it ships separately. It may use only the core's public API (no `InternalsVisibleTo`),
  which keeps the core's channel API honest.
- Lockstep versions for both packages until 1.0. The 95% coverage target applies to each assembly separately (not a CI gate).

## Repository layout

```
SshSharp.sln
Directory.Build.props      # TFMs, nullable, analyzers, warnings-as-errors, deterministic builds
Directory.Packages.props   # central package versions
src/SshSharp/              # core library (transport, auth, channels, config, forwarding, agent, SCP)
src/SshSharp.Sftp/         # SFTP client, separate package (M6), uses only the core's public API
tests/SshSharp.Tests/      # TUnit unit tests (in-memory, no network)
tests/SshSharp.Sftp.Tests/ # TUnit tests for SshSharp.Sftp (M6)
tests/SshSharp.Integration/# TUnit tests against OpenSSH in Docker (Testcontainers)
tests/SshSharp.Fuzz/       # parser/packet fuzz harness (not part of the coverage target)
docs/
```

## Testing and CI

- **TUnit** with `Microsoft.Testing.Extensions.CodeCoverage`; Cobertura output and ReportGenerator for local reports.
- **Coverage target is 95%+ line and branch, but it is not a CI gate.** CI collects and publishes the numbers. We check
  them locally from time to time (`scripts/coverage.ps1`, which writes an HTML report) and fix gaps as part of regular work.
  Only generated code and clearly marked platform glue may be excluded, with `[ExcludeFromCodeCoverage]` plus a justification.
- **Design for testability from day one:**
  - `ITransport` (in-memory duplex pipe) so the whole protocol stack runs without sockets.
  - `TimeProvider` for rekey timers and timeouts; an injectable random source for deterministic test vectors.
  - Filesystem, environment, and `exec` Match calls behind small interfaces.
- **Layer 1, unit tests (no network):** known-answer vectors (RFC/crypto), parser corpus (OpenSSH regress tests), protocol
  tests against a scripted in-memory fake server, property and fuzz tests for the packet decoder and both config parsers.
- **Layer 2, Docker integration tests (Testcontainers, Linux only):** several OpenSSH versions and Dropbear, a multi-hop
  ProxyJump chain, every KEX/cipher/MAC/key type, rekeying with data in flight, SCP, forwarding, host-key change and
  revoked keys, and fault injection (Toxiproxy: drops, delays, half-closed connections). Image digests are pinned.
  Tests skip with a clear message when Docker is unavailable; `docker compose` file for local use.
- **Layer 3, platform matrix (GitHub Actions):** each cell runs on net8.0 and net10.0.

  | Runner | Arch | Runs |
  |---|---|---|
  | `ubuntu-latest` | amd64 | Unit, Docker integration, coverage report |
  | `ubuntu-24.04-arm` | arm64 | Unit, Docker integration |
  | `windows-latest` | amd64 | Unit, named-pipe agent, paths, CRLF, native OpenSSH interop |
  | `windows-11-arm` | arm64 | Unit |
  | `macos-latest` | arm64 | Unit, Unix agent, `sshd` smoke test |

  No macOS Intel runner. Docker tests run on Linux only (Windows and macOS runners cannot run Linux containers).
  arm64 runners are free only for public repos, so while the repo is private they may be limited to nightly or release builds.
- **Workflows:** on PR, Linux amd64 unit and integration tests plus Windows and macOS unit tests; nightly, the full matrix,
  the long fuzz run and the old/new server matrix; on release tag, everything plus `dotnet pack` and package checks.
- **Rules:** no code merges without tests. Timing-dependent tests use the fake clock, not real sleeps; flaky tests are
  tracked, not hidden.

## Milestones

### M0: Scaffold
- Repo init, solution, projects, `Directory.Build.props`, `.editorconfig`, MIT license, README.
- CI (GitHub Actions): build and TUnit tests on net8.0 and net10.0, coverage report (no gate), the platform matrix from "Testing and CI".
- **Done when:** empty solution builds and a sample TUnit test runs in CI with coverage reporting wired up.

### M1: Config parsers
- `KnownHostsFile`: hashed hosts (`|1|salt|hash`), wildcards and negation, `[host]:port`, `@cert-authority`, `@revoked`,
  lookup, add/remove, save with comments and order preserved.
- `SshConfig`: first-match-wins, `Host` and `Match` (`host`, `user`, `exec`, `all`, `canonical`), `Include` with globs,
  token expansion (`%h %p %r %u %d`), `~` and env vars, the main directives (HostName, Port, User, IdentityFile,
  IdentitiesOnly, IdentityAgent, ProxyJump, ProxyCommand, UserKnownHostsFile, StrictHostKeyChecking, algorithm lists with
  `+ - ^`, ServerAliveInterval, ConnectTimeout, AddressFamily). `Resolve(host)` returns a typed effective config.
- More `ssh_config` directives: `CanonicalizeHostname`, `Match exec`, `CertificateFile`, `HostKeyAlias`, `RequestTTY`,
  `SendEnv`/`SetEnv`, `LocalForward`/`RemoteForward`/`DynamicForward`, `ForwardAgent`. `ControlMaster`/`ControlPath`
  are parsed and ignored cleanly (no multiplexing).
- **Done when:** the OpenSSH-corpus tests pass, round-trip tests pass, and a local coverage check shows these namespaces near the 95% target.

### M2: Transport and crypto
- Binary reader/writer, packet framing, version exchange, `Pipe`-based async pump, rekeying (bytes and time).
- Algorithm registry (reorder/disable). KEX: `curve25519-sha256`, `ecdh-sha2-nistp*`, `diffie-hellman-group14/16-sha256`.
  Ciphers: `chacha20-poly1305@openssh.com`, `aes*-gcm@openssh.com`, `aes*-ctr`. MACs: `hmac-sha2-*-etm`.
  Host/user keys: `ssh-ed25519`, `rsa-sha2-256/512`, `ecdsa-sha2-*`.
- BCL primitives where available; managed X25519 and Ed25519 where not, validated with RFC 7748/8032 vectors.
- **Strict KEX** (Terrapin, CVE-2023-48795) on by default; rekeying tested with data in flight.
- **Connect over any `Stream`** (`SshClient.ConnectAsync(Stream, ...)`), so users can tunnel over WebSockets, named pipes
  or their own transport. The socket path is one implementation of this.
- **Typed exceptions** with a reason enum (`KexFailed`, `AuthFailed`, `HostKeyRejected`, `ChannelClosed`, `Timeout`, ...)
  and a channel-closed notification when the remote side closes.
- **FIPS mode:** one option that restricts the algorithm registry to FIPS-approved algorithms.
- **Observability:** `ILogger` (no-op by default), `ActivitySource` for tracing, `Meter` for metrics (bytes, rekeys, channels).
- `none` and `password` auth, `exec` channel. Integration tests against OpenSSH in Docker.
- **Done when:** `RunCommandAsync` works against OpenSSH and the in-memory fake server, and a local coverage check is near the 95% target.

### M3: Config-driven connect and host verification
- `SshClient.ConnectAsync("alias", config, options, ct)`.
- `IHostKeyVerifier` with `StrictHostKeyChecking` policies (`yes`, `accept-new`, `no`, `ask`) and `UpdateHostKeys`.
- OpenSSH certificates (user and host), `@cert-authority` verification.
- ProxyJump chains and `ProxyCommand`. Key loading: OpenSSH new format (encrypted too), PEM/PKCS#8, PuTTY `.ppk`.
- Reliable keep-alive and dead-connection detection: `ServerAliveInterval`/`ServerAliveCountMax` from config,
  responding to server keep-alive requests, `IsConnected` that reflects the real state.
- **Done when:** a connect through a two-hop ProxyJump to a Docker target succeeds using only an `ssh_config` alias.

### M4: Agent, SCP, forwarding, interactive
- ssh-agent: Unix `SSH_AUTH_SOCK`, Windows OpenSSH named pipe, Pageant.
- SCP upload/download (recursive, progress, `CancellationToken`).
- Local/remote port forwarding, `direct-streamlocal`, shell + PTY, keyboard-interactive.
- Dynamic forwarding: a SOCKS5 proxy (`DynamicForward`), with `LocalForward`/`RemoteForward` taken from `ssh_config`.
- Agent forwarding (`ForwardAgent`), in addition to using an agent for auth.

### M5: Hardening and release
- Fuzzing, interop matrix (OpenSSH versions, Dropbear, Windows OpenSSH), timing/side-channel review of the managed crypto.
- Docs, samples, NuGet package metadata, SourceLink, symbols, versioning.
- Make the repo public only after you confirm (publishing is hard to undo).

### M6 (post-release): SFTP (`SshSharp.Sftp` package)
- SFTP v3 plus common OpenSSH extensions (`posix-rename`, `statvfs`, `hardlink`, `fsync`, `copy-data`), on the existing channel layer.
- Async and zero-copy by design: pipelined requests, `Stream` adapters, directory listing as `IAsyncEnumerable`.
- Avoid the SSH.NET problems: thread-safe client, no hangs on dispose, bounded buffers, `.`/`..` filtered from listings,
  recursive delete and `CreateDirectory` on existing paths handled explicitly.
- Same 95% coverage target; Docker interop tests (OpenSSH `internal-sftp`, Dropbear/other servers).

## Risks

- **Managed X25519/Ed25519** is the riskiest code. It needs test vectors, a review, and a README note. Prefer the BCL where
  it provides the primitive on both target frameworks.
- **Reaching 95% coverage on network code** depends on the in-memory transport and fake server. Build those in M2 before writing
  much protocol code, or coverage will lag behind.
- **TUnit** is Microsoft.Testing.Platform based, so `dotnet test` and coverage collection need the right SDK settings
  (a `global.json` test-runner setting on .NET 10). Verify in M0 before building on it.
- **Name overlap:** an unrelated toy repo, `rzikm/SshSharp`, exists. NuGet ID `SshSharp` was free when checked; reserve it early.

## Working rules

- Git email is `zcsizmadia@gmail.com` (GitHub repo). Check `git log --format='%ae %ce'` before every push.
- Nothing is pushed or published without your confirmation.
