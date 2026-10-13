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
| No `netstandard2.0` | The design depends on `Span`/`Memory` in the BCL APIs, Pipelines, `AesGcm`, `TimeProvider`, `SearchValues` and modern ECDH/RSA APIs. .NET Framework and Windows PowerShell 5.1 users stay on SSH.NET. |
| Public API is tracked | `PublicAPI.Shipped/Unshipped.txt` (PublicApiAnalyzers); every public change shows in review. Package validation on pack. |
| Sync API | **Async-only for now** (decided after M2). No synchronous methods and no sync-over-async in the core. A migration guide mapping SSH.NET calls to SshSharp ships with the docs (M5). An SSH.NET-shaped `SshSharp.Compat` package with synchronous wrappers may be revisited once the async API is stable. |

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
tests/SshSharp.Tests/      # TUnit tests: in-memory unit tests, Fuzz/ (mutation fuzzing of every parser, always on),
                           #   Integration/ (env-gated tests against a real sshd; CI starts one on the Linux runners)
tests/SshSharp.Sftp.Tests/ # TUnit tests for SshSharp.Sftp (M6)
tests/SshSharp.Fuzz/       # coverage-guided SharpFuzz harness for nightly runs (M3; not part of the coverage target)
tests/SshSharp.Benchmarks/ # BenchmarkDotNet; allocation checks (M2) and the SSH.NET comparison (M5)
docs/
```

## Testing and CI

- **TUnit** with `Microsoft.Testing.Extensions.CodeCoverage`; Cobertura output and ReportGenerator for local reports.
- **Coverage target is 95%+ line and branch, but it is not a CI gate.** CI collects and publishes the numbers. We check
  them locally from time to time (`scripts/coverage.ps1`, which writes an HTML report) and fix gaps as part of regular work.
  Only generated code and clearly marked platform glue may be excluded, with `[ExcludeFromCodeCoverage]` plus a justification.
- **Design for testability from day one:**
  - The protocol stack runs over any `Stream`; tests use in-memory duplex pipes and scripted fake servers
    (`FakeSshServer`, `FakeSessionServer`), so nothing needs sockets.
  - `TimeProvider` for rekey timers and timeouts. Randomness comes straight from `RandomNumberGenerator` (no injectable
    source); deterministic KEX transcripts are tested through known-answer vectors instead.
  - Filesystem, environment, and `exec` Match calls behind small delegates.
- **Layer 1, unit tests (no network):** known-answer vectors (RFC/crypto), parser corpus (OpenSSH regress tests), protocol
  tests against a scripted in-memory fake server, and mutation fuzzing of every parser that reads untrusted input
  (`tests/SshSharp.Tests/Fuzz`, a few seconds per run).
- **Layer 2, real-server interop:** today, an `sshd` started on the Linux CI runners (amd64 and arm64) with a throwaway
  account; the env-gated tests in `Integration/` run against it on net8.0 and net10.0. From M3: a pinned-digest container
  matrix on Linux (OpenSSH 7.4, 8.x and latest, plus Dropbear) as service containers, CI-generated user keys and a host
  certificate for publickey and certificate tests, Windows OpenSSH Server on `windows-latest`, a multi-hop ProxyJump chain,
  every KEX/cipher/MAC/key type, host-key change and revoked keys, and fault injection (drops, delays, half-closed
  connections). A script under `scripts/` starts the same server locally.
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
- **Workflows:** on PR, the unit tests on the whole platform matrix plus Linux interop; nightly (from M3), the long
  coverage-guided fuzz run and the old/new server matrix; on release tag, everything plus `dotnet pack` and package checks.
- **Supply chain:** actions pinned by commit SHA, Dependabot for NuGet and Actions, `packages.lock.json` restored in locked
  mode, NuGet audit failing the build on vulnerable packages, per-job timeouts. CodeQL once the repo is public (code
  scanning on a private personal repo needs GitHub Advanced Security).
- **Rules:** no code merges without tests. Timing-dependent tests use the fake clock or wait on a signal, not real sleeps;
  real-time delays are only allowed for negative checks and bounded polling. Flaky tests are fixed or tracked, not hidden.

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
- Zero-copy check: a small BenchmarkDotNet project (`tests/SshSharp.Benchmarks`) and allocation-assert tests on the hot path
  (encrypt, send, receive), so allocation regressions show up early.
- **Done when:** `RunCommandAsync` works against OpenSSH and the in-memory fake server, and a local coverage check is near the 95% target.
- **Status:** done (#1–#25). A four-part review after M2 (crypto, transport, config/API, plan/CI) led to hardening PRs
  #26–#30: cancellation-safe sends and channel opens, packet-count rekey, Ed25519/RSA key validation, shell-safe config
  inputs and OpenSSH-accurate resolution (checked with `ssh -G`), no user names in logs, supply-chain CI, public API
  tracking, and parser mutation fuzzing.

### M3: Config-driven connect and host verification
- **API groundwork first** (before the public types grow):
  - Host key verification gets a context (host, port, alias, key, certificate) and returns a result rather than a bool;
    ready-made verifiers for `known_hosts` and each `StrictHostKeyChecking` policy (`yes`, `accept-new`, `no`, `ask`),
    `UpdateHostKeys`, and "another key type is already known for this host" reported, to stop downgrades.
  - Exception types: authentication (with the allowed methods), host key, connection; socket errors wrapped.
  - Authentication dispatcher per method (publickey `PK_OK`, keyboard-interactive later), partial success, banner callback;
    global request reply FIFO (keep-alive, `hostkeys-00@openssh.com`, later `tcpip-forward`); `IsConnected` and a
    disconnected event.
- `SshClient.ConnectAsync("alias", config, options, ct)`.
- OpenSSH certificates (user and host), `@cert-authority` verification.
- ProxyJump chains and `ProxyCommand`. Key loading: OpenSSH new format (encrypted too), PEM/PKCS#8, PuTTY `.ppk`.
  Publickey authentication, choosing `rsa-sha2-*` from `server-sig-algs`.
- Reliable keep-alive and dead-connection detection: `ServerAliveInterval`/`ServerAliveCountMax` from config,
  responding to server keep-alive requests, `IsConnected` that reflects the real state.
- **Moved up from M5:**
  - A constant-time review of the managed Ed25519 signing path (it signs with users' long-term keys from M3 on), with a
    dudect-style timing test, before publickey auth ships.
  - Coverage-guided fuzzing (`tests/SshSharp.Fuzz`, SharpFuzz) for the key, PEM, `.ppk` and certificate parsers, nightly.
  - The interop container matrix described under "Testing and CI".
  - Versioning (MinVer or Nerdbank.GitVersioning, 0.x prereleases), `dotnet pack` with package validation in CI, and
    reserving the NuGet ID.
- **Done when:** a connect through a two-hop ProxyJump to a Docker target succeeds using only an `ssh_config` alias.

### M4a: Agent and interactive sessions
- ssh-agent: Unix `SSH_AUTH_SOCK`, Windows OpenSSH named pipe, Pageant.
- Shell + PTY, keyboard-interactive.

### M4b: Forwarding and SCP
- SCP upload/download (recursive, progress, `CancellationToken`).
- Local/remote port forwarding, `direct-streamlocal`.
- Dynamic forwarding: a SOCKS5 proxy (`DynamicForward`), with `LocalForward`/`RemoteForward` taken from `ssh_config`.
- Agent forwarding (`ForwardAgent`), in addition to using an agent for auth.

### M5: Hardening and release
- Outside review of the managed crypto (X25519, Ed25519, Poly1305, ChaCha20) before 1.0; mutation testing (Stryker.NET)
  on `Crypto/`, `PacketCodec` and `Config/`; an AOT-published smoke app in CI to prove trimming/AOT compatibility.
- CodeQL and the threat model reviewed when the repo goes public; `SECURITY.md` is already in place.
- Docs, samples (including an SSH.NET migration guide), NuGet package metadata, SourceLink, symbols. Decide on strong naming.
- **Benchmark against SSH.NET** (BenchmarkDotNet, `tests/SshSharp.Benchmarks`, not part of normal CI), with a short results
  section in the docs:
  - Measure throughput (exec channel, SCP), connect/handshake and small-command latency, allocations and GC counts per MB,
    parallel channels and thread count, and peak memory on a long stream (SSH.NET #1204). SFTP is added after M6.
  - Fair setup: the same OpenSSH container, the same forced cipher/MAC/KEX, the same payloads, a Release build, warmup, and
    both loopback and injected-latency runs. Pin the SSH.NET version, compare against its async methods where they exist, and
    report algorithms it lacks as "not supported".
  - SSH.NET is referenced only by the benchmark project, never by the shipped packages.
  - Expect crypto to dominate raw throughput; the likely differences are allocations, threads and latency. Publish hardware
    and versions with the results, and never trade correctness or security for a benchmark.
- Make the repo public only after you confirm (publishing is hard to undo).

### M6 (post-release): SFTP (`SshSharp.Sftp` package)
- SFTP v3 plus common OpenSSH extensions (`posix-rename`, `statvfs`, `hardlink`, `fsync`, `copy-data`), on the existing channel layer.
- Async and zero-copy by design: pipelined requests, `Stream` adapters, directory listing as `IAsyncEnumerable`.
- Avoid the SSH.NET problems: thread-safe client, no hangs on dispose, bounded buffers, `.`/`..` filtered from listings,
  recursive delete and `CreateDirectory` on existing paths handled explicitly.
- Same 95% coverage target; Docker interop tests (OpenSSH `internal-sftp`, Dropbear/other servers).

## Risks

- **Managed X25519/Ed25519** is the riskiest code. It needs test vectors, a review, and a README note. Prefer the BCL where
  it provides the primitive on both target frameworks. Signing with long-term user keys (M3) raises the stakes: a timing
  leak there leaks the key, so the constant-time review comes before publickey auth ships.
- **`ssh_config` runs commands** (`Match exec`, `ProxyCommand`). Inputs from the caller are validated, `Match exec` is
  opt-in, and the threat model (`docs/threat-model.md`) records what is trusted.
- **Reaching 95% coverage on network code** depends on the in-memory transport and fake server. Build those in M2 before writing
  much protocol code, or coverage will lag behind.
- **TUnit** is Microsoft.Testing.Platform based, so `dotnet test` and coverage collection need the right SDK settings
  (a `global.json` test-runner setting on .NET 10). Verify in M0 before building on it.
- **Name overlap:** an unrelated toy repo, `rzikm/SshSharp`, exists. NuGet ID `SshSharp` was free when checked; reserve it early.

## Working rules

- Git email is `zcsizmadia@gmail.com` (GitHub repo). Check `git log --format='%ae %ce'` before every push.
- Nothing is pushed or published without your confirmation.
