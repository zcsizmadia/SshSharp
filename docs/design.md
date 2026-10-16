# Design notes

The decisions behind SshSharp and the rules the code follows. Work items live in the GitHub issues.

## Decisions

| Topic | Decision |
|---|---|
| Target frameworks | `net8.0` and `net10.0` only |
| No `netstandard2.0` | The design depends on `Span`/`Memory` in the BCL APIs, Pipelines, `AesGcm`, `TimeProvider`, `SearchValues` and modern ECDH/RSA APIs. .NET Framework and Windows PowerShell 5.1 users stay on SSH.NET. |
| Protocol | Pure managed C#, no native dependencies |
| API style | Async-only for now: `CancellationToken` everywhere, `IAsyncDisposable`, no synchronous network methods and no sync-over-async (parsing local files such as `ssh_config` and `known_hosts` has synchronous helpers too). An SSH.NET-shaped `SshSharp.Compat` package with synchronous wrappers may be revisited once the async API is stable. |
| Public API | Tracked in `PublicAPI.Shipped/Unshipped.txt` (PublicApiAnalyzers), so every public change shows in review; package validation on pack |
| Test framework | TUnit (Microsoft.Testing.Platform) |
| Coverage | Target 95%+ line and branch per assembly; reported, **not a CI gate**; reviewed locally with `scripts/coverage.ps1` |
| Versioning | MinVer: the version comes from `v*` git tags; untagged commits are `0.x` prereleases |
| Strong naming | Not strong-named. .NET (Core) does not validate strong names, and the .NET Framework consumers who need them cannot use SshSharp. Because modern .NET does not check the public key token either, a strong name could still be added later without breaking consumers. |
| License | MIT |

## Engineering principles

**Modern C#.** `readonly record struct` for small values, `required`/`init`, primary constructors, collection expressions,
pattern matching, `ref struct` parsers, `[GeneratedRegex]`, `SearchValues<T>`, `FrozenDictionary`, `TimeProvider`. Nullable
reference types on, warnings as errors, analyzers on, AOT- and trim-compatible (`IsAotCompatible`): no reflection, no runtime
code generation.

**Async and zero copy.**
- I/O is built on `System.IO.Pipelines`. Packets are parsed from `ReadOnlySequence<byte>` and written through
  `IBufferWriter<byte>`; no intermediate `byte[]` per packet.
- Decrypt in place and verify MACs/AEAD tags over the same buffer. Channel data reaches the caller as slices of the pooled
  packet buffer, released when read, with `Stream` adapters on top.
- Backpressure comes from the SSH channel window.
- Secrets (keys, passwords) are zeroed after use (`CryptographicOperations.ZeroMemory`).
- Allocation budgets are tested: allocation-assert tests on the hot path (encrypt, send, receive) and BenchmarkDotNet.
- No blocking calls. Cancellation and timeouts are honored at every await.

## Scope

In: transport, modern algorithms, password/publickey/keyboard-interactive authentication, Kerberos (`gssapi-with-mic`, .NET 10
only), `ext-info-in-auth@openssh.com`, certificates, agents (OpenSSH's agent and PuTTY's Pageant), agent key management
(`AddKeyAsync`, `RemoveKeyAsync`, `RemoveAllKeysAsync`, `LockAsync`, `AddKeysToAgent`), exec/shell/PTY sessions, BREAK
(`SendBreakAsync`, RFC 4335) and `expect`-style scripting, port forwarding (local, remote, dynamic SOCKS 4/4a/5, remote dynamic,
remote Unix socket), agent forwarding and destination-constrained agent keys (`restrict-destination-v00@openssh.com`), SCP, SFTP
(experimental API) with segmented downloads, ProxyJump, ProxyCommand and HTTP/SOCKS proxies, `known_hosts`, `KnownHostsCommand`,
revoked host keys (`RevokedHostKeys`: OpenSSH KRLs and key lists), host key scanning, `ssh_config` (including `Match localnetwork`,
`sessiontype` and `command`, and `RefuseConnection`), config-driven connect, connect over any `Stream`, key generation, SSH
signatures (SSHSIG), typed exceptions, keep-alive, `ping@openssh.com` (`PingAsync`), client-side channel idle timeouts
(`ChannelTimeout`), FIPS mode, logging/tracing/metrics following OpenTelemetry's semantic conventions; adapters that expose SFTP as
`IFileSystem` and `IFileProvider`.

Out: server-side SSH, `ControlMaster` multiplexing, GSSAPI key exchange (`gssapi-keyex`), X11 forwarding.

## Packages

| Package | Contents |
|---|---|
| `SshSharp` | Transport, crypto, auth, channels, agent, forwarding, proxies, `known_hosts`, `ssh_config`, ProxyJump, SCP, SFTP (`SshSharp.Sftp` namespace), keys and signatures |
| `SshSharp.FileProviders` | `SftpFileProvider`: a remote directory as a `Microsoft.Extensions.FileProviders.IFileProvider` |
| `SshSharp.IO.Abstractions` | `SftpFileSystem`: SFTP as a System.IO.Abstractions `IFileSystem` |

- SCP is small (a text protocol over one exec channel), so it stays in the core; trimming removes it when unused.
- SFTP lives in the core too (namespace `SshSharp.Sftp`, opened with `client.OpenSftpAsync()`), so it can share the channel
  internals; its API is marked `[Experimental("SSHSHARP001")]` until it settles. The adapters are separate packages because they
  bring their own dependencies, and they use only the core's public API.
- Lockstep versions until 1.0.

## Repository layout

```
Directory.Build.props      # nullable, analyzers, warnings as errors, deterministic builds, NuGet audit
Directory.Packages.props   # central package versions
src/SshSharp/              # the library
src/SshSharp.FileProviders/   # IFileProvider over SFTP
src/SshSharp.IO.Abstractions/ # IFileSystem over SFTP
tests/SshSharp.Tests/      # TUnit: in-memory unit tests, Fuzz/ (mutation fuzzing of every parser),
                           #   Integration/ (env-gated tests against real servers)
tests/docker/              # the OpenSSH and Dropbear containers of the interop matrix
tests/sftp-servers/        # other SFTP servers for interop (a Go pkg/sftp server)
tests/SshSharp.Fuzz/       # coverage-guided SharpFuzz harness, run nightly
tests/SshSharp.Benchmarks/ # BenchmarkDotNet, the SSH.NET comparison, the constant-time check (--timing)
tests/SshSharp.AotSmoke/   # Native AOT smoke test against a real server
samples/                   # an ssh-like sample tool, built with the solution
docs/                      # guides, design notes, the API reference site (DocFX)
```

## Testing

- **Testable by design.** The protocol stack runs over any `Stream`; tests use in-memory duplex pipes, scripted fake servers
  (`FakeSshServer`, `FakeSessionServer`, `FakeSftpServer`) and a fake agent, so unit tests need no network. Time comes from
  `TimeProvider`; filesystem, environment and `Match exec` sit behind small delegates.
- **Validation in depth:** reference and Wycheproof vectors, real-server interop (OpenSSH old and new on Linux and Windows,
  Dropbear, AsyncSSH, Apache MINA SSHD, SFTP-only servers), network fault injection, coverage-guided fuzzing, mutation testing, and stress runs
  with an instrumented build. [Testing and validation](testing.md) describes each, what it found, and what is not covered yet.
- **Rules:** no code merges without tests. Timing-dependent tests use the fake clock or wait on a signal, not real sleeps.
  Flaky tests are fixed or tracked, not hidden.

## CI and releases

- `ci.yml`: on every PR and push to main, the unit tests on the platform matrix, interop on Linux, and `dotnet pack`.
- `fuzz.yml`: nightly coverage-guided fuzzing; a short run on PRs that touch the fuzzing setup.
- `mutation.yml`: Stryker.NET mutation testing, incremental weekly and full on demand; HTML and JSON reports as artifacts.
- `stress.yml`: on demand, the tests in a loop with the instrumented build, to catch intermittent failures (see Testing).
- `publish.yml`: on a `v*` tag on main (`v0.3.0`, `v1.0.0-preview.1`, ...), tests, packs and pushes to nuget.org with
  trusted publishing (GitHub OIDC exchanged for a short-lived key; no API key is stored).
- `docs.yml`: builds the documentation site (guides and API reference) on every change; release tags publish it to GitHub Pages
  (https://zcsizmadia.github.io/SshSharp/), so it matches the package on nuget.org.
- Supply chain: actions pinned by commit SHA, Dependabot for NuGet and Actions, central package versions, NuGet audit
  failing the build on vulnerable packages, per-job timeouts.

## Risks

- **Managed X25519/Ed25519** is the riskiest code: it signs with users' long-term keys. The managed sntrup761 handles the
  post-quantum half of a key exchange. Both are checked against official vectors, reviewed for constant time with a
  dudect-style timing test (`docs/crypto-review.md`), and await an outside review before 1.0. The BCL is used wherever it
  provides the primitive on both target frameworks.
- **`ssh_config` runs commands** (`Match exec`, `ProxyCommand`). Caller inputs are validated, `Match exec` is opt-in, and
  the threat model (`docs/threat-model.md`) records what is trusted.
- **Name overlap:** an unrelated toy repository, `rzikm/SshSharp`, exists; the NuGet ID `SshSharp` belongs to this project.
