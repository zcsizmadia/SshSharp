# Design notes

The decisions behind SshSharp and the rules the code follows. Work items live in the GitHub issues (one per milestone:
M4 #5, M5 #6, M6 #7, plus individual issues).

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

In: transport, modern algorithms, password/publickey/keyboard-interactive authentication, certificates, agents,
exec/shell/PTY sessions, port forwarding (local, remote, SOCKS5), agent forwarding, SCP, ProxyJump and ProxyCommand,
`known_hosts`, `ssh_config`, config-driven connect, connect over any `Stream`, typed exceptions, keep-alive, FIPS mode,
logging/tracing/metrics. After the first release: SFTP as the separate `SshSharp.Sftp` package.

Out: server-side SSH, `ControlMaster` multiplexing, GSSAPI, X11 forwarding.

## Packages

| Package | Contents |
|---|---|
| `SshSharp` | Transport, crypto, auth, channels, agent, forwarding, `known_hosts`, `ssh_config`, ProxyJump, SCP |
| `SshSharp.Sftp` | SFTP client (planned); depends on `SshSharp`, exposed as extension methods on `SshClient` |

- SCP is small (a text protocol over one exec channel), so it stays in the core; trimming removes it when unused.
- SFTP is a large API, so it ships separately and may use only the core's public API (no `InternalsVisibleTo`), which keeps
  the core's channel API honest.
- Lockstep versions until 1.0.

## Repository layout

```
Directory.Build.props      # nullable, analyzers, warnings as errors, deterministic builds, NuGet audit
Directory.Packages.props   # central package versions
src/SshSharp/              # the library
tests/SshSharp.Tests/      # TUnit: in-memory unit tests, Fuzz/ (mutation fuzzing of every parser),
                           #   Integration/ (env-gated tests against real servers)
tests/SshSharp.Fuzz/       # coverage-guided SharpFuzz harness, run nightly
tests/SshSharp.Benchmarks/ # BenchmarkDotNet, the SSH.NET comparison, the Ed25519/X25519 timing test (--timing)
tests/SshSharp.AotSmoke/   # Native AOT smoke test against a real server
samples/                   # an ssh-like sample tool, built with the solution
docs/                      # guides, design notes, the API reference site (DocFX)
```

## Testing

- **Testable by design.** The protocol stack runs over any `Stream`; tests use in-memory duplex pipes and scripted fake
  servers (`FakeSshServer`, `FakeSessionServer`) and a fake agent, so unit tests need no network. Time comes from
  `TimeProvider`; filesystem, environment and `Match exec` sit behind small delegates.
- **Unit tests:** RFC and crypto known-answer vectors, parser corpora from OpenSSH, protocol tests against the fake servers,
  and mutation fuzzing of every parser that reads untrusted input.
- **Coverage-guided fuzzing:** `tests/SshSharp.Fuzz` with SharpFuzz and libFuzzer, nightly (`fuzz.yml`).
- **Mutation testing:** Stryker.NET over `Crypto/`, `PacketCodec` and `Config/`, weekly and on demand (`mutation.yml`),
  in parallel scopes. A surviving mutant is a change no test notices. The score is reported, not a gate.
- **Real-server interop** (`Integration/`, enabled by `SSHSHARP_TEST_*` environment variables): CI starts sshd on the Linux
  runners with throwaway keys of every type and format, a CA for host and user certificates, `ssh-agent`, and PAM for
  keyboard-interactive; a container matrix of older and newer OpenSSH releases and Dropbear; and OpenSSH for Windows on a
  Windows runner (Git Bash as its shell; signals, the exit status through ConPTY and keep-alives are not tested there).
- **Platform matrix:** Linux (amd64, arm64), Windows (amd64, arm64) and macOS (arm64), each on net8.0 and net10.0.
- **Rules:** no code merges without tests. Timing-dependent tests use the fake clock or wait on a signal, not real sleeps.
  Flaky tests are fixed or tracked, not hidden.

## CI and releases

- `ci.yml`: on every PR and push to main, the unit tests on the platform matrix, interop on Linux, and `dotnet pack`.
- `fuzz.yml`: nightly coverage-guided fuzzing; a short run on PRs that touch the fuzzing setup.
- `mutation.yml`: weekly and on-demand Stryker.NET mutation testing; HTML and JSON reports as artifacts.
- `publish.yml`: on a `v*` tag on main (`v0.1.0`, `v1.0.0-preview.1`, ...), tests, packs and pushes to nuget.org with
  trusted publishing (GitHub OIDC exchanged for a short-lived key; no API key is stored).
- `docs.yml`: builds the API reference site.
- Supply chain: actions pinned by commit SHA, Dependabot for NuGet and Actions, central package versions, NuGet audit
  failing the build on vulnerable packages, per-job timeouts.

## Risks

- **Managed X25519/Ed25519** is the riskiest code: it signs with users' long-term keys. It is checked against RFC vectors,
  reviewed for constant time with a dudect-style timing test (`docs/crypto-review.md`), and awaits an outside review
  before 1.0. The BCL is used wherever it provides the primitive on both target frameworks.
- **`ssh_config` runs commands** (`Match exec`, `ProxyCommand`). Caller inputs are validated, `Match exec` is opt-in, and
  the threat model (`docs/threat-model.md`) records what is trusted.
- **Name overlap:** an unrelated toy repository, `rzikm/SshSharp`, exists; the NuGet ID is reserved by the first publish.

## Working rules

- Commits on this repository use `zcsizmadia@gmail.com`; check `git log --format='%ae %ce'` before pushing.
- Nothing is published (packages, a public repository) without the owner's confirmation.
