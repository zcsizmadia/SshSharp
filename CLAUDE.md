# SshSharp

A managed, async-first SSH client library for .NET. Packages:
- **SshSharp**, plus the adapters **SshSharp.Extensions.DependencyInjection**, **SshSharp.FileProviders** and
  **SshSharp.IO.Abstractions**.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the library.

## Documentation ships with the feature

Every new feature, option, API or ssh_config directive ships with its documentation in the same pull request:
- how-to pages;
- the affected guides, reference, concept and scenario pages;
- Mermaid diagrams where they help;
- XML doc comments.

Examples go in `docs/snippets/` (compiled in CI) and are included by region. A feature without docs is not done. Don't open a
follow-up for its docs.

Run the Docs workflow's steps locally (CONTRIBUTING.md, "Checking the site locally"). The build must have zero warnings.

## Compatibility and the public API

- **1.x is additive.** Never change or remove anything in `PublicAPI.Shipped.txt`. New public members go in
  `PublicAPI.Unshipped.txt`. Package validation compares each package with the last release.
- **Target frameworks:** `net8.0` and `net10.0`.
  - `net8.0` stays well past its November 2026 end of support. Don't propose dropping it.
  - `net11.0` is added only after .NET 11 is GA (draft #267). Don't merge it before then.
  - Code that needs a newer runtime goes behind `#if NET10_0_OR_GREATER` (or later) with a working fallback.
- **Native AOT:** the library is AOT-compatible (`IsAotCompatible`). No reflection-based serialization, no dynamic code. The AOT
  smoke test (`tests/SshSharp.AotSmoke`) must keep publishing cleanly.

## Code

- Warnings are errors (`TreatWarningsAsErrors`, `latest-recommended` analyzers, code style enforced in the build). Fix the cause; a
  suppression needs a justification in the code.
- Nullable reference types are on everywhere.
- **Async all the way:**
  - every I/O method takes a `CancellationToken`;
  - library code awaits with `ConfigureAwait(false)`;
  - no sync-over-async (`.Result`, `.Wait()`) on anything that may not have completed.
- Match the surrounding code: its comment density, naming and idioms. Comments explain why, in plain sentences.
- **Privacy:** the library never logs or records host names, user names, passwords, passphrases or key material. Telemetry
  carries no host names, by design (see `docs/diagnostics.md` and `docs/threat-model.md`).

## Cryptography and security

- **Use the platform (BCL) for every primitive it provides on the target.** Managed implementations exist only where it doesn't:
  X25519, Ed25519, sntrup761, ChaCha20, Poly1305, bcrypt_pbkdf, BLAKE2b, Argon2.
- **Managed crypto must stay constant time:** no branches or table lookups on secret data.
- Any change to the managed crypto needs:
  - the reference vectors (RFC, OpenSSL, Wycheproof);
  - the mutation scope still killing every mutant;
  - `docs/crypto-review.md` updated.
- New algorithms are modern only. SHA-1, CBC and other legacy algorithms stay out by design.
- **Anything that changes trust updates `docs/threat-model.md`:** what is trusted, what runs locally (ProxyCommand,
  KnownHostsCommand, `Match exec`), or what is sent to which server. Credentials go only to the destination, never to a
  ProxyJump hop.
- Security reports follow `SECURITY.md`, not public issues.

## Tests

- TUnit on Microsoft.Testing.Platform. Run the test assembly directly, for example
  `dotnet tests/SshSharp.Tests/bin/Debug/net10.0/SshSharp.Tests.dll --treenode-filter "/*/*/X25519Tests/*"`.
- **New behavior needs tests:** unit tests against the fake servers in `tests/SshSharp.Tests`, and interop tests (`Integration/`)
  when the behavior depends on a real server. CI runs the interop tests against OpenSSH, Dropbear, AsyncSSH, Apache MINA, Erlang
  and the Windows OpenSSH port.
- **Flaky tests are root-caused, never retried until they pass.** A failure under the stress workflow is a bug in the library or
  the test until shown otherwise.
- Mutation testing (`.github/workflows/mutation.yml`) runs per scope of source files. When adding crypto, parser or config code,
  add it to a scope.

## Repository hygiene

- **No personal data or internal infrastructure** in files, commits, PRs or issues: no real email addresses, user names,
  internal hostnames or real IP addresses. Examples use `example.com`, documentation ranges (`192.0.2.0/24`, `2001:db8::/32`) and
  generic users.
- Never write a plaintext password anywhere, including tests (generate it, as CI does) and examples (read it from configuration
  or the environment).
- GitHub Actions are pinned by commit SHA, with the version in a comment.
- Releases are cut by pushing a `v*` tag (MinVer computes versions from tags). Only the maintainer decides to tag or release.
