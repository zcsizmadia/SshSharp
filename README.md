# SshSharp

Managed-only, async-first SSH client library for .NET 8 and .NET 10, with OpenSSH `known_hosts` and `ssh_config` support.

Status: in development, not yet released. Milestones M0–M2 are done: transport, modern key exchange and ciphers, strict KEX,
rekeying, password authentication, `RunCommandAsync`, and the `known_hosts`/`ssh_config` parsers. M3 (config-driven connect,
publickey authentication, ProxyJump, certificates) is next. See [PLAN.md](PLAN.md).

The managed cryptography (X25519, Ed25519, ChaCha20-Poly1305) is tested against RFC and OpenSSL vectors but has not had an
outside review yet. See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

## Development

- .NET SDK 10.0.401 or later (see `global.json`); the library targets `net8.0` and `net10.0`.
- Build: `dotnet build -c Release`
- Test (TUnit): `dotnet test --project tests/SshSharp.Tests -c Release`
- Local coverage report: `./scripts/coverage.ps1` (target 95%+, not enforced in CI)
