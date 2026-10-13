# SshSharp

Managed-only, async-first SSH client library for .NET 8 and .NET 10, with OpenSSH `known_hosts` and `ssh_config` support.

Status: planning. See [PLAN.md](PLAN.md).

## Development

- .NET SDK 10.0.401 or later (see `global.json`); the library targets `net8.0` and `net10.0`.
- Build: `dotnet build -c Release`
- Test (TUnit): `dotnet test --project tests/SshSharp.Tests -c Release`
- Local coverage report: `./scripts/coverage.ps1` (target 95%+, not enforced in CI)
