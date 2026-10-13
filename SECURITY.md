# Security policy

SshSharp implements SSH, including managed cryptography (X25519, Ed25519, ChaCha20-Poly1305) that the .NET base library
does not provide. Security reports are welcome and taken seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository
(a private security advisory). Do not open a public issue for a security problem.

Include what you can: the affected version or commit, the algorithm or feature involved, a description of the impact, and
steps or a test case that reproduces it. You will get an acknowledgement within a week, and we will agree on a disclosure
date with you once a fix is ready.

## Supported versions

SshSharp is pre-1.0. Only the latest release (and `main`) receives security fixes.

## Scope

In scope: anything a malicious or compromised **server**, a network attacker, or untrusted **input files** (keys,
`known_hosts`, `ssh_config`) can do to an application using SshSharp, for example memory exhaustion, crashes or hangs,
authentication or host-key verification bypasses, downgrade attacks, key or secret disclosure (including through timing),
and command injection through configuration handling.

See [docs/threat-model.md](docs/threat-model.md) for what is and is not trusted.
