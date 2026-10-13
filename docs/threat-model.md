# Threat model

SshSharp is an SSH **client** library. This page lists who and what it trusts, and what it does about the rest.
It is reviewed at each milestone and before the repository goes public.

## Trusted

- **The application** that uses the library, its options and callbacks (host key verifier, loggers, `Match exec` runner).
- **The local machine**: the process, its memory, and files the application chooses to load (private keys, `ssh_config`,
  `known_hosts`). Their *contents* are still parsed defensively; see below.
- **The .NET runtime and OS cryptography** (AES, SHA-2, HMAC, RSA, ECDSA, ECDH, random numbers).

## Not trusted

### The network and the server

A man in the middle can read, change, drop and inject bytes. The server itself may be malicious or compromised.

- **Host authentication:** the server must prove possession of a host key, and the application's verifier decides whether
  to trust it. There is deliberately no accept-everything default. A re-exchange must prove the same key.
- **Downgrade and prefix attacks:** only modern algorithms are offered (no SHA-1 KEX or MACs, no CBC, no `ssh-rsa`
  SHA-1 signatures, RSA ≥ 2048 bits). Strict KEX (Terrapin, CVE-2023-48795) is negotiated whenever the server supports it.
- **Malformed input:** every parser treats its input as hostile, rejecting it with a protocol error, never with an
  unexpected exception (mutation-fuzzed in every test run). Peer public keys are validated: points on the curve,
  no small-order Ed25519 keys, an RSA exponent ≥ 3.
- **Resource exhaustion:** packets are limited to 256 KiB, channel data to the advertised window and maximum packet size,
  command output to `MaxCommandOutputBytes`, and banners, identification lines and `EXT_INFO` entries are bounded.
  A peer that overruns the window is a protocol error.
- **Keys and nonces:** keys are renewed after 1 GiB (configurable, capped at 64 GiB), 2^31 packets or one hour, so sequence
  numbers (the ChaCha20-Poly1305 nonce) never wrap under one key.

### Secrets in memory and logs

- Passwords, private keys and command text are never logged. User names and host names are not logged either; host key
  fingerprints and algorithm names are.
- Derived keys and key material are wiped (`CryptographicOperations.ZeroMemory`) when no longer needed. Managed strings
  (the `Password` option) cannot be wiped; this is a known limitation.
- The managed X25519, Ed25519 and Poly1305 code avoids branches and table lookups on secret data. DH (group14/16) uses
  `BigInteger.ModPow`, which is not constant-time, on an ephemeral exponent used once; curve25519 and ECDH are preferred.

### Configuration input

`ssh_config` can run local commands (`Match exec`, `ProxyCommand`), as in OpenSSH.

- `Match exec` runs nothing unless the application opts in with an exec runner.
- Host and user names supplied by the caller are refused when they contain shell metacharacters, control characters or a
  leading `-`, because they are substituted into those commands (the CVE-2023-51385 pattern).
- The config file itself is trusted to the same degree OpenSSH trusts it: whoever can edit it can run commands as the user.

## Out of scope

- A compromised local machine or process (memory dumps, debuggers, malicious code in the same process).
- Denial of service by a server the user chose to connect to, beyond the bounds above (a server can always refuse service).
- Physical side channels (power, EM) and microarchitectural attacks across processes.
