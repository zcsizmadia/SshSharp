# Threat model

SshSharp is an SSH **client** library. This page lists who and what it trusts, and what it does about the rest.
It is reviewed at each milestone; the last review covered everything up to M5 (forwarding, agent forwarding, SCP, host key
rotation and the post-quantum key exchange).

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
- **Post-quantum key exchange:** `mlkem768x25519-sha256` uses the platform's ML-KEM (on .NET 10 where the OS provides it), checks
  the server's reply length exactly and still rejects low-order X25519 points, so it is never weaker than curve25519 alone.
- **Host key rotation (`UpdateHostKeys`):** off by default. A new key is recorded only after the server proves it holds it
  (`hostkeys-prove-00@openssh.com`), and any invalid proof cancels the whole update. Nothing is updated when the connection's
  own key is not in `known_hosts`: a changed key let through by `StrictHostKeyChecking no` proves nothing, and must not get the
  real keys removed as stale. Only exact, plain host lines in the first user file are ever removed.
- **Recording host keys:** the host name is written into `known_hosts` only if it is a literal name. White space, control
  characters, commas, `*`, `?` and `!` are refused, since they would add lines or hosts, or turn the entry into a pattern that
  trusts the key for other hosts.

### Channels the server opens

- Only three kinds of server-opened channel are accepted: `forwarded-tcpip` for a port the client asked to forward,
  `forwarded-streamlocal@openssh.com` for a socket path the client asked to forward (matched exactly), and
  `auth-agent@openssh.com` when agent forwarding is on. Everything else (X11, unknown types) is refused. Either way, the
  connection goes only to the target the client named for that forwarding, never to one the server picks.
- The client does not check the address a `forwarded-tcpip` channel names, only the port. The server picks which forwarding
  to use anyway.
- **Agent forwarding** relays the agent protocol unchanged, as `ssh -A` does: while the connection is up, the server can ask the
  agent to sign with any of its keys. Forward the agent only to servers you trust, and use the agent's own confirmation
  (`ssh-add -c`) for sensitive keys.
- A malicious server can open many forwarded connections or send unlimited data within the channel windows (2 MiB per channel).
  There is no cap on the number of channels; that is denial of service by a server the user chose (see out of scope).

### Local listeners (port forwarding and SOCKS)

- `ForwardLocalPortAsync` and `ForwardDynamicPortAsync` bind where the application says. Forwardings from `ssh_config` bind
  to loopback unless the configuration names an address or sets `GatewayPorts`, as with `ssh`.
- The SOCKS proxy has no authentication (like `ssh -D`) and supports only CONNECT (SOCKS 4, 4a and 5). Anyone who can reach
  its address can use the SSH connection, so it should listen on loopback.

### SCP downloads

- Names the server sends must be single path components: not empty, `.` or `..`, and free of separators, drive colons and
  control characters (the CVE-2019-6111 pattern). On Windows, device names (`CON`, `NUL`, `COM1`, ...) and names ending
  in a dot or space are refused too.
- A single-file download refuses a second file or a directory.
- File modes from the server apply only with `PreserveTimes`, and only the permission bits, never set-id or sticky.
- Remote paths are passed to the server's shell quoted as one word.
- Total size, file count and directory depth are not limited: a server can fill the target's disk.

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
- `ProxyCommand` runs by default, as with `ssh`. Applications that load configurations they do not control can turn it off
  with `SshConfigConnectOptions.AllowProxyCommand = false`.
- Host and user names supplied by the caller are substituted into those commands (`%h`, `%n`, `%r`), so they are refused when
  they contain shell metacharacters, control characters or a leading `-` (the CVE-2023-51385 pattern). Host names may not
  contain white space either, which would split `%h` into extra arguments. User names may (Windows account names can).
- The config file itself is trusted to the same degree OpenSSH trusts it: whoever can edit it can run commands as the user.
  Values it sets (`HostName`, `User`) are used as written.

## Out of scope

- A compromised local machine or process (memory dumps, debuggers, malicious code in the same process).
- Denial of service by a server the user chose to connect to, beyond the bounds above (a server can always refuse service).
- Physical side channels (power, EM) and microarchitectural attacks across processes.
