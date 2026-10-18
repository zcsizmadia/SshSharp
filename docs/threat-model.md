# Threat model

SshSharp is an SSH **client** library. This page lists who and what it trusts, and what it does about the rest.
It is reviewed before each release; the last review covered everything up to 1.0.0, including SFTP and its adapters,
proxies, remote dynamic and Unix-socket forwarding, destination-constrained agent keys, SSH signatures, sntrup761, Kerberos
(`gssapi-with-mic`), adding keys to the agent and Pageant, revoked host keys (KRLs), `ping@openssh.com`, channel idle timeouts
(`ChannelTimeout`) and segmented SFTP downloads, and the areas added in 1.0.0: keys held elsewhere (`SshKeySigner`), SFTP
`Preserve` with permissions, and the dependency injection package (`SshSharp.Extensions.DependencyInjection`).

## Trusted

- **The application** that uses the library, its options and callbacks (host key verifier, loggers, `Match exec` runner).
- **Signers** (`SshKeySigner`, `SshPrivateKey.FromSigner`, `FromRsa`, `FromECDsa`): application code, or a key service it trusts,
  that signs for a key SshSharp never sees. Each request says what it is for (`SshSignRequest.Purpose`: logging in, or an SSH
  signature with its namespace), so a signer can refuse by policy. What it signs includes the session identifier and the user name,
  which matters to a signer that logs its requests. Every signature it returns is verified against the public key before use.
- **The local machine**: the process, its memory, and files the application chooses to load (private keys, `ssh_config`,
  `known_hosts`). Their *contents* are still parsed defensively; see below.
- **The .NET runtime and OS cryptography** (AES, SHA-2, HMAC, RSA, ECDSA, ECDH, random numbers).
- **The platform's Kerberos** (SSPI on Windows, MIT or Heimdal GSS-API elsewhere) and its KDC, when `gssapi-with-mic` is turned on:
  the library passes tokens through and checks only the SSH framing. The server's tokens are parsed by the GSS-API library, not
  here. Mutual authentication is required, the MIC binds the exchange to the SSH session id, and the host key is still verified
  by the usual verifier, so a Kerberos service ticket never replaces host key checking. Delegating the ticket
  (`DelegateCredentials`) gives the server your Kerberos identity, so it is off by default.

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
- **Post-quantum key exchange:** `mlkem768x25519-sha256` and the FIPS-compatible `mlkem768nistp256-sha256` and
  `mlkem1024nistp384-sha384` use the platform's ML-KEM (on .NET 10 where the OS provides it), and
  `sntrup761x25519-sha512` a managed sntrup761 (everywhere; see the [cryptography review](crypto-review.md)). Both check the
  server's reply length exactly and still reject low-order X25519 points, so neither is weaker than curve25519 alone.
- **Host key rotation (`UpdateHostKeys`):** off by default. A new key is recorded only after the server proves it holds it
  (`hostkeys-prove-00@openssh.com`), and any invalid proof cancels the whole update. Nothing is updated when the connection's
  own key is not in `known_hosts`: a changed key let through by `StrictHostKeyChecking no` proves nothing, and must not get the
  real keys removed as stale. Only exact, plain host lines in the first user file are ever removed.
- **Recording host keys:** the host name is written into `known_hosts` only if it is a literal name. White space, control
  characters, commas, `*`, `?` and `!` are refused, since they would add lines or hosts, or turn the entry into a pattern that
  trusts the key for other hosts.
- **Revoked host keys (`RevokedHostKeys`):** checked before anything else, in every `StrictHostKeyChecking` mode, for the plain key
  and a certificate's authority, serial and key id. A file that cannot be read, or a KRL that is malformed or has a section or
  critical extension this library does not know, refuses every host key, as ssh does, rather than let a revoked key through. The
  KRL parser is bounded (16 MiB files, 1 MiB per serial bitmap) and fuzzed. KRL signatures are not verified: the file is local
  configuration, trusted like `known_hosts`.

### Channels the server opens

- Only these server-opened channels are accepted: `forwarded-tcpip` for a port the client asked to forward,
  `forwarded-streamlocal@openssh.com` for a socket path the client asked to forward (matched exactly), and
  `auth-agent@openssh.com` or `agent-connect` (RFC 9987) when agent forwarding is on. Everything else (X11, unknown types) is
  refused.
- For remote port and Unix-socket forwarding, a connection goes only to the target the client named for that forwarding.
  **Remote dynamic forwarding** (`ForwardRemoteDynamicPortAsync`, `ssh -R port`) is different: the server's side names the
  destination in a SOCKS request, so anyone who can reach the forwarded port on the server can use this machine's network.
  As with `ssh`, every destination is allowed unless the application passes `allowDestination`. The filter sees canonical
  forms: an IP literal in any spelling (`127.1`, `::ffff:127.0.0.1`) as its canonical address, and a host name both as
  given and as each address it resolves to here, and the connection goes only to an address that passed.
- The client does not check the address a `forwarded-tcpip` channel names, only the port. The server picks which forwarding
  to use anyway.
- **Agent forwarding** relays the agent protocol unchanged, as `ssh -A` does: while the connection is up, the server can ask the
  agent to sign with any of its keys. Forward the agent only to servers you trust, and use the agent's own confirmation
  (`ssh-add -c`) for sensitive keys.
- **Transport pings** (`ping@openssh.com`) are answered with a pong, as OpenSSH answers them. Pongs not yet sent are capped
  (256 KiB), so a server that pings but stops reading cannot grow the client's memory; pings past the cap go unanswered.
- Forwarded connections the server opens are capped (`SshClientOptions.MaxForwardedConnections`, 1,000 by default); above
  it, new ones are refused. Within that, a server can still send data up to each channel's window (2 MiB).

### The agent

- **Windows named pipes:** any user can create a pipe under a name nobody holds yet, so another user on the same machine could
  create the OpenSSH agent's pipe while the service is stopped, or Pageant's (its name is derived from the user name and a value
  every process on the machine computes alike). SshSharp therefore uses an agent pipe only when its owner is the current user,
  SYSTEM or the Administrators group, as PuTTY checks Pageant's pipe; otherwise no signing request or key is sent to it.
- **Adding keys** (`AddKeyAsync`, `AddKeysToAgent`): the private key goes to the agent the application named. `AddKeysToAgent`
  adds only identity-file keys the server accepted, never keys the application passed in `PrivateKeys`. The lock passphrase
  (`LockAsync`) is a managed string and cannot be wiped.

### Local listeners (port forwarding and SOCKS)

- `ForwardLocalPortAsync` and `ForwardDynamicPortAsync` bind where the application says. Forwardings from `ssh_config` bind
  to loopback unless the configuration names an address or sets `GatewayPorts`, as with `ssh`.
- The SOCKS proxy has no authentication (like `ssh -D`) and supports only CONNECT (SOCKS 4, 4a and 5). Anyone who can reach
  its address can use the SSH connection, so it should listen on loopback.

### Proxies

- An HTTP or SOCKS proxy (`SshProxy`) sees the destination host and port; the SSH traffic through it is encrypted and the
  host key is verified as usual, so a hostile proxy can refuse or delay the connection but not read or change it.
- Proxy credentials (HTTP Basic, SOCKS 5 user name and password) are sent as the protocols define them, in clear text to the
  proxy; they never appear in exceptions or logs. Replies are bounded (HTTP headers to 16 KiB) and validated, and host names
  that a protocol cannot carry are refused rather than altered.

### SFTP

- Every reply is parsed as hostile (and fuzzed): lengths, counts and request ids are checked, a packet is at most 1 MiB, a
  directory listing is bounded, and names that are not valid UTF-8 are decoded with replacement characters instead of failing.
- Recursive downloads apply the same name checks as SCP (no `.`, `..`, separators, NUL, or Windows device names; `:` and `\`
  only matter on Windows) and keep every path inside the target directory. Uploads skip special files (FIFOs, sockets,
  devices).
- With `Preserve`, a download applies the server's permission bits (read, write and execute for owner, group and others; never
  set-id or sticky) where this machine has Unix modes, without the local umask, as `sftp -p` does: a server can make what it sends
  world-writable. A directory's mode is applied after its contents, and a name listed twice is fetched once.
- `SshSharp.FileProviders` treats backslashes as separators and refuses `..` and NUL in subpaths, so a web request cannot leave
  the configured root by name, and bounds its cache. The server follows symbolic links, including ones that point out of the root.

### SSH signatures and allowed-signers files

- A signature is accepted only for its exact namespace, with SHA-256 or SHA-512, and never with SHA-1 RSA (`ssh-rsa`).
- An allowed-signers file is parsed strictly, as `ssh-keygen` does: an unknown or repeated option rejects the whole file
  rather than silently dropping a restriction. A `cert-authority` line accepts only user certificates it issued, within their
  validity, for a principal the certificate names and the line allows.

### SCP downloads

- Names the server sends must be single path components: not empty, `.` or `..`, and free of separators, drive colons and
  control characters (the CVE-2019-6111 pattern). On Windows, device names (`CON`, `NUL`, `COM1`, ...) and names ending
  in a dot or space are refused too.
- A single-file download refuses a second file or a directory.
- File modes from the server apply only with `Preserve`, and only the permission bits, never set-id or sticky.
- Remote paths are passed to the server's shell quoted as one word.
- Total size, file count and directory depth are not limited: a server can fill the target's disk.

### Secrets in memory and logs

- Passwords, private keys and command text are never logged. User names and host names are not logged either; host key
  fingerprints and algorithm names are.
- Derived keys and key material are wiped (`CryptographicOperations.ZeroMemory`) when no longer needed. Managed strings
  (the `Password` option) cannot be wiped; this is a known limitation. The same holds for `SshGssapiOptions.Credential`: a
  `NetworkCredential` keeps its password as a managed string, so prefer the platform's ticket (`kinit`, or the Windows logon
  session) to an explicit credential.
- The managed X25519, Ed25519, sntrup761 and Poly1305 code avoids branches and table lookups on secret data. DH (group14/16) uses
  `BigInteger.ModPow`, which is not constant-time, on an ephemeral exponent used once; curve25519 and ECDH are preferred.

### Configuration input

`ssh_config` can run local commands (`Match exec`, `ProxyCommand`, `KnownHostsCommand`), as in OpenSSH.

- `Match exec` runs nothing unless the application opts in with an exec runner.
- `ProxyCommand` runs by default, as with `ssh`. Applications that load configurations they do not control can turn it off
  with `SshConfigConnectOptions.AllowProxyCommand = false`.
- The password and keyboard-interactive answers given in `SshConfigConnectOptions` go to the destination only: a `ProxyJump`
  hop, perhaps run by someone else, is never offered them, and logs in with keys or the agent.
- `Include` is bounded: at most 16 levels deep and 1,024 files in all, so a configuration cannot make resolution parse without end.
- `KnownHostsCommand` runs only with `SshConfigConnectOptions.AllowKnownHostsCommand = true`. It is off by default, unlike
  `ProxyCommand`, because its output is trusted as known_hosts lines: a configuration the application does not control must not
  be able to vouch for host keys. With it off, a configuration that names one fails the connection. As in OpenSSH, no shell is
  involved (the command is split into arguments, each expanded on its own, the program taken as written, and the program must be
  an absolute path), so
  token values cannot inject commands; the run is limited to 30 seconds and 1 MiB of output. On Windows a batch file (`.bat`,
  `.cmd`) is refused, because Windows runs it through `cmd.exe`, which would reparse the arguments.
- `Match localnetwork` reads the local interface addresses. As ssh_config(5) warns, a network address is not a trustworthy
  criterion: anyone who controls the network can choose which block applies.
- Host and user names supplied by the caller are substituted into those commands (`%h`, `%n`, `%r`), so they are refused when
  they contain shell metacharacters, control characters or a leading `-` (the CVE-2023-51385 pattern). Host names may not
  contain white space either, which would split `%h` into extra arguments. User names may (Windows account names can).
- The config file itself is trusted to the same degree OpenSSH trusts it: whoever can edit it can run commands as the user.
  Values it sets (`HostName`, `User`) are used as written.

### Dependency injection

- `SshEndpointOptions` can hold a password, a key passphrase, private keys as text (`PrivateKeys`) and a proxy URI with a password,
  bound from configuration: bind them from a secret store, not a checked-in file. They are not logged, validation errors name an
  entry without its value, and `SshEndpointPrivateKey.ToString()` and the debugger do not show them.
- Host keys are checked strictly by default: an unknown host fails unless `AcceptNewHostKeys` is set (which trusts the first key it
  sees), and a changed key always fails.
- `HostKeyFingerprints` replaces known_hosts with pinned fingerprints; whoever can change the configuration decides which servers
  are trusted, as with a known_hosts file. Combining it with `KnownHostsFiles`, `AcceptNewHostKeys` or `ConfigAlias` fails validation
  rather than widening trust to either source.
- With `ConfigAlias`, the connection takes ssh_config's settings and the core defaults (`ProxyCommand` allowed, the agent used,
  `ForwardAgent` and `StrictHostKeyChecking` as the file says); an unknown host is refused, since there is no one to ask.
- The health check's description names no server software and carries no server text, since health endpoints are often reachable
  without authentication. Its exception is attached for logging: do not write it to a public response.

## Out of scope

- A compromised local machine or process (memory dumps, debuggers, malicious code in the same process).
- Denial of service by a server the user chose to connect to, beyond the bounds above (a server can always refuse service).
- Physical side channels (power, EM) and microarchitectural attacks across processes.
