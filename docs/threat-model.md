# Threat model

SshSharp is an SSH **client** library. This page lists who and what it trusts, and what it does about the rest.
It is reviewed before each release; the last review covered everything up to 1.1.0. Up to 1.0.0 that included SFTP and its
adapters, proxies, remote dynamic and Unix-socket forwarding, destination-constrained agent keys, SSH signatures, sntrup761,
Kerberos (`gssapi-with-mic`), adding keys to the agent and Pageant, revoked host keys (KRLs), `ping@openssh.com`, channel idle
timeouts (`ChannelTimeout`), segmented SFTP downloads, keys held elsewhere (`SshKeySigner`), SFTP `Preserve` with permissions,
and the dependency injection package (`SshSharp.Extensions.DependencyInjection`). The 1.1.0 review added: Diffie-Hellman group
exchange, the in-process agent (`SshAgent.FromKeys`) and the forwarded agent's filter, jump hosts (`JumpHosts`, and their
credentials), custom proxies, SOCKS 5 authentication on the local SOCKS proxy, issuing certificates (`SshCertificateBuilder`),
the public KRL reader (`SshKeyRevocationList`), the built-in DNS canonicalizer, segmented SFTP uploads, recursive SFTP listings
and deletes, and local Unix-socket forwarding. Compression is not part of it; it is reviewed with its own change.

## Trusted

- **The application** that uses the library, its options and callbacks (host key verifier, loggers, `Match exec` runner, a custom
  proxy's connector, `ConfigureSocket`, which gets the TCP socket before it connects, and `ConfirmAddKeyToAgent`).
- **Signers** (`SshKeySigner`, `SshPrivateKey.FromSigner`, `FromRsa`, `FromECDsa`): application code, or a key service it trusts,
  that signs for a key SshSharp never sees. Each request says what it is for (`SshSignRequest.Purpose`: logging in, an SSH
  signature with its namespace, a certificate the key issues as a CA, or `Other`: data of another form that a program on a server asked a forwarded in-process agent to sign), so a signer can refuse by policy. What it signs includes the session identifier and the user name,
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
- **Public-key signatures for keys the server refuses:** a key held in the process signs its first `publickey` request, without
  asking first whether the server accepts it ([why](authentication.md#signing-straight-away-or-asking-first)), so a server that
  refuses the key still receives a signature from it. That gives the server nothing it could not have had otherwise: the public
  key is in the request either way, a malicious server could answer "accepted" to a query and get the same signature, and the
  signed data starts with this session's identifier (and, host-bound, names this server's host key), so the signature logs in
  nowhere else. Keys held by an agent or a signer, whose signature may need the user's confirmation, a touch or a remote call, are
  still offered first and sign only for a server that accepts them.
- **Passwords and password changes:** passwords go only to the server whose host key was verified, inside the encrypted
  transport. A server that answers with a password change request (RFC 4252 section 8) receives the old password again and the new
  one the application's `ChangePassword` returns; without that handler nothing more is sent. A server cannot make the client loop:
  it gets at most 3 new passwords per password, `PasswordProvider` is asked at most `NumberOfPasswordPrompts` times per connection,
  and keyboard-interactive rounds and walks of the method order stay bounded as before. What the server says in a change request
  (`SshPasswordChangeRequest.Prompt`) is its own text, for the application to clean before showing.
- **Downgrade and prefix attacks:** only modern algorithms are offered (no SHA-1 KEX or MACs, no CBC, no `ssh-rsa`
  SHA-1 signatures, RSA ≥ 2048 bits). Strict KEX (Terrapin, CVE-2023-48795) is negotiated whenever the server supports it.
  The application can narrow or reorder the algorithm lists (`SshClientOptions.KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`,
  `Macs`, or the `ssh_config` directives), but only among the algorithms SshSharp implements, so no list brings a legacy one back,
  and `FipsMode` still applies on top. The one setting that lowers the bar is the smallest RSA host key
  (`SshClientOptions.RequiredRsaSize`, `RequiredRSASize` in `ssh_config`): an application may accept down to 1024 bits for an old
  device, as `ssh` allows, and never less.
- **Malformed input:** every parser treats its input as hostile, rejecting it with a protocol error, never with an
  unexpected exception (mutation-fuzzed in every test run). Peer public keys are validated: points on the curve,
  no small-order Ed25519 keys, an RSA exponent ≥ 3, and an RSA modulus of at most 16384 bits (OpenSSH's limit), so a server or a
  file cannot make each verification cost what a 64000-bit key would. Public keys the application reads itself (`SshPublicKey.Parse` and
  `FromBlob`: `.pub` and `authorized_keys` lines, key blobs) get the same checks, are bounded to 8 KiB, and are refused with
  `FormatException`; a line with `authorized_keys` options is refused rather than read without its restrictions.
- **What the client says before encryption:** the identification line (`SSH-2.0-SshSharp_x.y.z`) is sent in the clear, as every
  SSH client's is, so anyone on the path learns the library and its version. `SshClientOptions.VersionAddendum` adds the
  application's own comment to it, equally in the clear and kept in server logs; nothing else is added, and the documentation
  warns against putting secrets or personal data there.
- **Resource exhaustion:** packets are limited to 256 KiB, channel data to the advertised window (`ChannelWindowSize`, 2 MiB by
  default and at most 1 GiB, which is also the most unread data one channel can buffer) and maximum packet size,
  command output to `MaxCommandOutputBytes`, and banners, identification lines and `EXT_INFO` entries are bounded.
  A peer that overruns the window is a protocol error. With compression on, a packet must also inflate to less than 256 KiB
  ([Compression](#compression)).
- **Keys and nonces:** keys are renewed after 1 GiB (configurable, capped at 64 GiB), 2^31 packets or one hour, so sequence
  numbers (the ChaCha20-Poly1305 nonce) never wrap under one key.
- **Post-quantum key exchange:** `mlkem768x25519-sha256` and the FIPS-compatible `mlkem768nistp256-sha256` and
  `mlkem1024nistp384-sha384` use the platform's ML-KEM (on .NET 10 where the OS provides it), and
  `sntrup761x25519-sha512` a managed sntrup761 (everywhere; see the [cryptography review](crypto-review.md)). Both check the
  server's reply length exactly and still reject low-order X25519 points, so neither is weaker than curve25519 alone.
- **Server-chosen Diffie-Hellman groups (`diffie-hellman-group-exchange-sha256`):** the server picks the prime and generator.
  They are covered by the exchange hash the server signs, so a man in the middle cannot substitute a weak group; only the server
  can, and a malicious server holds the session keys anyway. The checks guard against a server with a broken or weak group,
  which would expose the session to an eavesdropper: the prime must have 2048 to 8192 bits (OpenSSH's client checks only this),
  be 3 mod 4, have no odd factor below 4096 in p or (p-1)/2, and pass one Miller-Rabin round with a random base; the generator
  must lie in [2, p-2], and the server's public value in (1, p-1). That (p-1)/2 is prime is not proven: it would cost another
  full-size exponentiation (about 0.65 s at 8192 bits) on every connection. A failed check fails the connection with
  `KeyExchangeFailed` before the client's public value is sent.
- **Host key rotation (`UpdateHostKeys`):** off by default. A new key is recorded only after the server proves it holds it
  (`hostkeys-prove-00@openssh.com`), and any invalid proof cancels the whole update. Nothing is updated when the connection's
  own key is not in `known_hosts`: a changed key let through by `StrictHostKeyChecking no` proves nothing, and must not get the
  real keys removed as stale. Only exact, plain host lines in the first user file are ever removed.
- **Recording host keys:** the host name is written into `known_hosts` only if it is a literal name. White space, control
  characters, commas, `*`, `?` and `!` are refused, since they would add lines or hosts, or turn the entry into a pattern that
  trusts the key for other hosts, and so is a leading `@` or `#`. Every line the library writes for the application
  (`KnownHostsEntry`, `KnownHostsFile.Add`, `AppendAsync`) is checked the same way: host patterns and the key type must be single
  fields, the host patterns must not start with `@` (the line would be read as a marker line: `@cert-authority * <key> <comment>`
  would trust the key in the comment as an authority for every host) or `#` (a comment), and the comment must not contain CR, LF or
  other control characters (a tab is allowed), so a value from the application, such as a comment taken from user input, cannot add
  a line (an `@cert-authority` line, say) to the file or turn the line into one.
- **Revoked host keys (`RevokedHostKeys`):** checked before anything else, in every `StrictHostKeyChecking` mode, for the plain key
  and a certificate's authority, serial and key id. A file that cannot be read, or a KRL that is malformed or has a section or
  critical extension this library does not know, refuses every host key, as ssh does, rather than let a revoked key through. In a
  text key list, a malformed certificate line of a type SshSharp accepts (Ed25519, ECDSA, RSA, FIDO) does the same; a certificate
  line of a type it never accepts (DSA, or one it does not know) is skipped, as OpenSSH skips it, since no key it could name is ever
  accepted. The KRL parser is bounded (16 MiB files, 1 MiB per serial bitmap) and fuzzed. KRL signatures are not verified: the file
  is local configuration, trusted like `known_hosts`. Refusals name the directive (`RevokedHostKeys`), not the file's path.

### Compression

Off by default, as in `ssh`. `SshClientOptions.Compression` (`Compression yes` in `ssh_config`) offers `zlib@openssh.com`, and the
server decides whether it is used. It changes two things.

**What packet lengths say.** Encryption hides content but not length, and compressed data is as long as it is compressible. When
secrets and data an attacker can choose share a compression context, the attacker can guess a secret piece by piece and watch the
length of the packets: a guess that matches compresses better (CRIME and BREACH against TLS and HTTP, and "Crossing the Streams"
against SSH, where every channel of a connection shares one zlib stream per direction). This is the main reason compression is off
by default.

- **What SshSharp sends** is compressed with Huffman coding only, as OpenSSH has done since September 2026: no LZ77, so nothing
  refers back to earlier data, and a packet's length depends on its own bytes alone, not on whether they repeat a secret sent
  before. Huffman coding still lets the length reflect how varied a packet's own bytes are. On .NET 8, where the strategy cannot be
  chosen, SshSharp does not compress what it sends at all.
- **What the server sends** is compressed however the server chooses. OpenSSH before that change, and other servers, use LZ77, so
  a secret the server sends (a file's content, a command's output) and attacker-influenced data in another channel of the same
  connection can leak through the lengths of the server's packets.
- So keep compression off for a connection that carries both secrets and data from a party that also watches the network, for
  example a tunnel that forwards a browser's traffic next to a session that reads credentials. It is fine for what it is meant
  for: command output, logs and files over a slow link, with no untrusted party feeding the same connection.

**What the decompressor sees.** Only delayed compression is supported: nothing is compressed or inflated before the server has
accepted the user's authentication, and every packet is decrypted and its MAC or tag checked before it is inflated. So the zlib
decoder only ever reads data from the server whose host key was verified, after login. Plain `zlib`, which starts with the first
packet and exposes the decoder to an unauthenticated peer, is not implemented, by design (OpenSSH removed it from its client in
2024). The decoder is .NET's (`System.IO.Compression`, zlib), and its output is bounded: a packet that inflates to 256 KiB or more
(a decompression bomb) or is not valid zlib data fails the connection with a protocol error, before any of it reaches a channel.

Compression is not a cryptographic algorithm, so `FipsMode` allows it.

**What stays in memory.** With compression on, plaintext is left behind in buffers SshSharp cannot wipe, unlike its own packet
buffers (which are zeroed before they go back to the pool, a packet that fails to inflate included):

- zlib's native state: its window of recent data (up to 32 KiB per direction) is freed, not wiped, when the stream ends.
- .NET's `ZLibStream` (a `DeflateStream`) rents an 8 KiB buffer from the process-wide `ArrayPool<byte>.Shared` for each direction.
  When inflating, it holds the server's last compressed payloads; when compressing, SshSharp's last compressed payloads. Compressed
  is not encrypted: anyone who can inflate it reads the plaintext. The stream returns the buffer to the shared pool without clearing
  it when it is disposed (at each key exchange and when the connection ends), and the next code in the process that rents an array
  of that size gets it, contents and all.

This matters only to a threat that can read the process's memory or that shares its array pool with code it does not trust; such a
threat can usually read the data where the application uses it anyway. With compression off there are none of these buffers.

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
  given and as each address it resolves to here, and the connection goes only to an address that passed. A forwarding started
  from `ssh_config` (`RemoteForward port`) is filtered by `PermitRemoteOpen` instead, with `ssh`'s rules: an IP literal is still
  compared in canonical form, but a host name is compared only as given and then resolved and connected to here, so an entry
  that names a host trusts this machine's resolver for it. Unset, `PermitRemoteOpen` allows everything, as in `ssh`; an entry
  that does not parse allows nothing.
- The client does not check the address a `forwarded-tcpip` channel names, only the port. The server picks which forwarding
  to use anyway.
- **Remote forwarding to a handler** (`ForwardRemotePortAsync` and `ForwardRemoteUnixSocketAsync` with a handler) runs the
  application's code for every connection the server forwards, so anyone who can reach the forwarded port or socket on the server
  (every user there, and other machines with a non-loopback bind address and `GatewayPorts`) can send it data. The handler must
  treat what it reads as untrusted input: bound sizes and time, validate, and authenticate requests where it matters.
  `SshForwardedConnection`'s addresses and ports are what the server reported; they describe the connection and do not
  authenticate the peer. Each forwarding serves at most `maxConnections` (100 by default) at once and refuses the server's channels
  above it; a handler that throws closes its own connection only, and its exception is logged by type, never with its message.
  Disposal waits `HandlerShutdownTimeout` (5 seconds by default) for cancelled handlers, then closes their connections; with
  `Timeout.InfiniteTimeSpan`, a handler that ignores its token holds disposal up for as long as it runs. A connection that the client
  takes only after disposal has gathered the ones it waits for is closed without reaching the handler: none escapes the bound.
- **Agent forwarding** relays the agent protocol unchanged, as `ssh -A` does: while the connection is up, the server can ask the
  agent to sign with any of its keys. Forward the agent only to servers you trust, and narrow what it can do: with
  `ForwardAgentFilter`, destination constraints (`ssh-add -h`), or the agent's own confirmation (`ssh-add -c`) for sensitive keys.
- **`ForwardAgentFilter`** puts the application between the server and the agent. A compromised server (or anyone with root on it)
  can then get only what the filter allows: each listed key and each signature is the filter's decision, and requests to add, remove
  or lock keys are refused, so they never reach a real agent. What it judges by:
  - The key, the purpose and the user name come from the request: the server's side chooses them. The purpose is what the data's form
    shows (a login request, an SSH signature, a certificate); data of any other form has no purpose (null). Such data is signed when
    the filter allows it, so other programs that sign through agents keep working (pam_ssh_agent_auth). An agent signs whatever data
    it is given, so a forwarded agent is a signing service for any protocol that uses the same key; a filter that allows only the
    purposes the application knows (logins and SSH signatures, say) turns that off.
  - `DestinationHostKey` is set only from a session binding (`session-bind@openssh.com`) whose host key signature over the session
    identifier verified, and a login request must then be for that session (and, host-bound, name that host key) or it is refused.
    It proves which server's key exchange the program on the server took part in, not that the server is honest; an older `ssh` that
    does not bind gives no destination.
  - `ForwardingHostKeys`' first entry is this client's own server (from its key exchange); later hops are as the hops reported them.
  - A refused request is `SSH_AGENT_FAILURE`, as a declined confirmation is. Anything the filter throws refuses the request.
  - Without a filter, nothing changes: a real agent's connection is relayed byte for byte.
- **The in-process agent** (`SshAgent.FromKeys`) answers forwarded agent channels in this process. A program on the server reaches
  only its protocol server, which parses every request in full before acting, bounds each message at 256 KiB (OpenSSH's limit; a
  larger or empty one closes the channel, not the connection), answers malformed requests with `SSH_AGENT_FAILURE`, and serves each
  channel on its own. It is read-only and never signs RSA with SHA-1. Like `ssh-agent`, it signs data of any form it is asked to (other
  programs sign their own challenges through agents), so without a filter a program on the server can use it to sign for other
  protocols that use the same key; `ForwardAgentFilter` limits it to known purposes, and a key behind an `SshKeySigner` sees such data
  as `SshSignaturePurpose.Other`, which its policy can refuse. Its keys are the application's: a key loaded from a file is held in
  this process's memory for as long as the agent is used, where a crash dump or a debugger can reach it, as with any key passed in
  `PrivateKeys`, whereas `ssh-agent` keeps keys in another process. For sensitive keys, serve a key behind an `SshKeySigner` (a KMS,
  an HSM, a smart card): its private half never enters the process, and the signer's own policy (`SshSignRequest.Purpose`) is a
  second check after the filter.
- **Transport pings** (`ping@openssh.com`) are answered with a pong, as OpenSSH answers them. Pongs not yet sent are capped
  (256 KiB), so a server that pings but stops reading cannot grow the client's memory; pings past the cap go unanswered.
- Forwarded connections the server opens are capped (`SshClientOptions.MaxForwardedConnections`, 1,000 by default, and a
  handler forwarding's `maxConnections`); above it, new ones are refused. Within that, a server can still send data up to each
  channel's window (2 MiB), and no more until it is read: a handler that stops reading holds the server back.

### The agent

- **Windows named pipes:** any user can create a pipe under a name nobody holds yet, so another user on the same machine could
  create the OpenSSH agent's pipe while the service is stopped, or Pageant's (its name is derived from the user name and a value
  every process on the machine computes alike). SshSharp therefore uses an agent pipe only when its owner is the current user,
  SYSTEM or the Administrators group, as PuTTY checks Pageant's pipe; otherwise no signing request or key is sent to it.
- **The agent's path** (a socket, or a pipe whose name, as Pageant's, holds the user name) is never put in an exception message or
  a log: an agent that cannot be reached is reported by the system error's type or socket error code, not its message, which can
  quote the path.
- **Adding keys** (`AddKeyAsync`, `AddKeysToAgent`): the private key goes to the agent the application named. `AddKeysToAgent`
  adds only identity-file keys the server accepted, never keys the application passed in `PrivateKeys`. With `AddKeysToAgent ask`,
  a key goes only after the application's `ConfirmAddKeyToAgent` says yes; without that callback, or in `BatchMode`, none goes,
  so a configuration cannot put keys into the agent unasked. The prompt it gets carries the identity file's path and the key's
  comment, which can name the user; they are given to the application, not logged. The lock passphrase (`LockAsync`) is a managed
  string and cannot be wiped.
- **An in-process agent** (`SshAgent.FromKeys`) is trusted like the keys it holds: it is the application's own code and keys, reached
  through no socket or pipe, so no other local user can pose as it or connect to it. It refuses to add, remove or lock keys, so
  `AddKeysToAgent` and `AddKeyAsync` cannot put keys into it.

### Local listeners (port forwarding and SOCKS)

- `ForwardLocalPortAsync` and `ForwardDynamicPortAsync` bind where the application says. Forwardings from `ssh_config` bind
  to loopback unless the configuration names an address or sets `GatewayPorts`, as with `ssh`.
- `ForwardLocalUnixSocketAsync` (and `LocalForward /path ...`) listens on a Unix socket file it creates, owner-only by default: mode
  0600 on Unix (`ssh`'s default `StreamLocalBindMask 0177`), an ACL with only the current user on Windows. The application (a
  `socketMode`) or the configuration (`StreamLocalBindMask`) can widen it on Unix, for example to the owner's group; everyone the
  mode lets connect can then use the SSH connection. Windows keeps the current-user ACL whatever the mode: a Unix mode has no
  faithful ACL counterpart, and the library narrows rather than guesses. The permission is set between `bind` and `listen`, while
  the socket refuses connections, so no one the mode leaves out can connect in between. It never replaces an existing file unless
  `ssh_config` says `StreamLocalBindUnlink yes` (then whatever file is at that path is deleted, as `ssh` does), and it removes its
  socket file when it stops. The paths come from the application or the configuration; they are not logged.
- The SOCKS proxy supports only CONNECT (SOCKS 4, 4a and 5). Started without credentials it has no authentication (like `ssh -D`):
  anyone who can reach its address can use the SSH connection, so it should listen on loopback. Started with a `NetworkCredential`,
  it takes only SOCKS 5 with username/password authentication (RFC 1929) and refuses SOCKS 4 and clients that do not authenticate,
  so it can listen beyond loopback. That protects against those who cannot see the traffic, not against those who can: RFC 1929
  sends the credentials in clear text, and the application's traffic to the proxy is plain TCP (only the hop from this machine to
  the server is encrypted), so anyone on that network path can read the password and reuse it, and read or change the traffic.
  Loopback stays the safer choice where it will do. The forwarder keeps only HMAC-SHA256 digests of the user name and password, under
  a random key made for it, and compares each attempt's digests in constant time (both fields, without stopping at the first that
  differs), so response timing reveals nothing about the expected values or their lengths. Failed attempts are logged without the
  client's address and are not rate limited: the password must be long and random.
- Remote forwarding to a handler opens no listener on this machine: its connections reach the application's code only through
  the SSH connection (see [Channels the server opens](#channels-the-server-opens) for what that code must expect).

### Proxies

- An HTTP or SOCKS proxy (`SshProxy`) sees the destination host and port; the SSH traffic through it is encrypted and the
  host key is verified as usual, so a hostile proxy can refuse or delay the connection but not read or change it.
- Proxy credentials (HTTP Basic, SOCKS 5 user name and password) are sent as the protocols define them, in clear text to the
  proxy; they never appear in exceptions or logs. Replies are bounded (HTTP headers to 16 KiB) and validated, and host names
  that a protocol cannot carry are refused rather than altered.
- A custom proxy (`SshProxy.FromConnector`) is the application's own code, run in-process; it is given the host and port of the
  first network hop and nothing else (no credentials, no host keys). The stream it returns is trusted no more than a TCP
  connection: the host key is verified over it, so a transport that misbehaves can refuse, delay or break the connection but not
  read or change it. Its exception messages are not copied into the library's own (they may name the host); the exception is kept
  as the inner exception for the application.

### Jump hosts

A jump host (`SshClientOptions.JumpHosts`, or `ProxyJump` in `ssh_config`) relays the next hop's SSH connection through a
`direct-tcpip` channel. It sees the next host's name and port and the encrypted traffic, and can refuse, delay or end the
connection, but not read or change it: each host's key is verified end to end, by that host's own verifier.

- Credentials go only to the host they belong to. With `JumpHosts`, each hop is offered only what its own `SshJumpHost.Options`
  hold, and the destination's password, keys, keyboard-interactive handler and agent forwarding are never offered to a hop (nor
  a hop's to the destination). With `ProxyJump`, see [Configuration input](#configuration-input).
- A hop's options cannot carry a proxy, a local address or jump hosts of their own (`ArgumentException`), so which network
  connection a setting applies to is never ambiguous: the destination's `Proxy`, `LocalEndPoint` and `AddressFamily` apply to
  the first hop.
- An application that passes the same `SshClientOptions` object to a hop and to the destination offers the same credentials to
  both, by its own choice.
- A connection that fails partway closes the hops already opened, and disposing the destination closes the whole chain, so no
  authenticated hop is left open behind a failed or finished connection.

### SFTP

- Every reply is parsed as hostile (and fuzzed): lengths, counts and request ids are checked, a packet is at most 1 MiB, a
  directory listing is bounded, and names that are not valid UTF-8 are decoded with replacement characters instead of failing.
- Recursive downloads apply the same name checks as SCP (no `.`, `..`, separators, NUL, or Windows device names; `:` and `\`
  only matter on Windows) and keep every path inside the target directory. Uploads skip special files (FIFOs, sockets,
  devices).
- With `Preserve`, a download applies the server's permission bits (read, write and execute for owner, group and others; never
  set-id or sticky) where this machine has Unix modes, without the local umask, as `sftp -p` does: a server can make what it sends
  world-writable. A directory's mode is applied after its contents, and a name listed twice is fetched once.
- A recursive delete (`DeleteDirectoryAsync(path, recursive: true)`) removes symbolic links without following them, and checks
  every subdirectory with `LSTAT` before entering it, so a listing that describes a link as a directory cannot lead it outside the
  tree. It is bounded like a directory download (64 levels; each listing bounded) and touches only the server's files. The
  checks cannot be atomic: SFTP has no `O_NOFOLLOW` or `openat`, so every request names a path the server resolves again. Someone
  else who can write inside the tree on the server (another user, a process there) can swap a checked directory for a link between
  the `LSTAT` and the requests that follow, and the delete then removes the files the link leads to, as far as this login's rights
  on the server reach. Delete recursively only trees no one else can change while it runs.
- A listing keeps up to 8 READDIR requests in flight on its handle and takes the batches in the order it asked for them; the
  replies to requests past the end (EOF, or an error from some servers) are read and dropped before the handle is closed. A
  recursive listing (`SftpListOptions.Recursive`) only reads: it goes at most `MaxDepth` levels down (64 by default, 1024 at most),
  enters each name a directory lists once, and holds at most `MaxConcurrentDirectories` handles. It does not enter links unless
  `FollowSymbolicLinks` is set; then a link may lead anywhere the server lets the user see, and a loop is recognized by the path the
  server's `REALPATH` resolves (a server that does not resolve links leaves it to `MaxDepth`). The server decides what a listing
  contains, so a hostile one can make a recursive listing as large as `MaxDepth` allows; stop or cancel it to bound the work.
- `SftpTransferOptions.SkipUnchanged` trusts the sizes and modification times the server reports (in a download's listing, or of
  the remote files an upload would replace): a server can make a transfer leave files it should have replaced (`TimeTolerance`
  gives it nothing more: it can report any time it likes). It cannot make anything be written that it did not send. With
  `SkipUnreadableDirectories` (transfers and recursive listings), a server can leave a directory out by refusing it with
  `PermissionDenied`; a transfer lists every such directory in `SftpTransferSummary.UnreadableDirectories` (a listing reports it to
  `UnreadableDirectory`), and any other error still fails the transfer. `SftpTransferOptions.Filter` is the caller's code, run
  locally for each entry; in a download it sees the server's names and attributes, already checked as above.
- A server that stops answering holds a request until the session ends, unless `SftpClient.OperationTimeout` is set; it then
  fails the request (`Timeout`) once the server has been silent that long.
- Segmented transfers (`Segments`) open more SFTP sessions as channels of the same connection: nothing new is authenticated or sent
  anywhere else. A segmented upload that fails cuts the remote file it created or truncated to its unbroken start, or deletes that
  file where the server cannot cut it, so a later resume cannot keep a gap; it never touches another path. A server that stops
  answering can only delay this by `OperationTimeout` (or 5 s) per step; a cleanup that did not finish is marked on the exception
  (`SftpClient.UploadCleanupIncompleteKey`), so the application knows not to resume a file that may have gaps.
- A file hash (`GetFileHashAsync`, `check-file` or `md5-hash`) is computed by the server, so a match is only as good as the server:
  it detects a truncated or damaged file, not a server that lies. Only SHA-2 is accepted unless the application names `md5`,
  `sha1` or `crc32`, which detect accidental damage only. The reply must name an algorithm that was asked for and carry a digest
  of that algorithm's length.
- A raw extended request (`SendExtendedRequestAsync`) sends the name and bytes the application gives, to the SFTP server of this
  session only. The reply is returned as untrusted bytes for the application to parse; only a status is parsed, and its message is
  stripped of control characters and cut to 200 characters, as for every other status.
- `SshSharp.FileProviders` treats backslashes as separators and refuses `..` and NUL in subpaths, so a web request cannot leave
  the configured root by name, and bounds its cache. The server follows symbolic links, including ones that point out of the root.

### SSH signatures and allowed-signers files

- A signature is accepted only for its exact namespace, with SHA-256 or SHA-512, and never with SHA-1 RSA (`ssh-rsa`).
- An allowed-signers file is parsed strictly, as `ssh-keygen` does: an unknown or repeated option rejects the whole file
  rather than silently dropping a restriction. A `cert-authority` line accepts only user certificates it issued, within their
  validity, for a principal the certificate names and the line allows.

### Certificates the application checks or issues

- **Checking** (`SshCertificate`): a certificate is parsed as hostile input (and fuzzed). `VerifySignature` proves only that the
  key in the certificate's `AuthorityKey` signed it; anyone can make a CA, so trusting a certificate means comparing its authority
  with one you trust. `IsValidFor` does both, then the type, the validity window (`valid_after <= now < valid_before`), the principal
  (exact for users, a pattern for hosts; a certificate without principals is no one's) and refuses any critical option, since only
  the application can enforce `force-command` or `source-address`. The CA's signature must be SHA-2 or Ed25519 (never SHA-1
  `ssh-rsa`), from an RSA key of 2048 bits or more; the same rules apply to host certificates in `known_hosts` and to certificates
  in allowed-signers files. Revocation is not part of these checks: check it with `SshKeyRevocationList` (a KRL or a key list, as
  sshd's `RevokedKeys`), which revokes a certificate by serial or key id for its authority, and when its certified key or its
  authority's key is revoked. The list is parsed with the same bounds and strictness as `RevokedHostKeys` (a malformed KRL, or one
  with a section this library does not know, throws rather than being read in part). In a text key list, a certificate line
  revokes the key it certifies, FIDO security-key certificates (`sk-...-cert-v01@openssh.com`) included, and a certificate line
  of an accepted type whose key cannot be read throws for the whole list rather than being skipped, so it cannot leave a revoked key
  accepted (a DSA or unknown certificate line is skipped: its key is never accepted). Its
  signatures are not verified: it is
  local configuration, as trusted as the code that loads it. Vendor extension values (`ExtensionValues`) are what the CA wrote;
  servers ignore extensions they do not know, and an application that acts on one is trusting the CA for it.
- **Signatures by an expected key** (`SshSignature.Verify(message, namespace, expectedKey)`): accepted when that key, or a
  certificate for it, made the signature; such a certificate's authority, validity and principals are not checked, since the key
  itself is what is trusted.
- **Issuing** (`SshCertificateBuilder`): the application is then the certificate authority, and **whoever can sign with the CA key
  can log in as any principal on every server that trusts it**. Keep the key out of the process: in an SSH agent, or in a key vault,
  KMS or HSM through an `SshKeySigner` that allows `SshSignaturePurpose.Certificate` and nothing else (and, the other way round,
  have login keys refuse that purpose). Issue for the shortest time that works (there is no default end, so nothing is valid
  forever by accident), name principals exactly (at least one is required, so no certificate is valid for any user), drop the
  extensions a use does not need, give each certificate its own serial for revocation, and log what is issued. The builder checks
  option names and values before anything is signed, writes options sorted and once each, uses a fresh 32-byte random nonce, signs
  RSA with `rsa-sha2-512` (never `ssh-rsa`), and verifies the signature before returning the certificate, so a signer or agent that
  answers with the wrong key or algorithm fails instead of producing a certificate servers would refuse.
- **What it decides:** who gets a certificate is the application's decision. The library does not authenticate the requester.

### SCP downloads

- Names the server sends must be single path components: not empty, `.` or `..`, and free of separators, drive colons and
  control characters (the CVE-2019-6111 pattern). On Windows, device names (`CON`, `NUL`, `COM1`, ...) and names ending
  in a dot or space are refused too.
- A single-file download refuses a second file or a directory.
- File modes from the server apply only with `Preserve`, and only the permission bits, never set-id or sticky.
- Remote paths, for downloads and uploads, are passed to the server's shell as one single-quoted word. That is safe with a POSIX
  shell. On a Windows OpenSSH server the command runs through `cmd.exe`, which does not treat single quotes as quotes, or
  PowerShell, which escapes a quote inside them differently. There, a path the application does not control can run a command as
  the logged-in user: the issue behind CVE-2020-15778 and SSH.NET's GHSA-mggc-4xg6-vcxf. Applications pass such paths to SFTP,
  which runs no shell.
- Total size, file count and directory depth are not limited: a server can fill the target's disk.

### Secrets in memory and logs

- Passwords, private keys and command text are never logged. User names and host names are not logged either; host key
  fingerprints and algorithm names are. The connection's addresses (`SshClient.RemoteEndPoint`, `LocalEndPoint`) and session id
  are there for the application to read, and are never logged or recorded in telemetry.
- Exception messages, which applications log, follow the same rule: no user names, host names (the canonicalizer's failure
  included) or names that usually are user names (a certificate's principals, the agent's path). A file or SFTP path the
  application passed to the failing call can appear, as in .NET's own I/O exceptions; a path that comes from ssh_config does not
  (an `Include`d file is named by its file name only, a `RevokedHostKeys` file by the directive), nor does an agent destination's
  `[user@]host`. A ProxyJump hop that refuses to log in is named by its place in the list ("ProxyJump hop 2"), not by its name.
- Log values that carry an exception (an agent failure, say) are formatted to a sanitized reason and expose no public property
  holding the exception, so a structured log sink that records properties cannot record the agent's path from it either.
- Traces and metrics carry no user name, host name, file or directory path, forwarding address, port or socket path, SOCKS
  destination, or dependency injection endpoint name. SFTP and SCP transfer spans carry byte and file counts, forwarding instruments only the
  kind of forwarding, and the authentication span the method that succeeded and the number of requests, never which key was
  offered.
- `SshAuthenticationException` (its message and `Attempts`) names methods, outcomes and the SHA-256 fingerprints of the keys
  offered, which identify public keys only. It never holds a password, a keyboard-interactive answer or the user name. A key
  fingerprint can link a failed login to its owner, as it can in the server's own log; treat it as you treat host key fingerprints.
- `PasswordProvider` and `ChangePassword` get the user name and the host as the caller gave it, to show a prompt. The library
  keeps neither the passwords they return nor the new password after authentication.
- Derived keys and key material are wiped (`CryptographicOperations.ZeroMemory`) when no longer needed. Managed strings
  (the `Password` option) cannot be wiped; this is a known limitation. The same holds for `SshGssapiOptions.Credential`: a
  `NetworkCredential` keeps its password as a managed string, so prefer the platform's ticket (`kinit`, or the Windows logon
  session) to an explicit credential.
- The managed X25519, Ed25519, sntrup761 and Poly1305 code avoids branches and table lookups on secret data. DH (group14/16/18
  and group exchange) uses `BigInteger.ModPow`, which is not constant-time, on an ephemeral exponent used once; the post-quantum
  hybrids, curve25519 and ECDH are preferred.

### Configuration input

`ssh_config` can run local commands (`Match exec`, `ProxyCommand`, `KnownHostsCommand`), as in OpenSSH.

- `Match exec` runs nothing unless the application opts in with an exec runner.
- `ProxyCommand` runs by default, as with `ssh`. Applications that load configurations they do not control can turn it off
  with `SshConfigConnectOptions.AllowProxyCommand = false`.
- The password, keyboard-interactive answers and keys given in `SshConfigConnectOptions` (`Password`, `KeyboardInteractive`,
  `PrivateKeys`) go to the destination only: a `ProxyJump` hop, perhaps run by someone else, is never offered them, and logs in
  with its own configuration's identity files and the agent. The same holds for `PasswordProvider` and `ChangePassword`: they are
  never called for a hop, nor in `BatchMode`. (Before 1.1, `PrivateKeys` were offered to every hop as well: a hop learned the
  public keys, and could have accepted one of them.)
- `PubkeyAcceptedAlgorithms` narrows which keys are offered, as in `ssh`; it only ever removes keys from what would otherwise be
  offered, and never brings SHA-1 `ssh-rsa` signatures back.
- `Include` is bounded: at most 16 levels deep and 1,024 files in all, so a configuration cannot make resolution parse without end.
- `KnownHostsCommand` runs only with `SshConfigConnectOptions.AllowKnownHostsCommand = true`. It is off by default, unlike
  `ProxyCommand`, because its output is trusted as known_hosts lines: a configuration the application does not control must not
  be able to vouch for host keys. With it off, a configuration that names one fails the connection. As in OpenSSH, no shell is
  involved (the command is split into arguments, each expanded on its own, the program taken as written, and the program must be
  an absolute path), so
  token values cannot inject commands; the run is limited to 30 seconds and 1 MiB of output. On Windows a batch file (`.bat`,
  `.cmd`) is refused, because Windows runs it through `cmd.exe`, which would reparse the arguments.
- When the library stops one of these commands (`Match exec` cancelled or past its 30 seconds, `KnownHostsCommand` past its limit,
  a `ProxyCommand` when its connection closes), it kills the command and every process it started. These processes run in the
  application's own process group. Each gets `SIGKILL` alone, never `SIGSTOP` first: .NET's own tree kill stops each process
  before killing it, and a background child left stopped when its shell died made macOS send `SIGHUP` to that group, which
  terminates the application (#432). A process started while the tree is being killed can escape it.
- `Match localnetwork` reads the local interface addresses. As ssh_config(5) warns, a network address is not a trustworthy
  criterion: anyone who controls the network can choose which block applies.
- Host name canonicalization (`CanonicalizeHostname`) with the built-in DNS canonicalizer (`UseDnsCanonicalizer`, off by default)
  sends a lookup for each candidate name (the host with each `CanonicalDomains` entry) to the system's resolver, and so to its DNS
  servers, usually unencrypted: they learn the names tried, as with `ssh`. The answers decide the `HostName` and, through the second
  pass, which `Host` and `Match` blocks apply (an `IdentityFile`, a `ProxyJump`, a `User`), so whoever can answer those queries can
  choose among the names tried and the blocks written for them. The host key is still checked for the name connected to, so a
  forged answer cannot impersonate a host whose key is known; with `StrictHostKeyChecking` other than `yes`, a new name may be
  accepted as for any new host. A CNAME target replaces the name only when `CanonicalizePermittedCNAMEs` allows that pair, which
  keeps a forged CNAME from moving the connection (and its known_hosts lookup) to an arbitrary name. Canonicalization makes no
  lookups for a host reached through `ProxyJump`, `ProxyCommand` or `SshConfigConnectOptions.Proxy` unless the configuration says
  `always`, so with a proxy that resolves names itself (`socks5h`, HTTP), the names are not sent to this machine's DNS. That
  includes the hops of a `ProxyJump` chain after the first: each is reached through the hop before it, which resolves its name, so
  internal names behind a bastion are not looked up here.
- Host and user names supplied by the caller are substituted into those commands (`%h`, `%n`, `%r`), so they are refused when
  they contain shell metacharacters, control characters or a leading `-` (the CVE-2023-51385 pattern). Host names may not
  contain white space either, which would split `%h` into extra arguments. User names may (Windows account names can).
- The config file itself is trusted to the same degree OpenSSH trusts it: whoever can edit it can run commands as the user.
  Values it sets (`HostName`, `User`) are used as written.
- Socket paths in `LocalForward` and `RemoteForward` take `%` tokens and `${VAR}`, as in `ssh`; only paths on this machine take
  `~`, so a path on the server never carries this machine's home directory (and user name). A server-side path is expanded
  on this machine and sent to the server as one string (no shell is involved on either side), so a caller-supplied host or user
  name in `%h` or `%r` can only change which path is asked for; the server's own `StreamLocalBindMask` and permissions apply there.
  `StreamLocalBindMask` can widen a local socket's permissions (see [Local listeners](#local-listeners-port-forwarding-and-socks)).
- `TCPKeepAlive` and `IPQoS` set socket options only: keep-alive probes and the type-of-service mark are visible on the network
  path, as with `ssh`, and say nothing the connection's existence does not.

### Dependency injection

- `SshEndpointOptions` can hold a password, a key passphrase, private keys as text (`PrivateKeys`) and a proxy URI with a password,
  bound from configuration: bind them from a secret store, not a checked-in file. They are not logged, validation errors name an
  entry without its value, and `SshEndpointPrivateKey.ToString()` and the debugger do not show them.
- Host keys are checked strictly by default: an unknown host fails unless `AcceptNewHostKeys` is set (which trusts the first key it
  sees), and a changed key always fails.
- `HostKeyFingerprints` replaces known_hosts with pinned keys (fingerprints, `.pub` lines or known_hosts lines); whoever can change
  the configuration decides which servers are trusted, as with a known_hosts file. Combining it with `KnownHostsFiles`,
  `AcceptNewHostKeys` or `ConfigAlias` fails validation rather than widening trust to either source. A known_hosts line's host field
  is not checked (the entry pins its key), and marked lines (`@cert-authority`, `@revoked`) are refused rather than turned into
  pins.
- `JumpHosts` reaches the server through bastions. Each hop is offered only its own credentials (password, keys, the agent when its
  own `UseAgent` is set): the endpoint's never reach a jump host, and a hop's never reach the destination. Every hop's host key is
  checked: against its own pins or known_hosts files, or else the endpoint's known_hosts files (with the endpoint's
  `AcceptNewHostKeys`); behind an endpoint that pins its keys, a hop without its own fails validation rather than falling back to
  files a pinned deployment does not have.
- `UseAgent` lets the endpoint (or a hop) sign with the agent's keys: an `SshAgent` registered in the container, else the user's
  agent (with `ConfigAlias` too, in place of ssh_config's `IdentityAgent`). Every key the agent holds is offered to that server, as with ssh; an application that should offer one key only registers
  an in-process agent (`SshAgent.FromKeys`) with it. Nothing is added to the agent.
- `UseSshTunnel` sends an `HttpClient`'s connections through the endpoint's server, which resolves the host names and connects to
  them (`direct-tcpip`): the server sees which services are called, but not the traffic when it is HTTPS, as TLS runs end to end.
- Connection events (`WatchAsync`) name the endpoint by its registered name only, with no host or user name; the error they carry
  can hold the server's disconnect text.
- With `ConfigAlias`, the connection takes ssh_config's settings and the core defaults (`ProxyCommand` allowed, the agent used,
  `ForwardAgent` and `StrictHostKeyChecking` as the file says); an unknown host is refused, since there is no one to ask.
- The health check's description names no server software and carries no server text, since health endpoints are often reachable
  without authentication. Its exception is attached for logging: do not write it to a public response.

## Out of scope

- A compromised local machine or process (memory dumps, debuggers, malicious code in the same process).
- Denial of service by a server the user chose to connect to, beyond the bounds above (a server can always refuse service).
- Physical side channels (power, EM) and microarchitectural attacks across processes.
