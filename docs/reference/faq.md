# FAQ

## General

**Which .NET versions are supported?**
.NET 8 and .NET 10, on Windows, Linux and macOS. .NET Framework and .NET Standard are not supported: the library depends on APIs they
lack (`System.IO.Pipelines`-based I/O, `AesGcm`, modern ECDH and RSA APIs). If you need them, SSH.NET is the established choice.

**Is there a synchronous API?**
No. Every network operation is asynchronous and takes a `CancellationToken`, and there is no sync-over-async inside. Parsing local
files (`SshConfig.Load`, `KnownHostsFile.Load`) has synchronous helpers. Two adapters are synchronous by their interfaces'
contracts: `IFileProvider` and parts of `IFileSystem`.

**Does it need OpenSSH (or any native library) installed?**
No. It is pure managed C#. The only external programs it ever runs are the ones your configuration names (`ProxyCommand`, an
opt-in `Match exec` or `KnownHostsCommand`) and `scp` on the server for SCP transfers.

**How does it compare with SSH.NET and Tmds.Ssh?**
The README compares them feature by feature:
[Why not SSH.NET?](https://github.com/zcsizmadia/SshSharp#why-not-sshnet) and
[Compared with Tmds.Ssh](https://github.com/zcsizmadia/SshSharp#compared-with-tmdsssh), with the versions and dates checked and
the sources. [Benchmarks](../benchmarks.md) measures SshSharp against SSH.NET.

**Is it a server too?**
No, SshSharp is a client library. Server-side SSH is out of scope.

**Which servers does it work with?**
It is tested against OpenSSH (old and new, on Linux and Windows), Dropbear, AsyncSSH, Apache MINA SSHD, Erlang/OTP's SSH, and
SFTP-only servers; see [Testing and validation](../testing.md). Any server that speaks a modern algorithm should work.

**Is it production-ready?**
1.0 follows semantic versioning, and the library is extensively tested (unit, interop, fault injection, fuzzing, mutation testing).
The managed cryptography has had an internal constant-time review but not yet an outside one. SSH.NET has a much longer track
record. Read the [cryptography review](../crypto-review.md) and decide for your risk profile.

## Connecting

**How do I accept any host key, for a test?**
Write the verifier explicitly so it is visible in review:
`SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true))`. Never ship it: it turns off protection against
interception. For test containers, pinning the container's key or using `StrictHostKeyChecking.AcceptNew` with a throwaway
`known_hosts` file is nearly as easy and keeps verification on.

**Can I reuse one connection for many operations?**
Yes, and you should: commands, shells, SFTP sessions and tunnels all run as channels over one `SshClient`, concurrently. See
[Threading and concurrency](../concepts/threading.md).

**Does it reconnect automatically?**
No. A connection that ends stays ended, and `ConnectionClosed` tells you. Open a new one yourself, or use the dependency injection
package's `ISshConnectionProvider`, which reconnects on the next call. See [Keep-alive and reconnecting](../how-to/keepalive-and-reconnect.md).
The file adapters follow a reconnecting connection when built from a session factory; see
[Follow a connection that drops](../how-to/file-system-adapters.md#follow-a-connection-that-drops).

**Does it support `ControlMaster` / connection multiplexing between processes?**
No. Within a process, one `SshClient` already multiplexes any number of channels.

**Can I connect through an HTTP or SOCKS proxy?**
Yes: `SshClientOptions.Proxy = SshProxy.Http(...)`, `SshProxy.Socks5(...)` or `SshProxy.FromUri(...)`.

**Can I set socket options, such as TCP keep-alive or buffer sizes?**
Yes, with `SshClientOptions.ConfigureSocket` (or `SshConfigConnectOptions.ConfigureSocket` when connecting by alias), called with
the socket before it connects. By alias, `ssh_config`'s `TCPKeepAlive` (on by default, as in `ssh`) and `IPQoS` apply first. See
[Tune and inspect a connection](../how-to/tune-and-inspect-connections.md#set-socket-options).

**Can the SOCKS proxy (`ForwardDynamicPortAsync`) require a password?**
Yes: pass a `NetworkCredential`, and the proxy takes only SOCKS 5 with username/password authentication (RFC 1929). The password
crosses the local network in clear text, so keep the proxy on loopback when the applications run on the same machine. See
[Dynamic forwarding with a password](../how-to/port-forwarding.md#with-a-password-beyond-loopback).

**Can I force a key re-exchange?**
Yes: `client.RekeyAsync()`, as ssh's `~R` escape. Keys are also renewed on their own after `RekeyAfterBytes` or `RekeyAfterTime`.

## Authentication

**In what order are credentials tried?**
As `ssh` does: Kerberos (if on), each public key, keyboard-interactive, then password. See
[Authentication](../authentication.md#the-order-methods-are-tried-in).

**Where should the password come from?**
From configuration, a secret store or an environment variable, never source code. With dependency injection, bind
`SshEndpointOptions.Password` from user secrets or a vault.

**Can I use keys in a hardware token, TPM or cloud KMS?**
Yes: FIDO keys through the agent; Windows key stores and the TPM through `SshPrivateKey.FromRsa`/`FromECDsa`; anything else with
`SshKeySigner`. See [Keys and the SSH agent](../how-to/agent-and-keys.md).

**How do I get a key's fingerprint?**
`Fingerprint` on a key, a host key or a certificate is the `SHA256:...` form `ssh-keygen -lf` prints. For a `.pub` file or an
`authorized_keys` line, read it with `SshPublicKey.Parse(line)` first. `GetFingerprint(HashAlgorithmName.MD5)` gives the legacy
`MD5:aa:bb:...` form (`ssh-keygen -l -E md5`) for inventories that still list it. `SshPrivateKey`, `SshHostKey`,
`KnownHostsEntry`, `SshCertificate`, `SshSignature`, `SshKeySigner` and `SshAgentHostKey` all have `GetPublicKey()`. See
[Read a public key and its fingerprint](../how-to/agent-and-keys.md#read-a-public-key-and-its-fingerprint).

**Can my application issue SSH certificates, as `ssh-keygen -s` does?**
Yes: `SshCertificateBuilder` issues user and host certificates, signed with any `SshPrivateKey`, including one in an SSH agent or a
KMS (`SshKeySigner`, which sees `SshSignaturePurpose.Certificate`). There is no default end of validity: set `ValidBefore`. To check
a certificate someone presents, use `SshCertificate.IsValidFor` with the CA you trust; `VerifySignature` alone does not say the CA
is one you trust. See [Certificates](../how-to/certificates.md#act-as-a-certificate-authority).

**Why does `IsValidFor` refuse a certificate that sshd accepts?**
It refuses any critical option (`force-command`, `source-address`, `verify-required`), because it cannot enforce them; sshd can.
If your application enforces them, check the parts (`GetAuthorityKey`, `Type`, `VerifySignature`, `IsValidAt`, `Principals`,
`CriticalOptions`) yourself. It also refuses a certificate without principals, as sshd does for `TrustedUserCAKeys`.

**Does it support `ssh-rsa` (SHA-1) or DSA keys?**
No. RSA keys sign with `rsa-sha2-256` or `rsa-sha2-512`, which every OpenSSH since 7.2 accepts. DSA is not supported.

## Features

**X11 forwarding? `gssapi-keyex`?**
Not supported.

**Compression?**
Yes: OpenSSH's delayed `zlib@openssh.com`, off by default as in `ssh`. Set `SshClientOptions.Compression = true`, or
`Compression yes` in `ssh_config`. It helps on slow links with text, and costs CPU on fast ones. Plain `zlib`, which starts before
authentication, is not supported by design. See [Compress a slow link](../how-to/tune-and-inspect-connections.md#compress-a-slow-link).

**Why is there no interface for `SshClient`?**
An interface can be added later without breaking anyone, but changing one after it ships breaks every implementation. Put your own
small interface in front of what you use; see [Unit-test code that uses SshSharp](../how-to/unit-testing.md).

**Does it work with Native AOT and trimming?**
Yes, all four packages. See [Native AOT](../how-to/native-aot.md).

**Is FIPS mode FIPS validation?**
No. `FipsMode` restricts negotiation to FIPS-approved algorithms; validation depends on the platform's cryptographic module. See
[FIPS mode](../how-to/fips-mode.md).

## See also

- [Troubleshooting](troubleshooting.md)
- [Migrate from SSH.NET](../migrating-from-sshnet.md)
