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

**Does it support `ControlMaster` / connection multiplexing between processes?**
No. Within a process, one `SshClient` already multiplexes any number of channels.

**Can I connect through an HTTP or SOCKS proxy?**
Yes: `SshClientOptions.Proxy = SshProxy.Http(...)`, `SshProxy.Socks5(...)` or `SshProxy.FromUri(...)`.

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
`KnownHostsEntry`, `SshCertificate` and `SshSignature` all have `GetPublicKey()`. See
[Read a public key and its fingerprint](../how-to/agent-and-keys.md#read-a-public-key-and-its-fingerprint).

**Does it support `ssh-rsa` (SHA-1) or DSA keys?**
No. RSA keys sign with `rsa-sha2-256` or `rsa-sha2-512`, which every OpenSSH since 7.2 accepts. DSA is not supported.

## Features

**X11 forwarding? `gssapi-keyex`? Compression?**
Not supported. Compression is `none` only.

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
