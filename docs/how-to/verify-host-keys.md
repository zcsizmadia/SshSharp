# Verify host keys

Every SSH server proves it holds a host key during the key exchange. Checking that key against one you trust is what stops a
man-in-the-middle, so `SshClientOptions.HostKeyVerifier` is required and has no "accept anything" default. This page shows the
common policies and how to choose.

## When to use which verifier

| Situation | Verifier |
|---|---|
| Hosts are in the user's `known_hosts` (interactive tools, admin scripts) | `KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes)` |
| A service with its own trust store, learning hosts on first contact | `new KnownHostsVerifier([path]) { Policy = AcceptNew }` |
| A few fixed servers whose fingerprints you know | `SshHostKeyVerifier.Pinned(...)` with fingerprints |
| A few fixed servers whose `.pub` files you have | `SshHostKeyVerifier.Pinned(...)` with `SshPublicKey`s |
| An endpoint registered with `AddSshClient` (a container, Kubernetes) | the `HostKeyFingerprints` setting, from configuration |
| Hosts with OpenSSH host certificates | `@cert-authority` lines in `known_hosts`, or a custom verifier |
| An inventory, CMDB or vault knows the keys | `SshHostKeyVerifier.FromDelegate(...)` |
| Connecting by `ssh_config` alias | nothing: the configuration's `known_hosts` and `StrictHostKeyChecking` apply |

## `known_hosts`, strictly

[!code-csharp[](../snippets/HostKeys.cs#strict)]

## A trust store of your own

[!code-csharp[](../snippets/HostKeys.cs#app-file)]

| Policy | Known key | Unknown host | Changed key |
|---|---|---|---|
| `Yes` | accepted | rejected | rejected |
| `AcceptNew` | accepted | recorded and accepted, unless another key type is already known for the host | rejected |
| `Ask` (default) | accepted | `AskHostKey` decides (rejected without it); recorded when accepted | rejected |
| `No` | accepted | accepted and recorded | accepted (not recorded), [without passwords or forwarding](#a-changed-key-under-no) |

> [!CAUTION]
> `StrictHostKeyChecking.No` accepts a changed key, which is exactly what an interception looks like. Use it only where
> interception is not a concern, such as a throwaway container in a test.

### A changed key under `No`

When the server's key differs from the one `known_hosts` has, `No` lets the connection go on, as ssh does, but does not trust it.
Nothing a man in the middle could use is given to the server:

| On a connection whose key changed | What happens |
|---|---|
| `Password`, `PasswordProvider`, `ChangePassword` | Not used, and the provider is not asked. |
| `KeyboardInteractive` (and a password answering it) | Not used. |
| `PrivateKeys`, the agent's keys, GSS-API | Used as usual. |
| `ForwardAgent` | Not forwarded: not asked for, and the server's agent channels are refused. |
| `LocalForward`, `RemoteForward`, `DynamicForward` | Not started (logged); with `ExitOnForwardFailure`, the connection fails with `SshHostKeyException`. |
| `ForwardLocalPortAsync`, `ForwardRemotePortAsync`, `ForwardDynamicPortAsync` and the other forwarding methods | Throw `SshHostKeyException`, "Port forwarding is disabled to avoid man-in-the-middle attacks". |
| `OpenTcpTunnelAsync`, `OpenUnixSocketTunnelAsync` (as `ssh -W`, and ProxyJump through this host) | Work as usual. |
| `UpdateHostKeys` | Nothing is updated. |

When a password was the only way in, authentication fails with `SshAuthenticationException`, whose message says the password was
disabled because the host key changed, and whose `Attempts` list `password` (or `keyboard-interactive`) as `Unavailable`. A
`Warning` with the new key's fingerprint is logged once per connection. Each ProxyJump hop is checked on its own: a hop whose key
changed loses its own password and agent forwarding, not the destination's.

If the change is expected (the server was reinstalled), confirm the new fingerprint out of band and remove the old line
(`ssh-keygen -R host`), or let `UpdateHostKeys` follow planned rotations, rather than relying on `No`.

## Pin fingerprints

[!code-csharp[](../snippets/HostKeys.cs#pinned)]

Fingerprints are written as `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints them, with the `SHA256:` prefix.

## Pin keys

When you have the server's public keys themselves (its `/etc/ssh/ssh_host_*_key.pub` files, or the lines your provisioning
printed), pin the keys instead of their fingerprints:

[!code-csharp[](../snippets/HostKeys.cs#pinned-keys)]

The server's key must be one of them byte for byte; for a host certificate, the certified key counts. `SshPublicKey.Parse` reads
a `.pub` line and refuses anything else with `FormatException`, so a mistyped key fails at startup rather than at the first
connection. See [Read a public key](agent-and-keys.md#read-a-public-key-and-its-fingerprint) for the format.

### With dependency injection

An endpoint registered with `AddSshClient` pins fingerprints through its `HostKeyFingerprints` setting, so they can come from
configuration (`appsettings.json`, an environment variable such as `Ssh__Deploy__HostKeyFingerprints__0`) with no code:

[!code-csharp[](../snippets/DependencyInjection.cs#pin-in-code)]

An entry can also be the key itself: the server's `.pub` line (`ssh-ed25519 AAAA...`) or a known_hosts line, as `ssh-keyscan`
prints it, so a key file can be pasted into configuration as it is. They replace known_hosts for that endpoint: `KnownHostsFiles` or
`AcceptNewHostKeys` alongside them fails validation, and an entry that is none of these fails it at startup (with `ValidateOnStart`).
See [Dependency injection: containers and Kubernetes](../dependency-injection.md#containers-and-kubernetes).

## Ask your own source of truth

[!code-csharp[](../snippets/HostKeys.cs#delegate)]

## Write a verifier

Derive from `SshHostKeyVerifier` for full control. This one accepts only host certificates from one authority, issued for the host
being connected to:

[!code-csharp[](../snippets/HostKeys.cs#custom)]

With `known_hosts`, a single line trusts the same authority: `@cert-authority *.example.com ssh-ed25519 AAAA...`. Unlike this
verifier, `KnownHostsVerifier` then checks a certificate that cannot be used (expired, or for another name) as its plain key, as
`ssh` does ([Host certificates that cannot be used](../host-keys.md#host-certificates-that-cannot-be-used)).

## Get a new server's keys

[!code-csharp[](../snippets/HostKeys.cs#scan)]

> [!WARNING]
> A scan proves the server holds the keys, not that you reached the right server. Compare the fingerprints with ones obtained another
> way (provisioning output, a cloud console) before you trust them.

## Handle a rejected key

[!code-csharp[](../snippets/HostKeys.cs#rejected)]

## Use the key after connecting

`client.HostKey.GetPublicKey()` (and `SshHostKeyContext.HostKey.GetPublicKey()` in a verifier) is the server's key as an
`SshPublicKey`: compare it with a key you hold, write it out as a line, or print another fingerprint.

[!code-csharp[](../snippets/HostKeys.cs#compare-key)]

To record a key you trust in a `known_hosts` file, or check one against it, `KnownHostsFile` takes an `SshPublicKey` too:

[!code-csharp[](../snippets/HostKeys.cs#record-key)]

To write a `known_hosts` line without a file (for a configuration template, a provisioning tool, or a file you build in memory),
make a `KnownHostsEntry` from the key. `KnownHostsEntry.ForHost` writes the host as `ssh` does, hashed if you ask (as
`HashKnownHosts yes`, with a fresh salt each time); the constructor takes any host patterns and a marker:

[!code-csharp[](../snippets/HostKeys.cs#known-hosts-entry)]

`KnownHostsFile.Parse` reads these lines back, as `ssh` does. Neither writes the key's own comment (`SshPublicKey.Comment`, often a
user and machine name): pass `comment` for one.

Every value written into a line is checked first, so a value from your application cannot add a line (an `@cert-authority` line,
say) to the file. Host patterns and the key type must not contain white space or control characters, and the comment must not
contain control characters other than a tab (no CR or LF). `KnownHostsEntry`, `ForHost`, `KnownHostsFile.Add` and `AppendAsync`
throw `ArgumentException` for such a value and write nothing.

## Notes and pitfalls

- **Connections over a stream** (a tunnel, `ProxyCommand`) have no host name: set `HostKeyAlias` so `known_hosts` can be consulted.
- **Revocation.** `RevokedHostKeys` (a key list or an OpenSSH KRL) refuses keys in every mode, even ones `known_hosts` trusts.
  So does an `@revoked` line in `known_hosts`; written without a port, it applies to the host on every port.
- **Key rotation.** `UpdateHostKeys = true` adds keys the server proves it holds after login and removes ones it no longer has, so a
  rotation does not break the next connection. As in `ssh`, it skips hosts with wildcard or `@cert-authority` lines, keys under
  several names, and the first `AcceptNew` connection; behind a load balancer, use a host certificate instead.
- **After connecting**, `client.HostKey` is the verified key (`KeyType`, `Fingerprint`, `PublicKey`, and `Certificate` for a host
  certificate). `client.HostKey.GetPublicKey()` gives it as an `SshPublicKey` (see [Use the key after
  connecting](#use-the-key-after-connecting)).

## See also

- [Host keys](../host-keys.md) (in-depth: `UpdateHostKeys`, revocation lists, scanning options)
- [Security model](../concepts/security-model.md)
- <xref:SshSharp.KnownHostsVerifier>, <xref:SshSharp.SshHostKeyVerifier> and <xref:SshSharp.SshPublicKey> in the API reference
