# Verify host keys

Every SSH server proves it holds a host key during the key exchange. Checking that key against one you trust is what stops a
man-in-the-middle, so `SshClientOptions.HostKeyVerifier` is required and has no "accept anything" default. This page shows the
common policies and how to choose.

## When to use which verifier

| Situation | Verifier |
|---|---|
| Hosts are in the user's `known_hosts` (interactive tools, admin scripts) | `KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes)` |
| A service with its own trust store, learning hosts on first contact | `new KnownHostsVerifier([path]) { Policy = AcceptNew }` |
| A few fixed servers whose fingerprints you know | `SshHostKeyVerifier.Pinned(...)` |
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
| `No` | accepted | accepted and recorded | accepted (not recorded) |

> [!CAUTION]
> `StrictHostKeyChecking.No` accepts a changed key, which is exactly what an interception looks like. Use it only where
> interception is not a concern, such as a throwaway container in a test.

## Pin fingerprints

[!code-csharp[](../snippets/HostKeys.cs#pinned)]

Fingerprints are written as `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints them, with the `SHA256:` prefix.

## Ask your own source of truth

[!code-csharp[](../snippets/HostKeys.cs#delegate)]

## Write a verifier

Derive from `SshHostKeyVerifier` for full control. This one accepts only host certificates from one authority, issued for the host
being connected to:

[!code-csharp[](../snippets/HostKeys.cs#custom)]

With `known_hosts`, the same is a single line: `@cert-authority *.example.com ssh-ed25519 AAAA...`.

## Get a new server's keys

[!code-csharp[](../snippets/HostKeys.cs#scan)]

> [!WARNING]
> A scan proves the server holds the keys, not that you reached the right server. Compare the fingerprints with ones obtained another
> way (provisioning output, a cloud console) before you trust them.

## Handle a rejected key

[!code-csharp[](../snippets/HostKeys.cs#rejected)]

## Notes and pitfalls

- **Connections over a stream** (a tunnel, `ProxyCommand`) have no host name: set `HostKeyAlias` so `known_hosts` can be consulted.
- **Revocation.** `RevokedHostKeys` (a key list or an OpenSSH KRL) refuses keys in every mode, even ones `known_hosts` trusts.
- **Key rotation.** `UpdateHostKeys = true` adds keys the server proves it holds after login and removes ones it no longer has, so a
  rotation does not break the next connection.
- **After connecting**, `client.HostKey` is the verified key (`KeyType`, `Fingerprint`, `PublicKey`, and `Certificate` for a host
  certificate).

## See also

- [Host keys](../host-keys.md) (in-depth: `UpdateHostKeys`, revocation lists, scanning options)
- [Security model](../concepts/security-model.md)
- <xref:SshSharp.KnownHostsVerifier> and <xref:SshSharp.SshHostKeyVerifier> in the API reference
