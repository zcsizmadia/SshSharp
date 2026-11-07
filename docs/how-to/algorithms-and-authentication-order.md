# Choose algorithms and authentication methods

SshSharp's defaults are modern only and need no tuning for most servers. When a policy, an audit or an odd server asks for more
control, `SshClientOptions` takes the same settings as `ssh_config`, typed:

| `SshClientOptions` | `ssh_config` | Sets |
|---|---|---|
| `KexAlgorithms` | `KexAlgorithms` | Key exchange methods offered. |
| `HostKeyAlgorithms` | `HostKeyAlgorithms` | Host key algorithms accepted. |
| `Ciphers` | `Ciphers` | Ciphers offered. |
| `Macs` | `MACs` | MACs offered (used only with the `aes*-ctr` ciphers). |
| `PubkeyAcceptedAlgorithms` | `PubkeyAcceptedAlgorithms` | Which keys are offered, and the signature algorithm each uses. |
| `PreferredAuthentications` | `PreferredAuthentications` | Which authentication methods are tried, in what order. |
| `RequiredRsaSize` | `RequiredRSASize` | The smallest RSA host key accepted, in bits. |

## When to use

- A security policy rules algorithms out (no finite-field Diffie-Hellman, encrypt-then-MAC only), or lists the only ones allowed.
- You want to prefer an algorithm the defaults rank lower, such as AES-128-GCM on a CPU-bound link.
- A service account must log in with its key only, never fall back to a password prompt.
- Only some key types may be used to log in (Ed25519 only, say), even when the agent holds others.
- Servers' RSA host keys must be larger than 2048 bits.

When you connect by `ssh_config` alias, the directives in the table apply instead; see
[Use ssh_config and known_hosts](ssh-config-and-known-hosts.md).

## Change the defaults, or replace them

An `SshAlgorithmList` takes one of `ssh_config`'s four forms:

| Form | `ssh_config` | Result |
|---|---|---|
| `SshAlgorithmList.Remove("a", "b*")` | `-a,b*` | The defaults without these. Wildcards `*` and `?` match several. |
| `SshAlgorithmList.Prepend("a")` | `^a` | The defaults, with these moved to the front. |
| `SshAlgorithmList.Append("a")` | `+a` | The defaults, with these added at the end. One already among them stays where it is. |
| `SshAlgorithmList.Only("a", "b")` | `a,b` | Exactly these, in this order. |

The first three follow the defaults as they change in later versions (a new post-quantum method, say); `Only` fixes the list. A
list means what the same text means in `ssh_config`. Every name must be one SshSharp implements for that option (see
[Algorithms](../reference/algorithms.md)): a typo or an unsupported algorithm such as `aes128-cbc` throws `ArgumentException` when
the option is set, with the supported names in the message, and only `Remove` takes wildcards. This is stricter than
`ssh_config`, where SshSharp ignores names it does not implement and a wildcard in any form stands for the names it matches.

Remove what a policy rules out:

[!code-csharp[](../snippets/Algorithms.cs#algorithms-remove)]

Allow only a fixed set:

[!code-csharp[](../snippets/Algorithms.cs#algorithms-only)]

Prefer an algorithm without dropping the others:

[!code-csharp[](../snippets/Algorithms.cs#algorithms-prefer)]

Read a list from your own settings, in `ssh_config`'s syntax. `ToString()` writes it back the same way.

[!code-csharp[](../snippets/Algorithms.cs#algorithms-parse)]

```mermaid
flowchart LR
    defaults["SshSharp's defaults"] --> list["Your list<br/>Only, Append, Prepend or Remove"]
    list --> platform["Platform<br/>(ML-KEM only where available)"]
    platform --> fips["FipsMode<br/>(FIPS-approved only)"]
    fips --> offer["Offered to the server,<br/>in this order"]
```

## Choose which keys are offered, and how they sign

`PubkeyAcceptedAlgorithms` lists the signature algorithms public-key authentication may use, as `ssh_config`'s directive of
that name does. A key is offered only with an algorithm the list allows, and is skipped when the list allows none of its own:

| Key | Its algorithms |
|---|---|
| Ed25519, ECDSA | its type: `ssh-ed25519`, `ecdsa-sha2-nistp256` (or 384, 521) |
| RSA | `rsa-sha2-512` and `rsa-sha2-256` (never SHA-1 `ssh-rsa`) |
| FIDO security key, through an agent | `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` |
| A key with its certificate | the certificate's, such as `ssh-ed25519-cert-v01@openssh.com`; the plain name does not allow it |

Offer only Ed25519 keys, whatever else the application or the agent holds:

[!code-csharp[](../snippets/Algorithms.cs#pubkey-accepted)]

The list's order matters for RSA: the key signs with the first of the list's RSA algorithms that the server accepts (its
`server-sig-algs`), as `ssh` picks it. Without a list, it signs with SHA-512 when the server takes it.

[!code-csharp[](../snippets/Algorithms.cs#pubkey-rsa-sha256)]

```mermaid
flowchart TD
    key["Each key, in order"] --> allowed{"An algorithm of the key's<br/>in PubkeyAcceptedAlgorithms?"}
    allowed -- no --> skip["Skipped: NoAcceptedAlgorithm<br/>(nothing is sent)"]
    allowed -- yes --> server{"One of them in the server's<br/>server-sig-algs? (in the list's order)"}
    server -- no --> skip
    server -- yes --> offer["Offered, and signed with it"]
```

A skipped key shows in `SshAuthenticationException.Attempts` as `NoAcceptedAlgorithm`, with its fingerprint. Null (the default)
allows every algorithm a key has. `FipsMode` does not restrict the client's own keys.

## Choose the authentication methods

`PreferredAuthentications` lists the methods to try, in order: any of `gssapi-with-mic`, `publickey`, `keyboard-interactive` and
`password`. A method that is left out is never tried, even when its credentials are set:

[!code-csharp[](../snippets/Algorithms.cs#auth-order)]

Without it, the client uses `ssh`'s order (see [Authentication](../authentication.md#the-order-methods-are-tried-in)). Either way, a
method is tried only when the server offers it and its credentials are set.

## Require larger RSA host keys

[!code-csharp[](../snippets/Algorithms.cs#required-rsa-size)]

A smaller RSA host key fails the connection with `SshFailureReason.HostKeyRejected`. The default is 2048 bits. The setting can go as
low as 1024 for an old device that cannot have a larger key, as `ssh_config`'s `RequiredRSASize` can, but no lower; prefer
replacing the key.

## Notes and pitfalls

- **No algorithm in common.** A list that leaves nothing the server offers fails the connection with
  `SshFailureReason.KeyExchangeFailed`, and the message lists what each side offered. A list that leaves nothing at all (for
  example `Only` with a cipher `FipsMode` excludes) throws `ArgumentException` before anything is sent.
- **FIPS mode still applies.** With `FipsMode = true`, the algorithms it excludes are removed from your transport lists too (not from `PubkeyAcceptedAlgorithms`); see
  [FIPS mode](fips-mode.md).
- **ML-KEM needs the platform.** The `mlkem*` methods are accepted everywhere but offered only on .NET 10 and later with platform ML-KEM, so
  the same options work on .NET 8.
- **Host certificates.** When the host key verifier trusts a certificate authority for the host, the certificate versions of the
  allowed host key algorithms are asked for first, as `ssh` does, with the defaults or an `Append` or `Remove` list (whose patterns
  remove certificate algorithms too). A list that sets the order itself (`Only`, `Prepend`) is used as written, as `ssh` uses an
  explicit `HostKeyAlgorithms`: list the certificate algorithms in it, for example
  `SshAlgorithmList.Only("ssh-ed25519-cert-v01@openssh.com")` to accept the host's certificate only.
- **Strict key exchange** (the Terrapin fix) and `ext-info-c` are always offered; they are not part of `KexAlgorithms`.
- **What was negotiated:** `client.Algorithms`, also for an audit log.

## See also

- [Algorithms](../reference/algorithms.md): every algorithm, its default position, and whether FIPS mode allows it
- [FIPS mode](fips-mode.md)
- [Authentication](../authentication.md)
- <xref:SshSharp.SshAlgorithmList> and <xref:SshSharp.SshClientOptions> in the API reference
