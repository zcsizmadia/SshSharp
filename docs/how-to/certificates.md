# Certificates

An OpenSSH user certificate is a public key signed by a certificate authority (CA), with the principals (user names) it may log in
as and a validity period. Servers that trust the CA (sshd's `TrustedUserCAKeys`) accept it without an `authorized_keys` entry, which
is how many organizations hand out short-lived SSH access. Host certificates work the other way, letting clients trust servers by
their CA.

## When to use

- Your organization issues SSH certificates (`ssh-keygen -s`, HashiCorp Vault's SSH secrets engine, step-ca, Teleport, cloud
  identity-aware proxies).
- You want access that expires on its own instead of keys in `authorized_keys`.

## Log in with a certificate

[!code-csharp[](../snippets/Keys.cs#certificate)]

`WithCertificate` pairs the key with its certificate; the pair is offered first, and the plain key after it in case the server
does not take the certificate.

## A certificate for an agent key

[!code-csharp[](../snippets/Keys.cs#certificate-agent)]

## From `ssh_config`

Connecting by alias finds certificates as `ssh` does: `CertificateFile` entries, and `<identity>-cert.pub` next to each identity
file.

## Trust hosts by their certificates

A host certificate lets clients trust every server the CA signed, without a `known_hosts` line per server. Add the CA to
`known_hosts`:

```
@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

`KnownHostsVerifier` then accepts a host certificate from that CA for matching host names, within its validity period. To apply
your own rules, see the [custom verifier](verify-host-keys.md#write-a-verifier).

## Notes and pitfalls

- **Principals.** The server checks that the user name you log in as is one of the certificate's principals
  (`certificate.Principals`); a mismatch is an ordinary authentication failure.
- **Expiry.** An expired certificate is refused by the server; check `ValidBefore` and renew in time, as above.
- **Critical options** such as `force-command` or `source-address` are enforced by the server (`certificate.CriticalOptions` lists
  them).
- **Revocation.** Servers revoke user certificates with `RevokedKeys`; on the client side, `RevokedHostKeys` can revoke host
  certificates by serial or key id.

## See also

- [Authentication: certificates](../authentication.md#certificates)
- [Host keys](../host-keys.md)
- <xref:SshSharp.SshCertificate> in the API reference
