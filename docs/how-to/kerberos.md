# Kerberos

With a Kerberos ticket, an SSH server can let you in without a password or key: `gssapi-with-mic` authentication (RFC 4462), what
`ssh` does with `GSSAPIAuthentication yes`. The ticket comes from the platform: the Windows logon session in an Active Directory
domain (SSPI), or elsewhere the credential cache that `kinit` fills (MIT or Heimdal GSS-API).

## When to use

- Servers are joined to Active Directory or an MIT Kerberos realm, and users already have tickets.
- A service account should log in with its domain identity instead of a stored key.

## Log in with the current ticket

[!code-csharp[](../snippets/Keys.cs#kerberos)]

## Connect by address

Kerberos names the server's service principal after its DNS name (`host/<name>@REALM`), so connecting by IP address or over a
stream needs the name given explicitly:

[!code-csharp[](../snippets/Keys.cs#kerberos-address)]

## From `ssh_config`

```
Host build
  HostName build.corp.example.com
  GSSAPIAuthentication yes
  GSSAPIDelegateCredentials no
```

`HostName` is the target, and `PreferredAuthentications` can place `gssapi-with-mic` anywhere in the order.

## Notes and pitfalls

- **.NET 10 only.** It relies on `NegotiateAuthentication.ComputeIntegrityCheck`, which .NET 8 lacks. Check
  `SshGssapiOptions.IsSupported`; on .NET 8 the method is not offered and the others are tried.
- **Order.** When on, Kerberos is tried first (as in `ssh`'s default order), and only if the server offers it. If it fails (no
  ticket, an unknown service principal), the other methods follow.
- **Delegation.** `DelegateCredentials = true` forwards your ticket to the server so programs there can authenticate onward as you.
  Leave it off unless you trust the server.
- **Explicit credentials.** `SshGssapiOptions.Credential` takes a user, password and realm instead of the current ticket; read the
  password from a secret store.
- **Host keys still matter.** The host key is verified as always: `gssapi-keyex` (Kerberos instead of host keys) is not supported.

## See also

- [Authentication: Kerberos](../authentication.md#kerberos-gssapi)
- <xref:SshSharp.SshGssapiOptions> in the API reference
