# Signing files and git commits

SSH keys can sign data as well as log in. `SshSignature` makes and checks signatures in OpenSSH's SSHSIG format, the one
`ssh-keygen -Y sign` and `-Y verify` use and git uses for signed commits and tags with `gpg.format=ssh`. Signatures made here
verify with `ssh-keygen`, and the reverse is also true.

## Signing

```csharp
using var key = await SshPrivateKey.LoadFileAsync("/home/me/.ssh/id_ed25519", passphrase);
await using var release = File.OpenRead("release.tar.gz");
var signature = await SshSignature.SignAsync(key, release, "file");
await File.WriteAllTextAsync("release.tar.gz.sig", signature.ToString());   // -----BEGIN SSH SIGNATURE----- ...
```

The **namespace** (`"file"` here) says what the signature is for: git uses `git`, `ssh-keygen -Y sign` asks for one, and an
application can use its own (`backup@example.com`). A signature is valid only for its namespace, so one made for one purpose
cannot be passed off as another.

Any key works, Ed25519, ECDSA or RSA (signed with `rsa-sha2-512`), including a key held by an agent, which never leaves the
agent:

```csharp
var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
var key = (await agent.GetKeysAsync()).First();
var signature = await SshSignature.SignAsync(key, commitBytes, "git");
```

A key paired with a certificate (`key.WithCertificate(...)`) signs with the certificate. A verifier that trusts the certificate's
authority then accepts it (see `cert-authority` below). Messages are hashed with SHA-512 by default; pass `"sha256"` for SHA-256.

## Verifying

Verification asks two questions. Is the signature valid, and is the key that made it allowed to sign as the person it claims?
`SshAllowedSigners` answers both, as `ssh-keygen -Y verify` does:

```csharp
var signers = await SshAllowedSigners.LoadFileAsync("/etc/ssh/allowed_signers");
var signature = SshSignature.Parse(await File.ReadAllTextAsync("release.tar.gz.sig"));
await using var file = File.OpenRead("release.tar.gz");
if (!await signers.VerifyAsync(signature, "release@example.com", file, "file"))
{
    throw new InvalidOperationException("The release is not signed by the release key.");
}
```

`signers.FindPrincipals(signature)` returns who the signing key may sign as (`ssh-keygen -Y find-principals`). For example,
it finds the principal to check before verifying. `signature.Verify(message, namespace)` checks only the signature itself.
Use it when you compare `signature.PublicKey` with the key you expect.

### The allowed-signers file

The format is OpenSSH's (`man ssh-keygen`, ALLOWED SIGNERS), the same file git's `gpg.ssh.allowedSignersFile` names:

```
# principals            [options]                               key
alice@example.com       ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
*@example.com,!intern@example.com namespaces="git" ssh-ed25519 AAAAC3...
*@example.com           cert-authority ssh-ed25519 AAAAC3...    company signing CA
release@example.com     valid-after="20260101",valid-before="20271231Z" ecdsa-sha2-nistp256 AAAAE2...
```

- **Principals** are a comma-separated pattern list (`*`, `?`, `!` excludes) and are case-sensitive.
- **`namespaces="..."`** limits the namespaces the key may sign for (patterns, too).
- **`cert-authority`** makes the key a certificate authority. A signature by any *user* certificate it issued is accepted for
  a principal named in the certificate, while the certificate is valid and if the line's principals allow it.
- **`valid-after`** and **`valid-before`** bound when the key is accepted: `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`,
  in local time, or UTC with a trailing `Z`. Checks use the current time unless `time:` is given.

A malformed line, or an option this library does not know, rejects the whole file with the line number, as `ssh-keygen`
does, rather than skipping a line that may have been meant to restrict a key.

## Git

Git signs by running `ssh-keygen -Y sign -n git` over the commit object and stores the armored signature in the commit's
`gpgsig` header. To check a commit in .NET, verify `SshSignature.Parse(gpgsig)` against the commit object without that
header, with namespace `git`. The allowed-signers file is the one `gpg.ssh.allowedSignersFile` names, and the principal is
the committer's email.
