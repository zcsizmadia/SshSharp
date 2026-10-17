# Keys and the SSH agent

Public-key authentication is the usual way to log in to SSH servers. SshSharp loads key files, uses the keys an SSH agent holds,
generates new keys, and signs with keys that never leave a TPM, smart card, HSM or cloud key service.

## When to use which

| Where the key lives | Use |
|---|---|
| A file (`~/.ssh/id_ed25519`, a `.pem`, a PuTTY `.ppk`) | `SshPrivateKey.LoadAsync` |
| A secret store or CI variable | `SshPrivateKey.Parse` |
| `ssh-agent`, the Windows OpenSSH agent, or Pageant (including FIDO security keys) | `SshAgent.FromEnvironment()` and `GetKeysAsync` |
| A Windows key store, the TPM, a smart card | `SshPrivateKey.FromRsa` / `FromECDsa` with `RSACng` / `ECDsaCng` |
| A cloud KMS, an HSM, a signing service | `SshPrivateKey.FromSigner` with your `SshKeySigner` |

Connecting by `ssh_config` alias needs none of this: `IdentityFile` and the agent are used automatically.

## Load a key file

[!code-csharp[](../snippets/Keys.cs#load-key)]

Formats: OpenSSH (`BEGIN OPENSSH PRIVATE KEY`, encrypted too), PKCS#8 (encrypted too), PKCS#1 and SEC1 PEM, and PuTTY `.ppk` versions
2 and 3. Key types: Ed25519, ECDSA (P-256, P-384, P-521) and RSA of 2048 bits or more.

## Load a key from a secret

[!code-csharp[](../snippets/Keys.cs#key-from-secret)]

## Use the SSH agent

[!code-csharp[](../snippets/Keys.cs#agent)]

Agent keys work wherever key files do, including with certificates and for [signing files](../signing.md). FIDO security keys
(`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) work through the agent: the agent and a touch of the key make
each signature.

## Forward the agent

[!code-csharp[](../snippets/Keys.cs#agent-forwarding)]

> [!WARNING]
> While you are connected, anyone with enough rights on the server can ask your forwarded agent to sign (they cannot read the keys).
> Forward only to servers you trust, and prefer keys added with destination constraints
> ([`SshAgentKeyConstraints.Destinations`](../authentication.md#managing-the-agents-keys)).

## Add a key to the agent

[!code-csharp[](../snippets/Keys.cs#agent-add)]

## Generate a key

[!code-csharp[](../snippets/Keys.cs#generate)]

`SaveAsync` writes the private key in the OpenSSH format (encrypted with `aes256-ctr` and `bcrypt_pbkdf` when given a passphrase),
readable only by the current user, and the public key next to it as `.pub`. It never overwrites an existing file.

## Use a key in the Windows key store or the TPM

[!code-csharp[](../snippets/Keys.cs#cng)]

The same works with `ECDsaCng` and `SshPrivateKey.FromECDsa`, and with any software `RSA` or `ECDsa`. The
[sample tool](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples)'s `run-cng` command logs in this way.

## Use a key held by a remote service

Derive from `SshKeySigner`: SshSharp gives it each request to sign, with the algorithm and what the signature is for, and checks
the answer against the public key before using it.

[!code-csharp[](../snippets/Keys.cs#signer)]

[!code-csharp[](../snippets/Keys.cs#use-signer)]

## Notes and pitfalls

- **Order.** Keys are tried in the order given, and the server is asked whether it accepts each one before anything is signed. A
  server that allows few attempts (sshd's `MaxAuthTries`, 6 by default) may disconnect before it reaches a key late in a long
  list: put the right key first.
- **Dispose keys.** Disposing a loaded key clears its private key material. The client does not dispose the keys you pass it.
- **RSA.** RSA keys sign with `rsa-sha2-256` or `rsa-sha2-512`, never SHA-1 `ssh-rsa`. Keys under 2048 bits are refused.
- **ssh.com format** keys are not read; convert them with `ssh-keygen -i`.
- **Never log a key.** `ToOpenSshPrivateKey` returns the private key's text, for a secret store.

## See also

- [Authentication](../authentication.md) (in-depth: method order, agent constraints, keyboard-interactive, banners)
- [Certificates](certificates.md)
- [Signing files and commits](../signing.md)
- <xref:SshSharp.SshPrivateKey>, <xref:SshSharp.SshAgent> and <xref:SshSharp.SshKeySigner> in the API reference
