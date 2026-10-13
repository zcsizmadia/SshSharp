# Authentication

`SshClientOptions` carries the credentials. The client tries methods in `ssh`'s order: `none` (which tells it what the
server accepts), then **publickey** with each key, then **keyboard-interactive**, then **password**. When the server needs
more than one method (sshd's `AuthenticationMethods publickey,keyboard-interactive`, for example), it reports a partial
success and the client continues with the next method. If nothing works, `SshAuthenticationException.AllowedMethods`
lists what the server would accept.

## Password

```csharp
var options = new SshClientOptions { UserName = "deploy", Password = password, HostKeyVerifier = verifier };
```

When the server takes passwords only through keyboard-interactive (sshd with PAM and `PasswordAuthentication no`), the
password answers a round that asks for exactly one hidden input. It is never sent to a visible prompt or to a second round.

## Private keys

```csharp
using var ed25519 = await SshPrivateKey.LoadFileAsync("id_ed25519");
using var rsa = await SshPrivateKey.LoadFileAsync("legacy.pem", passphrase: "correct horse");
var options = new SshClientOptions { UserName = "deploy", PrivateKeys = [ed25519, rsa], HostKeyVerifier = verifier };
```

Formats: the OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`, also encrypted), PKCS#8 (also encrypted, for RSA and ECDSA),
PKCS#1 and SEC1 PEM, and PuTTY `.ppk` versions 2 and 3 (also encrypted). Key types: Ed25519, ECDSA (nistp256/384/521) and
RSA (2048 bits or more; signs with `rsa-sha2-256/512` as the server's `server-sig-algs` allows). The server is asked
whether it accepts a key before anything is signed. `SshPrivateKey.Parse` reads a key from a string.

`Fingerprint`, `Comment`, `PublicKey` and `ToAuthorizedKeysLine()` describe a key. Dispose keys when done: it clears the
private key material.

## Certificates

An OpenSSH user certificate (`id_ed25519-cert.pub`, made with `ssh-keygen -s`) lets servers that trust its authority
(`TrustedUserCAKeys`) accept the key without an `authorized_keys` entry.

```csharp
using var key = await SshPrivateKey.LoadFileAsync("id_ed25519");
var certificate = SshCertificate.Parse(await File.ReadAllTextAsync("id_ed25519-cert.pub"));
var options = new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key.WithCertificate(certificate), key], // the certificate first, then the plain key
    HostKeyVerifier = verifier,
};
```

Connecting by `ssh_config` alias finds certificates as `ssh` does: `CertificateFile` entries and `<identity>-cert.pub`.

## SSH agent

Keys held by `ssh-agent` (or the Windows OpenSSH agent service) never enter your process: the agent signs.

```csharp
var agent = SshAgent.FromEnvironment(); // SSH_AUTH_SOCK, or the Windows OpenSSH pipe
var keys = agent is null ? [] : await agent.GetKeysAsync();
var options = new SshClientOptions { UserName = "deploy", PrivateKeys = keys, HostKeyVerifier = verifier };
```

`new SshAgent(path)` names a Unix socket or, on Windows, a pipe such as `\\.\pipe\openssh-ssh-agent`. Agent keys work with
`WithCertificate` too. A key the agent will not sign with (removed, or a declined `ssh-add -c` confirmation) is skipped.

Connecting by `ssh_config` alias uses the agent automatically, as `ssh` does: `IdentityAgent`, else `SSH_AUTH_SOCK`.
Agent keys that match an `IdentityFile` come first (and an encrypted identity file is not opened at all), and
`IdentitiesOnly yes` leaves the agent's other keys out. `UseAgent = false` turns it off.

### Agent forwarding

`ForwardAgent` (`ssh -A`) offers your agent to the server, so programs there (`ssh`, `git`) can authenticate onward with your
keys while you are connected:

```csharp
var options = new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = keys,
    HostKeyVerifier = verifier,
    ForwardAgent = agent,
};
```

Each session asks the server for it, and the agent connections the server opens are relayed to the local agent. Forward only to
servers you trust: while you are connected, anyone with enough rights on the server can make your agent sign (they cannot read
the keys). Connecting by `ssh_config` alias follows `ForwardAgent yes`.

Pageant is not discovered automatically yet; it works through `IdentityAgent` when it exposes an OpenSSH-compatible pipe.

## Keyboard-interactive

One-time codes, PAM prompts and other challenge-response logins (RFC 4256):

```csharp
var options = new SshClientOptions
{
    UserName = "deploy",
    HostKeyVerifier = verifier,
    KeyboardInteractive = async (request, ct) =>
    {
        if (request.Instruction.Length > 0)
        {
            Console.WriteLine(request.Instruction);
        }

        var answers = new List<string>();
        foreach (var prompt in request.Prompts)
        {
            answers.Add(await ReadAnswerAsync(prompt.Text, hidden: !prompt.Echo, ct));
        }

        return answers; // or null to give up on this method
    },
};
```

Prompts and instructions come from the server: strip control characters before showing them in a terminal. A round with
no prompts is answered with an empty list.

## Banner

```csharp
var options = new SshClientOptions
{
    UserName = "deploy",
    Password = password,
    HostKeyVerifier = verifier,
    AuthenticationBanner = (text, ct) => { Console.Write(text); return ValueTask.CompletedTask; },
};
```

## With `ssh_config`

`PreferredAuthentications`, `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication`,
`IdentityFile`, `CertificateFile`, `IdentityAgent`, `IdentitiesOnly` and `BatchMode` (no prompts) are honored;
`SshConfigConnectOptions` supplies the password, passphrases and the keyboard-interactive handler.
