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
using var rsa = await SshPrivateKey.LoadFileAsync("legacy.pem", passphrase: Environment.GetEnvironmentVariable("KEY_PASSPHRASE"));
var options = new SshClientOptions { UserName = "deploy", PrivateKeys = [ed25519, rsa], HostKeyVerifier = verifier };
```

Formats: the OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`, also encrypted), PKCS#8 (also encrypted, for RSA and ECDSA),
PKCS#1 and SEC1 PEM, and PuTTY `.ppk` versions 2 and 3 (also encrypted). Key types: Ed25519, ECDSA (nistp256/384/521) and
RSA (2048 bits or more; signs with `rsa-sha2-256/512` as the server's `server-sig-algs` allows). The server is asked
whether it accepts a key before anything is signed. `SshPrivateKey.Parse` reads a key from a string.

`Fingerprint`, `Comment`, `PublicKey` and `ToAuthorizedKeysLine()` describe a key. Dispose keys when done: it clears the
private key material.

### Generating keys

`SshPrivateKey.Generate` makes a new key pair, and `SaveAsync` writes it as `ssh-keygen` does: the private key in the OpenSSH
format (encrypted with `aes256-ctr` and `bcrypt_pbkdf` when you give a passphrase), and the public key next to it as `.pub`.

```csharp
using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, comment: "deploy@build-agent");
await key.SaveAsync("/home/deploy/.ssh/id_ed25519", passphrase);
Console.WriteLine(key.ToAuthorizedKeysLine()); // for the server's authorized_keys
```

The private key file is created readable only by the current user (mode 0600 on Unix; on Windows an ACL with just the current
user, as OpenSSH for Windows requires). `SaveAsync` never overwrites: it fails if either file exists. Types: `Ed25519`,
`EcdsaNistp256/384/521`, and `Rsa` (3072 bits by default, `rsaBits` for 2048 to 16384). `ToOpenSshPrivateKey(passphrase)` returns
the file's text instead, for a secret store; it holds the private key, so never log it. Keys loaded from any format can be
written this way too, which converts them to the OpenSSH format; keys held by an agent cannot.

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

Keys held by `ssh-agent` (or the Windows OpenSSH agent service, or PuTTY's Pageant) never enter your process: the agent signs.

```csharp
var agent = SshAgent.FromEnvironment(); // SSH_AUTH_SOCK, or on Windows the OpenSSH agent, else Pageant
var keys = agent is null ? [] : await agent.GetKeysAsync();
var options = new SshClientOptions { UserName = "deploy", PrivateKeys = keys, HostKeyVerifier = verifier };
```

`new SshAgent(path)` names a Unix socket or, on Windows, a pipe such as `\\.\pipe\openssh-ssh-agent`. Agent keys work with
`WithCertificate` too. A key the agent will not sign with (removed, or a declined `ssh-add -c` confirmation) is skipped.
FIDO security keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) and their certificates work through
the agent: the agent and the key's touch make the signature. `QueryExtensionsAsync` lists the protocol extensions an agent
supports (RFC 9987).

Keys added with destination constraints (`ssh-add -h host`) work as they do with `ssh`. Before each signature the agent connection
is bound to the SSH session (`session-bind@openssh.com`: the server's host key, the session identifier and the host key's
signature over it, which the agent verifies). Authentication is host-bound (`publickey-hostbound-v00@openssh.com`, signing the
server's host key too) whenever the server offers it, as OpenSSH 8.9 and later do. The agent then signs with a constrained key only
for the hosts it allows. Forwarded agent connections are bound as forwarding ones, so constraints along a chain of hosts
(`ssh-add -h "a>b"`) apply too. Agents without the extension sign as before.

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

Each session asks the server for it, and the agent connections the server opens are relayed to the local agent. A server that
announces RFC 9987's `agent-forward` (OpenSSH 10.3+) is asked with the standard `agent-req`; others with OpenSSH's
`auth-agent-req@openssh.com`. Forward only to
servers you trust: while you are connected, anyone with enough rights on the server can make your agent sign (they cannot read
the keys). Connecting by `ssh_config` alias follows `ForwardAgent yes`.

On Windows, when `SSH_AUTH_SOCK` is not set and the OpenSSH agent service is not running, `FromEnvironment()` finds PuTTY's Pageant
(0.75 and later) on the pipe it creates for the current user; `SshAgent.Pageant()` asks for Pageant specifically. Pageant's keys work like
any agent's, including for signing (`SshSignature`) and agent forwarding.

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
