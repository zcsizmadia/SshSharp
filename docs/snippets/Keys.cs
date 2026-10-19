using System.Runtime.Versioning;
using System.Security.Cryptography;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/agent-and-keys.md, docs/how-to/certificates.md and docs/how-to/kerberos.md.</summary>
internal static class Keys
{
    public static async Task LoadKeyAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <load-key>
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        using var key = await SshPrivateKey.LoadAsync(
            Path.Combine(home, ".ssh", "id_ed25519"),
            passphrase: Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE"),   // null for a key without one
            cancellationToken);
        Console.WriteLine($"{key.KeyType} {key.Fingerprint} {key.Comment}");

        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = verifier,
        }, cancellationToken);
        // </load-key>
    }

    public static async Task KeyFromSecretAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <key-from-secret>
        // A key kept in a secret store (here: an environment variable a CI system fills), never in a file on the build agent.
        using var key = SshPrivateKey.Parse(
            Environment.GetEnvironmentVariable("DEPLOY_SSH_KEY") ?? throw new InvalidOperationException("DEPLOY_SSH_KEY is not set."));
        // </key-from-secret>
        await Task.CompletedTask;
        _ = (verifier, cancellationToken);
    }

    public static async Task AgentAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <agent>
        // SSH_AUTH_SOCK, else on Windows the OpenSSH agent service, else Pageant (found without blocking a thread).
        var agent = await SshAgent.FromEnvironmentAsync(cancellationToken) ?? throw new InvalidOperationException("No SSH agent is running.");
        var keys = await agent.GetKeysAsync(cancellationToken);   // the agent signs; the private keys never enter this process

        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = keys,
            HostKeyVerifier = verifier,
        }, cancellationToken);
        // </agent>
    }

    public static async Task AgentForwardingAsync(SshAgent agent, SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <agent-forwarding>
        await using var client = await SshClient.ConnectAsync("build.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await agent.GetKeysAsync(cancellationToken),
            HostKeyVerifier = verifier,
            ForwardAgent = agent,   // ssh -A: git on the server can authenticate with your keys while you are connected
        }, cancellationToken);
        await client.RunCommandAsync("git -C /srv/app pull", cancellationToken);
        // </agent-forwarding>
    }

    public static async Task InProcessAgentAsync(SshKeySigner kmsSigner, SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <agent-in-process>
        // An agent served by this process: no ssh-agent needed. Keys from files, generated keys, and keys behind an SshKeySigner.
        using var deployKey = await SshPrivateKey.LoadAsync("deploy_ed25519", Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE"), cancellationToken);
        using var kmsKey = SshPrivateKey.FromSigner(kmsSigner, comment: "kms:deploy");   // the private key stays in the KMS
        var agent = SshAgent.FromKeys(deployKey, kmsKey);

        await using var client = await SshClient.ConnectAsync("build.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await agent.GetKeysAsync(cancellationToken),   // authenticate through it, as with any agent
            HostKeyVerifier = verifier,
            ForwardAgent = agent,   // and forward it: ssh and git on the server sign through this process
        }, cancellationToken);
        await client.RunCommandAsync("git -C /srv/app pull", cancellationToken);
        // </agent-in-process>
    }

    public static async Task AgentFilterAsync(SshAgent agent, IReadOnlySet<SshPublicKey> appServers, SshHostKeyVerifier verifier,
        CancellationToken cancellationToken)
    {
        // <agent-filter>
        // appServers: the host keys of the servers the bastion may log in to with your keys (from their known_hosts lines).
        await using var client = await SshClient.ConnectAsync("bastion.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await agent.GetKeysAsync(cancellationToken),
            HostKeyVerifier = verifier,
            ForwardAgent = agent,
            ForwardAgentFilter = (request, _) => ValueTask.FromResult(request switch
            {
                // List every key; decide when one is used.
                { Operation: SshAgentOperation.ListKeys } => true,

                // Logins onward, as deploy, to those servers only (OpenSSH 8.9 or later on the bastion reports where it logs in to).
                // Never file or commit signatures, and nothing for a destination that is not known.
                { Purpose: SshSignaturePurpose.Authentication, UserName: "deploy", DestinationHostKey: { } destination }
                    => appServers.Contains(destination),
                _ => false,
            }),
        }, cancellationToken);
        // </agent-filter>
    }

    public static SshClientOptions AgentKnownPurposes(SshAgent agent, IReadOnlyList<SshPrivateKey> keys, SshHostKeyVerifier verifier)
    {
        // <agent-known-purposes>
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = keys,
            HostKeyVerifier = verifier,
            ForwardAgent = agent,

            // Logins and SSH signatures (git, ssh-keygen -Y) only. Purpose is null for data of a form SshSharp does not recognise
            // (pam_ssh_agent_auth's challenge, for one): refused here, as is issuing certificates.
            ForwardAgentFilter = (request, _) => ValueTask.FromResult(
                request.Operation == SshAgentOperation.ListKeys
                || request.Purpose is SshSignaturePurpose.Authentication or SshSignaturePurpose.FileSignature),
        };
        // </agent-known-purposes>
        return options;
    }

    public static async Task AgentConfirmAsync(SshAgent agent, SshHostKeyVerifier verifier, Func<string, CancellationToken, Task<bool>> askUser,
        CancellationToken cancellationToken)
    {
        // <agent-confirm>
        // As ssh-add -c: each signature waits for the user. askUser is your UI (a dialog, a push notification).
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await agent.GetKeysAsync(cancellationToken),
            HostKeyVerifier = verifier,
            ForwardAgent = agent,
            ForwardAgentFilter = async (request, ct) =>
                request.Operation == SshAgentOperation.ListKeys
                || await askUser(
                    $"Allow a {request.Purpose?.ToString() ?? "unrecognised"} signature with {request.Key.Fingerprint} ({request.Key.Comment})" +
                    (request.DestinationHostKey is { } destination ? $" for the server with host key {destination.Fingerprint}?" : "?"),
                    ct),
        };
        // </agent-confirm>
        await using var client = await SshClient.ConnectAsync("build.example.com", 22, options, cancellationToken);
    }

    public static async Task AddToAgentAsync(CancellationToken cancellationToken)
    {
        // <agent-add>
        var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
        using var key = await SshPrivateKey.LoadAsync("deploy_ed25519", Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE"), cancellationToken);
        await agent.AddKeyAsync(key, new SshAgentKeyConstraints { Lifetime = TimeSpan.FromHours(1) }, cancellationToken); // ssh-add -t 1h
        // </agent-add>
    }

    public static async Task AddKeysToAgentAskAsync(CancellationToken cancellationToken)
    {
        // <add-keys-to-agent-ask>
        // ~/.ssh/config:  Host *
        //                   AddKeysToAgent ask
        // Once a server has accepted a key from an identity file, ask before it goes to the agent, as ssh asks with ssh-askpass.
        await using var client = await SshClient.ConnectAsync("deploy@build", new SshConfigConnectOptions
        {
            ConfirmAddKeyToAgent = (prompt, ct) =>
            {
                Console.Write($"Add key {prompt.IdentityFile} ({prompt.Comment ?? prompt.Fingerprint}) to the agent? [y/N] ");
                return ValueTask.FromResult(Console.ReadLine()?.Trim() is "y" or "Y");
            },
        }, cancellationToken);
        // </add-keys-to-agent-ask>
    }

    public static async Task GenerateAsync(CancellationToken cancellationToken)
    {
        // <generate>
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, comment: "ci-deploy");
        await key.SaveAsync("ci_ed25519", Environment.GetEnvironmentVariable("NEW_KEY_PASSPHRASE"), cancellationToken); // and ci_ed25519.pub
        Console.WriteLine(key.ToAuthorizedKeysLine()); // the line for the server's ~/.ssh/authorized_keys
        // </generate>
    }

    public static async Task SaveWithRoundsAsync(SshPrivateKey key, CancellationToken cancellationToken)
    {
        // <save-rounds>
        // As ssh-keygen -a 64: more bcrypt_pbkdf rounds make guessing the passphrase slower (and loading the key too).
        await key.SaveAsync("ci_ed25519", Environment.GetEnvironmentVariable("NEW_KEY_PASSPHRASE"), kdfRounds: 64, cancellationToken);
        // </save-rounds>
    }

    public static async Task ExportAsync(CancellationToken cancellationToken)
    {
        // <export>
        var passphrase = Environment.GetEnvironmentVariable("KEY_PASSPHRASE") ?? throw new InvalidOperationException("KEY_PASSPHRASE is not set.");
        using var key = await SshPrivateKey.LoadAsync("id_ecdsa", passphrase, cancellationToken);

        // For PuTTY, Pageant or WinSCP: a version 3 .ppk file (and id_ecdsa.ppk.pub), readable only by the current user.
        await key.SaveAsync("id_ecdsa.ppk", SshPrivateKeyFormat.Putty, passphrase, cancellationToken);

        // For OpenSSL or the .NET cryptography APIs: PKCS#8 PEM, here as text for a secret store. It holds the private key: never log it.
        var pem = key.ToPkcs8PrivateKey(passphrase);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromEncryptedPem(pem, passphrase);
        // </export>
    }

    public static async Task PublicKeysAsync(SshAgent agent, CancellationToken cancellationToken)
    {
        // <public-key>
        // A .pub file, or one authorized_keys line without options: "<type> <base64> [comment]".
        var key = SshPublicKey.Parse(await File.ReadAllTextAsync("id_ed25519.pub", cancellationToken));
        Console.WriteLine($"{key.KeySizeBits} {key.Fingerprint} {key.Comment} ({key.KeyType})");   // as ssh-keygen -lf prints it
        Console.WriteLine(key.GetFingerprint(HashAlgorithmName.MD5));                                // ssh-keygen -l -E md5: MD5:aa:bb:...

        // Which of the agent's keys is it? Keys are equal when their key bytes are; comments are ignored.
        var agentKeys = await agent.GetKeysAsync(cancellationToken);
        var match = agentKeys.FirstOrDefault(k => k.GetPublicKey() == key);
        // </public-key>
        _ = match;
    }

    public static async Task<bool> VerifyBySignerKeyAsync(CancellationToken cancellationToken)
    {
        // <signer-key>
        var releaseKey = SshPublicKey.Parse(await File.ReadAllTextAsync("release_ed25519.pub", cancellationToken));
        var signature = SshSignature.Parse(await File.ReadAllTextAsync("release.tar.gz.sig", cancellationToken));
        await using var file = File.OpenRead("release.tar.gz");
        var valid = await signature.VerifyAsync(file, "file", releaseKey, cancellationToken);   // signed by releaseKey, for "file"
        // </signer-key>
        return valid;
    }

    public static bool VerifySignature(SshPublicKey key, byte[] data, byte[] signature)
    {
        // <verify-signature>
        // signature is in the SSH encoding (string algorithm, string signature), as an agent or an SshKeySigner makes it.
        // False for a wrong or malformed signature, and for SHA-1 ssh-rsa.
        var valid = key.VerifySignature(data, signature);
        // </verify-signature>
        return valid;
    }

    [SupportedOSPlatform("windows")]
    public static async Task CngAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <cng>
        // A non-exportable RSA key in a Windows key store: the TPM (Microsoft Platform Crypto Provider), a smart card, or the
        // software provider. SshSharp sees the public key and asks the key for each signature.
        using var rsa = new RSACng(CngKey.Open("deploy-key"));
        using var key = SshPrivateKey.FromRsa(rsa, comment: "cng:deploy-key");   // rsa stays ours: disposing key does not dispose it

        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = verifier,
        }, cancellationToken);
        // </cng>
    }

    // <signer>
    /// <summary>A key held by a remote signing service (a cloud KMS or an HSM): only the public key is local.</summary>
    internal sealed class KmsSigner(IKeyService service, string keyId, ReadOnlyMemory<byte> publicKey) : SshKeySigner(publicKey)
    {
        // ECDSA P-256 in the service: it signs a SHA-256 digest and answers in DER.
        public override DSASignatureFormat EcdsaSignatureFormat => DSASignatureFormat.Rfc3279DerSequence;

        public override async ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken)
        {
            if (request.Purpose != SshSignaturePurpose.Authentication)
            {
                throw new UnauthorizedAccessException("This key is for logging in only.");
            }

            return await service.SignDigestAsync(keyId, SHA256.HashData(request.Data.Span), cancellationToken);
        }
    }

    /// <summary>Your key service's client.</summary>
    internal interface IKeyService
    {
        Task<byte[]> SignDigestAsync(string keyId, byte[] digest, CancellationToken cancellationToken);
    }
    // </signer>

    public static void UseSigner(IKeyService service, ReadOnlyMemory<byte> publicKeyBlob)
    {
        // <use-signer>
        using var key = SshPrivateKey.FromSigner(new KmsSigner(service, "ssh-deploy", publicKeyBlob), comment: "kms:ssh-deploy");
        // Use it like any other key: PrivateKeys = [key]. Each signature is checked against the public key before it is sent.
        // </use-signer>
    }

    public static async Task SignerPublicKeyAsync(IKeyService service, ReadOnlyMemory<byte> publicKeyBlob, CancellationToken cancellationToken)
    {
        // <signer-public-key>
        var signer = new KmsSigner(service, "ssh-deploy", publicKeyBlob);
        var line = signer.GetPublicKey().ToAuthorizedKeysLine() + " kms:ssh-deploy";   // "ssh-ed25519 AAAA... kms:ssh-deploy"
        await File.AppendAllTextAsync("authorized_keys.d/deploy", line + "\n", cancellationToken);
        // </signer-public-key>
    }

    public static async Task CertificateAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <certificate>
        using var key = await SshPrivateKey.LoadAsync("id_ed25519", cancellationToken: cancellationToken);
        var certificate = SshCertificate.Parse(await File.ReadAllTextAsync("id_ed25519-cert.pub", cancellationToken));

        if (certificate.ValidBefore < DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new InvalidOperationException($"Certificate {certificate.KeyId} expires at {certificate.ValidBefore:u}; renew it.");
        }

        Console.WriteLine($"{certificate.KeyId}: principals {string.Join(", ", certificate.Principals)}, signed by {certificate.AuthorityFingerprint}");

        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key.WithCertificate(certificate), key],   // the certificate first, the plain key as a fallback
            HostKeyVerifier = verifier,
        }, cancellationToken);
        // </certificate>
    }

    public static async Task CertificateFromAgentAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <certificate-agent>
        // A short-lived certificate from your CA, for a key the agent holds.
        var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
        var certificate = SshCertificate.Parse(await File.ReadAllTextAsync("id_ed25519-cert.pub", cancellationToken));
        var agentKey = (await agent.GetKeysAsync(cancellationToken)).First(k => k.PublicKey.Span.SequenceEqual(certificate.PublicKey.Span));
        var options = new SshClientOptions { UserName = "deploy", PrivateKeys = [agentKey.WithCertificate(certificate)], HostKeyVerifier = verifier };
        // </certificate-agent>
        _ = options;
    }

    public static async Task KerberosAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <kerberos>
        if (!SshGssapiOptions.IsSupported)
        {
            throw new PlatformNotSupportedException("Kerberos authentication needs .NET 10.");
        }

        await using var client = await SshClient.ConnectAsync("build.corp.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            HostKeyVerifier = verifier,
            Gssapi = new SshGssapiOptions(),   // the current ticket (Windows logon, or kinit); host/build.corp.example.com@REALM
        }, cancellationToken);
        // </kerberos>
    }

    public static async Task KerberosByAddressAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <kerberos-address>
        await using var client = await SshClient.ConnectAsync("192.0.2.10", 22, new SshClientOptions
        {
            UserName = "deploy",
            HostKeyVerifier = verifier,
            // Kerberos names services by DNS name: say which one when connecting by address or over a stream.
            Gssapi = new SshGssapiOptions { TargetHost = "build.corp.example.com" },
        }, cancellationToken);
        // </kerberos-address>
    }

    public static async Task CheckCertificateAsync(CancellationToken cancellationToken)
    {
        // <certificate-check>
        // The authority you trust, and a certificate someone presents (a user's -cert.pub, say, uploaded to your bastion's portal).
        var trustedCa = SshPublicKey.Parse(await File.ReadAllTextAsync("user_ca.pub", cancellationToken));
        var certificate = SshCertificate.Parse(await File.ReadAllTextAsync("id_ed25519-cert.pub", cancellationToken));

        if (!certificate.IsValidFor(trustedCa, SshCertificateType.User, "deploy", DateTimeOffset.UtcNow, out var reason))
        {
            throw new InvalidOperationException($"Certificate {certificate.KeyId} is not acceptable: {reason}.");
        }
        // </certificate-check>
    }

    public static string? ExtensionValue(SshCertificate certificate)
    {
        // <certificate-extension-values>
        // A vendor extension's value: null when the CA did not write the extension.
        var login = certificate.ExtensionValues.TryGetValue("login@example.com", out var value) ? value : null;
        var canPty = certificate.ExtensionValues.ContainsKey("permit-pty");   // the standard ones have no value
        // </certificate-extension-values>
        return canPty ? login : null;
    }

    public static async Task CheckRevocationAsync(SshCertificate certificate, SshPublicKey userKey, CancellationToken cancellationToken)
    {
        // <certificate-revocation>
        // The file sshd's RevokedKeys names: a KRL from ssh-keygen -k, or one public key per line.
        var revoked = await SshKeyRevocationList.LoadAsync("/etc/ssh/revoked_keys", cancellationToken);

        if (revoked.IsRevoked(certificate))   // its serial, its key id, its key, or its authority's key
        {
            throw new InvalidOperationException($"Certificate {certificate.KeyId} (serial {certificate.Serial}) is revoked.");
        }

        var keyRevoked = revoked.IsRevoked(userKey);   // a plain key, from an authorized_keys line, say
        // </certificate-revocation>
        _ = keyRevoked;
    }

    public static async Task CheckCertificatePartsAsync(SshPublicKey trustedCa, SshCertificate certificate)
    {
        // <certificate-check-parts>
        // Only the signature: proves the holder of AuthorityKey issued it, not that you trust that authority.
        var signed = certificate.VerifySignature();

        // Your own rules, for an application that enforces the critical options itself.
        var acceptable = signed
            && certificate.GetAuthorityKey() == trustedCa
            && certificate.Type == SshCertificateType.User
            && certificate.IsValidAt(DateTimeOffset.UtcNow)
            && certificate.Principals.Contains("deploy")
            && certificate.CriticalOptions.Keys.All(option => option == SshCertificateBuilder.ForceCommand);
        // </certificate-check-parts>
        await Task.CompletedTask;
        _ = acceptable;
    }

    public static async Task IssueUserCertificateAsync(SshHostKeyVerifier verifier, string buildId, ulong buildNumber, CancellationToken cancellationToken)
    {
        // <certificate-issue-user>
        // The CA key, read from a secret store (see below for one that stays in an agent or a KMS).
        using var ca = SshPrivateKey.Parse(Environment.GetEnvironmentVariable("SSH_USER_CA_KEY") ?? throw new InvalidOperationException("SSH_USER_CA_KEY is not set."));

        // A key for this build only, and a certificate for it that expires with the build.
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, $"ci-build-{buildId}");
        var builder = new SshCertificateBuilder(key.GetPublicKey(), SshCertificateType.User, keyId: $"ci-build-{buildId}")
        {
            Serial = buildNumber,                              // unique, so a revocation list can name it
            Principals = { "deploy" },                         // the user it may log in as
            ValidBefore = DateTimeOffset.UtcNow.AddMinutes(30),
        };
        builder.Extensions.Clear();                            // commands only: no terminal, no forwarding
        var certificate = await builder.SignAsync(ca, cancellationToken);

        await using var client = await SshClient.ConnectAsync("build.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key.WithCertificate(certificate)],
            HostKeyVerifier = verifier,
        }, cancellationToken);
        // </certificate-issue-user>
    }

    public static async Task IssueHostCertificateAsync(SshPrivateKey ca, CancellationToken cancellationToken)
    {
        // <certificate-issue-host>
        var hostKey = SshPublicKey.Parse(await File.ReadAllTextAsync("ssh_host_ed25519_key.pub", cancellationToken));
        var builder = new SshCertificateBuilder(hostKey, SshCertificateType.Host, keyId: "web1")
        {
            Principals = { "web1.example.com", "web1" },
            ValidBefore = DateTimeOffset.UtcNow.AddDays(90),
        };
        var certificate = await builder.SignAsync(ca, cancellationToken);

        // sshd_config: HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
        await File.WriteAllTextAsync("ssh_host_ed25519_key-cert.pub", certificate.ToAuthorizedKeysLine() + "\n", cancellationToken);
        // </certificate-issue-host>
    }

    public static async Task CertificateAuthorityInAgentAsync(CancellationToken cancellationToken)
    {
        // <certificate-ca-agent>
        // The CA key stays in the agent (ssh-add on the signing host); only its fingerprint is configuration.
        var caFingerprint = Environment.GetEnvironmentVariable("SSH_USER_CA_FINGERPRINT") ?? throw new InvalidOperationException("Set SSH_USER_CA_FINGERPRINT.");
        var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
        var ca = (await agent.GetKeysAsync(cancellationToken)).Single(k => k.Fingerprint == caFingerprint);
        // </certificate-ca-agent>
        _ = ca;
    }

    // <certificate-ca-signer>
    /// <summary>
    /// A certificate authority whose key is in a key service: it signs certificates only, so a stolen API credential cannot use the CA
    /// key to log in anywhere. <c>signDigest</c> stands for your KMS client (an Ed25519 key signs the data itself; see SshKeySigner).
    /// </summary>
    internal sealed class CertificateAuthoritySigner(byte[] publicKey, Func<byte[], CancellationToken, Task<byte[]>> signDigest)
        : SshKeySigner(publicKey)
    {
        // An ECDSA P-256 key in the service: it signs a SHA-256 digest and answers DER.
        public override DSASignatureFormat EcdsaSignatureFormat => DSASignatureFormat.Rfc3279DerSequence;

        public override async ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken) =>
            request.Purpose == SshSignaturePurpose.Certificate
                ? await signDigest(SHA256.HashData(request.Data.Span), cancellationToken)
                : throw new UnauthorizedAccessException("The CA key issues certificates only.");
    }
    // </certificate-ca-signer>
}
