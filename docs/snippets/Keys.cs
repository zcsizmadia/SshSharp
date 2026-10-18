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
        // SSH_AUTH_SOCK, else on Windows the OpenSSH agent service, else Pageant.
        var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
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

    public static async Task AddToAgentAsync(CancellationToken cancellationToken)
    {
        // <agent-add>
        var agent = SshAgent.FromEnvironment() ?? throw new InvalidOperationException("No SSH agent is running.");
        using var key = await SshPrivateKey.LoadAsync("deploy_ed25519", Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE"), cancellationToken);
        await agent.AddKeyAsync(key, new SshAgentKeyConstraints { Lifetime = TimeSpan.FromHours(1) }, cancellationToken); // ssh-add -t 1h
        // </agent-add>
    }

    public static async Task GenerateAsync(CancellationToken cancellationToken)
    {
        // <generate>
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, comment: "ci-deploy");
        await key.SaveAsync("ci_ed25519", Environment.GetEnvironmentVariable("NEW_KEY_PASSPHRASE"), cancellationToken); // and ci_ed25519.pub
        Console.WriteLine(key.ToAuthorizedKeysLine()); // the line for the server's ~/.ssh/authorized_keys
        // </generate>
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
        var valid = signature.GetPublicKey() == releaseKey && await signature.VerifyAsync(file, "file", cancellationToken);
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
}
