using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>A key held by an SSH agent: only its public half is here, and the agent makes every signature.</summary>
internal sealed class AgentKey : SshPrivateKey
{
    private readonly SshAgent _agent;

    private AgentKey(SshAgent agent, string keyType, byte[] blob, string comment, IReadOnlyList<string> algorithms, SshCertificate? certificate)
        : base(keyType, blob, comment)
    {
        _agent = agent;
        SignatureAlgorithms = algorithms;
        Certificate = certificate;
    }

    internal override IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>A key for <paramref name="blob"/>, or null when its type is one SshSharp cannot authenticate with.</summary>
    public static AgentKey? TryCreate(SshAgent agent, byte[] blob, string comment)
    {
        string keyType;
        try
        {
            keyType = new SshReader(blob).ReadUtf8String();
        }
        catch (SshProtocolException)
        {
            return null;
        }

        SshCertificate? certificate = null;
        var plainType = keyType;
        if (SshCertificate.IsCertificateAlgorithm(keyType))
        {
            try
            {
                certificate = SshCertificate.FromBlob(blob);
            }
            catch (SshProtocolException)
            {
                return null; // a certificate type SshSharp does not read (security-key certificates, for example)
            }

            if (certificate.Type != SshCertificateType.User)
            {
                return null;
            }

            plainType = SshCertificate.BaseAlgorithm(keyType);
        }

        IReadOnlyList<string>? algorithms = plainType switch
        {
            "ssh-rsa" => [SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256],
            SshAlgorithms.SshEd25519 or "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" => [plainType],

            // FIDO security keys: the agent (and the key's touch) makes the signature; the server checks it.
            "sk-ssh-ed25519@openssh.com" or "sk-ecdsa-sha2-nistp256@openssh.com" when certificate is null => [plainType],
            _ => null,
        };
        if (algorithms is null)
        {
            return null;
        }

        if (certificate is not null)
        {
            algorithms = [.. algorithms.Select(a => a + "-cert-v01@openssh.com")];
        }

        return new AgentKey(agent, keyType, blob, comment, algorithms, certificate);
    }

    internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) =>
        throw new NotSupportedException("A key held by an SSH agent signs only asynchronously.");

    internal override ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (!SignatureAlgorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            throw new ArgumentException($"This {KeyType} key does not sign with '{algorithm}'.", nameof(algorithm));
        }

        return _agent.SignAsync(PublicKey, SshCertificate.BaseAlgorithm(algorithm), data, cancellationToken);
    }

    private protected override void DisposeCore()
    {
        // Nothing here: the private key stays in the agent.
    }
}
