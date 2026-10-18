namespace SshSharp;

/// <summary>What a signature made with a private key is for (<see cref="SshSignRequest.Purpose"/>).</summary>
public enum SshSignaturePurpose
{
    /// <summary>Public key authentication: proving the key to a server while logging in (RFC 4252 section 7).</summary>
    Authentication,

    /// <summary>An SSH signature over a file or other data (SSHSIG, <c>ssh-keygen -Y sign</c>), with its <see cref="SshSignRequest.Namespace"/>.</summary>
    FileSignature,

    /// <summary>
    /// Issuing an OpenSSH certificate as its certificate authority (<see cref="SshCertificateBuilder.SignAsync"/>, <c>ssh-keygen -s</c>):
    /// the data is the certificate without its signature. A signer that holds a CA key can allow this purpose alone.
    /// </summary>
    Certificate,

    /// <summary>
    /// Data of a form SshSharp does not recognise, which a program on a server asked an in-process agent (<see cref="SshAgent.FromKeys"/>)
    /// to sign through agent forwarding: a challenge of its own, such as pam_ssh_agent_auth's. A signer whose policy allows only the
    /// purposes above refuses it by throwing.
    /// </summary>
    Other,
}

/// <summary>
/// One signature asked of an <see cref="SshKeySigner"/>: the algorithm, the data, and what the signature is for, so a signer can apply
/// a policy (a key service that allows authentication only, say), log what it signs, or ask its user.
/// </summary>
public sealed class SshSignRequest
{
    /// <summary>Creates a request (SshSharp makes them; this is for testing a signer).</summary>
    /// <param name="algorithm">The signature algorithm, one of <see cref="SshKeySigner.SignatureAlgorithms"/>.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="purpose">What the signature is for.</param>
    public SshSignRequest(string algorithm, ReadOnlyMemory<byte> data, SshSignaturePurpose purpose)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        Algorithm = algorithm;
        Data = data;
        Purpose = purpose;
    }

    /// <summary>
    /// The signature algorithm. It fixes the hash: SHA-256 for <c>rsa-sha2-256</c> and <c>ecdsa-sha2-nistp256</c>, SHA-384 for nistp384,
    /// SHA-512 for <c>rsa-sha2-512</c> and nistp521; Ed25519 signs the data itself.
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// The data to sign: for authentication, the session identifier and the login request; for a file signature, the SSHSIG structure
    /// holding the namespace and the file's hash; for a certificate, the certificate up to its signature. It is valid only until the signing task completes; copy it to keep it.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>What the signature is for.</summary>
    public SshSignaturePurpose Purpose { get; }

    /// <summary>For a <see cref="SshSignaturePurpose.FileSignature"/>, its namespace (for example <c>git</c> or <c>file</c>); otherwise null.</summary>
    public string? Namespace { get; init; }

    /// <summary>The same request with another algorithm (a certificate signs as its key).</summary>
    internal SshSignRequest WithAlgorithm(string algorithm) => new(algorithm, Data, Purpose) { Namespace = Namespace };
}
