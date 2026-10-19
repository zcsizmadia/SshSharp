using System.Security.Cryptography;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// Signs with a private key that SshSharp never sees: one in Azure Key Vault or AWS KMS, in an HSM behind PKCS#11, on a smart card.
/// Derive from it, then pass it to <see cref="SshPrivateKey.FromSigner"/> to use the key like any other (for public key
/// authentication, with a certificate, or for SSH signatures). For a key that .NET's <see cref="RSA"/> or <see cref="ECDsa"/> already
/// holds, including non-exportable Windows CNG keys, use <see cref="SshPrivateKey.FromRsa"/> or <see cref="SshPrivateKey.FromECDsa"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every signature is checked against <see cref="PublicKey"/> before it is used, so a signature in the wrong format, or from another
/// key, fails at once with a <see cref="CryptographicException"/> rather than as an authentication failure on the server.
/// </para>
/// <para>Key types: Ed25519, ECDSA (P-256, P-384, P-521) and RSA (2048 bits or more).</para>
/// </remarks>
public abstract class SshKeySigner
{
    /// <summary>Creates a signer for the key whose public half is <paramref name="publicKey"/>.</summary>
    /// <param name="publicKey">The public key in SSH wire format (what <c>authorized_keys</c> holds, base64-decoded).</param>
    /// <exception cref="FormatException">The public key is malformed, of an unsupported type, or an RSA key under 2048 bits.</exception>
    protected SshKeySigner(ReadOnlyMemory<byte> publicKey)
    {
        VerifyingKey key;
        try
        {
            key = VerifyingKey.Parse(publicKey.Span);
        }
        catch (SshProtocolException ex)
        {
            throw new FormatException($"Not a supported public key: {ex.Message}", ex);
        }

        if (key.KeyType == "ssh-rsa" && key.KeySizeBits < 2048)
        {
            throw new FormatException($"RSA keys must be at least 2048 bits; this one is {key.KeySizeBits}.");
        }

        PublicKey = publicKey.ToArray();
        KeyType = key.KeyType;
        _publicKey = SshPublicKey.FromVerifyingKey(key);
    }

    private readonly SshPublicKey _publicKey;

    /// <summary>The public key in SSH wire format.</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>
    /// <see cref="PublicKey"/> as an <see cref="SshPublicKey"/>, for example to write the <c>authorized_keys</c> line for a key held in a
    /// key service (<see cref="SshPublicKey.ToAuthorizedKeysLine"/>). It has no comment.
    /// </summary>
    public SshPublicKey GetPublicKey() => _publicKey;

    /// <summary>The key type: <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c> (or 384, 521) or <c>ssh-rsa</c>.</summary>
    public string KeyType { get; }

    /// <summary>
    /// The SSH signature algorithms this signer can sign with, most preferred first: <c>ssh-ed25519</c>, the key's own
    /// <c>ecdsa-sha2-*</c>, or <c>rsa-sha2-512</c> then <c>rsa-sha2-256</c> for RSA (never SHA-1 <c>ssh-rsa</c>). Override to offer
    /// fewer, for a service that signs only with SHA-256, for example. Read once, by <see cref="SshPrivateKey.FromSigner"/>.
    /// </summary>
    public virtual IReadOnlyList<string> SignatureAlgorithms => KeyType switch
    {
        "ssh-rsa" => [SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256],
        _ => [KeyType],
    };

    /// <summary>
    /// How <see cref="SignAsync"/> returns an ECDSA signature: r || s at the curve's width (<see cref="DSASignatureFormat.IeeeP1363FixedFieldConcatenation"/>,
    /// as .NET's <see cref="ECDsa.SignData(byte[], HashAlgorithmName)"/> does) by default, or DER (<see cref="DSASignatureFormat.Rfc3279DerSequence"/>),
    /// as many key services and PKCS#11 tokens answer. Ignored for other key types.
    /// </summary>
    public virtual DSASignatureFormat EcdsaSignatureFormat => DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

    /// <summary>
    /// Signs <see cref="SshSignRequest.Data"/> with <see cref="SshSignRequest.Algorithm"/>, one of <see cref="SignatureAlgorithms"/>; the
    /// algorithm fixes the hash, and a service that signs a digest hashes the data first. <see cref="SshSignRequest.Purpose"/> says what
    /// the signature is for (logging in, or an SSH signature with its <see cref="SshSignRequest.Namespace"/>), so the signer can refuse
    /// what its policy does not allow by throwing.
    /// </summary>
    /// <returns>
    /// The signature: the PKCS#1 v1.5 signature for RSA, the 64-byte signature for Ed25519, and for ECDSA the signature in
    /// <see cref="EcdsaSignatureFormat"/>. SshSharp encodes it as SSH carries it.
    /// </returns>
    /// <remarks>
    /// A <see cref="ValueTask{TResult}"/>, unlike SshSharp's public methods: this is a callback that many signers answer at once (a key in
    /// memory), so it should not allocate a task each time.
    /// </remarks>
    public abstract ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken);
}
