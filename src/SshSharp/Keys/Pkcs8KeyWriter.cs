using System.Security.Cryptography;

namespace SshSharp.Keys;

/// <summary>
/// Writes PKCS#8 PEM (RFC 5208, RFC 5958): <c>BEGIN PRIVATE KEY</c>, or <c>BEGIN ENCRYPTED PRIVATE KEY</c> (PBES2 with PBKDF2-HMAC-SHA256
/// and AES-256-CBC, RFC 8018) when there is a passphrase. RSA and ECDSA keys are exported and encrypted by the platform; an Ed25519
/// PrivateKeyInfo (RFC 8410) is built here, as the platform has no Ed25519, and cannot be encrypted.
/// </summary>
internal static class Pkcs8KeyWriter
{
    /// <summary>
    /// PBKDF2-HMAC-SHA256 iterations for an encrypted key: OWASP's recommendation (2023) for password storage. OpenSSL's default, 2048,
    /// is far too few to slow down guessing a passphrase; loading the key costs a fraction of a second.
    /// </summary>
    public const int Iterations = 600_000;

    private static readonly PbeParameters Encryption = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Iterations);

    // The DER of an RFC 8410 PrivateKeyInfo up to the seed: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET
    // STRING (32 bytes) } }. The structure is fixed, so it is written as bytes, which keeps the seed out of an ASN.1 writer's buffers.
    private static ReadOnlySpan<byte> Ed25519Prefix =>
        [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

    /// <summary>The PEM text as UTF-8 bytes; the caller zeroes them.</summary>
    public static byte[] Write(SshPrivateKey key, string? passphrase)
    {
        var encrypted = !string.IsNullOrEmpty(passphrase);
        var der = key.ExportPkcs8(encrypted ? passphrase : null);
        try
        {
            return OpenSshKeyWriter.Armor(encrypted ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY", der, 64);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }
    }

    /// <summary>A platform key's PrivateKeyInfo, or its EncryptedPrivateKeyInfo when <paramref name="passphrase"/> is not null.</summary>
    public static byte[] Export(AsymmetricAlgorithm key, string? passphrase) =>
        passphrase is null ? key.ExportPkcs8PrivateKey() : key.ExportEncryptedPkcs8PrivateKey(passphrase, Encryption);

    /// <summary>The PrivateKeyInfo of an Ed25519 key (RFC 8410 section 7), as OpenSSL writes it: version 0, without the public key.</summary>
    public static byte[] Ed25519(ReadOnlySpan<byte> seed)
    {
        var der = new byte[Ed25519Prefix.Length + seed.Length];
        Ed25519Prefix.CopyTo(der);
        seed.CopyTo(der.AsSpan(Ed25519Prefix.Length));
        return der;
    }
}
