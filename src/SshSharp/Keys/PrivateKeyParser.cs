using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>Reads private keys from the OpenSSH key format and from PEM (PKCS#8, PKCS#1, SEC1).</summary>
internal static class PrivateKeyParser
{
    private const int MinimumRsaBits = 2048;
    private const string OpenSshBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string OpenSshEnd = "-----END OPENSSH PRIVATE KEY-----";
    private static readonly byte[] OpenSshMagic = "openssh-key-v1\0"u8.ToArray();

    private const string OidRsa = "1.2.840.113549.1.1.1";
    private const string OidEc = "1.2.840.10045.2.1";
    private const string OidEd25519 = "1.3.101.112";

    public static SshPrivateKey Parse(string text, string? passphrase) => SelfChecked(ParseUnchecked(text, passphrase));

    private static SshPrivateKey ParseUnchecked(string text, string? passphrase)
    {
        try
        {
            if (text.Contains(OpenSshBegin, StringComparison.Ordinal))
            {
                return ParseOpenSsh(text, passphrase);
            }

            if (text.StartsWith("PuTTY-User-Key-File-", StringComparison.Ordinal))
            {
                throw new FormatException("PuTTY .ppk keys are not supported yet; convert the key with puttygen to OpenSSH format.");
            }

            if (text.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
            {
                return ParseEncryptedPkcs8(text, passphrase);
            }

            if (text.Contains("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
            {
                return ParsePkcs8(text);
            }

            if (text.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal))
            {
                throw new FormatException(
                    "Legacy encrypted PEM keys (Proc-Type: 4,ENCRYPTED) are not supported; convert with 'ssh-keygen -p -f <file>' (OpenSSH format) or to PKCS#8.");
            }

            if (text.Contains("-----BEGIN RSA PRIVATE KEY-----", StringComparison.Ordinal))
            {
                var rsa = RSA.Create();
                return Import(rsa, () => rsa.ImportFromPem(text), () => FromRsa(rsa, null));
            }

            if (text.Contains("-----BEGIN EC PRIVATE KEY-----", StringComparison.Ordinal))
            {
                var ecdsa = ECDsa.Create();
                return Import(ecdsa, () => ecdsa.ImportFromPem(text), () => FromEcdsa(ecdsa, null));
            }

            throw new FormatException("Not a supported private key format (expected an OpenSSH, PKCS#8, PKCS#1 or SEC1 private key).");
        }
        catch (SshProtocolException ex)
        {
            throw new FormatException($"The private key is malformed: {ex.Message}", ex);
        }
    }

    // ---- OpenSSH format (PROTOCOL.key) ----

    private static SshPrivateKey ParseOpenSsh(string text, string? passphrase)
    {
        var start = text.IndexOf(OpenSshBegin, StringComparison.Ordinal) + OpenSshBegin.Length;
        var end = text.IndexOf(OpenSshEnd, start, StringComparison.Ordinal);
        if (end < 0)
        {
            throw new FormatException("The OpenSSH private key has no END line.");
        }

        byte[] data;
        try
        {
            data = Convert.FromBase64String(text[start..end]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("The OpenSSH private key is not valid base64.", ex);
        }

        try
        {
            if (!data.AsSpan().StartsWith(OpenSshMagic))
            {
                throw new FormatException("Not an OpenSSH private key (bad magic).");
            }

            var reader = new SshReader(data.AsSpan(OpenSshMagic.Length));
            var cipher = reader.ReadUtf8String();
            var kdf = reader.ReadUtf8String();
            var kdfOptions = reader.ReadString();
            if (reader.ReadUInt32() != 1)
            {
                throw new FormatException("OpenSSH key files with more than one key are not supported.");
            }

            var publicBlob = reader.ReadString().ToArray();
            var privateSection = reader.ReadString();

            SshPrivateKey key;
            if (cipher == "none" && kdf == "none")
            {
                key = ParseOpenSshPrivate(privateSection);
            }
            else
            {
                // AEAD ciphers append their tag after the encrypted section.
                var decrypted = OpenSshKeyDecryptor.Decrypt(cipher, kdf, kdfOptions, privateSection, ref reader, passphrase);
                try
                {
                    key = ParseOpenSshPrivate(decrypted);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                }
            }

            if (!key.PublicKey.Span.SequenceEqual(publicBlob))
            {
                key.Dispose();
                throw new FormatException("The OpenSSH private key does not match its public key.");
            }

            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private static SshPrivateKey ParseOpenSshPrivate(ReadOnlySpan<byte> section)
    {
        var reader = new SshReader(section);
        if (reader.ReadUInt32() != reader.ReadUInt32())
        {
            throw new FormatException("The private key check values differ (wrong passphrase or a corrupt file).");
        }

        var type = reader.ReadUtf8String();
        SshPrivateKey key;
        switch (type)
        {
            case SshAlgorithms.SshEd25519:
            {
                var publicKey = reader.ReadString();
                var secret = reader.ReadString(); // seed || public key
                if (publicKey.Length != Ed25519.PublicKeySize || secret.Length != 64 || !secret[32..].SequenceEqual(publicKey))
                {
                    throw new FormatException("The Ed25519 private key is malformed.");
                }

                key = new SshPrivateKey.Ed25519Key(secret[..32].ToArray(), Comment(ref reader));
                break;
            }

            case SshAlgorithms.EcdsaNistp256 or SshAlgorithms.EcdsaNistp384 or SshAlgorithms.EcdsaNistp521:
            {
                var curve = reader.ReadUtf8String() switch
                {
                    "nistp256" => NistCurve.P256,
                    "nistp384" => NistCurve.P384,
                    "nistp521" => NistCurve.P521,
                    var other => throw new FormatException($"Unsupported ECDSA curve '{other}'."),
                };
                var point = reader.ReadString();
                var d = reader.ReadMpint();
                if ("ecdsa-sha2-" + curve.Name != type || point.Length != 1 + (2 * curve.FieldSize) || point[0] != 4 || d.Length > curve.FieldSize)
                {
                    throw new FormatException("The ECDSA private key is malformed.");
                }

                var parameters = new ECParameters
                {
                    Curve = curve.Curve,
                    Q = new ECPoint { X = point.Slice(1, curve.FieldSize).ToArray(), Y = point[(1 + curve.FieldSize)..].ToArray() },
                    D = new byte[curve.FieldSize],
                };
                d.CopyTo(parameters.D.AsSpan(curve.FieldSize - d.Length));
                var ecdsa = ECDsa.Create();
                try
                {
                    ecdsa.ImportParameters(parameters);
                }
                catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
                {
                    ecdsa.Dispose();
                    throw new FormatException("The ECDSA private key is not valid for its curve.", ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(parameters.D);
                }

                key = new SshPrivateKey.EcdsaKey(curve, ecdsa, Comment(ref reader));
                break;
            }

            case "ssh-rsa":
            {
                var n = reader.ReadMpint();
                var e = reader.ReadMpint();
                var d = reader.ReadMpint();
                var iqmp = reader.ReadMpint();
                var p = reader.ReadMpint();
                var q = reader.ReadMpint();
                RequireRsaSize(n.TrimStart((byte)0).Length * 8);
                key = SshPrivateKey.RsaKey.FromComponents(n, e, d, iqmp, p, q, Comment(ref reader));
                break;
            }

            default:
                throw new FormatException($"Unsupported private key type '{type}'.");
        }

        // Padding is 1, 2, 3, ... up to the cipher block size.
        var padding = reader.Remaining;
        for (var i = 0; i < padding.Length; i++)
        {
            if (padding[i] != (byte)(i + 1))
            {
                key.Dispose();
                throw new FormatException("The private key padding is invalid.");
            }
        }

        return key;
    }

    private static string? Comment(ref SshReader reader)
    {
        var comment = Encoding.UTF8.GetString(reader.ReadString());
        return comment.Length == 0 ? null : comment;
    }

    // ---- PEM ----

    private static SshPrivateKey ParsePkcs8(string text)
    {
        var der = PemBody(text, "PRIVATE KEY");
        try
        {
            switch (Pkcs8Algorithm(der))
            {
                case OidRsa:
                {
                    var rsa = RSA.Create();
                    return Import(rsa, () => rsa.ImportPkcs8PrivateKey(der, out _), () => FromRsa(rsa, null));
                }

                case OidEc:
                {
                    var ecdsa = ECDsa.Create();
                    return Import(ecdsa, () => ecdsa.ImportPkcs8PrivateKey(der, out _), () => FromEcdsa(ecdsa, null));
                }

                case OidEd25519:
                    return new SshPrivateKey.Ed25519Key(Ed25519Seed(der), null);

                case var other:
                    throw new FormatException($"Unsupported PKCS#8 key algorithm {other}.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }
    }

    private static SshPrivateKey ParseEncryptedPkcs8(string text, string? passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new FormatException("The private key is encrypted; a passphrase is required.");
        }

        // The framework decrypts PKCS#8 for RSA and ECDSA keys; try each.
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromEncryptedPem(text, passphrase);
            return FromRsa(rsa, null);
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromEncryptedPem(text, passphrase);
            return FromEcdsa(ecdsa, null);
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            ecdsa.Dispose();
            throw new FormatException("Could not decrypt the private key: the passphrase is wrong, or it is not an RSA or ECDSA key.", ex);
        }
    }

    /// <summary>
    /// Signs and verifies once. Platforms differ in how much they check when a key is imported (macOS accepts some inconsistent RSA keys
    /// that then fail to sign), so every RSA and ECDSA key is proven usable here, and a broken one is a format error on every platform.
    /// </summary>
    private static SshPrivateKey SelfChecked(SshPrivateKey key)
    {
        if (key is SshPrivateKey.Ed25519Key)
        {
            return key; // its public key was derived from the seed and compared already
        }

        try
        {
            var data = "SshSharp private key consistency check"u8;
            var algorithm = key.SignatureAlgorithms[0];
            if (SshPublicKey.Parse(key.PublicKey.Span).VerifySignature(algorithm, key.Sign(algorithm, data), data))
            {
                return key;
            }
        }
        catch (Exception ex) when (ex is CryptographicException or SshProtocolException)
        {
            // Reported below.
        }

        key.Dispose();
        throw new FormatException("The private key is inconsistent: its parts do not form a usable key.");
    }

    private static SshPrivateKey Import(IDisposable algorithm, Action import, Func<SshPrivateKey> create)
    {
        try
        {
            import();
            return create();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or PlatformNotSupportedException)
        {
            algorithm.Dispose();
            throw new FormatException("The PEM private key could not be read.", ex);
        }
        catch
        {
            algorithm.Dispose();
            throw;
        }
    }

    private static SshPrivateKey.RsaKey FromRsa(RSA rsa, string? comment)
    {
        RequireRsaSize(rsa.KeySize);
        return new SshPrivateKey.RsaKey(rsa, comment);
    }

    private static SshPrivateKey.EcdsaKey FromEcdsa(ECDsa ecdsa, string? comment)
    {
        var curve = ecdsa.ExportParameters(false).Curve;
        var nist = curve.Oid?.Value switch
        {
            "1.2.840.10045.3.1.7" => NistCurve.P256,
            "1.3.132.0.34" => NistCurve.P384,
            "1.3.132.0.35" => NistCurve.P521,
            _ => ecdsa.KeySize switch
            {
                256 => NistCurve.P256,
                384 => NistCurve.P384,
                521 => NistCurve.P521,
                _ => throw new FormatException("Only nistp256, nistp384 and nistp521 ECDSA keys are supported."),
            },
        };
        return new SshPrivateKey.EcdsaKey(nist, ecdsa, comment);
    }

    private static void RequireRsaSize(int bits)
    {
        if (bits < MinimumRsaBits)
        {
            throw new FormatException($"RSA keys must be at least {MinimumRsaBits} bits; this one is {bits}.");
        }
    }

    private static byte[] PemBody(string text, string label)
    {
        if (!PemEncoding.TryFind(text, out var fields) || text[fields.Label] != label)
        {
            throw new FormatException($"Expected a PEM '{label}' block.");
        }

        return Convert.FromBase64String(text[fields.Base64Data]);
    }

    /// <summary>The algorithm OID of a PKCS#8 PrivateKeyInfo.</summary>
    private static string Pkcs8Algorithm(byte[] der)
    {
        try
        {
            var info = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            info.ReadInteger(); // version
            return info.ReadSequence().ReadObjectIdentifier();
        }
        catch (AsnContentException ex)
        {
            throw new FormatException("The PKCS#8 key is malformed.", ex);
        }
    }

    /// <summary>RFC 8410: the Ed25519 private key is an OCTET STRING holding an OCTET STRING with the 32-byte seed.</summary>
    private static byte[] Ed25519Seed(byte[] der)
    {
        try
        {
            var info = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            info.ReadInteger();
            info.ReadSequence();
            var wrapped = info.ReadOctetString();
            var seed = new AsnReader(wrapped, AsnEncodingRules.DER).ReadOctetString();
            CryptographicOperations.ZeroMemory(wrapped);
            return seed.Length == Ed25519.SeedSize ? seed : throw new FormatException("The Ed25519 PKCS#8 key must hold a 32-byte seed.");
        }
        catch (AsnContentException ex)
        {
            throw new FormatException("The Ed25519 PKCS#8 key is malformed.", ex);
        }
    }
}
