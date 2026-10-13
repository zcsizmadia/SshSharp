using System.Buffers;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>
/// Freshly generated private keys written in the formats SshPrivateKey reads, so no private key is ever committed. The OpenSSH writer
/// follows PROTOCOL.key; interop CI checks the reader against keys made by the real ssh-keygen.
/// </summary>
internal static class TestKeys
{
    public static string OpenSshEd25519(out byte[] publicBlob, string comment = "test@example", int? checkOverride = null, byte[]? padding = null,
        string? passphrase = null, string cipher = "aes256-ctr")
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        publicBlob = Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(pub);
            w.WriteString([.. seed, .. pub]);
        }, comment, checkOverride, padding, passphrase, cipher);
    }

    public static string OpenSshEcdsa(ECCurve curve, string curveName, out byte[] publicBlob, string comment = "")
    {
        using var ecdsa = ECDsa.Create(curve);
        var p = ecdsa.ExportParameters(true);
        byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
        var type = "ecdsa-sha2-" + curveName;
        publicBlob = Blob(w => { w.WriteString(type); w.WriteString(curveName); w.WriteString(point); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString(type);
            w.WriteString(curveName);
            w.WriteString(point);
            w.WriteMpint(p.D);
        }, comment);
    }

    public static string OpenSshRsa(int bits, out byte[] publicBlob)
    {
        using var rsa = RSA.Create(bits);
        var p = rsa.ExportParameters(true);
        publicBlob = Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent); w.WriteMpint(p.Modulus); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint(p.Modulus);
            w.WriteMpint(p.Exponent);
            w.WriteMpint(p.D);
            w.WriteMpint(p.InverseQ);
            w.WriteMpint(p.P);
            w.WriteMpint(p.Q);
        }, "rsa-key");
    }

    /// <summary>RFC 8410 PKCS#8 for an Ed25519 seed.</summary>
    public static string Pkcs8Ed25519(out byte[] publicBlob)
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        publicBlob = Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });

        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteOctetString(seed);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.112");
            }

            writer.WriteOctetString(inner.Encode());
        }

        return PemEncoding.WriteString("PRIVATE KEY", writer.Encode()) + "\n";
    }

    /// <summary>A PuTTY .ppk file (version 2 or 3, optionally aes256-cbc encrypted) for a fresh Ed25519, ECDSA P-256 or RSA key.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350", Justification = "PuTTY version 2 files are defined with SHA-1.")]
    public static string Ppk(int version, string keyType, out byte[] publicBlob, string? passphrase = null, string comment = "ppk-test",
        bool corruptMac = false)
    {
        byte[] privateBlob;
        switch (keyType)
        {
            case "ssh-ed25519":
            {
                var seed = RandomNumberGenerator.GetBytes(32);
                var pub = new byte[32];
                Ed25519.GetPublicKey(seed, pub);
                publicBlob = Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });
                privateBlob = Blob(w => w.WriteString(seed));
                break;
            }

            case "ecdsa-sha2-nistp256":
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var p = ecdsa.ExportParameters(true);
                publicBlob = EcdsaPublicBlob(ecdsa, "nistp256");
                privateBlob = Blob(w => w.WriteMpint(p.D));
                break;
            }

            default:
            {
                using var rsa = RSA.Create(2048);
                var p = rsa.ExportParameters(true);
                publicBlob = RsaPublicBlob(rsa);
                privateBlob = Blob(w => { w.WriteMpint(p.D); w.WriteMpint(p.P); w.WriteMpint(p.Q); w.WriteMpint(p.InverseQ); });
                break;
            }
        }

        var encryption = passphrase is null ? "none" : "aes256-cbc";
        var phrase = Encoding.UTF8.GetBytes(passphrase ?? string.Empty);
        if (passphrase is not null)
        {
            // Padding to the cipher block (PuTTY fills it with hash bytes; any bytes do, as the MAC covers them).
            privateBlob = [.. privateBlob, .. RandomNumberGenerator.GetBytes((16 - (privateBlob.Length % 16)) % 16)];
        }

        var salt = RandomNumberGenerator.GetBytes(16);
        byte[] cipherKey = [], iv = new byte[16], macKey;
        if (version == 3)
        {
            if (passphrase is not null)
            {
                var derived = new byte[80];
                Argon2.Hash(Argon2Type.Argon2id, phrase, salt, 64, 2, 1, derived);
                (cipherKey, iv, macKey) = (derived[..32], derived[32..48], derived[48..]);
            }
            else
            {
                macKey = [];
            }
        }
        else
        {
            macKey = SHA1.HashData([.. "putty-private-key-file-mac-key"u8, .. phrase]);
            cipherKey = [.. SHA1.HashData([0, 0, 0, 0, .. phrase]), .. SHA1.HashData([0, 0, 0, 1, .. phrase])];
            cipherKey = cipherKey[..32];
        }

        var publicCopy = publicBlob;
        var macData = Blob(w =>
        {
            w.WriteString(keyType);
            w.WriteString(encryption);
            w.WriteString(comment);
            w.WriteString(publicCopy);
            w.WriteString(privateBlob);
        });
        var mac = version == 3 ? HMACSHA256.HashData(macKey, macData) : HMACSHA1.HashData(macKey, macData);
        if (corruptMac)
        {
            mac[0] ^= 1;
        }

        var stored = privateBlob;
        if (passphrase is not null)
        {
            using var aes = Aes.Create();
            aes.Key = cipherKey;
            stored = aes.EncryptCbc(privateBlob, iv, PaddingMode.None);
        }

        static string Lines(byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            var lines = Enumerable.Range(0, (base64.Length + 63) / 64).Select(i => base64.Substring(i * 64, Math.Min(64, base64.Length - (i * 64)))).ToList();
            return $"{lines.Count}\n{string.Join('\n', lines)}\n";
        }

        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"PuTTY-User-Key-File-{version}: {keyType}\nEncryption: {encryption}\nComment: {comment}\n");
        sb.Append("Public-Lines: ").Append(Lines(publicBlob));
        if (version == 3 && passphrase is not null)
        {
            sb.Append(CultureInfo.InvariantCulture, $"Key-Derivation: Argon2id\nArgon2-Memory: 64\nArgon2-Passes: 2\nArgon2-Parallelism: 1\nArgon2-Salt: {Convert.ToHexString(salt).ToLowerInvariant()}\n");
        }

        sb.Append("Private-Lines: ").Append(Lines(stored));
        sb.Append(CultureInfo.InvariantCulture, $"Private-MAC: {Convert.ToHexString(mac).ToLowerInvariant()}\n");
        return sb.ToString();
    }

    public static byte[] RsaPublicBlob(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        return Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent); w.WriteMpint(p.Modulus); });
    }

    public static byte[] EcdsaPublicBlob(ECDsa ecdsa, string curveName)
    {
        var q = ecdsa.ExportParameters(false).Q;
        return Blob(w => { w.WriteString("ecdsa-sha2-" + curveName); w.WriteString(curveName); w.WriteString([4, .. q.X!, .. q.Y!]); });
    }

    public static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static string OpenSsh(byte[] publicBlob, Action<SshWriter> writeKey, string comment, int? checkOverride = null, byte[]? padding = null,
        string? passphrase = null, string cipher = "aes256-ctr")
    {
        var check = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        var section = Blob(w =>
        {
            w.WriteUInt32(check);
            w.WriteUInt32(checkOverride is { } other ? (uint)other : check);
            writeKey(w);
            w.WriteString(comment);
        });
        var blockSize = passphrase is null ? 8 : 16;
        var pad = padding ?? Enumerable.Range(1, (blockSize - (section.Length % blockSize)) % blockSize).Select(i => (byte)i).ToArray();
        byte[] privateSection = [.. section, .. pad];

        // Encrypted like ssh-keygen: bcrypt_pbkdf(passphrase, salt, 16 rounds) gives key || IV for the cipher.
        var salt = RandomNumberGenerator.GetBytes(16);
        byte[] tag = [];
        if (passphrase is not null)
        {
            var gcm = cipher == "aes256-gcm@openssh.com";
            var keyAndIv = new byte[32 + (gcm ? 12 : 16)];
            BcryptPbkdf.DeriveKey(Encoding.UTF8.GetBytes(passphrase), salt, 16, keyAndIv);
            if (gcm)
            {
                tag = new byte[16];
                var sealedSection = new byte[privateSection.Length];
                using var aesGcm = new AesGcm(keyAndIv.AsSpan(0, 32), 16);
                aesGcm.Encrypt(keyAndIv.AsSpan(32), privateSection, sealedSection, tag);
                privateSection = sealedSection;
            }
            else
            {
                using var ctr = new AesCtr(keyAndIv.AsSpan(0, 32), keyAndIv.AsSpan(32));
                ctr.Transform(privateSection);
            }
        }

        var body = Blob(w =>
        {
            w.WriteBytes("openssh-key-v1\0"u8);
            w.WriteString(passphrase is null ? "none" : cipher);
            w.WriteString(passphrase is null ? "none" : "bcrypt");
            if (passphrase is null)
            {
                w.WriteString(ReadOnlySpan<byte>.Empty);
            }
            else
            {
                w.WriteString(Blob(o => { o.WriteString(salt); o.WriteUInt32(16); }));
            }

            w.WriteUInt32(1);
            w.WriteString(publicBlob);
            w.WriteString(privateSection);
            w.WriteBytes(tag);
        });

        var base64 = Convert.ToBase64String(body);
        var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < base64.Length; i += 70)
        {
            sb.Append(base64.AsSpan(i, Math.Min(70, base64.Length - i))).Append('\n');
        }

        return sb.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
    }
}
