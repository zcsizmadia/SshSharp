using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>
/// Reads PuTTY private key files (<c>.ppk</c>), versions 2 and 3, unencrypted or encrypted with <c>aes256-cbc</c>.
/// Version 2 derives the key with SHA-1 and authenticates the file with HMAC-SHA1; version 3 uses Argon2 and HMAC-SHA256.
/// The MAC covers the key type, encryption, comment, public blob and decrypted private blob, so a wrong passphrase or any edit is detected.
/// </summary>
internal static class PuttyKeyParser
{
    // Argon2 limits beyond anything PuTTYgen writes; a hostile file must not make loading take minutes or gigabytes.
    private const int MaxArgon2MemoryKiB = 1 << 20;
    private const int MaxArgon2Passes = 1000;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350",
        Justification = "PuTTY's version 2 key file format is defined with SHA-1 and HMAC-SHA1; reading existing files requires them. Nothing on the wire uses SHA-1.")]
    public static SshPrivateKey Parse(string text, string? passphrase)
    {
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var position = 0;

        string Header(string expected, bool trim = true)
        {
            while (position < lines.Length && lines[position].Length == 0)
            {
                position++;
            }

            if (position >= lines.Length)
            {
                throw new FormatException($"The .ppk file ends before '{expected}'.");
            }

            var line = lines[position++];
            var colon = line.IndexOf(": ", StringComparison.Ordinal);
            if (colon < 0 || line[..colon] != expected)
            {
                throw new FormatException($"Expected '{expected}' in the .ppk file.");
            }

            // PuTTY takes a value to the end of the line, and its MAC covers the comment as it is, so the comment is not trimmed.
            return trim ? line[(colon + 2)..].Trim() : line[(colon + 2)..];
        }

        byte[] Base64Lines(string header)
        {
            var count = Number(Header(header));
            if (count < 0 || count > 10_000 || position + count > lines.Length)
            {
                throw new FormatException("The .ppk file is truncated.");
            }

            var base64 = string.Concat(lines[position..(position + count)]).Trim();
            position += count;
            return Convert.FromBase64String(base64);
        }

        var first = lines[0];
        var version = first.StartsWith("PuTTY-User-Key-File-3: ", StringComparison.Ordinal) ? 3
            : first.StartsWith("PuTTY-User-Key-File-2: ", StringComparison.Ordinal) ? 2
            : throw new FormatException("Unsupported PuTTY key file version (versions 2 and 3 are supported).");
        var algorithm = Header($"PuTTY-User-Key-File-{version}");
        var encryption = Header("Encryption");
        var comment = Header("Comment", trim: false);
        var publicBlob = Base64Lines("Public-Lines");

        Argon2Type argonType = default;
        int memory = 0, passes = 0, parallelism = 0;
        byte[] argonSalt = [];
        if (version == 3 && encryption != "none")
        {
            argonType = Header("Key-Derivation") switch
            {
                "Argon2id" => Argon2Type.Argon2id,
                "Argon2i" => Argon2Type.Argon2i,
                "Argon2d" => Argon2Type.Argon2d,
                var other => throw new FormatException($"Unsupported .ppk key derivation '{other}'."),
            };
            memory = Number(Header("Argon2-Memory"));
            passes = Number(Header("Argon2-Passes"));
            parallelism = Number(Header("Argon2-Parallelism"));
            argonSalt = Convert.FromHexString(Header("Argon2-Salt"));
            if (memory > MaxArgon2MemoryKiB || passes > MaxArgon2Passes || parallelism is < 1 or > 64)
            {
                throw new FormatException("The .ppk file's Argon2 parameters are out of range.");
            }
        }

        var privateBlob = Base64Lines("Private-Lines");
        var mac = Convert.FromHexString(Header("Private-MAC"));

        if (encryption is not ("none" or "aes256-cbc"))
        {
            throw new FormatException($"Unsupported .ppk encryption '{encryption}'.");
        }

        var encrypted = encryption != "none";
        if (encrypted && string.IsNullOrEmpty(passphrase))
        {
            throw new FormatException("The private key is encrypted; a passphrase is required.");
        }

        var passphraseBytes = Encoding.UTF8.GetBytes(encrypted ? passphrase! : string.Empty);
        byte[] cipherKey = [], iv = new byte[16], macKey;
        try
        {
            if (version == 3)
            {
                if (encrypted)
                {
                    var derived = new byte[80];
                    Argon2.Hash(argonType, passphraseBytes, argonSalt, memory, passes, parallelism, derived);
                    cipherKey = derived[..32];
                    iv = derived[32..48];
                    macKey = derived[48..];
                    CryptographicOperations.ZeroMemory(derived);
                }
                else
                {
                    macKey = [];
                }
            }
            else
            {
                macKey = SHA1.HashData([.. "putty-private-key-file-mac-key"u8, .. passphraseBytes]);
                if (encrypted)
                {
                    cipherKey = [.. SHA1.HashData([0, 0, 0, 0, .. passphraseBytes]), .. SHA1.HashData([0, 0, 0, 1, .. passphraseBytes])];
                    cipherKey = cipherKey[..32];
                }
            }

            if (encrypted)
            {
                if (privateBlob.Length == 0 || privateBlob.Length % 16 != 0)
                {
                    throw new FormatException("The .ppk private blob has an invalid length.");
                }

                using var aes = Aes.Create();
                aes.Key = cipherKey;
                privateBlob = aes.DecryptCbc(privateBlob, iv, PaddingMode.None);
            }

            var macData = SshPrivateKey.Encode(w =>
            {
                w.WriteString(algorithm);
                w.WriteString(encryption);
                w.WriteString(comment);
                w.WriteString(publicBlob);
                w.WriteString(privateBlob);
            });
            var expected = version == 3 ? HMACSHA256.HashData(macKey, macData) : HMACSHA1.HashData(macKey, macData);
            if (!CryptographicOperations.FixedTimeEquals(expected, mac))
            {
                throw new FormatException(encrypted
                    ? "Could not decrypt the .ppk key: the passphrase is wrong (or the file was modified)."
                    : "The .ppk file's MAC does not match: the file was modified or is corrupt.");
            }

            return FromBlobs(algorithm, publicBlob, privateBlob, comment.Length == 0 ? null : comment);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
            CryptographicOperations.ZeroMemory(cipherKey);
            CryptographicOperations.ZeroMemory(privateBlob);
        }
    }

    /// <summary>A non-negative decimal header value; anything else (including overflow) is a format error.</summary>
    private static int Number(string value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            ? number
            : throw new FormatException($"'{value}' is not a valid number in the .ppk file.");

    private static SshPrivateKey FromBlobs(string algorithm, byte[] publicBlob, byte[] privateBlob, string? comment)
    {
        var pub = new SshReader(publicBlob);
        if (pub.ReadUtf8String() != algorithm)
        {
            throw new FormatException("The .ppk public key does not match its declared type.");
        }

        var priv = new SshReader(privateBlob);
        switch (algorithm)
        {
            case SshAlgorithms.SshEd25519:
            {
                var publicKey = pub.ReadString();
                var seed = priv.ReadString();
                if (seed.Length != Ed25519.SeedSize)
                {
                    throw new FormatException("The .ppk Ed25519 private key must be 32 bytes.");
                }

                var publicKeyLength = publicKey.Length;
                return PrivateKeyParser.Checked(
                    new SshPrivateKey.Ed25519Key(seed.ToArray(), comment),
                    k => k.PublicKey.Span.SequenceEqual(publicBlob) && publicKeyLength == Ed25519.PublicKeySize,
                    "The .ppk Ed25519 private key does not match its public key.");
            }

            case SshAlgorithms.EcdsaNistp256 or SshAlgorithms.EcdsaNistp384 or SshAlgorithms.EcdsaNistp521:
            {
                var curve = NistCurve.FromSshName(algorithm["ecdsa-sha2-".Length..]);
                if (pub.ReadUtf8String() != curve.Name)
                {
                    throw new FormatException("The .ppk ECDSA key's curve does not match its type.");
                }

                var point = pub.ReadString();
                var d = priv.ReadMpint();
                if (point.Length != 1 + (2 * curve.FieldSize) || point[0] != 4 || d.Length > curve.FieldSize)
                {
                    throw new FormatException("The .ppk ECDSA key is malformed.");
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
                    throw new FormatException("The .ppk ECDSA key is not valid for its curve.", ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(parameters.D);
                }

                return new SshPrivateKey.EcdsaKey(curve, ecdsa, comment);
            }

            case "ssh-rsa":
            {
                var e = pub.ReadMpint();
                var n = pub.ReadMpint();
                var d = priv.ReadMpint();
                var p = priv.ReadMpint();
                var q = priv.ReadMpint();
                var iqmp = priv.ReadMpint();
                if (n.TrimStart((byte)0).Length * 8 < 2048)
                {
                    throw new FormatException("RSA keys must be at least 2048 bits.");
                }

                return SshPrivateKey.RsaKey.FromComponents(n, e, d, iqmp, p, q, comment);
            }

            default:
                throw new FormatException($"Unsupported .ppk key type '{algorithm}'.");
        }
    }
}
