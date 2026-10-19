using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>
/// Writes PuTTY version 3 key files (<c>.ppk</c>) as PuTTYgen 0.75 and later does: unencrypted, or encrypted with <c>aes256-cbc</c>
/// under a key from Argon2id. The MAC (HMAC-SHA256) covers the key type, encryption, comment, public blob and the private blob before
/// encryption, as <see cref="PuttyKeyParser"/> checks it. Version 2 (SHA-1) is never written.
/// </summary>
internal static class PuttyKeyWriter
{
    /// <summary>
    /// Argon2id memory in KiB: 46 MiB with one pass and one lane is OWASP's first recommended setting for Argon2id (2023). It is more
    /// memory than PuTTYgen's default (8 MiB, with as many passes as take 100 ms), which is what makes guessing on GPUs costly, and keeps
    /// saving and loading in this library's single-threaded Argon2 to a fraction of a second. Every PuTTY that reads version 3 reads it.
    /// </summary>
    public const int Argon2MemoryKiB = 46 * 1024;

    /// <summary>Argon2id passes (t).</summary>
    public const int Argon2Passes = 1;

    /// <summary>Argon2id lanes (p), as PuTTYgen writes.</summary>
    public const int Argon2Parallelism = 1;

    private const int SaltLength = 16;
    private const int LineLength = 64;

    // The Argon2 output: the AES-256 key, the CBC IV, then the HMAC-SHA256 key.
    private const int CipherKeyLength = 32;
    private const int IvLength = 16;
    private const int MacKeyLength = 32;

    /// <summary>The file's text as UTF-8 bytes; the caller zeroes them.</summary>
    public static byte[] Write(SshPrivateKey key, string? passphrase)
    {
        var comment = key.Comment ?? string.Empty;
        if (comment.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            throw new NotSupportedException("A .ppk file cannot hold a comment with a line break.");
        }

        var encrypted = !string.IsNullOrEmpty(passphrase);
        var encryption = encrypted ? "aes256-cbc" : "none";

        // The private fields of the OpenSSH format (this throws for a key whose private material is not here), rewritten in PuTTY's order.
        using var fields = new ZeroingBufferWriter(OpenSshKeyWriter.EstimatePrivateSectionSize(key));
        key.WritePrivateFields(new SshWriter(fields));
        using var blob = new ZeroingBufferWriter(fields.WrittenCount + 16);
        Transcode(key.KeyType, fields.WrittenSpan, new SshWriter(blob));
        if (encrypted)
        {
            // aes256-cbc needs whole blocks. PuTTYgen pads with bytes of a hash of the blob; any bytes do, as the MAC covers them.
            var padding = (16 - (blob.WrittenCount % 16)) % 16;
            RandomNumberGenerator.Fill(blob.GetSpan(padding)[..padding]);
            blob.Advance(padding);
        }

        var salt = encrypted ? RandomNumberGenerator.GetBytes(SaltLength) : [];
        var derived = new byte[CipherKeyLength + IvLength + MacKeyLength];
        byte[]? privateBlob = null;
        try
        {
            if (encrypted)
            {
                var passphraseBytes = Encoding.UTF8.GetBytes(passphrase!);
                try
                {
                    Argon2.Hash(Argon2Type.Argon2id, passphraseBytes, salt, Argon2MemoryKiB, Argon2Passes, Argon2Parallelism, derived);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(passphraseBytes);
                }
            }

            string mac;
            using (var macData = new ZeroingBufferWriter(blob.WrittenCount + key.PublicKey.Length + comment.Length + 128))
            {
                var writer = new SshWriter(macData);
                writer.WriteString(key.KeyType);
                writer.WriteString(encryption);
                writer.WriteString(comment);
                writer.WriteString(key.PublicKey.Span);
                writer.WriteString(blob.WrittenSpan);

                // Unencrypted files are authenticated with an empty key. PuTTY compares the MAC as lowercase hex.
                var macKey = encrypted ? derived.AsSpan(CipherKeyLength + IvLength) : [];
                mac = Convert.ToHexString(HMACSHA256.HashData(macKey, macData.WrittenSpan)).ToLowerInvariant();
            }

            privateBlob = encrypted ? Encrypt(blob.WrittenSpan, derived) : blob.WrittenSpan.ToArray();

            using var text = new ZeroingBufferWriter(((privateBlob.Length + key.PublicKey.Length) * 2) + comment.Length + 512);
            Line(text, $"PuTTY-User-Key-File-3: {key.KeyType}");
            Line(text, $"Encryption: {encryption}");
            Line(text, $"Comment: {comment}");
            Base64Lines(text, "Public-Lines", key.PublicKey.Span);
            if (encrypted)
            {
                Line(text, "Key-Derivation: Argon2id");
                Line(text, string.Create(CultureInfo.InvariantCulture, $"Argon2-Memory: {Argon2MemoryKiB}"));
                Line(text, string.Create(CultureInfo.InvariantCulture, $"Argon2-Passes: {Argon2Passes}"));
                Line(text, string.Create(CultureInfo.InvariantCulture, $"Argon2-Parallelism: {Argon2Parallelism}"));
                Line(text, $"Argon2-Salt: {Convert.ToHexString(salt).ToLowerInvariant()}");
            }

            Base64Lines(text, "Private-Lines", privateBlob);
            Line(text, $"Private-MAC: {mac}");
            return text.WrittenSpan.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
            if (privateBlob is not null)
            {
                CryptographicOperations.ZeroMemory(privateBlob);
            }
        }
    }

    /// <summary>
    /// Rewrites the OpenSSH private fields (PROTOCOL.key) as PuTTY's private blob: Ed25519 the 32-byte seed as a string; ECDSA the
    /// scalar; RSA d, p, q and iqmp (q^-1 mod p in both formats).
    /// </summary>
    private static void Transcode(string keyType, ReadOnlySpan<byte> fields, SshWriter writer)
    {
        var reader = new SshReader(fields);
        switch (keyType)
        {
            case SshAlgorithms.SshEd25519:
                reader.ReadString(); // public key
                writer.WriteString(reader.ReadString()[..Ed25519.SeedSize]); // seed || public key
                break;

            case "ssh-rsa":
                reader.ReadMpint(); // n
                reader.ReadMpint(); // e
                var d = reader.ReadMpint();
                var iqmp = reader.ReadMpint();
                var p = reader.ReadMpint();
                var q = reader.ReadMpint();
                writer.WriteMpint(d);
                writer.WriteMpint(p);
                writer.WriteMpint(q);
                writer.WriteMpint(iqmp);
                break;

            default: // ECDSA
                reader.ReadString(); // curve
                reader.ReadString(); // public point
                writer.WriteMpint(reader.ReadMpint());
                break;
        }
    }

    private static byte[] Encrypt(ReadOnlySpan<byte> plain, byte[] derived)
    {
        var cipherKey = derived[..CipherKeyLength];
        try
        {
            using var aes = Aes.Create();
            aes.Key = cipherKey;
            return aes.EncryptCbc(plain, derived.AsSpan(CipherKeyLength, IvLength), PaddingMode.None);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cipherKey);
        }
    }

    private static void Line(ZeroingBufferWriter output, string line)
    {
        var count = Encoding.UTF8.GetByteCount(line);
        var span = output.GetSpan(count + 1);
        Encoding.UTF8.GetBytes(line, span);
        span[count] = (byte)'\n';
        output.Advance(count + 1);
    }

    /// <summary>A <c>header: count</c> line, then the data in base64 lines of 64 characters, as PuTTY writes it.</summary>
    private static void Base64Lines(ZeroingBufferWriter output, string header, ReadOnlySpan<byte> data)
    {
        var base64Length = ((data.Length + 2) / 3) * 4;
        var lines = (base64Length + LineLength - 1) / LineLength;
        Line(output, string.Create(CultureInfo.InvariantCulture, $"{header}: {lines}"));
        var base64 = new byte[base64Length];
        try
        {
            System.Buffers.Text.Base64.EncodeToUtf8(data, base64, out _, out _);
            for (var i = 0; i < base64Length; i += LineLength)
            {
                var length = Math.Min(LineLength, base64Length - i);
                var span = output.GetSpan(length + 1);
                base64.AsSpan(i, length).CopyTo(span);
                span[length] = (byte)'\n';
                output.Advance(length + 1);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(base64);
        }
    }
}
