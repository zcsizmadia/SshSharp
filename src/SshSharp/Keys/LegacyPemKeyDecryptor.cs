using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp.Keys;

/// <summary>
/// Decrypts a traditional encrypted PEM key (<c>BEGIN RSA PRIVATE KEY</c> or <c>BEGIN EC PRIVATE KEY</c> with the RFC 1421 headers
/// <c>Proc-Type: 4,ENCRYPTED</c> and <c>DEK-Info: &lt;cipher&gt;,&lt;IV in hex&gt;</c>), as <c>ssh-keygen -m PEM</c> and OpenSSL's
/// <c>-traditional</c> output write them. The key comes from OpenSSL's legacy <c>EVP_BytesToKey</c> with MD5, one iteration, and the
/// first 8 bytes of the IV as the salt. It is used only to read such files; SshSharp never writes them.
/// </summary>
/// <remarks>
/// Only AES-128/192/256-CBC are read. DES and 3DES (<c>DES-CBC</c>, <c>DES-EDE3-CBC</c>, <c>DES-EDE3-CFB</c>) stay out by design,
/// like every other legacy algorithm: those keys are refused with a message that says how to re-encrypt them.
/// </remarks>
internal static class LegacyPemKeyDecryptor
{
    private const int IvLength = 16;
    private const int SaltLength = 8;
    private const int Md5Length = 16;

    /// <summary>
    /// Returns the decrypted DER (PKCS#1 RSAPrivateKey or SEC1 ECPrivateKey) of the PEM block labelled <paramref name="label"/>. The caller
    /// clears it after use.
    /// </summary>
    public static byte[] Decrypt(string text, string label, string? passphrase)
    {
        var (dekInfo, body) = Split(text, label);
        var comma = dekInfo.IndexOf(',', StringComparison.Ordinal);
        if (comma < 0)
        {
            throw new FormatException("The encrypted PEM private key's DEK-Info header has no IV.");
        }

        var cipher = dekInfo[..comma].Trim();
        var keyLength = cipher.ToUpperInvariant() switch
        {
            "AES-128-CBC" => 16,
            "AES-192-CBC" => 24,
            "AES-256-CBC" => 32,
            var other when other.StartsWith("DES", StringComparison.Ordinal) => throw new FormatException(
                $"The private key is encrypted with {cipher}, a legacy cipher SshSharp does not read; re-encrypt it with " +
                "'ssh-keygen -p -f <file>', which rewrites it in the OpenSSH format with AES."),
            _ => throw new FormatException(
                $"Unsupported cipher '{cipher}' in the encrypted PEM private key (AES-128/192/256-CBC are read); re-encrypt it with 'ssh-keygen -p -f <file>'."),
        };

        byte[] iv;
        try
        {
            iv = Convert.FromHexString(dekInfo.AsSpan(comma + 1).Trim());
        }
        catch (FormatException ex)
        {
            throw new FormatException("The encrypted PEM private key's IV is not valid hex.", ex);
        }

        if (iv.Length != IvLength)
        {
            throw new FormatException("The encrypted PEM private key's IV must be 16 bytes.");
        }

        byte[] encrypted;
        try
        {
            encrypted = Convert.FromBase64String(body);
        }
        catch (FormatException ex)
        {
            throw new FormatException("The encrypted PEM private key is not valid base64.", ex);
        }

        if (encrypted.Length == 0 || encrypted.Length % IvLength != 0)
        {
            throw new FormatException("The encrypted PEM private key has an invalid length.");
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            throw new FormatException("The private key is encrypted; a passphrase is required.");
        }

        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        var key = new byte[keyLength];
        try
        {
            DeriveKey(passphraseBytes, iv.AsSpan(0, SaltLength), key);
            using var aes = Aes.Create();
            aes.Key = key; // the setter keeps its own copy
            try
            {
                return aes.DecryptCbc(encrypted, iv, PaddingMode.PKCS7);
            }
            catch (CryptographicException ex)
            {
                // A wrong passphrase almost always leaves invalid padding; the rare one that does not fails to parse as a key.
                throw new FormatException("Could not decrypt the private key: the passphrase is wrong.", ex);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// OpenSSL's <c>EVP_BytesToKey</c> with MD5 and one iteration: D_1 = MD5(passphrase || salt), D_i = MD5(D_(i-1) || passphrase || salt),
    /// and the key is D_1 || D_2 || ... cut to its length. The IV is not derived, as the file carries it.
    /// </summary>
    [SuppressMessage("Security", "CA5351",
        Justification = "The traditional PEM encryption is defined with MD5 (EVP_BytesToKey); reading existing files requires it. It is never written.")]
    internal static void DeriveKey(ReadOnlySpan<byte> passphrase, ReadOnlySpan<byte> salt, Span<byte> key)
    {
        var input = new byte[Md5Length + passphrase.Length + salt.Length];
        Span<byte> digest = stackalloc byte[Md5Length];
        try
        {
            passphrase.CopyTo(input.AsSpan(Md5Length));
            salt.CopyTo(input.AsSpan(Md5Length + passphrase.Length));
            var offset = 0;
            var first = true;
            while (offset < key.Length)
            {
                // The first round hashes passphrase || salt alone; later ones prefix the previous digest.
                MD5.HashData(first ? input.AsSpan(Md5Length) : input, digest);
                first = false;
                var count = Math.Min(Md5Length, key.Length - offset);
                digest[..count].CopyTo(key[offset..]);
                digest.CopyTo(input);
                offset += count;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>The DEK-Info value and the base64 body of the PEM block, after checking that its headers say it is encrypted.</summary>
    private static (string DekInfo, string Body) Split(string text, string label)
    {
        var begin = $"-----BEGIN {label}-----";
        var end = $"-----END {label}-----";
        var start = text.IndexOf(begin, StringComparison.Ordinal);
        // The END line is looked for after the BEGIN line, not inside it: their dashes can overlap.
        var stop = start < 0 ? -1 : text.IndexOf(end, start + begin.Length, StringComparison.Ordinal);
        if (stop < 0)
        {
            throw new FormatException($"Expected a PEM '{label}' block with an END line.");
        }

        // RFC 1421: header lines, a blank line, then the base64 body. OpenSSL writes Proc-Type first and DEK-Info second.
        var lines = text[(start + begin.Length)..stop].Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        string? procType = null, dekInfo = null;
        var index = 0;
        while (index < lines.Length && lines[index].Trim().Length == 0)
        {
            index++;
        }

        for (; index < lines.Length && lines[index].Trim().Length > 0; index++)
        {
            var line = lines[index];
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                break; // the body, with no blank line before it
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Equals("Proc-Type", StringComparison.OrdinalIgnoreCase))
            {
                procType = value;
            }
            else if (name.Equals("DEK-Info", StringComparison.OrdinalIgnoreCase))
            {
                dekInfo = value;
            }
        }

        if (procType != "4,ENCRYPTED" || dekInfo is null)
        {
            throw new FormatException("The encrypted PEM private key needs both a 'Proc-Type: 4,ENCRYPTED' and a 'DEK-Info' header.");
        }

        return (dekInfo, string.Concat(lines[index..]));
    }
}
