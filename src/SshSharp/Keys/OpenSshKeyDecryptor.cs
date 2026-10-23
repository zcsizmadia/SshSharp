using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>
/// Decrypts the private section of a passphrase-protected OpenSSH key (PROTOCOL.key): the key and IV come from
/// <c>bcrypt_pbkdf</c>(passphrase, salt, rounds), and the section is encrypted with AES-CTR (ssh-keygen's default), AES-CBC, AES-GCM or
/// <c>chacha20-poly1305@openssh.com</c>.
/// </summary>
/// <remarks>
/// For <c>chacha20-poly1305@openssh.com</c>, OpenSSH's <c>sshkey.c</c> (<c>private2_decrypt</c>) derives 64 bytes and no IV (the
/// cipher's key length is 64 and its IV length 0 in <c>cipher.c</c>), and calls <c>cipher_crypt</c> with sequence number 0, no
/// additional data and the 16-byte tag that follows the encrypted section. So, unlike a packet, there is no encrypted length: the tag
/// covers the section alone, and the second half of the key (the packet cipher's length key) is never used. The cipher's block size is
/// 8, which the section length must be a multiple of.
/// </remarks>
internal static class OpenSshKeyDecryptor
{
    private const int MaxRounds = 1 << 16;

    public static byte[] Decrypt(string cipher, string kdf, ReadOnlySpan<byte> kdfOptions, ReadOnlySpan<byte> encrypted, ref SshReader reader, string? passphrase)
    {
        if (kdf != "bcrypt")
        {
            throw new FormatException($"Unsupported key derivation '{kdf}' in the OpenSSH private key.");
        }

        var (mode, keyLength, ivLength, blockSize) = cipher switch
        {
            "aes128-ctr" => (Mode.Ctr, 16, 16, 16),
            "aes192-ctr" => (Mode.Ctr, 24, 16, 16),
            "aes256-ctr" => (Mode.Ctr, 32, 16, 16),
            "aes128-cbc" => (Mode.Cbc, 16, 16, 16),
            "aes192-cbc" => (Mode.Cbc, 24, 16, 16),
            "aes256-cbc" => (Mode.Cbc, 32, 16, 16),
            "aes128-gcm@openssh.com" => (Mode.Gcm, 16, 12, 16),
            "aes256-gcm@openssh.com" => (Mode.Gcm, 32, 12, 16),
            "chacha20-poly1305@openssh.com" => (Mode.ChaChaPoly, ChaCha20Poly1305OpenSsh.KeySize, 0, 8),
            _ => throw new FormatException($"Unsupported cipher '{cipher}' in the OpenSSH private key (re-encrypt it with 'ssh-keygen -p -Z aes256-ctr')."),
        };

        var tag = mode is Mode.Gcm or Mode.ChaChaPoly ? reader.ReadBytes(16) : default;
        if (encrypted.Length == 0 || encrypted.Length % blockSize != 0)
        {
            throw new FormatException("The encrypted private key section has an invalid length.");
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            throw new FormatException("The private key is encrypted; a passphrase is required.");
        }

        var options = new SshReader(kdfOptions);
        var salt = options.ReadString();
        var rounds = options.ReadUInt32();
        if (salt.IsEmpty || rounds is 0 or > MaxRounds)
        {
            throw new FormatException("The private key's bcrypt parameters are invalid.");
        }

        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        var keyAndIv = new byte[keyLength + ivLength];
        var output = new byte[encrypted.Length];
        try
        {
            BcryptPbkdf.DeriveKey(passphraseBytes, salt, (int)rounds, keyAndIv);
            var key = keyAndIv.AsSpan(0, keyLength);
            var iv = keyAndIv.AsSpan(keyLength);
            switch (mode)
            {
                case Mode.Ctr:
                {
                    encrypted.CopyTo(output);
                    using var ctr = new AesCtr(key, iv);
                    ctr.Transform(output);
                    break;
                }

                case Mode.Cbc:
                {
                    using var aes = Aes.Create();
                    var keyCopy = key.ToArray();
                    aes.Key = keyCopy; // the setter keeps its own copy
                    CryptographicOperations.ZeroMemory(keyCopy);
                    aes.DecryptCbc(encrypted, iv, output, PaddingMode.None);
                    break;
                }

                case Mode.ChaChaPoly:
                {
                    // The tag is checked (in constant time) before anything is decrypted, so a wrong passphrase or an edited file never
                    // yields bytes to parse.
                    using var chacha = new ChaCha20Poly1305OpenSsh(key);
                    if (!chacha.TryDecryptWithoutLength(0, encrypted, tag, output))
                    {
                        throw new FormatException("Could not decrypt the private key: the passphrase is wrong.");
                    }

                    break;
                }

                default:
                {
                    using var gcm = new AesGcm(key, 16);
                    try
                    {
                        gcm.Decrypt(iv, encrypted, tag, output);
                    }
                    catch (AuthenticationTagMismatchException ex)
                    {
                        throw new FormatException("Could not decrypt the private key: the passphrase is wrong.", ex);
                    }

                    break;
                }
            }

            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
            CryptographicOperations.ZeroMemory(keyAndIv);
        }
    }

    private enum Mode
    {
        Ctr,
        Cbc,
        Gcm,
        ChaChaPoly,
    }
}
