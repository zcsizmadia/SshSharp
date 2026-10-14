using System.Buffers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>
/// Writes the OpenSSH private key format (PROTOCOL.key), as <c>ssh-keygen</c> does: unencrypted, or encrypted with
/// <c>aes256-ctr</c> under a key from <c>bcrypt_pbkdf</c>(passphrase, a random 16-byte salt, rounds).
/// </summary>
internal static class OpenSshKeyWriter
{
    private const string Begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string End = "-----END OPENSSH PRIVATE KEY-----";
    private const int SaltLength = 16;
    private const int KeyLength = 32;
    private const int IvLength = 16;

    /// <summary>The most bcrypt rounds the reader accepts; a file written with more could not be read back.</summary>
    public const int MaxRounds = 1 << 16;

    /// <summary>The key file's text as UTF-8 bytes; the caller zeroes them.</summary>
    public static byte[] Write(SshPrivateKey key, string? passphrase, int rounds)
    {
        var encrypted = !string.IsNullOrEmpty(passphrase);
        var blockSize = encrypted ? 16 : 8;

        // The private section: two equal check values, the key, its comment, then padding 1, 2, 3, ... to the block size.
        var section = new ArrayBufferWriter<byte>(1024);
        byte[]? plain = null;
        byte[]? file = null;
        try
        {
            var writer = new SshWriter(section);
            var check = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
            writer.WriteUInt32(check);
            writer.WriteUInt32(check);
            writer.WriteString(key.KeyType);
            key.WritePrivateFields(writer);
            writer.WriteString(Encoding.UTF8.GetBytes(key.Comment ?? string.Empty));
            for (byte pad = 1; section.WrittenCount % blockSize != 0; pad++)
            {
                writer.WriteByte(pad);
            }

            plain = section.WrittenSpan.ToArray();
            byte[] kdfOptions = [];
            if (encrypted)
            {
                var salt = RandomNumberGenerator.GetBytes(SaltLength);
                kdfOptions = SshPrivateKey.Encode(w =>
                {
                    w.WriteString(salt);
                    w.WriteUInt32((uint)rounds);
                });
                Encrypt(plain, passphrase!, salt, rounds);
            }

            var body = new ArrayBufferWriter<byte>(plain.Length + key.PublicKey.Length + 128);
            body.Write("openssh-key-v1\0"u8);
            var outer = new SshWriter(body);
            outer.WriteString(encrypted ? "aes256-ctr" : "none");
            outer.WriteString(encrypted ? "bcrypt" : "none");
            outer.WriteString(kdfOptions);
            outer.WriteUInt32(1);
            outer.WriteString(key.PublicKey.Span);
            outer.WriteString(plain);
            file = body.WrittenSpan.ToArray();
            body.Clear();
            return Armor(file);
        }
        finally
        {
            section.Clear(); // ArrayBufferWriter.Clear zeroes what was written
            if (plain is not null)
            {
                CryptographicOperations.ZeroMemory(plain);
            }

            if (file is not null)
            {
                CryptographicOperations.ZeroMemory(file);
            }
        }
    }

    /// <summary>The PEM-style text as UTF-8 bytes, base64 in 70-character lines as ssh-keygen writes it; built without an intermediate string.</summary>
    private static byte[] Armor(ReadOnlySpan<byte> data)
    {
        var base64Length = ((data.Length + 2) / 3) * 4;
        var lines = (base64Length + 69) / 70;
        var output = new byte[Begin.Length + 1 + base64Length + lines + End.Length + 1];
        var base64 = new byte[base64Length];
        try
        {
            System.Buffers.Text.Base64.EncodeToUtf8(data, base64, out _, out _);
            var at = Encoding.ASCII.GetBytes(Begin, output);
            output[at++] = (byte)'\n';
            for (var i = 0; i < base64Length; i += 70)
            {
                var length = Math.Min(70, base64Length - i);
                base64.AsSpan(i, length).CopyTo(output.AsSpan(at));
                at += length;
                output[at++] = (byte)'\n';
            }

            at += Encoding.ASCII.GetBytes(End, output.AsSpan(at));
            output[at] = (byte)'\n';
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(base64);
        }
    }

    private static void Encrypt(Span<byte> section, string passphrase, ReadOnlySpan<byte> salt, int rounds)
    {
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        var keyAndIv = new byte[KeyLength + IvLength];
        try
        {
            BcryptPbkdf.DeriveKey(passphraseBytes, salt, rounds, keyAndIv);
            using var ctr = new AesCtr(keyAndIv.AsSpan(0, KeyLength), keyAndIv.AsSpan(KeyLength));
            ctr.Transform(section);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
            CryptographicOperations.ZeroMemory(keyAndIv);
        }
    }

    /// <summary>
    /// Creates a new file only its owner can read and write: mode 0600 on Unix, and on Windows an ACL with only the current user (not
    /// inherited), which OpenSSH for Windows requires of private keys. Fails if the file exists.
    /// </summary>
    public static FileStream CreateOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            using var identity = WindowsIdentity.GetCurrent();
            security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read, FileShare.None, 4096, FileOptions.Asynchronous, security);
        }

        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }
}
