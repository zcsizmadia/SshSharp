using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>Builds the packet protector for one direction from the negotiated algorithms and derived keys.</summary>
internal static class PacketProtectorFactory
{
    public static PacketProtector Create(CipherInfo cipher, MacInfo? mac, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        if (encryptionKey.Length != cipher.KeyLength)
        {
            // Stryker disable once String : the message is for people
            throw new ArgumentException($"{cipher.Name} needs a {cipher.KeyLength}-byte key.", nameof(encryptionKey));
        }

        switch (cipher.Kind)
        {
            case CipherKind.ChaCha20Poly1305:
                return new ChaCha20Poly1305Protector(encryptionKey);
            case CipherKind.AesGcm:
                return new AesGcmProtector(encryptionKey, iv);
            case CipherKind.AesCtr:
                ArgumentNullException.ThrowIfNull(mac);
                if (integrityKey.Length != mac.KeyLength)
                {
                    // Stryker disable once String : the message is for people
                    throw new ArgumentException($"{mac.Name} needs a {mac.KeyLength}-byte key.", nameof(integrityKey));
                }

                return mac.EncryptThenMac
                    ? new AesCtrEtmProtector(encryptionKey, iv, integrityKey, mac.Hash)
                    : new AesCtrHmacProtector(encryptionKey, iv, integrityKey, mac.Hash);
            default:
                // Stryker disable once String : the message is for people
                throw new ArgumentOutOfRangeException(nameof(cipher), cipher.Kind, "Unsupported cipher kind.");
        }
    }
}