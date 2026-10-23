using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// The <c>chacha20-poly1305@openssh.com</c> packet cipher (OpenSSH PROTOCOL.chacha20poly1305). It is not the RFC 8439 AEAD:
/// the 4-byte packet length is encrypted with a separate key (K_1), the payload with K_2 from block 1, the Poly1305 key is
/// block 0 of K_2, and the tag covers the encrypted length plus the encrypted payload with no padding or length trailer.
/// The nonce is the packet sequence number as a 64-bit big-endian value.
/// </summary>
internal sealed class ChaCha20Poly1305OpenSsh : IDisposable
{
    public const int KeySize = 64;
    public const int TagSize = Poly1305.TagSize;
    public const int LengthSize = 4;

    private readonly byte[] _payloadKey = new byte[ChaCha20.KeySize]; // K_2: first half of the 64-byte key
    private readonly byte[] _lengthKey = new byte[ChaCha20.KeySize];  // K_1: second half

    public ChaCha20Poly1305OpenSsh(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException("The key must be 64 bytes.", nameof(key));
        }

        key[..32].CopyTo(_payloadKey);
        key[32..].CopyTo(_lengthKey);
    }

    /// <summary>Decrypts the 4-byte packet length so the receiver knows how many bytes to read.</summary>
    public uint DecryptLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength)
    {
        Span<byte> nonce = stackalloc byte[8];
        Span<byte> length = stackalloc byte[LengthSize];
        Nonce(sequenceNumber, nonce);
        ChaCha20.Xor(_lengthKey, nonce, 0, encryptedLength[..LengthSize], length);
        return BinaryPrimitives.ReadUInt32BigEndian(length);
    }

    /// <summary>
    /// Verifies the tag over <paramref name="encryptedPacket"/> (encrypted length followed by the encrypted body) and, only if it is
    /// valid, decrypts the body into <paramref name="body"/>. Returns false (and writes nothing) on a bad tag.
    /// </summary>
    public bool TryDecrypt(uint sequenceNumber, ReadOnlySpan<byte> encryptedPacket, ReadOnlySpan<byte> tag, Span<byte> body)
    {
        if (encryptedPacket.Length < LengthSize || tag.Length != TagSize || body.Length != encryptedPacket.Length - LengthSize)
        {
            throw new ArgumentException("Sizes do not match.");
        }

        return TryOpen(sequenceNumber, encryptedPacket, LengthSize, tag, body);
    }

    /// <summary>
    /// Verifies and decrypts data that has no encrypted length in front, which is how OpenSSH encrypts a key file with this cipher
    /// (<c>sshkey.c</c> calls <c>cipher_crypt</c> with sequence number 0 and no additional data): the tag covers
    /// <paramref name="ciphertext"/> alone, and K_1 is never used. Returns false (and writes nothing) on a bad tag.
    /// </summary>
    public bool TryDecryptWithoutLength(uint sequenceNumber, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        if (tag.Length != TagSize || plaintext.Length != ciphertext.Length)
        {
            throw new ArgumentException("Sizes do not match.");
        }

        return TryOpen(sequenceNumber, ciphertext, 0, tag, plaintext);
    }

    /// <summary>Checks the tag over all of <paramref name="authenticated"/> in constant time, then decrypts what follows its first <paramref name="skip"/> bytes.</summary>
    private bool TryOpen(uint sequenceNumber, ReadOnlySpan<byte> authenticated, int skip, ReadOnlySpan<byte> tag, Span<byte> body)
    {
        Span<byte> nonce = stackalloc byte[8];
        Span<byte> polyKey = stackalloc byte[Poly1305.KeySize];
        Span<byte> expected = stackalloc byte[TagSize];
        Nonce(sequenceNumber, nonce);
        PolyKey(nonce, polyKey);
        Poly1305.ComputeTag(polyKey, authenticated, expected);
        var valid = CryptographicOperations.FixedTimeEquals(expected, tag);
        if (valid)
        {
            ChaCha20.Xor(_payloadKey, nonce, 1, authenticated[skip..], body);
        }

        polyKey.Clear();
        return valid;
    }

    /// <summary>Encrypts a packet: <paramref name="output"/> receives the encrypted length followed by the encrypted body, and <paramref name="tag"/> the tag.</summary>
    /// <param name="sequenceNumber">The packet sequence number.</param>
    /// <param name="packetLength">The plaintext packet_length field value.</param>
    /// <param name="body">padding_length || payload || padding.</param>
    /// <param name="output">Must be exactly 4 + body.Length bytes.</param>
    /// <param name="tag">16 bytes.</param>
    public void Encrypt(uint sequenceNumber, uint packetLength, ReadOnlySpan<byte> body, Span<byte> output, Span<byte> tag)
    {
        if (output.Length != LengthSize + body.Length || tag.Length != TagSize)
        {
            throw new ArgumentException("Sizes do not match.");
        }

        Span<byte> nonce = stackalloc byte[8];
        Span<byte> polyKey = stackalloc byte[Poly1305.KeySize];
        Span<byte> length = stackalloc byte[LengthSize];
        Nonce(sequenceNumber, nonce);
        PolyKey(nonce, polyKey);

        BinaryPrimitives.WriteUInt32BigEndian(length, packetLength);
        ChaCha20.Xor(_lengthKey, nonce, 0, length, output[..LengthSize]);
        ChaCha20.Xor(_payloadKey, nonce, 1, body, output[LengthSize..]);
        Poly1305.ComputeTag(polyKey, output, tag);
        polyKey.Clear();
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_payloadKey);
        CryptographicOperations.ZeroMemory(_lengthKey);
    }

    private static void Nonce(uint sequenceNumber, Span<byte> nonce)
    {
        nonce.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(nonce[4..], sequenceNumber);
    }

    private void PolyKey(ReadOnlySpan<byte> nonce, Span<byte> polyKey)
    {
        Span<byte> block = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Block(_payloadKey, 0, 0, BinaryPrimitives.ReadUInt32LittleEndian(nonce), BinaryPrimitives.ReadUInt32LittleEndian(nonce[4..]), block);
        block[..Poly1305.KeySize].CopyTo(polyKey);
        block.Clear();
    }
}