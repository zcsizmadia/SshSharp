using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Protocol;

/// <summary>
/// Protects one direction of the binary packet protocol (RFC 4253 section 6). A packet buffer holds
/// <c>packet_length (4) || padding_length (1) || payload || padding</c>; encryption and verification work in place so no extra
/// copy is needed. The tag is kept separately and sent after the packet.
/// </summary>
internal abstract class PacketProtector : IDisposable
{
    /// <summary>The initial, unprotected state before the first key exchange completes.</summary>
    public static PacketProtector None { get; } = new NonePacketProtector();

    /// <summary>The padding alignment (the cipher block size, at least 8).</summary>
    public abstract int Alignment { get; }

    /// <summary>The number of bytes of tag or MAC after each packet.</summary>
    public abstract int TagSize { get; }

    /// <summary>
    /// True when the 4-byte length field is left out of the padded region (AEAD and encrypt-then-MAC suites); false for the
    /// unprotected state, where the whole packet including the length is padded to the alignment.
    /// </summary>
    public abstract bool LengthExcludedFromAlignment { get; }

    /// <summary>Returns the plaintext <c>packet_length</c> given the first four bytes as received.</summary>
    public abstract uint ReadLength(uint sequenceNumber, ReadOnlySpan<byte> firstFourBytes);

    /// <summary>Encrypts <paramref name="packet"/> in place and writes the tag.</summary>
    public abstract void Encrypt(uint sequenceNumber, Span<byte> packet, Span<byte> tag);

    /// <summary>
    /// Verifies the tag and decrypts <paramref name="packet"/> in place (after this call everything but the 4 length bytes is plaintext).
    /// Returns false, leaving the plaintext unusable, when verification fails.
    /// </summary>
    public abstract bool TryDecrypt(uint sequenceNumber, Span<byte> packet, ReadOnlySpan<byte> tag);

    public abstract void Dispose();

    private sealed class NonePacketProtector : PacketProtector
    {
        public override int Alignment => 8;

        public override int TagSize => 0;

        public override bool LengthExcludedFromAlignment => false;

        public override uint ReadLength(uint sequenceNumber, ReadOnlySpan<byte> firstFourBytes) =>
            BinaryPrimitives.ReadUInt32BigEndian(firstFourBytes);

        public override void Encrypt(uint sequenceNumber, Span<byte> packet, Span<byte> tag)
        {
        }

        public override bool TryDecrypt(uint sequenceNumber, Span<byte> packet, ReadOnlySpan<byte> tag) => true;

        public override void Dispose()
        {
        }
    }
}

/// <summary><c>chacha20-poly1305@openssh.com</c>.</summary>
internal sealed class ChaCha20Poly1305Protector(ReadOnlySpan<byte> key) : PacketProtector
{
    private readonly ChaCha20Poly1305OpenSsh _cipher = new(key);

    public override int Alignment => 8;

    public override int TagSize => ChaCha20Poly1305OpenSsh.TagSize;

    public override bool LengthExcludedFromAlignment => true;

    public override uint ReadLength(uint sequenceNumber, ReadOnlySpan<byte> firstFourBytes) =>
        _cipher.DecryptLength(sequenceNumber, firstFourBytes);

    public override void Encrypt(uint sequenceNumber, Span<byte> packet, Span<byte> tag)
    {
        var length = BinaryPrimitives.ReadUInt32BigEndian(packet);
        _cipher.Encrypt(sequenceNumber, length, packet[ChaCha20Poly1305OpenSsh.LengthSize..], packet, tag);
    }

    public override bool TryDecrypt(uint sequenceNumber, Span<byte> packet, ReadOnlySpan<byte> tag) =>
        _cipher.TryDecrypt(sequenceNumber, packet, tag, packet[ChaCha20Poly1305OpenSsh.LengthSize..]);

    public override void Dispose() => _cipher.Dispose();
}

/// <summary><c>aes128-gcm@openssh.com</c> and <c>aes256-gcm@openssh.com</c> (RFC 5647 as profiled by OpenSSH): clear length as AAD, 12-byte IV = 4 fixed bytes + 64-bit big-endian counter.</summary>
internal sealed class AesGcmProtector : PacketProtector
{
    private const int IvSize = 12;
    private const int Tag = 16;

    private readonly AesGcm _gcm;
    private readonly byte[] _iv = new byte[IvSize];

    public AesGcmProtector(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length is not (16 or 32) || iv.Length < IvSize)
        {
            throw new ArgumentException("Expected a 16- or 32-byte key and at least 12 bytes of IV.");
        }

        _gcm = new AesGcm(key, Tag);
        iv[..IvSize].CopyTo(_iv);
    }

    public override int Alignment => 16;

    public override int TagSize => Tag;

    public override bool LengthExcludedFromAlignment => true;

    public override uint ReadLength(uint sequenceNumber, ReadOnlySpan<byte> firstFourBytes) =>
        BinaryPrimitives.ReadUInt32BigEndian(firstFourBytes);

    public override void Encrypt(uint sequenceNumber, Span<byte> packet, Span<byte> tag)
    {
        var body = packet[4..];
        _gcm.Encrypt(_iv, body, body, tag, packet[..4]);
        IncrementCounter();
    }

    public override bool TryDecrypt(uint sequenceNumber, Span<byte> packet, ReadOnlySpan<byte> tag)
    {
        var body = packet[4..];
        try
        {
            _gcm.Decrypt(_iv, body, tag, body, packet[..4]);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        IncrementCounter();
        return true;
    }

    public override void Dispose()
    {
        _gcm.Dispose();
        CryptographicOperations.ZeroMemory(_iv);
    }

    private void IncrementCounter()
    {
        // The last 8 bytes are a big-endian invocation counter.
        var counter = BinaryPrimitives.ReadUInt64BigEndian(_iv.AsSpan(4));
        BinaryPrimitives.WriteUInt64BigEndian(_iv.AsSpan(4), counter + 1);
    }
}

/// <summary><c>aes*-ctr</c> with <c>hmac-sha2-*-etm@openssh.com</c>: clear length, MAC over sequence number and the encrypted packet, verified before decrypting.</summary>
internal sealed class AesCtrEtmProtector : PacketProtector
{
    private readonly AesCtr _ctr;
    private readonly IncrementalHash _mac;
    private readonly int _macSize;

    public AesCtrEtmProtector(ReadOnlySpan<byte> aesKey, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> macKey, HashAlgorithmName hash)
    {
        _ctr = new AesCtr(aesKey, iv);
        _mac = IncrementalHash.CreateHMAC(hash, macKey);
        _macSize = _mac.HashLengthInBytes;
    }

    public override int Alignment => 16;

    public override int TagSize => _macSize;

    public override bool LengthExcludedFromAlignment => true;

    public override uint ReadLength(uint sequenceNumber, ReadOnlySpan<byte> firstFourBytes) =>
        BinaryPrimitives.ReadUInt32BigEndian(firstFourBytes);

    public override void Encrypt(uint sequenceNumber, Span<byte> packet, Span<byte> tag)
    {
        _ctr.Transform(packet[4..]);
        ComputeMac(sequenceNumber, packet, tag);
    }

    public override bool TryDecrypt(uint sequenceNumber, Span<byte> packet, ReadOnlySpan<byte> tag)
    {
        Span<byte> expected = stackalloc byte[_macSize];
        ComputeMac(sequenceNumber, packet, expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag))
        {
            return false;
        }

        _ctr.Transform(packet[4..]);
        return true;
    }

    public override void Dispose()
    {
        _ctr.Dispose();
        _mac.Dispose();
    }

    private void ComputeMac(uint sequenceNumber, ReadOnlySpan<byte> packet, Span<byte> destination)
    {
        Span<byte> sequence = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(sequence, sequenceNumber);
        _mac.AppendData(sequence);
        _mac.AppendData(packet);
        _mac.GetHashAndReset(destination);
    }
}