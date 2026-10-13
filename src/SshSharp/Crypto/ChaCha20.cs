using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace SshSharp.Crypto;

/// <summary>The ChaCha20 block function and stream cipher (RFC 8439 section 2), with the counter/nonce words exposed so both the RFC and OpenSSH layouts can use it.</summary>
internal static class ChaCha20
{
    public const int KeySize = 32;
    public const int BlockSize = 64;

    /// <summary>
    /// Produces one 64-byte keystream block. State words 12-15 are given directly: the RFC 8439 layout is (counter, nonce0, nonce1, nonce2);
    /// OpenSSH uses (counterLow, counterHigh, nonce0, nonce1).
    /// </summary>
    public static void Block(ReadOnlySpan<byte> key, uint word12, uint word13, uint word14, uint word15, Span<byte> output)
    {
        // The whole state lives in locals so the JIT can keep it in registers.
        const uint c0 = 0x61707865;
        const uint c1 = 0x3320646e;
        const uint c2 = 0x79622d32;
        const uint c3 = 0x6b206574;
        var k0 = BinaryPrimitives.ReadUInt32LittleEndian(key);
        var k1 = BinaryPrimitives.ReadUInt32LittleEndian(key[4..]);
        var k2 = BinaryPrimitives.ReadUInt32LittleEndian(key[8..]);
        var k3 = BinaryPrimitives.ReadUInt32LittleEndian(key[12..]);
        var k4 = BinaryPrimitives.ReadUInt32LittleEndian(key[16..]);
        var k5 = BinaryPrimitives.ReadUInt32LittleEndian(key[20..]);
        var k6 = BinaryPrimitives.ReadUInt32LittleEndian(key[24..]);
        var k7 = BinaryPrimitives.ReadUInt32LittleEndian(key[28..]);

        uint x0 = c0, x1 = c1, x2 = c2, x3 = c3;
        uint x4 = k0, x5 = k1, x6 = k2, x7 = k3, x8 = k4, x9 = k5, x10 = k6, x11 = k7;
        uint x12 = word12, x13 = word13, x14 = word14, x15 = word15;

        for (var round = 0; round < 10; round++)
        {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x1, ref x5, ref x9, ref x13);
            QuarterRound(ref x2, ref x6, ref x10, ref x14);
            QuarterRound(ref x3, ref x7, ref x11, ref x15);
            QuarterRound(ref x0, ref x5, ref x10, ref x15);
            QuarterRound(ref x1, ref x6, ref x11, ref x12);
            QuarterRound(ref x2, ref x7, ref x8, ref x13);
            QuarterRound(ref x3, ref x4, ref x9, ref x14);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output, x0 + c0);
        BinaryPrimitives.WriteUInt32LittleEndian(output[4..], x1 + c1);
        BinaryPrimitives.WriteUInt32LittleEndian(output[8..], x2 + c2);
        BinaryPrimitives.WriteUInt32LittleEndian(output[12..], x3 + c3);
        BinaryPrimitives.WriteUInt32LittleEndian(output[16..], x4 + k0);
        BinaryPrimitives.WriteUInt32LittleEndian(output[20..], x5 + k1);
        BinaryPrimitives.WriteUInt32LittleEndian(output[24..], x6 + k2);
        BinaryPrimitives.WriteUInt32LittleEndian(output[28..], x7 + k3);
        BinaryPrimitives.WriteUInt32LittleEndian(output[32..], x8 + k4);
        BinaryPrimitives.WriteUInt32LittleEndian(output[36..], x9 + k5);
        BinaryPrimitives.WriteUInt32LittleEndian(output[40..], x10 + k6);
        BinaryPrimitives.WriteUInt32LittleEndian(output[44..], x11 + k7);
        BinaryPrimitives.WriteUInt32LittleEndian(output[48..], x12 + word12);
        BinaryPrimitives.WriteUInt32LittleEndian(output[52..], x13 + word13);
        BinaryPrimitives.WriteUInt32LittleEndian(output[56..], x14 + word14);
        BinaryPrimitives.WriteUInt32LittleEndian(output[60..], x15 + word15);
    }

    /// <summary>
    /// XORs <paramref name="input"/> with the keystream (OpenSSH layout: 64-bit counter, 8-byte nonce) into <paramref name="output"/>.
    /// The spans may be the same (in-place) but must not partially overlap.
    /// </summary>
    public static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce8, ulong counter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (key.Length != KeySize || nonce8.Length != 8 || output.Length < input.Length)
        {
            throw new ArgumentException("ChaCha20 needs a 32-byte key, an 8-byte nonce and enough output space.");
        }

        var n0 = BinaryPrimitives.ReadUInt32LittleEndian(nonce8);
        var n1 = BinaryPrimitives.ReadUInt32LittleEndian(nonce8[4..]);
        Span<byte> block = stackalloc byte[BlockSize];
        for (var offset = 0; offset < input.Length; offset += BlockSize)
        {
            Block(key, (uint)counter, (uint)(counter >> 32), n0, n1, block);
            counter++;
            var count = Math.Min(BlockSize, input.Length - offset);
            XorHelper.Xor(input.Slice(offset, count), block, output[offset..]);
        }

        block.Clear();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = BitOperations.RotateLeft(d ^ a, 16);
        c += d;
        b = BitOperations.RotateLeft(b ^ c, 12);
        a += b;
        d = BitOperations.RotateLeft(d ^ a, 8);
        c += d;
        b = BitOperations.RotateLeft(b ^ c, 7);
    }
}