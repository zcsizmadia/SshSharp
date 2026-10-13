using System.Buffers.Binary;
using System.Numerics;

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
        Span<uint> state = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (var i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        }

        state[12] = word12;
        state[13] = word13;
        state[14] = word14;
        state[15] = word15;
        state.CopyTo(x);

        for (var round = 0; round < 10; round++)
        {
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }

        for (var i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], x[i] + state[i]);
        }

        x.Clear();
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
            for (var i = 0; i < count; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            }
        }

        block.Clear();
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}