using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>The three Argon2 variants (RFC 9106 section 3.1, the "y" value).</summary>
internal enum Argon2Type
{
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

/// <summary>
/// Argon2 version 0x13 (RFC 9106), which PuTTY uses to derive the key of an encrypted version 3 <c>.ppk</c> file. A straightforward
/// single-threaded port of the RFC's algorithm; lanes are processed in turn, which gives the same result as in parallel.
/// </summary>
internal static class Argon2
{
    private const int BlockSize = 1024;
    private const int BlockWords = BlockSize / 8;
    private const int SyncPoints = 4;
    private const uint Version = 0x13;

    /// <summary>Derives <paramref name="output"/>.Length bytes.</summary>
    /// <param name="type">Argon2d, Argon2i or Argon2id.</param>
    /// <param name="password">The password (P).</param>
    /// <param name="salt">The salt (S).</param>
    /// <param name="memoryKiB">Memory in KiB (m), at least 8 per lane.</param>
    /// <param name="passes">Number of passes (t).</param>
    /// <param name="parallelism">Number of lanes (p).</param>
    /// <param name="output">Receives the tag; its length is T.</param>
    /// <param name="secret">Optional secret (K).</param>
    /// <param name="associatedData">Optional associated data (X).</param>
    public static void Hash(Argon2Type type, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int memoryKiB, int passes, int parallelism,
        Span<byte> output, ReadOnlySpan<byte> secret = default, ReadOnlySpan<byte> associatedData = default)
    {
        if (parallelism < 1 || parallelism > 0xFFFFFF || passes < 1 || memoryKiB < 8 * parallelism || output.Length < 4 || salt.Length < 8)
        {
            throw new ArgumentException("Invalid Argon2 parameters.");
        }

        // Memory is a whole number of 4-slice segments per lane.
        var blocks = 4 * parallelism * (memoryKiB / (4 * parallelism));
        var laneLength = blocks / parallelism;
        var segmentLength = laneLength / SyncPoints;
        var memory = new ulong[blocks * BlockWords];

        try
        {
            Span<byte> h0 = stackalloc byte[64 + 8];
            InitialHash(type, password, salt, secret, associatedData, memoryKiB, passes, parallelism, output.Length, h0[..64]);

            Span<byte> blockBytes = stackalloc byte[BlockSize];
            for (var lane = 0; lane < parallelism; lane++)
            {
                for (var i = 0; i < 2; i++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(h0[64..], (uint)i);
                    BinaryPrimitives.WriteUInt32LittleEndian(h0[68..], (uint)lane);
                    VariableHash(h0, blockBytes);
                    LoadBlock(blockBytes, Block(memory, (lane * laneLength) + i));
                }
            }

            h0.Clear();
            blockBytes.Clear();

            for (var pass = 0; pass < passes; pass++)
            {
                for (var slice = 0; slice < SyncPoints; slice++)
                {
                    for (var lane = 0; lane < parallelism; lane++)
                    {
                        FillSegment(memory, type, pass, slice, lane, laneLength, segmentLength, parallelism, blocks, passes);
                    }
                }
            }

            // C = XOR of the last block of every lane; the tag is H'^T(C).
            Span<ulong> final = stackalloc ulong[BlockWords];
            Block(memory, laneLength - 1).CopyTo(final);
            for (var lane = 1; lane < parallelism; lane++)
            {
                Xor(final, Block(memory, (lane * laneLength) + laneLength - 1));
            }

            Span<byte> finalBytes = stackalloc byte[BlockSize];
            StoreBlock(final, finalBytes);
            VariableHash(finalBytes, output);
            final.Clear();
            finalBytes.Clear();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(memory.AsSpan()));
        }
    }

    private static void InitialHash(Argon2Type type, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> associatedData, int memoryKiB, int passes, int parallelism, int tagLength, Span<byte> h0)
    {
        var blake = new Blake2b(64);
        Uint(blake, (uint)parallelism);
        Uint(blake, (uint)tagLength);
        Uint(blake, (uint)memoryKiB);
        Uint(blake, (uint)passes);
        Uint(blake, Version);
        Uint(blake, (uint)type);
        WithLength(blake, password);
        WithLength(blake, salt);
        WithLength(blake, secret);
        WithLength(blake, associatedData);
        blake.Finish(h0);
    }

    private static void Uint(Blake2b blake, uint value)
    {
        Span<byte> word = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(word, value);
        blake.Update(word);
    }

    private static void WithLength(Blake2b blake, ReadOnlySpan<byte> value)
    {
        Uint(blake, (uint)value.Length);
        blake.Update(value);
    }

    /// <summary>H' (RFC 9106 section 3.3): BLAKE2b for outputs up to 64 bytes, a chain of BLAKE2b-512 for longer ones.</summary>
    private static void VariableHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)output.Length);
        if (output.Length <= 64)
        {
            var blake = new Blake2b(output.Length);
            blake.Update(length);
            blake.Update(input);
            blake.Finish(output);
            return;
        }

        Span<byte> v = stackalloc byte[64];
        var first = new Blake2b(64);
        first.Update(length);
        first.Update(input);
        first.Finish(v);

        var r = ((output.Length + 31) / 32) - 2;
        v[..32].CopyTo(output);
        var offset = 32;
        for (var i = 1; i < r; i++)
        {
            Blake2b.Hash(v.ToArray(), v);
            v[..32].CopyTo(output[offset..]);
            offset += 32;
        }

        var last = output.Length - (32 * r);
        Span<byte> tail = stackalloc byte[64];
        Blake2b.Hash(v, tail[..last]);
        tail[..last].CopyTo(output[offset..]);
        v.Clear();
        tail.Clear();
    }

    private static void FillSegment(ulong[] memory, Argon2Type type, int pass, int slice, int lane, int laneLength, int segmentLength,
        int parallelism, int blocks, int passes)
    {
        // Argon2i, and Argon2id in the first half of the first pass, choose references independently of the data (side-channel safe).
        var dataIndependent = type == Argon2Type.Argon2i || (type == Argon2Type.Argon2id && pass == 0 && slice < SyncPoints / 2);
        Span<ulong> input = stackalloc ulong[BlockWords];
        Span<ulong> address = stackalloc ulong[BlockWords];
        Span<ulong> zero = stackalloc ulong[BlockWords];
        if (dataIndependent)
        {
            input[0] = (ulong)pass;
            input[1] = (ulong)lane;
            input[2] = (ulong)slice;
            input[3] = (ulong)blocks;
            input[4] = (ulong)passes;
            input[5] = (ulong)type;
        }

        var start = 0;
        if (pass == 0 && slice == 0)
        {
            start = 2; // the first two blocks of each lane are already filled
            if (dataIndependent)
            {
                NextAddresses(input, address, zero);
            }
        }

        Span<ulong> temp = stackalloc ulong[BlockWords];
        for (var index = start; index < segmentLength; index++)
        {
            var current = (lane * laneLength) + (slice * segmentLength) + index;
            var previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1;

            ulong pseudoRandom;
            if (dataIndependent)
            {
                if (index % BlockWords == 0)
                {
                    NextAddresses(input, address, zero);
                }

                pseudoRandom = address[index % BlockWords];
            }
            else
            {
                pseudoRandom = memory[previous * BlockWords];
            }

            var j1 = (uint)pseudoRandom;
            var j2 = (uint)(pseudoRandom >> 32);
            var referenceLane = pass == 0 && slice == 0 ? lane : (int)(j2 % (uint)parallelism);
            var referenceIndex = ReferenceIndex(pass, slice, index, referenceLane == lane, j1, laneLength, segmentLength);
            var reference = (referenceLane * laneLength) + referenceIndex;

            // From the second pass on, the new block is XORed into the old one instead of replacing it.
            Compress(Block(memory, previous), Block(memory, reference), temp);
            var destination = Block(memory, current);
            if (pass == 0)
            {
                temp.CopyTo(destination);
            }
            else
            {
                Xor(destination, temp);
            }
        }

        input.Clear();
        address.Clear();
        temp.Clear();
    }

    /// <summary>Maps J1 to a block index within the reference area (RFC 9106 section 3.4.1.1).</summary>
    private static int ReferenceIndex(int pass, int slice, int index, bool sameLane, uint j1, int laneLength, int segmentLength)
    {
        long referenceAreaSize;
        if (pass == 0)
        {
            referenceAreaSize = slice == 0
                ? index - 1
                : sameLane ? (slice * segmentLength) + index - 1 : (slice * segmentLength) - (index == 0 ? 1 : 0);
        }
        else
        {
            referenceAreaSize = sameLane
                ? laneLength - segmentLength + index - 1
                : laneLength - segmentLength - (index == 0 ? 1 : 0);
        }

        ulong x = j1;
        x = (x * x) >> 32;
        var relative = referenceAreaSize - 1 - (long)(((ulong)referenceAreaSize * x) >> 32);
        long startPosition = pass != 0 && slice != SyncPoints - 1 ? (slice + 1) * segmentLength : 0;
        return (int)((startPosition + relative) % laneLength);
    }

    /// <summary>The next block of pseudo-random addresses: G(0, G(0, input)), after incrementing the input's counter.</summary>
    private static void NextAddresses(Span<ulong> input, Span<ulong> address, ReadOnlySpan<ulong> zero)
    {
        input[6]++;
        Span<ulong> temp = stackalloc ulong[BlockWords];
        Compress(zero, input, temp);
        Compress(zero, temp, address);
    }

    /// <summary>The compression function G (RFC 9106 section 3.5): R = X xor Y, apply P to rows then columns, then xor R back in.</summary>
    private static void Compress(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> result)
    {
        Span<ulong> r = stackalloc ulong[BlockWords];
        for (var i = 0; i < BlockWords; i++)
        {
            r[i] = x[i] ^ y[i];
        }

        r.CopyTo(result);

        // Rows: eight 128-byte rows of 16 words.
        for (var row = 0; row < 8; row++)
        {
            var b = 16 * row;
            Permute(result, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }

        // Columns: pairs of words, 16 words apart.
        for (var column = 0; column < 8; column++)
        {
            var b = 2 * column;
            Permute(result, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49, b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }

        Xor(result, r);
        r.Clear();
    }

    /// <summary>P: BLAKE2b's round on sixteen words, with the multiplication-hardened GB.</summary>
    private static void Permute(Span<ulong> v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
        int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
    {
        GB(v, v0, v4, v8, v12);
        GB(v, v1, v5, v9, v13);
        GB(v, v2, v6, v10, v14);
        GB(v, v3, v7, v11, v15);
        GB(v, v0, v5, v10, v15);
        GB(v, v1, v6, v11, v12);
        GB(v, v2, v7, v8, v13);
        GB(v, v3, v4, v9, v14);
    }

    private static void GB(Span<ulong> v, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + (2 * (ulong)(uint)v[a] * (uint)v[b]);
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + (2 * (ulong)(uint)v[c] * (uint)v[d]);
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + (2 * (ulong)(uint)v[a] * (uint)v[b]);
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + (2 * (ulong)(uint)v[c] * (uint)v[d]);
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
    }

    private static Span<ulong> Block(ulong[] memory, int index) => memory.AsSpan(index * BlockWords, BlockWords);

    private static void Xor(Span<ulong> target, ReadOnlySpan<ulong> other)
    {
        for (var i = 0; i < target.Length; i++)
        {
            target[i] ^= other[i];
        }
    }

    private static void LoadBlock(ReadOnlySpan<byte> bytes, Span<ulong> block)
    {
        for (var i = 0; i < BlockWords; i++)
        {
            block[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(8 * i)..]);
        }
    }

    private static void StoreBlock(ReadOnlySpan<ulong> block, Span<byte> bytes)
    {
        for (var i = 0; i < BlockWords; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[(8 * i)..], block[i]);
        }
    }
}
