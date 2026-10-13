using System.Buffers.Binary;
using System.Numerics;

namespace SshSharp.Crypto;

/// <summary>BLAKE2b (RFC 7693), unkeyed, with any output length from 1 to 64 bytes. Needed by Argon2 (PuTTY .ppk version 3).</summary>
internal sealed class Blake2b
{
    public const int BlockSize = 128;
    public const int MaxOutputSize = 64;

    private static readonly ulong[] IV =
    [
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    ];

    private static readonly byte[][] Sigma =
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    private readonly ulong[] _h = new ulong[8];
    private readonly byte[] _buffer = new byte[BlockSize];
    private readonly int _outputLength;
    private int _buffered;
    private ulong _counterLow;
    private ulong _counterHigh;

    public Blake2b(int outputLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(outputLength, MaxOutputSize);
        _outputLength = outputLength;
        IV.CopyTo(_h, 0);
        _h[0] ^= 0x01010000UL ^ (uint)outputLength; // parameter block: digest length, no key, fanout = depth = 1
    }

    /// <summary>One-shot hash of <paramref name="data"/> into <paramref name="output"/> (whose length is the digest size).</summary>
    public static void Hash(ReadOnlySpan<byte> data, Span<byte> output)
    {
        var blake = new Blake2b(output.Length);
        blake.Update(data);
        blake.Finish(output);
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            // The last block is compressed in Finish (with the final flag), so a full buffer is compressed only when more data follows.
            if (_buffered == BlockSize)
            {
                AddToCounter(BlockSize);
                Compress(_buffer, last: false);
                _buffered = 0;
            }

            var take = Math.Min(BlockSize - _buffered, data.Length);
            data[..take].CopyTo(_buffer.AsSpan(_buffered));
            _buffered += take;
            data = data[take..];
        }
    }

    public void Finish(Span<byte> output)
    {
        if (output.Length != _outputLength)
        {
            throw new ArgumentException($"The output must be {_outputLength} bytes.", nameof(output));
        }

        AddToCounter((ulong)_buffered);
        _buffer.AsSpan(_buffered).Clear();
        Compress(_buffer, last: true);

        Span<byte> full = stackalloc byte[MaxOutputSize];
        for (var i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(full[(8 * i)..], _h[i]);
        }

        full[..output.Length].CopyTo(output);
        full.Clear();
        Array.Clear(_h);
        Array.Clear(_buffer);
    }

    private void AddToCounter(ulong bytes)
    {
        _counterLow += bytes;
        if (_counterLow < bytes)
        {
            _counterHigh++;
        }
    }

    private void Compress(ReadOnlySpan<byte> block, bool last)
    {
        Span<ulong> m = stackalloc ulong[16];
        for (var i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block[(8 * i)..]);
        }

        Span<ulong> v = stackalloc ulong[16];
        _h.CopyTo(v);
        IV.CopyTo(v[8..]);
        v[12] ^= _counterLow;
        v[13] ^= _counterHigh;
        if (last)
        {
            v[14] = ~v[14];
        }

        for (var round = 0; round < 12; round++)
        {
            var s = Sigma[round % 10];
            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (var i = 0; i < 8; i++)
        {
            _h[i] ^= v[i] ^ v[i + 8];
        }

        m.Clear();
        v.Clear();
    }

    private static void G(Span<ulong> v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
    }
}
