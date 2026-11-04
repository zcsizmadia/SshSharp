using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace SshSharp.Crypto;

// The vectorized stream cipher: several keystream blocks computed at once.
//
// Lane layout ("word-sliced"): vector xN holds state word N (0-15) of consecutive blocks, one block per 32-bit lane. Lane j belongs to
// block counter + j: 4 lanes in a Vector128, 8 in a Vector256. The rounds then do on every block at once exactly what the scalar code
// does on one, and no operation moves data between lanes. Only words 12 and 13, the 64-bit counter, differ from lane to lane.
//
//              lane 0       lane 1       lane 2       lane 3
//     x0     sigma0       sigma0       sigma0       sigma0
//     ...
//     x4     key0         key0         key0         key0
//     ...
//     x12    ctr+0 low    ctr+1 low    ctr+2 low    ctr+3 low
//     x13    ctr+0 high   ctr+1 high   ctr+2 high   ctr+3 high
//     x14    nonce0       nonce0       nonce0       nonce0
//     x15    nonce1       nonce1       nonce1       nonce1
//
// After the rounds, each group of four words (0-3, 4-7, 8-11, 12-15) is transposed from one word per vector into one block per
// 128-bit row: 16 consecutive keystream bytes of one block, which are XORed with the input. A Vector256 is transposed as its two
// 128-bit halves (blocks 0-3 and 4-7).
//
// Only the cross-platform System.Runtime.Intrinsics operations are used (SSE/AVX2 on x64, AdvSimd on Arm64): add, xor, shifts, byte
// shuffles with constant indices, and selects with constant masks. As in the scalar code, nothing branches on or indexes memory with
// the key, the keystream or the data, and the loop bounds depend only on the length.
internal static partial class ChaCha20
{
    /// <summary>
    /// Whether the 8-block (Vector256) path may be used. On .NET 8 the JIT does not inline its output stage and it ran slower than the
    /// 4-block path (docs/benchmarks.md), so .NET 8 stops at 4 blocks.
    /// </summary>
#if NET10_0_OR_GREATER
    internal const bool Use256BitVectors = true;
#else
    internal const bool Use256BitVectors = false;
#endif

    private const uint Sigma0 = 0x61707865;
    private const uint Sigma1 = 0x3320646e;
    private const uint Sigma2 = 0x79622d32;
    private const uint Sigma3 = 0x6b206574;

    /// <summary>The number of blocks the stream cipher computes at once on this machine: 8, 4, or 1 (the scalar code alone).</summary>
    internal static readonly int ParallelBlocks =
        SelectParallelBlocks(BitConverter.IsLittleEndian, Use256BitVectors && Vector256.IsHardwareAccelerated, Vector128.IsHardwareAccelerated);

    /// <summary>
    /// 8 blocks at once with hardware 256-bit vectors, 4 with 128-bit ones, and the scalar code without either. The vector code keeps
    /// the keystream words in native byte order, so a big-endian machine uses the scalar code.
    /// </summary>
    internal static int SelectParallelBlocks(bool littleEndian, bool vector256, bool vector128) =>
        !littleEndian ? 1 : vector256 ? 8 : vector128 ? 4 : 1;

    /// <summary>
    /// XORs the whole groups of <paramref name="parallelBlocks"/> blocks at the start of <paramref name="input"/> (8 at once, then 4;
    /// nothing for 1), advancing <paramref name="counter"/> by the blocks done. Returns the number of bytes done; the caller finishes
    /// the rest, fewer than 4 blocks, with the scalar code.
    /// </summary>
    internal static int XorParallel(ReadOnlySpan<byte> key, uint n0, uint n1, ref ulong counter, ReadOnlySpan<byte> input, Span<byte> output, int parallelBlocks)
    {
        var done = 0;
        // Stryker disable once Block : without the 8-block path the 4-block path does the same blocks, with the same output; only the speed differs
        if (parallelBlocks == 8)
        {
            done = Xor8Blocks(key, n0, n1, ref counter, input, output);
        }

        if (parallelBlocks >= 4)
        {
            done += Xor4Blocks(key, n0, n1, ref counter, input[done..], output[done..]);
        }

        return done;
    }

    // The kernels skip tiered compilation: the first, unoptimized tiers would keep the vector state in memory, and which tier a
    // benchmark or a short transfer runs in made the timing vary by a factor of two.
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static int Xor4Blocks(ReadOnlySpan<byte> key, uint n0, uint n1, ref ulong counter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        const int Stride = 4 * BlockSize;
        var c0 = Vector128.Create(Sigma0);
        var c1 = Vector128.Create(Sigma1);
        var c2 = Vector128.Create(Sigma2);
        var c3 = Vector128.Create(Sigma3);
        var k0 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key));
        var k1 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[4..]));
        var k2 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[8..]));
        var k3 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[12..]));
        var k4 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[16..]));
        var k5 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[20..]));
        var k6 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[24..]));
        var k7 = Vector128.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[28..]));
        var nonce0 = Vector128.Create(n0);
        var nonce1 = Vector128.Create(n1);

        var done = 0;
        for (; done <= input.Length - Stride; done += Stride)
        {
            // Lane j counts block counter + j. A lane whose low word wrapped past 2^32 - 1 carries into the high word: the comparison is
            // all ones (-1) in that lane, so subtracting it adds the carry. At 2^64 both words wrap, as the scalar counter does.
            var low = Vector128.Create((uint)counter);
            var ctrLow = low + Vector128.Create(0u, 1, 2, 3);
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            var ctrHigh = Vector128.Create((uint)(counter >> 32)) - Vector128.LessThan(ctrLow, low);

            Vector128<uint> x0 = c0, x1 = c1, x2 = c2, x3 = c3;
            Vector128<uint> x4 = k0, x5 = k1, x6 = k2, x7 = k3, x8 = k4, x9 = k5, x10 = k6, x11 = k7;
            Vector128<uint> x12 = ctrLow, x13 = ctrHigh, x14 = nonce0, x15 = nonce1;

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

            var source = input.Slice(done, Stride);
            var target = output.Slice(done, Stride);
            XorRows(x0 + c0, x1 + c1, x2 + c2, x3 + c3, source, target, 0);
            XorRows(x4 + k0, x5 + k1, x6 + k2, x7 + k3, source, target, 16);
            XorRows(x8 + k4, x9 + k5, x10 + k6, x11 + k7, source, target, 32);
            XorRows(x12 + ctrLow, x13 + ctrHigh, x14 + nonce0, x15 + nonce1, source, target, 48);
            counter += 4;
        }

        return done;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static int Xor8Blocks(ReadOnlySpan<byte> key, uint n0, uint n1, ref ulong counter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        const int Stride = 8 * BlockSize;
        var c0 = Vector256.Create(Sigma0);
        var c1 = Vector256.Create(Sigma1);
        var c2 = Vector256.Create(Sigma2);
        var c3 = Vector256.Create(Sigma3);
        var k0 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key));
        var k1 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[4..]));
        var k2 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[8..]));
        var k3 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[12..]));
        var k4 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[16..]));
        var k5 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[20..]));
        var k6 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[24..]));
        var k7 = Vector256.Create(BinaryPrimitives.ReadUInt32LittleEndian(key[28..]));
        var nonce0 = Vector256.Create(n0);
        var nonce1 = Vector256.Create(n1);

        var done = 0;
        for (; done <= input.Length - Stride; done += Stride)
        {
            // As in Xor4Blocks, with 8 lanes.
            var low = Vector256.Create((uint)counter);
            var ctrLow = low + Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            var ctrHigh = Vector256.Create((uint)(counter >> 32)) - Vector256.LessThan(ctrLow, low);

            Vector256<uint> x0 = c0, x1 = c1, x2 = c2, x3 = c3;
            Vector256<uint> x4 = k0, x5 = k1, x6 = k2, x7 = k3, x8 = k4, x9 = k5, x10 = k6, x11 = k7;
            Vector256<uint> x12 = ctrLow, x13 = ctrHigh, x14 = nonce0, x15 = nonce1;

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

            var source = input.Slice(done, Stride);
            var target = output.Slice(done, Stride);
            XorRows(x0 + c0, x1 + c1, x2 + c2, x3 + c3, source, target, 0);
            XorRows(x4 + k0, x5 + k1, x6 + k2, x7 + k3, source, target, 16);
            XorRows(x8 + k4, x9 + k5, x10 + k6, x11 + k7, source, target, 32);
            XorRows(x12 + ctrLow, x13 + ctrHigh, x14 + nonce0, x15 + nonce1, source, target, 48);
            counter += 8;
        }

        return done;
    }

    /// <summary>The 8-lane form of the 4-lane <c>XorRows</c>: the low 128-bit halves are blocks 0-3, the high halves blocks 4-7.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorRows(Vector256<uint> a, Vector256<uint> b, Vector256<uint> c, Vector256<uint> d, ReadOnlySpan<byte> input, Span<byte> output, int column)
    {
        XorRows(a.GetLower(), b.GetLower(), c.GetLower(), d.GetLower(), input, output, column);
        XorRows(a.GetUpper(), b.GetUpper(), c.GetUpper(), d.GetUpper(), input[(4 * BlockSize)..], output[(4 * BlockSize)..], column);
    }

    /// <summary>
    /// Takes 4 consecutive state words of 4 blocks, one word per vector, and XORs each block's 16 keystream bytes into the bytes at
    /// <c>block * 64 + column</c>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorRows(Vector128<uint> a, Vector128<uint> b, Vector128<uint> c, Vector128<uint> d, ReadOnlySpan<byte> input, Span<byte> output, int column)
    {
        // A 4x4 transpose in two steps, each a swap within pairs: first of 32-bit lanes between a and b (and c and d), then of 64-bit
        // halves between the results. Each swap is a shuffle with constant indices and a select with a constant mask.
        var odd = Vector128.Create(0u, ~0u, 0u, ~0u);
        var high = Vector128.Create(0u, 0u, ~0u, ~0u);
        var ab0 = Vector128.ConditionalSelect(odd, Vector128.Shuffle(b, Vector128.Create(1u, 0, 3, 2)), a); // a0 b0 a2 b2
        var ab1 = Vector128.ConditionalSelect(odd, b, Vector128.Shuffle(a, Vector128.Create(1u, 0, 3, 2))); // a1 b1 a3 b3
        var cd0 = Vector128.ConditionalSelect(odd, Vector128.Shuffle(d, Vector128.Create(1u, 0, 3, 2)), c); // c0 d0 c2 d2
        var cd1 = Vector128.ConditionalSelect(odd, d, Vector128.Shuffle(c, Vector128.Create(1u, 0, 3, 2))); // c1 d1 c3 d3
        var row0 = Vector128.ConditionalSelect(high, Vector128.Shuffle(cd0, Vector128.Create(2u, 3, 0, 1)), ab0); // a0 b0 c0 d0
        var row1 = Vector128.ConditionalSelect(high, Vector128.Shuffle(cd1, Vector128.Create(2u, 3, 0, 1)), ab1); // a1 b1 c1 d1
        var row2 = Vector128.ConditionalSelect(high, cd0, Vector128.Shuffle(ab0, Vector128.Create(2u, 3, 0, 1))); // a2 b2 c2 d2
        var row3 = Vector128.ConditionalSelect(high, cd1, Vector128.Shuffle(ab1, Vector128.Create(2u, 3, 0, 1))); // a3 b3 c3 d3

        XorRow(row0, input, output, column);
        XorRow(row1, input, output, BlockSize + column);
        XorRow(row2, input, output, (2 * BlockSize) + column);
        XorRow(row3, input, output, (3 * BlockSize) + column);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorRow(Vector128<uint> keystream, ReadOnlySpan<byte> input, Span<byte> output, int offset) =>
        (Vector128.Create(input.Slice(offset, 16)) ^ keystream.AsByte()).CopyTo(output[offset..]);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
        a += b;
        d = RotateLeft16(d ^ a);
        c += d;
        b = RotateLeft(b ^ c, 12);
        a += b;
        d = RotateLeft8(d ^ a);
        c += d;
        b = RotateLeft(b ^ c, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
    {
        a += b;
        d = RotateLeft16(d ^ a);
        c += d;
        b = RotateLeft(b ^ c, 12);
        a += b;
        d = RotateLeft8(d ^ a);
        c += d;
        b = RotateLeft(b ^ c, 7);
    }

    // Rotations by 12 and 7 are two shifts and an OR. Rotations by 16 and 8 move whole bytes, so they are one byte shuffle with constant
    // indices within each 32-bit lane (pshufb on x64, tbl on Arm64). The words are little-endian: byte 0 is the least significant.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotateLeft(Vector128<uint> value, int count) =>
        Vector128.ShiftLeft(value, count) | Vector128.ShiftRightLogical(value, 32 - count);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateLeft(Vector256<uint> value, int count) =>
        Vector256.ShiftLeft(value, count) | Vector256.ShiftRightLogical(value, 32 - count);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotateLeft16(Vector128<uint> value) =>
        Vector128.Shuffle(value.AsByte(), Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13)).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotateLeft8(Vector128<uint> value) =>
        Vector128.Shuffle(value.AsByte(), Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateLeft16(Vector256<uint> value) =>
        Vector256.Shuffle(
            value.AsByte(),
            Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 18, 19, 16, 17, 22, 23, 20, 21, 26, 27, 24, 25, 30, 31, 28, 29)).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateLeft8(Vector256<uint> value) =>
        Vector256.Shuffle(
            value.AsByte(),
            Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 19, 16, 17, 18, 23, 20, 21, 22, 27, 24, 25, 26, 31, 28, 29, 30)).AsUInt32();
}
