using System.Runtime.Intrinsics;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>
/// The vectorized ChaCha20 (8 and 4 blocks at once) against the scalar block function, which the RFC vectors check. Every path is run
/// explicitly, so all three are tested on every machine; a vector width the CPU lacks runs through the runtime's software fallback.
/// </summary>
public class ChaCha20VectorTests
{
    private static readonly int[] Paths = [1, 4, 8];

    // Counters whose low word wraps inside each lane of a group of 8 or 4 blocks, around 2^32 and 2^64 (where the whole counter wraps).
    private static readonly ulong[] BoundaryCounters =
    [
        0, 1, 7, 0x7fffffff, 0x80000000, 0xfffffff8, 0xfffffff9, 0xfffffffa, 0xfffffffb, 0xfffffffc, 0xfffffffd, 0xfffffffe,
        0xffffffff, 0x100000000, 0x1fffffffd, 0x7ffffffffffffffd, 0xfffffffffffffff9, 0xfffffffffffffffc, 0xfffffffffffffffe,
        0xffffffffffffffff,
    ];

    private static byte[] Run(byte[] key, byte[] nonce, ulong counter, byte[] input, int parallelBlocks)
    {
        var output = new byte[input.Length];
        ChaCha20.Xor(key, nonce, counter, input, output, parallelBlocks);
        return output;
    }

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    [Test]
    public async Task EveryLengthUpTo2000_MatchesTheScalarCode()
    {
        var rng = new Random(277);
        for (var length = 0; length <= 2000; length++)
        {
            var key = new byte[32];
            var nonce = new byte[8];
            var input = new byte[length];
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(input);
            var counter = length % 3 == 0 ? BoundaryCounters[length / 3 % BoundaryCounters.Length] : (ulong)rng.NextInt64() * 2 + (ulong)(length & 1);

            var expected = Hex(Run(key, nonce, counter, input, 1));
            foreach (var path in Paths)
            {
                await Assert.That(Hex(Run(key, nonce, counter, input, path))).IsEqualTo(expected).Because($"length {length}, path {path}");
            }

            var dispatched = new byte[length];
            ChaCha20.Xor(key, nonce, counter, input, dispatched);
            await Assert.That(Hex(dispatched)).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task CountersCrossingThe32And64BitBoundaries_MatchTheScalarCode()
    {
        var rng = new Random(278);
        var key = new byte[32];
        var nonce = new byte[8];
        rng.NextBytes(key);
        rng.NextBytes(nonce);
        var input = new byte[20 * ChaCha20.BlockSize + 13];
        rng.NextBytes(input);

        foreach (var counter in BoundaryCounters)
        {
            var expected = Hex(Run(key, nonce, counter, input, 1));
            foreach (var path in Paths)
            {
                await Assert.That(Hex(Run(key, nonce, counter, input, path))).IsEqualTo(expected).Because($"counter {counter:x}, path {path}");
            }
        }
    }

    [Test]
    public async Task TheLowWordCarriesIntoTheHighWord()
    {
        // Independent of the stream code: block 2^32 is the block function with words 12 and 13 = (0, 1), and block 2^64 - 1 wraps to 0.
        var key = new byte[32];
        new Random(279).NextBytes(key);
        var nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var zeros = new byte[16 * ChaCha20.BlockSize];
        var afterCarry = new byte[ChaCha20.BlockSize];
        ChaCha20.Block(key, 0, 1, 0x04030201, 0x08070605, afterCarry);
        var afterWrap = new byte[ChaCha20.BlockSize];
        ChaCha20.Block(key, 0, 0, 0x04030201, 0x08070605, afterWrap);

        foreach (var path in Paths)
        {
            // Starting 5 blocks before 2^32, block 5 of the stream is block 2^32.
            var stream = Run(key, nonce, 0xfffffffb, zeros, path);
            await Assert.That(Hex(stream.AsSpan(5 * ChaCha20.BlockSize, ChaCha20.BlockSize))).IsEqualTo(Hex(afterCarry));

            // Starting 3 blocks before 2^64, block 3 of the stream is block 0.
            stream = Run(key, nonce, 0xfffffffffffffffd, zeros, path);
            await Assert.That(Hex(stream.AsSpan(3 * ChaCha20.BlockSize, ChaCha20.BlockSize))).IsEqualTo(Hex(afterWrap));
        }
    }

    [Test]
    public async Task LongBuffers_InPlaceAndSeparate_MatchTheScalarCode()
    {
        var rng = new Random(280);
        var key = new byte[32];
        var nonce = new byte[8];
        rng.NextBytes(key);
        rng.NextBytes(nonce);
        var input = new byte[(1 << 20) + 37];
        rng.NextBytes(input);
        const ulong counter = 0xffffff00; // crosses 2^32 a quarter of the way in

        var expected = Hex(Run(key, nonce, counter, input, 1));
        foreach (var path in Paths)
        {
            await Assert.That(Hex(Run(key, nonce, counter, input, path))).IsEqualTo(expected);

            var inPlace = (byte[])input.Clone();
            ChaCha20.Xor(key, nonce, counter, inPlace, inPlace, path);
            await Assert.That(Hex(inPlace)).IsEqualTo(expected);
        }
    }

    [Test]
    [Arguments(1, 0)]
    [Arguments(1, 1000)]
    [Arguments(4, 0)]
    [Arguments(4, 255)]
    [Arguments(4, 256)]
    [Arguments(4, 511)]
    [Arguments(4, 1000)]
    [Arguments(8, 255)]
    [Arguments(8, 256)]
    [Arguments(8, 511)]
    [Arguments(8, 512)]
    [Arguments(8, 767)]
    [Arguments(8, 768)]
    [Arguments(8, 1024)]
    [Arguments(8, 1300)]
    public async Task TheVectorCodeDoesWholeGroupsOnly_AndAdvancesTheCounter(int parallelBlocks, int length)
    {
        // 8 lanes take whole groups of 512 bytes and then at most one group of 256 with 4 lanes; 4 lanes take groups of 256; the
        // scalar code does the rest. Bytes past the groups are left alone, and the counter moves by the blocks done.
        var expected = parallelBlocks switch
        {
            8 => (length / 512 * 512) + (length % 512 / 256 * 256),
            4 => length / 256 * 256,
            _ => 0,
        };
        var key = new byte[32];
        var input = new byte[length];
        var output = new byte[length];
        Array.Fill(output, (byte)0xa5);
        var counter = 0xfffffffeUL;

        var done = ChaCha20.XorParallel(key, 0, 0, ref counter, input, output, parallelBlocks);

        await Assert.That(done).IsEqualTo(expected);
        await Assert.That(counter).IsEqualTo(0xfffffffeUL + (ulong)(expected / ChaCha20.BlockSize));
        await Assert.That(output.AsSpan(done).ToArray().All(b => b == 0xa5)).IsTrue();
        await Assert.That(Hex(output.AsSpan(0, done))).IsEqualTo(Hex(Run(key, new byte[8], 0xfffffffe, new byte[done], 1)));
    }

    [Test]
    [Arguments(4, 255, 0)]
    [Arguments(4, 256, 256)]
    [Arguments(4, 600, 512)]
    [Arguments(8, 511, 0)]
    [Arguments(8, 512, 512)]
    [Arguments(8, 1100, 1024)]
    public async Task EachKernelTakesEveryWholeGroup(int blocks, int length, int expected)
    {
        // Through XorParallel, a group the 8-block kernel skipped would still be done by the 4-block one; here each kernel runs alone.
        var key = new byte[32];
        var input = new byte[length];
        var output = new byte[length];
        var counter = 5UL;
        var done = blocks == 8
            ? ChaCha20.Xor8Blocks(key, 0, 0, ref counter, input, output)
            : ChaCha20.Xor4Blocks(key, 0, 0, ref counter, input, output);

        await Assert.That(done).IsEqualTo(expected);
        await Assert.That(counter).IsEqualTo(5UL + (ulong)(expected / ChaCha20.BlockSize));
        await Assert.That(Hex(output.AsSpan(0, done))).IsEqualTo(Hex(Run(key, new byte[8], 5, new byte[done], 1)));
    }

    [Test]
    public async Task ThePathFollowsTheHardware()
    {
        await Assert.That(ChaCha20.SelectParallelBlocks(littleEndian: true, vector256: true, vector128: true)).IsEqualTo(8);
        await Assert.That(ChaCha20.SelectParallelBlocks(littleEndian: true, vector256: false, vector128: true)).IsEqualTo(4);
        await Assert.That(ChaCha20.SelectParallelBlocks(littleEndian: true, vector256: false, vector128: false)).IsEqualTo(1);
        await Assert.That(ChaCha20.SelectParallelBlocks(littleEndian: false, vector256: true, vector128: true)).IsEqualTo(1);
        await Assert.That(ChaCha20.SelectParallelBlocks(littleEndian: false, vector256: false, vector128: true)).IsEqualTo(1);

        // .NET 8 stops at 4 blocks (see ChaCha20.Use256BitVectors).
#if NET10_0_OR_GREATER
        var wide = Vector256.IsHardwareAccelerated;
#else
        var wide = false;
#endif
        await Assert.That(ChaCha20.ParallelBlocks).IsEqualTo(
            ChaCha20.SelectParallelBlocks(BitConverter.IsLittleEndian, wide, Vector128.IsHardwareAccelerated));
    }
}
