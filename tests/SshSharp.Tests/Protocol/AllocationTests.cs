using System.Buffers;
using System.Security.Cryptography;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// Guards the zero-copy design: encoding and decoding a packet must not allocate in proportion to its size. The measurements use
/// per-thread allocation counters and run synchronously (no awaits) so that nothing else on the thread is counted.
/// </summary>
public class AllocationTests
{
    public static IEnumerable<string> Suites() => ["chacha20-poly1305", "aes256-gcm", "aes256-ctr+hmac-sha2-256-etm"];

    private static PacketProtector Create(string suite)
    {
        var key = new byte[64];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i * 7);
        }

        return suite switch
        {
            "chacha20-poly1305" => new ChaCha20Poly1305Protector(key),
            "aes256-gcm" => new AesGcmProtector(key.AsSpan(0, 32), key.AsSpan(32, 12)),
            _ => new AesCtrEtmProtector(key.AsSpan(0, 32), key.AsSpan(32, 16), key.AsSpan(0, 32), HashAlgorithmName.SHA256),
        };
    }

    /// <summary>Average bytes allocated per packet by Encode (and optionally Decode) in steady state.</summary>
    private static double AllocatedPerPacket(string suite, int payloadSize, bool decode)
    {
        using var sender = Create(suite);
        using var receiver = Create(suite);
        var payload = new byte[payloadSize];
        payload[0] = 94;
        var buffer = new ArrayBufferWriter<byte>(payloadSize + 1024);
        uint sequence = 0;

        void Once()
        {
            buffer.Clear();
            var current = sequence++;
            PacketCodec.Encode(buffer, payload, sender, current);
            if (decode)
            {
                PacketCodec.TryDecode(new ReadOnlySequence<byte>(buffer.WrittenMemory), receiver, current, out var packet, out _);
                packet!.Dispose();
            }
        }

        for (var i = 0; i < 2000; i++)
        {
            Once(); // warm up: JIT, tiered compilation, buffer pools
        }

        // The lowest of a few rounds: the runtime occasionally allocates on this thread for its own reasons (the shared array pool
        // trimming and refilling after a gen-2 GC, a late tier-up), which lands in one round and is not the codec's doing.
        const int iterations = 2000;
        var lowest = double.MaxValue;
        for (var round = 0; round < 3; round++)
        {
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < iterations; i++)
            {
                Once();
            }

            lowest = Math.Min(lowest, (GC.GetAllocatedBytesForCurrentThread() - before) / (double)iterations);
        }

        return lowest;
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task Encoding_AllocatesNothingInSteadyState(string suite)
    {
        var allocated = AllocatedPerPacket(suite, 1000, decode: false);
        await Assert.That(allocated).IsLessThanOrEqualTo(16.0);
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task Decoding_AllocatesOnlyTheSmallPacketWrapper(string suite)
    {
        if (Instrumentation.Enabled)
        {
            Skip.Test("The instrumented build tracks each pooled buffer, which allocates.");
            return;
        }

        var allocated = AllocatedPerPacket(suite, 1000, decode: true);
        await Assert.That(allocated).IsLessThanOrEqualTo(128.0);
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task AllocationDoesNotGrowWithThePacketSize(string suite)
    {
        if (Instrumentation.Enabled)
        {
            Skip.Test("The instrumented build tracks each pooled buffer, which allocates.");
            return;
        }

        // The signature of zero copy: a 16 KiB packet costs the same garbage as a 100 byte one.
        var small = AllocatedPerPacket(suite, 100, decode: true);
        var large = AllocatedPerPacket(suite, 16_000, decode: true);
        await Assert.That(large).IsLessThanOrEqualTo(small + 32.0);
    }
}