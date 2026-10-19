using System.IO.Compression;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// <c>zlib@openssh.com</c>'s two halves on their own: <see cref="ZlibCompressor"/> (Huffman coding only, one stream sync-flushed per
/// packet) and <see cref="ZlibDecompressor"/> (bounded, strict about what it is given).
/// </summary>
public class PacketCompressionTests
{
    private static byte[] Text(int size, int seed)
    {
        // Shell-like output: a few words repeated, so it compresses, varied by the seed so packets differ.
        var words = new[] { "total ", "drwxr-xr-x ", "deploy ", "staff ", "4096 ", "Oct 19 ", "config.json\n", "logs\n", "-rw-r--r-- " };
        var builder = new StringBuilder(size);
        var random = new Random(seed);
        while (builder.Length < size)
        {
            builder.Append(words[random.Next(words.Length)]);
        }

        return Encoding.ASCII.GetBytes(builder.ToString(0, size));
    }

    /// <summary>Compresses each payload with zlib's usual coding (LZ77 and Huffman), sync-flushed per payload, as older OpenSSH and other servers do.</summary>
    private static List<byte[]> CompressWithZlib(IEnumerable<byte[]> payloads)
    {
        var output = new MemoryStream();
        using var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true);
        var packets = new List<byte[]>();
        foreach (var payload in payloads)
        {
            output.SetLength(0);
            zlib.Write(payload);
            zlib.Flush();
            packets.Add(output.ToArray());
        }

        return packets;
    }

    private static byte[] Inflate(ZlibDecompressor decompressor, byte[] compressed)
    {
        using var packet = decompressor.Decompress(compressed);
        return packet.Payload.ToArray();
    }

    [Test]
    public async Task TheDecompressor_InflatesAZlibStreamPacketByPacket()
    {
        // Sizes around the decompressor's first buffer and the 8 KiB reads of the stream underneath, and one packet larger than both.
        var payloads = new[] { 1, 5, 100, 8191, 8192, 8193, 32_777, 65_535, 65_536, 65_537, 200_000 }
            .Select((size, i) => i % 3 == 2 ? System.Security.Cryptography.RandomNumberGenerator.GetBytes(size) : Text(size, i))
            .ToList();
        using var decompressor = new ZlibDecompressor();
        var compressed = CompressWithZlib(payloads);
        for (var i = 0; i < payloads.Count; i++)
        {
            await Assert.That(Inflate(decompressor, compressed[i]).AsSpan().SequenceEqual(payloads[i])).IsTrue();
        }
    }

    [Test]
    public async Task TheDecompressor_InflatesManyRandomPacketsOfOneStream()
    {
        // Packets whose compressed form ends anywhere in the stream's reads, some of it only the flush marker.
        var random = new Random(7);
        var payloads = Enumerable.Range(0, 400).Select(i => Text(random.Next(1, 40_000), i)).ToList();
        using var decompressor = new ZlibDecompressor();
        var compressed = CompressWithZlib(payloads);
        var mismatches = 0;
        for (var i = 0; i < payloads.Count; i++)
        {
            if (!Inflate(decompressor, compressed[i]).AsSpan().SequenceEqual(payloads[i]))
            {
                mismatches++;
            }
        }

        await Assert.That(mismatches).IsEqualTo(0);
    }

    [Test]
    public async Task APayloadAtTheLimit_FailsTheConnection_OneBelowItInflates()
    {
        // OpenSSH's bound: a decompressed payload must be shorter than the maximum packet length (here a smaller limit, to keep it quick).
        using (var decompressor = new ZlibDecompressor(limit: 1000))
        {
            var payload = Text(999, 1);
            await Assert.That(Inflate(decompressor, CompressWithZlib([payload])[0]).AsSpan().SequenceEqual(payload)).IsTrue();
        }

        using (var decompressor = new ZlibDecompressor(limit: 1000))
        {
            var compressed = CompressWithZlib([Text(1000, 1)])[0];
            var error = await Assert.That(() => Inflate(decompressor, compressed)).Throws<SshProtocolException>();
            await Assert.That(error!.Message).Contains("inflates to 1000 bytes or more");
        }
    }

    [Test]
    public async Task ADecompressionBomb_FailsAtTheMaximumPacketLength()
    {
        // 16 MiB of zeros compress to about 16 KiB: inflating stops at 256 KiB, the most a packet may carry, rather than buffering it all.
        var compressed = CompressWithZlib([new byte[16 * 1024 * 1024]])[0];
        await Assert.That(compressed.Length).IsLessThan(64 * 1024);
        using var decompressor = new ZlibDecompressor();
        var error = await Assert.That(() => Inflate(decompressor, compressed)).Throws<SshProtocolException>();
        await Assert.That(error!.Message).Contains($"inflates to {PacketCodec.MaxPacketLength} bytes or more");
    }

    [Test]
    [Arguments(new byte[] { 0x78, 0x00, 0x01, 0x00 })] // a zlib header whose check bits are wrong
    [Arguments(new byte[] { 0x78, 0x9C, 0x06, 0x00 })] // a block of the reserved type 3
    [Arguments(new byte[] { 0x79, 0x9C, 0x00, 0x00 })] // a compression method other than deflate
    [Arguments(new byte[] { 0x78, 0x20, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00 })] // a preset dictionary, which zlib refuses with ZLibException
    public async Task MalformedData_FailsWithAProtocolError(byte[] compressed)
    {
        using var decompressor = new ZlibDecompressor();
        var error = await Assert.That(() => Inflate(decompressor, compressed)).Throws<SshProtocolException>();
        await Assert.That(error!.InnerException is InvalidDataException or IOException).IsTrue();
        await Assert.That(error.Message).Contains("not valid zlib");
    }

    [Test]
    public async Task AStreamThatEndsInsideAPacket_FailsWithAProtocolError()
    {
        // A sender that finishes its zlib stream (a final block and the checksum) and puts more after it in the same packet. Bytes that
        // the stream has already read past the end (it reads 8 KiB at a time) are dropped with it; the next packet then fails, below.
        var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(Text(100, 1));
        }

        byte[] compressed = [.. output.ToArray(), .. new byte[20_000]];
        using var decompressor = new ZlibDecompressor();
        var error = await Assert.That(() => Inflate(decompressor, compressed)).Throws<SshProtocolException>();
        await Assert.That(error!.Message).Contains("ends the zlib stream");
    }

    [Test]
    public async Task APacketAfterTheStreamEnded_FailsAsEmpty()
    {
        // Once the stream has ended, nothing more inflates: the next packet gives no payload, which the transport rejects.
        var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(Text(100, 1));
        }

        using var decompressor = new ZlibDecompressor();
        await Assert.That(Inflate(decompressor, output.ToArray()).Length).IsEqualTo(100);
        await Assert.That(() => Inflate(decompressor, [0x01, 0x02])).Throws<SshProtocolException>();
    }

    [Test]
    public async Task TheCompressor_RoundTripsThroughTheDecompressor()
    {
        if (!SshAlgorithms.CanCompressOutgoing)
        {
            Skip.Test("Compressing outgoing packets needs .NET 10 (zlib's Huffman-only strategy).");
            return;
        }

        using var compressor = new ZlibCompressor();
        using var decompressor = new ZlibDecompressor();
        var random = new Random(3);
        for (var i = 0; i < 200; i++)
        {
            var payload = i % 5 == 4 ? System.Security.Cryptography.RandomNumberGenerator.GetBytes(random.Next(1, 70_000)) : Text(random.Next(1, 70_000), i);

            // The channel data path: a 9-byte header as the prefix, the data as the body.
            var split = Math.Min(9, payload.Length);
            var compressed = compressor.Compress(payload.AsSpan(0, split), payload.AsSpan(split)).ToArray();
            compressor.Clear();
            await Assert.That(Inflate(decompressor, compressed).AsSpan().SequenceEqual(payload)).IsTrue();
        }
    }

    [Test]
    public async Task TheCompressor_CompressesTextAndStartsWithAZlibHeader()
    {
        if (!SshAlgorithms.CanCompressOutgoing)
        {
            Skip.Test("Compressing outgoing packets needs .NET 10 (zlib's Huffman-only strategy).");
            return;
        }

        using var compressor = new ZlibCompressor();
        var payload = Text(32_768, 1);
        var first = compressor.Compress([], payload).ToArray();

        // 0x78 0x01: deflate with a 32 KiB window, at the fastest level (OpenSSH's Z_BEST_SPEED), then a sync flush's empty stored block.
        await Assert.That(first[0]).IsEqualTo((byte)0x78);
        await Assert.That((first[0] * 256 + first[1]) % 31).IsEqualTo(0);
        await Assert.That(first.AsSpan()[^4..].SequenceEqual(new byte[] { 0x00, 0x00, 0xFF, 0xFF })).IsTrue();
        await Assert.That(first.Length).IsLessThan(payload.Length * 3 / 4);
    }

    [Test]
    public async Task TheCompressor_UsesNoBackReferences_SoRepeatingEarlierDataDoesNotShortenAPacket()
    {
        if (!SshAlgorithms.CanCompressOutgoing)
        {
            Skip.Test("Compressing outgoing packets needs .NET 10 (zlib's Huffman-only strategy).");
            return;
        }

        // The CRIME-style probe: a secret goes out, then data an attacker chooses. With LZ77, a guess that repeats the secret is coded as
        // a short back-reference, so its packet is shorter. With Huffman coding only, a packet's length depends on its own bytes alone: the
        // guess costs the same whether or not the secret went before it.
        var secret = Encoding.ASCII.GetBytes("token=" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)));
        int Probe(bool secretFirst)
        {
            using var compressor = new ZlibCompressor();
            compressor.Compress([], secretFirst ? secret : new byte[secret.Length]);
            compressor.Clear();
            var length = compressor.Compress([], secret).Length;
            compressor.Clear();
            return length;
        }

        await Assert.That(Probe(secretFirst: true)).IsEqualTo(Probe(secretFirst: false));

        // zlib's usual coding gives the repeat away.
        var repeated = CompressWithZlib([secret, secret])[1].Length;
        var fresh = CompressWithZlib([new byte[secret.Length], secret])[1].Length;
        await Assert.That(repeated).IsLessThan(fresh);
    }

    [Test]
    public async Task ClientToServerCompression_IsOfferedOnlyWhereSshSharpCanCompress()
    {
        var init = KexInitMessage.ForClient(new AlgorithmPreferences { Compression = SshAlgorithms.EnabledCompression });
        await Assert.That(string.Join(",", init.CompressionServerToClient)).IsEqualTo("zlib@openssh.com,none");
        await Assert.That(string.Join(",", init.CompressionClientToServer))
            .IsEqualTo(SshAlgorithms.CanCompressOutgoing ? "zlib@openssh.com,none" : "none");

        var off = KexInitMessage.ForClient(new AlgorithmPreferences());
        await Assert.That(string.Join(",", off.CompressionClientToServer)).IsEqualTo("none");
        await Assert.That(string.Join(",", off.CompressionServerToClient)).IsEqualTo("none");
    }

#if NET10_0_OR_GREATER
    [Test]
    public async Task OnDotNet10_OutgoingCompressionIsAvailable() => await Assert.That(SshAlgorithms.CanCompressOutgoing).IsTrue();
#else
    [Test]
    public async Task OnDotNet8_OutgoingCompressionIsNotAvailable() => await Assert.That(SshAlgorithms.CanCompressOutgoing).IsFalse();
#endif
}
