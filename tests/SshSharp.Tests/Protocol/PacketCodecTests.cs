using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class PacketCodecTests
{
    private static readonly Random KeyRng = new(41);
    private static readonly byte[] ChachaKey = KeyBytes(64);
    private static readonly byte[] Gcm128Key = KeyBytes(16);
    private static readonly byte[] Gcm256Key = KeyBytes(32);
    private static readonly byte[] GcmIv = KeyBytes(12);
    private static readonly byte[] Ctr128Key = KeyBytes(16);
    private static readonly byte[] Ctr256Key = KeyBytes(32);
    private static readonly byte[] CtrIv = KeyBytes(16);
    private static readonly byte[] Mac256Key = KeyBytes(32);
    private static readonly byte[] Mac512Key = KeyBytes(64);

    private static byte[] KeyBytes(int count)
    {
        var bytes = new byte[count];
        KeyRng.NextBytes(bytes);
        return bytes;
    }

    public static IEnumerable<string> Suites() =>
    [
        "none", "chacha20-poly1305", "aes128-gcm", "aes256-gcm", "aes128-ctr+hmac-sha2-256-etm", "aes256-ctr+hmac-sha2-512-etm",
        "aes128-ctr+hmac-sha2-256", "aes256-ctr+hmac-sha2-512",
    ];

    // Each call creates a fresh protector (own counters/state) from the same keys, so sender and receiver stay in sync.
    private static PacketProtector Create(string suite) => suite switch
    {
        "none" => PacketProtector.None,
        "chacha20-poly1305" => new ChaCha20Poly1305Protector(ChachaKey),
        "aes128-gcm" => new AesGcmProtector(Gcm128Key, GcmIv),
        "aes256-gcm" => new AesGcmProtector(Gcm256Key, GcmIv),
        "aes128-ctr+hmac-sha2-256-etm" => new AesCtrEtmProtector(Ctr128Key, CtrIv, Mac256Key, HashAlgorithmName.SHA256),
        "aes256-ctr+hmac-sha2-512-etm" => new AesCtrEtmProtector(Ctr256Key, CtrIv, Mac512Key, HashAlgorithmName.SHA512),
        "aes128-ctr+hmac-sha2-256" => new AesCtrHmacProtector(Ctr128Key, CtrIv, Mac256Key, HashAlgorithmName.SHA256),
        "aes256-ctr+hmac-sha2-512" => new AesCtrHmacProtector(Ctr256Key, CtrIv, Mac512Key, HashAlgorithmName.SHA512),
        _ => throw new ArgumentOutOfRangeException(nameof(suite)),
    };
    private static byte[] Encode(PacketProtector protector, byte[] payload, uint sequence)
    {
        var buffer = new ArrayBufferWriter<byte>();
        PacketCodec.Encode(buffer, payload, protector, sequence);
        return buffer.WrittenSpan.ToArray();
    }

    private static (bool Ok, byte[]? Payload, long Consumed) Decode(PacketProtector protector, ReadOnlySequence<byte> input, uint sequence)
    {
        var ok = PacketCodec.TryDecode(input, protector, sequence, out var packet, out var consumed);
        using (packet)
        {
            return (ok, packet?.Payload.ToArray(), consumed);
        }
    }

    private static ReadOnlySequence<byte> Segmented(byte[] data, int chunk)
    {
        if (data.Length <= chunk)
        {
            return new ReadOnlySequence<byte>(data);
        }

        Segment? first = null;
        Segment? last = null;
        for (var offset = 0; offset < data.Length; offset += chunk)
        {
            var piece = data.AsMemory(offset, Math.Min(chunk, data.Length - offset));
            last = last is null ? (first = new Segment(piece)) : last.Append(piece);
        }

        return new ReadOnlySequence<byte>(first!, 0, last!, last!.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task RoundTrip_ManySizesAndSequences(string suite)
    {
        using var sender = Create(suite);
        using var receiver = Create(suite);
        var rng = new Random(42);
        uint sequence = 0;
        foreach (var size in new[] { 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 1000, 30000 })
        {
            var payload = new byte[size];
            rng.NextBytes(payload);
            var wire = Encode(sender, payload, sequence);

            var (ok, decoded, consumed) = Decode(receiver, new ReadOnlySequence<byte>(wire), sequence);
            await Assert.That(ok).IsTrue();
            await Assert.That(consumed).IsEqualTo(wire.Length);
            await Assert.That(Convert.ToHexString(decoded!)).IsEqualTo(Convert.ToHexString(payload));
            sequence++;
        }
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task Encoded_SizeAndAlignment_AreValid(string suite)
    {
        using var sender = Create(suite);
        using var receiver = Create(suite);
        foreach (var size in new[] { 1, 5, 12, 13, 27, 100 })
        {
            var wire = Encode(sender, new byte[size], 0);
            var firstFour = wire.AsSpan(0, 4);

            // An encrypted length (encrypt-and-MAC) is read with the receiver's keystream, so the receiver decodes each packet in turn.
            var length = receiver.ReadLength(0, firstFour);
            var (ok, _, _) = Decode(receiver, new ReadOnlySequence<byte>(wire), 0);
            await Assert.That(ok).IsTrue();

            await Assert.That(wire.Length).IsEqualTo((int)(4 + length + sender.TagSize));
            var aligned = sender.LengthExcludedFromAlignment ? length : length + 4;
            await Assert.That(aligned % (uint)sender.Alignment).IsEqualTo(0u);
            await Assert.That(length - 1 - size).IsGreaterThanOrEqualTo(4u); // padding >= 4
        }
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task Streaming_NeedsMoreDataUntilTheLastByte_AndWorksOverSegments(string suite)
    {
        using var sender = Create(suite);
        var payload = new byte[60];
        new Random(43).NextBytes(payload);
        var wire = Encode(sender, payload, 5);

        // Every strict prefix must report "need more data" without consuming or throwing.
        for (var prefix = 0; prefix < wire.Length; prefix += 7)
        {
            using var probe = Create(suite);
            var (ok, _, consumed) = Decode(probe, new ReadOnlySequence<byte>(wire.AsMemory(0, prefix)), 5);
            await Assert.That(ok).IsFalse();
            await Assert.That(consumed).IsEqualTo(0L);
        }

        foreach (var chunk in new[] { 1, 3, 4, 5, 17 })
        {
            using var receiver = Create(suite);
            var (ok, decoded, _) = Decode(receiver, Segmented(wire, chunk), 5);
            await Assert.That(ok).IsTrue();
            await Assert.That(Convert.ToHexString(decoded!)).IsEqualTo(Convert.ToHexString(payload));
        }
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task TrailingBytes_AreLeftAlone(string suite)
    {
        using var sender = Create(suite);
        using var receiver = Create(suite);
        var first = Encode(sender, [1, 2, 3], 0);
        var second = Encode(sender, [4, 5, 6, 7], 1);

        var (ok, payload, consumed) = Decode(receiver, new ReadOnlySequence<byte>([.. first, .. second]), 0);
        await Assert.That(ok).IsTrue();
        await Assert.That(consumed).IsEqualTo(first.Length);
        await Assert.That(Convert.ToHexString(payload!)).IsEqualTo("010203");
    }

    [Test]
    [MethodDataSource(nameof(Suites))]
    public async Task Tampering_NeverYieldsAPacket(string suite)
    {
        if (suite == "none")
        {
            return; // The unprotected state has no integrity protection by design.
        }

        using var sender = Create(suite);
        var wire = Encode(sender, new byte[50], 9);

        for (var i = 0; i < wire.Length; i++)
        {
            var bad = (byte[])wire.Clone();
            bad[i] ^= 0x01;
            using var receiver = Create(suite);
            var outcome = "decoded";
            try
            {
                var (ok, _, _) = Decode(receiver, new ReadOnlySequence<byte>(bad), 9);
                outcome = ok ? "decoded" : "need-more";
            }
            catch (SshProtocolException)
            {
                outcome = "rejected";
            }

            await Assert.That(outcome).IsNotEqualTo("decoded");
        }
    }

    [Test]
    [Arguments("chacha20-poly1305")]
    [Arguments("aes128-ctr+hmac-sha2-256-etm")]
    public async Task WrongSequenceNumber_FailsTheMac(string name)
    {
        using var sender = Create(name);
        using var receiver = Create(name);
        var wire = Encode(sender, new byte[20], 3);
        await Assert.That(() => Decode(receiver, new ReadOnlySequence<byte>(wire), 4)).Throws<SshProtocolException>();
    }

    private const string AuthenticationFailed = "Packet authentication failed (bad MAC or tag).";

    public static IEnumerable<string> PlainMacSuites() => ["aes128-ctr+hmac-sha2-256", "aes256-ctr+hmac-sha2-512"];

    /// <summary>
    /// Encrypt-and-MAC (RFC 4253 section 6.4), checked against an independent re-computation: the whole packet, length included, is
    /// AES-CTR encrypted, and the MAC is HMAC(key, sequence_number || plaintext packet).
    /// </summary>
    [Test]
    [MethodDataSource(nameof(PlainMacSuites))]
    public async Task PlainMac_EncryptsTheLength_AndMacsThePlaintext(string suite)
    {
        var (key, macKey, macSize) = suite.EndsWith("256", StringComparison.Ordinal) ? (Ctr128Key, Mac256Key, 32) : (Ctr256Key, Mac512Key, 64);
        using var sender = Create(suite);
        var payload = "encrypt-and-MAC"u8.ToArray();
        var first = Encode(sender, [0], 6); // check the second packet: the counter and the sequence number have both moved on
        var wire = Encode(sender, payload, 7);
        var packetSize = wire.Length - macSize;
        await Assert.That(sender.TagSize).IsEqualTo(macSize);
        await Assert.That(packetSize % 16).IsEqualTo(0);

        using var reference = new SshSharp.Crypto.AesCtr(key, CtrIv);
        reference.Transform(new byte[first.Length - macSize]);
        var plain = wire[..packetSize];
        reference.Transform(plain);
        await Assert.That(BinaryPrimitives.ReadUInt32BigEndian(plain)).IsEqualTo((uint)(packetSize - 4));
        await Assert.That(BinaryPrimitives.ReadUInt32BigEndian(wire)).IsNotEqualTo((uint)(packetSize - 4));
        await Assert.That(Convert.ToHexString(plain.AsSpan(5, payload.Length))).IsEqualTo(Convert.ToHexString(payload));

        var macInput = new byte[4 + packetSize];
        BinaryPrimitives.WriteUInt32BigEndian(macInput, 7);
        plain.CopyTo(macInput, 4);
        var expectedMac = macSize == 32 ? HMACSHA256.HashData(macKey, macInput) : HMACSHA512.HashData(macKey, macInput);
        await Assert.That(Convert.ToHexString(wire.AsSpan(packetSize))).IsEqualTo(Convert.ToHexString(expectedMac));
    }

    /// <summary>
    /// AES-GCM (RFC 5647), checked against the platform's AesGcm directly: the length is in clear as associated data and is a multiple of
    /// 16, and the 12-byte nonce is the IV with its 64-bit invocation counter incremented after each packet.
    /// </summary>
    [Test]
    [Arguments("aes128-gcm")]
    [Arguments("aes256-gcm")]
    public async Task Gcm_MatchesRfc5647_LayoutAndNonceSequence(string suite)
    {
        var key = suite == "aes128-gcm" ? Gcm128Key : Gcm256Key;
        using var sender = Create(suite);
        using var gcm = new AesGcm(key, 16);
        var fixedField = BinaryPrimitives.ReadUInt32BigEndian(GcmIv);
        var counter = BinaryPrimitives.ReadUInt64BigEndian(GcmIv.AsSpan(4));
        for (uint packet = 0; packet < 3; packet++)
        {
            var payload = new byte[25 + (int)packet];
            payload.AsSpan().Fill((byte)(packet + 1));
            var wire = Encode(sender, payload, packet);

            var length = BinaryPrimitives.ReadUInt32BigEndian(wire);
            await Assert.That(length % 16).IsEqualTo(0u);
            await Assert.That(wire.Length).IsEqualTo(4 + (int)length + 16);

            var nonce = new byte[12];
            BinaryPrimitives.WriteUInt32BigEndian(nonce, fixedField);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), counter + packet);
            var plain = new byte[length];
            gcm.Decrypt(nonce, wire.AsSpan(4, (int)length), wire.AsSpan(4 + (int)length), plain, wire.AsSpan(0, 4));
            var padding = plain[0];
            await Assert.That((int)padding).IsGreaterThanOrEqualTo(4);
            await Assert.That(Convert.ToHexString(plain.AsSpan(1, plain.Length - 1 - padding))).IsEqualTo(Convert.ToHexString(payload));
        }
    }

    [Test]
    [MethodDataSource(nameof(PlainMacSuites))]
    public async Task PlainMac_ReadLengthDecryptsWithoutAdvancing(string suite)
    {
        using var sender = Create(suite);
        using var receiver = Create(suite);
        var wire = Encode(sender, new byte[40], 0);
        var expected = (uint)(wire.Length - receiver.TagSize - 4);

        // The codec asks again each time more data arrives: the answer must not change, and the packet must still decode afterwards.
        await Assert.That(receiver.ReadLength(0, wire.AsSpan(0, 4))).IsEqualTo(expected);
        await Assert.That(receiver.ReadLength(0, wire.AsSpan(0, 4))).IsEqualTo(expected);
        var (ok, payload, _) = Decode(receiver, new ReadOnlySequence<byte>(wire), 0);
        await Assert.That(ok).IsTrue();
        await Assert.That(payload!.Length).IsEqualTo(40);
    }

    [Test]
    [MethodDataSource(nameof(PlainMacSuites))]
    public async Task PlainMac_TamperedMac_FailsAuthentication(string suite)
    {
        using var sender = Create(suite);
        var wire = Encode(sender, new byte[30], 2);
        foreach (var index in new[] { wire.Length - sender.TagSize, wire.Length - 1 })
        {
            var bad = (byte[])wire.Clone();
            bad[index] ^= 0x80;
            using var receiver = Create(suite);
            var ex = Assert.Throws<SshProtocolException>(() => Decode(receiver, new ReadOnlySequence<byte>(bad), 2));
            await Assert.That(ex.Message).IsEqualTo(AuthenticationFailed);
            await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        }
    }

    [Test]
    [MethodDataSource(nameof(PlainMacSuites))]
    public async Task PlainMac_TamperedCiphertext_FailsAuthentication(string suite)
    {
        using var sender = Create(suite);
        var wire = Encode(sender, new byte[30], 2);

        // Every byte after the encrypted length: the padding length, payload and padding are all covered by the MAC.
        for (var index = 4; index < wire.Length - sender.TagSize; index++)
        {
            var bad = (byte[])wire.Clone();
            bad[index] ^= 0x01;
            using var receiver = Create(suite);
            var ex = Assert.Throws<SshProtocolException>(() => Decode(receiver, new ReadOnlySequence<byte>(bad), 2));
            await Assert.That(ex.Message).IsEqualTo(AuthenticationFailed);
        }
    }

    [Test]
    [MethodDataSource(nameof(PlainMacSuites))]
    public async Task PlainMac_WrongSequenceNumber_FailsAuthentication(string suite)
    {
        using var sender = Create(suite);
        var wire = Encode(sender, new byte[20], 3);
        foreach (var sequence in new uint[] { 2, 4, 3 | 0x80000000 })
        {
            using var receiver = Create(suite);
            var ex = Assert.Throws<SshProtocolException>(() => Decode(receiver, new ReadOnlySequence<byte>(wire), sequence));
            await Assert.That(ex.Message).IsEqualTo(AuthenticationFailed);
        }
    }

    [Test]
    public async Task Gcm_ReplayedPacketFailsBecauseTheIvCounterMoved()
    {
        using var sender = Create("aes128-gcm");
        using var receiver = Create("aes128-gcm");
        var wire = Encode(sender, [1, 2, 3], 0);
        var (ok, _, _) = Decode(receiver, new ReadOnlySequence<byte>(wire), 0);
        await Assert.That(ok).IsTrue();
        await Assert.That(() => Decode(receiver, new ReadOnlySequence<byte>(wire), 1)).Throws<SshProtocolException>();
    }

    private static byte[] RawNonePacket(uint length, byte padding, int bodyLength)
    {
        var bytes = new byte[4 + bodyLength];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, length);
        if (bytes.Length > 4)
        {
            bytes[4] = padding;
        }

        return bytes;
    }

    [Test]
    public async Task Decode_RejectsInvalidLengths()
    {
        var none = PacketProtector.None;
        foreach (var length in new uint[] { 0, 1, 4, 8, 11, 13, (uint)PacketCodec.MaxPacketLength + 8, uint.MaxValue })
        {
            var wire = RawNonePacket(length, 4, 16);
            await Assert.That(() => Decode(none, new ReadOnlySequence<byte>(wire), 0)).Throws<SshProtocolException>();
        }
    }

    [Test]
    public async Task Decode_RejectsInvalidPadding()
    {
        var none = PacketProtector.None;
        // length 12 is aligned (12 + 4 = 16); padding 3 is below the minimum, padding 12 leaves no room for the padding byte itself.
        await Assert.That(() => Decode(none, new ReadOnlySequence<byte>(RawNonePacket(12, 3, 12)), 0)).Throws<SshProtocolException>();
        await Assert.That(() => Decode(none, new ReadOnlySequence<byte>(RawNonePacket(12, 12, 12)), 0)).Throws<SshProtocolException>();
        await Assert.That(() => Decode(none, new ReadOnlySequence<byte>(RawNonePacket(12, 255, 12)), 0)).Throws<SshProtocolException>();

        var ok = RawNonePacket(12, 4, 12);
        var (decoded, payload, _) = Decode(none, new ReadOnlySequence<byte>(ok), 0);
        await Assert.That(decoded).IsTrue();
        await Assert.That(payload!.Length).IsEqualTo(7);

        // The largest padding allowed, length - 1, leaves an empty payload: the codec accepts it, and the layer above judges the message.
        (decoded, payload, _) = Decode(none, new ReadOnlySequence<byte>(RawNonePacket(12, 11, 12)), 0);
        await Assert.That(decoded).IsTrue();
        await Assert.That(payload!.Length).IsEqualTo(0);
    }

    public static IEnumerable<string> ProtectedSuites() => Suites().Where(s => s != "none");

    [Test]
    [MethodDataSource(nameof(ProtectedSuites))]
    public async Task TamperedTag_FailsAuthentication_ItselfAndNotALaterCheck(string suite)
    {
        // Only the tag changes, so the packet itself would decrypt to a valid one: the authentication check alone must refuse it.
        using var sender = Create(suite);
        var wire = Encode(sender, new byte[30], 5);
        var bad = (byte[])wire.Clone();
        bad[^1] ^= 0x01;
        using var receiver = Create(suite);
        var ex = Assert.Throws<SshProtocolException>(() => Decode(receiver, new ReadOnlySequence<byte>(bad), 5));
        await Assert.That(ex.Message).IsEqualTo(AuthenticationFailed);
    }

    private static byte[] EtmLengthOnly(uint length)
    {
        // Encrypt-then-MAC sends the length in clear and aligns it by itself, so any multiple of 16 reaches the length check alone.
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, length);
        return bytes;
    }

    [Test]
    public async Task Decode_LengthLimit_IsExact()
    {
        using var etm = Create("aes128-ctr+hmac-sha2-256-etm");

        // The largest length allowed waits for the rest of the packet.
        var (ok, _, consumed) = Decode(etm, new ReadOnlySequence<byte>(EtmLengthOnly(PacketCodec.MaxPacketLength)), 0);
        await Assert.That(ok).IsFalse();
        await Assert.That(consumed).IsEqualTo(0);

        // One block more is refused at once, before any of it is buffered, by the length check itself.
        var tooLong = PacketCodec.MaxPacketLength + 16;
        var ex = Assert.Throws<SshProtocolException>(() => Decode(etm, new ReadOnlySequence<byte>(EtmLengthOnly((uint)tooLong)), 0));
        await Assert.That(ex.Message).IsEqualTo($"Invalid packet length {tooLong}.");

        ex = Assert.Throws<SshProtocolException>(() => Decode(etm, new ReadOnlySequence<byte>(EtmLengthOnly(uint.MaxValue & ~15u)), 0));
        await Assert.That(ex.Message).IsEqualTo($"Invalid packet length {uint.MaxValue & ~15u}.");
    }

    [Test]
    public async Task Decode_ShortAndMisalignedLengths_FailTheirOwnChecks()
    {
        var none = PacketProtector.None;

        // 4 is aligned (4 + 4 = 8) but leaves no room for the padding length byte and the minimum padding.
        var ex = Assert.Throws<SshProtocolException>(() => Decode(none, new ReadOnlySequence<byte>(RawNonePacket(4, 4, 16)), 0));
        await Assert.That(ex.Message).IsEqualTo("Invalid packet length 4.");

        ex = Assert.Throws<SshProtocolException>(() => Decode(none, new ReadOnlySequence<byte>(RawNonePacket(13, 4, 16)), 0));
        await Assert.That(ex.Message).IsEqualTo("Packet length 13 is not a multiple of the cipher block size.");
    }

    [Test]
    public async Task Encode_LengthLimit_IsExact()
    {
        // With encrypt-then-MAC, payload MaxPacketLength - 5 needs exactly the minimum padding (4) to reach MaxPacketLength.
        using var etm = Create("aes128-ctr+hmac-sha2-256-etm");
        var largest = new byte[PacketCodec.MaxPacketLength - 5];
        var wire = Encode(etm, largest, 0);
        await Assert.That(BinaryPrimitives.ReadUInt32BigEndian(wire)).IsEqualTo((uint)PacketCodec.MaxPacketLength);
        using var receiver = Create("aes128-ctr+hmac-sha2-256-etm");
        var (ok, payload, _) = Decode(receiver, new ReadOnlySequence<byte>(wire), 0);
        await Assert.That(ok).IsTrue();
        await Assert.That(payload!.Length).IsEqualTo(largest.Length);

        var buffer = new ArrayBufferWriter<byte>();
        await Assert.That(() => PacketCodec.Encode(buffer, new byte[PacketCodec.MaxPacketLength - 4], etm, 1)).Throws<ArgumentException>();
    }

    [Test]
    public async Task Encode_RejectsOversizedPayload()
    {
        var buffer = new ArrayBufferWriter<byte>();
        await Assert.That(() => PacketCodec.Encode(buffer, new byte[PacketCodec.MaxPacketLength], PacketProtector.None, 0)).Throws<ArgumentException>();
    }

    [Test]
    public async Task DecodedPacket_ZeroesAndInvalidatesOnDispose()
    {
        var wire = Encode(PacketProtector.None, [9, 9, 9], 0);
        PacketCodec.TryDecode(new ReadOnlySequence<byte>(wire), PacketProtector.None, 0, out var packet, out _);
        var view = packet!.Payload;
        await Assert.That(view.Length).IsEqualTo(3);
        packet.Dispose();
        packet.Dispose(); // idempotent
        await Assert.That(() => packet.Payload).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Protectors_ValidateTheirKeys()
    {
        await Assert.That(() => new AesGcmProtector(new byte[24], new byte[12])).Throws<ArgumentException>();
        // Refused by the check itself (ThrowsExactly: slicing a short IV would throw an ArgumentOutOfRangeException anyway).
        await Assert.That(() => new AesGcmProtector(new byte[16], new byte[11])).ThrowsExactly<ArgumentException>();
        using (new AesGcmProtector(new byte[16], new byte[16]))
        {
            // A longer IV is fine: the first 12 bytes are used, as the key derivation produces more than that.
        }

        await Assert.That(() => new ChaCha20Poly1305Protector(new byte[10])).Throws<ArgumentException>();
        await Assert.That(PacketProtector.None.TagSize).IsEqualTo(0);
    }

    [Test]
    public async Task ChaCha20Poly1305_AlignsThePacketLengthWithoutTheLengthField()
    {
        // chacha20-poly1305@openssh.com encrypts the length separately; packet_length itself (not length + 4) is a multiple of 8.
        using var sender = Create("chacha20-poly1305");
        for (uint packet = 0; packet < 20; packet++)
        {
            var wire = Encode(sender, new byte[(int)packet * 3], packet);
            using var reader = Create("chacha20-poly1305");
            var length = reader.ReadLength(packet, wire.AsSpan(0, 4));
            await Assert.That(length % 8).IsEqualTo(0u);
            await Assert.That(wire.Length).IsEqualTo(4 + (int)length + 16);
        }
    }
}