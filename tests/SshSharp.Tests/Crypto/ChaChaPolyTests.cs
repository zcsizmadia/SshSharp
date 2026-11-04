using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class ChaChaPolyTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] Tag(byte[] key, byte[] message)
    {
        var tag = new byte[16];
        Poly1305.ComputeTag(key, message, tag);
        return tag;
    }

    [Test]
    public async Task ChaCha20_Rfc8439_BlockFunctionVector()
    {
        // RFC 8439 section 2.3.2: key 00..1f, counter 1, nonce 00:00:00:09:00:00:00:4a:00:00:00:00.
        var key = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            key[i] = (byte)i;
        }

        var block = new byte[64];
        ChaCha20.Block(key, 1, 0x09000000, 0x4a000000, 0, block);
        await Assert.That(Hex(block)).IsEqualTo(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    [Test]
    public async Task ChaCha20_KeystreamMatchesTheFrameworkAead_ForManyLengths()
    {
        // With word13 = 0 the OpenSSH layout equals RFC 8439's (32-bit counter, 96-bit nonce whose first word is 0).
        var rng = new Random(5);
        var key = new byte[32];
        rng.NextBytes(key);
        var nonce8 = new byte[8];
        rng.NextBytes(nonce8);
        var nonce12 = new byte[12];
        nonce8.CopyTo(nonce12, 4);

        // The longer lengths go through the vectorized code (groups of 8 and 4 blocks) as well as the scalar tail.
        foreach (var length in new[] { 0, 1, 63, 64, 65, 127, 128, 129, 500, 512, 513, 767, 768, 1000, 4100 })
        {
            var plain = new byte[length];
            rng.NextBytes(plain);

            var expected = new byte[length];
            var expectedTag = new byte[16];
            using (var aead = new ChaCha20Poly1305(key))
            {
                aead.Encrypt(nonce12, plain, expected, expectedTag);
            }

            var actual = new byte[length];
            ChaCha20.Xor(key, nonce8, 1, plain, actual);
            await Assert.That(Hex(actual)).IsEqualTo(Hex(expected));

            // The RFC 8439 tag is Poly1305 over pad16(aad) || pad16(ciphertext) || le64(aadLen) || le64(ctLen), keyed by block 0.
            var block0 = new byte[64];
            ChaCha20.Block(key, 0, 0, BinaryPrimitives.ReadUInt32LittleEndian(nonce8), BinaryPrimitives.ReadUInt32LittleEndian(nonce8.AsSpan(4)), block0);
            var macData = new byte[((length + 15) / 16 * 16) + 16];
            expected.CopyTo(macData, 0);
            BinaryPrimitives.WriteUInt64LittleEndian(macData.AsSpan(macData.Length - 8), (ulong)length);
            await Assert.That(Hex(Tag(block0[..32], macData))).IsEqualTo(Hex(expectedTag));
        }
    }

    [Test]
    public async Task ChaCha20_InPlaceAndCounterContinuation()
    {
        var key = new byte[32];
        new Random(9).NextBytes(key);
        var nonce = new byte[8];
        var data = new byte[200];
        new Random(10).NextBytes(data);

        var separate = new byte[200];
        ChaCha20.Xor(key, nonce, 7, data, separate);

        var inPlace = (byte[])data.Clone();
        ChaCha20.Xor(key, nonce, 7, inPlace, inPlace);
        await Assert.That(Hex(inPlace)).IsEqualTo(Hex(separate));

        // Block 8 of a stream starting at counter 7 is the second 64 bytes.
        var second = new byte[64];
        ChaCha20.Xor(key, nonce, 8, data.AsSpan(64, 64), second);
        await Assert.That(Hex(second)).IsEqualTo(Hex(separate.AsSpan(64, 64)));
    }

    [Test]
    public async Task ChaCha20_ChecksSizes()
    {
        // Exactly ArgumentException: a check that let a bad size through would fail later with ArgumentOutOfRangeException instead.
        await Assert.That(() => ChaCha20.Xor(new byte[31], new byte[8], 0, [], [])).ThrowsExactly<ArgumentException>();
        await Assert.That(() => ChaCha20.Xor(new byte[32], new byte[7], 0, [], [])).ThrowsExactly<ArgumentException>();
        await Assert.That(() => ChaCha20.Xor(new byte[32], new byte[8], 0, new byte[4], new byte[3])).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task Poly1305_Rfc8439_Section252_Vector()
    {
        var key = H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var message = "Cryptographic Forum Research Group"u8.ToArray();
        await Assert.That(Hex(Tag(key, message))).IsEqualTo("a8061dc1305136c6c22b8baf0c0127a9");
    }

    [Test]
    public async Task Poly1305_Rfc8439_AppendixA3_EdgeCases()
    {
        // #1: all zero key and message.
        await Assert.That(Hex(Tag(new byte[32], new byte[64]))).IsEqualTo(new string('0', 32));

        // #5: r = 2, s = 0, message = 2^128 - 1: result is 3 (checks the carry out of the last limb).
        var key5 = new byte[32];
        key5[0] = 2;
        await Assert.That(Hex(Tag(key5, H(new string('f', 32))))).IsEqualTo("03" + new string('0', 30));

        // #6: r = 2, s = 2^128 - 1, message = 2: result is 3 (checks h + s wraps mod 2^128).
        var key6 = new byte[32];
        key6[0] = 2;
        Array.Fill(key6, (byte)0xff, 16, 16);
        var msg6 = new byte[16];
        msg6[0] = 2;
        await Assert.That(Hex(Tag(key6, msg6))).IsEqualTo("03" + new string('0', 30));
    }

    [Test]
    public async Task Poly1305_EmptyMessageIsJustS_AndSizesAreChecked()
    {
        var key = new byte[32];
        for (var i = 16; i < 32; i++)
        {
            key[i] = (byte)(i - 15);
        }

        await Assert.That(Hex(Tag(key, []))).IsEqualTo("0102030405060708090a0b0c0d0e0f10");
        // Exactly ArgumentException, with its message: a check that let a bad size through would fail later with
        // ArgumentOutOfRangeException instead.
        await Assert.That(() => Poly1305.ComputeTag(new byte[31], [], new byte[16])).ThrowsExactly<ArgumentException>()
            .WithMessageContaining("32-byte key");
        await Assert.That(() => Poly1305.ComputeTag(new byte[32], [], new byte[15])).ThrowsExactly<ArgumentException>()
            .WithMessageContaining("16-byte tag");
    }

    private static ChaCha20Poly1305OpenSsh NewCipher(out byte[] key)
    {
        key = new byte[64];
        new Random(21).NextBytes(key);
        return new ChaCha20Poly1305OpenSsh(key);
    }

    [Test]
    public async Task OpenSsh_EncryptMatchesTheDocumentedConstruction()
    {
        using var cipher = NewCipher(out var key);
        var body = new byte[37];
        new Random(22).NextBytes(body);
        const uint seq = 0x01020304;
        const uint packetLength = 37;

        var output = new byte[4 + body.Length];
        var tag = new byte[16];
        cipher.Encrypt(seq, packetLength, body, output, tag);

        // Re-derive by hand: nonce = seq as big-endian u64; K_1 = key[32..], K_2 = key[..32].
        var nonce = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, seq);
        var lengthBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, packetLength);
        var encLength = new byte[4];
        ChaCha20.Xor(key.AsSpan(32), nonce, 0, lengthBytes, encLength);
        var encBody = new byte[body.Length];
        ChaCha20.Xor(key.AsSpan(0, 32), nonce, 1, body, encBody);
        var polyKey = new byte[32];
        ChaCha20.Xor(key.AsSpan(0, 32), nonce, 0, new byte[32], polyKey);
        var expectedTag = Tag(polyKey, [.. encLength, .. encBody]);

        await Assert.That(Hex(output.AsSpan(0, 4))).IsEqualTo(Hex(encLength));
        await Assert.That(Hex(output.AsSpan(4))).IsEqualTo(Hex(encBody));
        await Assert.That(Hex(tag)).IsEqualTo(Hex(expectedTag));
    }

    [Test]
    public async Task OpenSsh_RoundTrip_AndLengthDecryption()
    {
        using var enc = NewCipher(out var key);
        using var dec = new ChaCha20Poly1305OpenSsh(key);
        var rng = new Random(23);
        foreach (var bodyLength in new[] { 1, 15, 16, 17, 100, 1000 })
        {
            var body = new byte[bodyLength];
            rng.NextBytes(body);
            var seq = (uint)rng.Next();
            var packet = new byte[4 + bodyLength];
            var tag = new byte[16];
            enc.Encrypt(seq, (uint)bodyLength, body, packet, tag);

            await Assert.That(dec.DecryptLength(seq, packet)).IsEqualTo((uint)bodyLength);
            var plain = new byte[bodyLength];
            await Assert.That(dec.TryDecrypt(seq, packet, tag, plain)).IsTrue();
            await Assert.That(Hex(plain)).IsEqualTo(Hex(body));
        }
    }

    [Test]
    public async Task OpenSsh_RejectsTamperingAndWrongSequence_WithoutWritingPlaintext()
    {
        using var enc = NewCipher(out var key);
        using var dec = new ChaCha20Poly1305OpenSsh(key);
        var body = new byte[40];
        new Random(24).NextBytes(body);
        var packet = new byte[44];
        var tag = new byte[16];
        enc.Encrypt(7, 40, body, packet, tag);

        var plain = new byte[40];
        await Assert.That(dec.TryDecrypt(8, packet, tag, plain)).IsFalse();
        await Assert.That(plain.All(b => b == 0)).IsTrue();

        for (var i = 0; i < packet.Length; i += 5)
        {
            var bad = (byte[])packet.Clone();
            bad[i] ^= 0x80;
            await Assert.That(dec.TryDecrypt(7, bad, tag, plain)).IsFalse();
        }

        for (var i = 0; i < 16; i += 5)
        {
            var badTag = (byte[])tag.Clone();
            badTag[i] ^= 1;
            await Assert.That(dec.TryDecrypt(7, packet, badTag, plain)).IsFalse();
        }

        await Assert.That(plain.All(b => b == 0)).IsTrue();
        await Assert.That(dec.TryDecrypt(7, packet, tag, plain)).IsTrue();
    }

    [Test]
    public async Task OpenSsh_WithoutLength_IsTheKeyFileConstruction()
    {
        // sshkey.c encrypts a key file with chachapoly_crypt(seqnr, aadlen = 0): no encrypted length, K_2 = key[..32] from block 1,
        // the Poly1305 key from K_2's block 0, and the tag over the ciphertext alone. K_1 = key[32..] plays no part.
        using var cipher = NewCipher(out var key);
        var rng = new Random(25);
        foreach (var (length, seq) in new[] { (8, 0u), (64, 0u), (200, 0u), (40, 0x01020304u) })
        {
            var plain = new byte[length];
            rng.NextBytes(plain);
            var nonce = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(nonce, seq);
            var sealedBytes = new byte[length];
            ChaCha20.Xor(key.AsSpan(0, 32), nonce, 1, plain, sealedBytes);
            var polyKey = new byte[32];
            ChaCha20.Xor(key.AsSpan(0, 32), nonce, 0, new byte[32], polyKey);
            var tag = Tag(polyKey, sealedBytes);

            var opened = new byte[length];
            await Assert.That(cipher.TryDecryptWithoutLength(seq, sealedBytes, tag, opened)).IsTrue();
            await Assert.That(Hex(opened)).IsEqualTo(Hex(plain));

            // A key whose second half differs opens it the same way: the length key is unused.
            var otherLengthKey = (byte[])key.Clone();
            otherLengthKey[40] ^= 1;
            using (var other = new ChaCha20Poly1305OpenSsh(otherLengthKey))
            {
                var again = new byte[length];
                await Assert.That(other.TryDecryptWithoutLength(seq, sealedBytes, tag, again)).IsTrue();
                await Assert.That(Hex(again)).IsEqualTo(Hex(plain));
            }

            // Any changed bit of the ciphertext or the tag, or another sequence number, fails before anything is written.
            var untouched = new byte[length];
            for (var i = 0; i < length; i += 7)
            {
                var bad = (byte[])sealedBytes.Clone();
                bad[i] ^= 0x40;
                await Assert.That(cipher.TryDecryptWithoutLength(seq, bad, tag, untouched)).IsFalse();
            }

            for (var i = 0; i < 16; i += 3)
            {
                var badTag = (byte[])tag.Clone();
                badTag[i] ^= 0x02;
                await Assert.That(cipher.TryDecryptWithoutLength(seq, sealedBytes, badTag, untouched)).IsFalse();
            }

            await Assert.That(cipher.TryDecryptWithoutLength(seq + 1, sealedBytes, tag, untouched)).IsFalse();
            await Assert.That(untouched.All(b => b == 0)).IsTrue();
        }
    }

    [Test]
    public async Task OpenSsh_ArgumentChecks()
    {
        await Assert.That(() => new ChaCha20Poly1305OpenSsh(new byte[63])).Throws<ArgumentException>();
        using var cipher = NewCipher(out _);
        await Assert.That(() => cipher.Encrypt(0, 1, new byte[1], new byte[4], new byte[16])).Throws<ArgumentException>();
        await Assert.That(() => cipher.Encrypt(0, 1, new byte[1], new byte[5], new byte[15])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecrypt(0, new byte[3], new byte[16], [])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecrypt(0, new byte[8], new byte[15], new byte[4])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecrypt(0, new byte[8], new byte[16], new byte[5])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecryptWithoutLength(0, new byte[8], new byte[15], new byte[8])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecryptWithoutLength(0, new byte[8], new byte[16], new byte[7])).Throws<ArgumentException>();
        await Assert.That(() => cipher.TryDecryptWithoutLength(0, new byte[8], new byte[16], new byte[9])).Throws<ArgumentException>();

        // Exactly ArgumentException, for sizes that would otherwise go through: an output longer than the packet, a tag that is too long.
        await Assert.That(() => cipher.Encrypt(0, 1, new byte[1], new byte[6], new byte[16])).ThrowsExactly<ArgumentException>();
        await Assert.That(() => cipher.Encrypt(0, 1, new byte[1], new byte[5], new byte[17])).ThrowsExactly<ArgumentException>();

        // A packet of just the length, with an empty body, is the smallest one there is.
        var output = new byte[4];
        var tag = new byte[16];
        cipher.Encrypt(7, 0, [], output, tag);
        await Assert.That(cipher.TryDecrypt(7, output, tag, [])).IsTrue();
    }

    [Test]
    public async Task OpenSsh_DisposeZeroesKeys()
    {
        // Both halves of the key are wiped: the disposed cipher encrypts as one made from 64 zero bytes would.
        var cipher = NewCipher(out _);
        cipher.Dispose();
        var packet = new byte[8];
        var tag = new byte[16];
        var body = new byte[4];
        cipher.Encrypt(1, 4, body, packet, tag);
        using var zero = new ChaCha20Poly1305OpenSsh(new byte[64]);
        var packet2 = new byte[8];
        var tag2 = new byte[16];
        zero.Encrypt(1, 4, body, packet2, tag2);
        await Assert.That(Hex(packet)).IsEqualTo(Hex(packet2));
        await Assert.That(Hex(tag)).IsEqualTo(Hex(tag2));
    }
}