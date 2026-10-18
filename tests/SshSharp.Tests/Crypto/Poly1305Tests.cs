using System.Numerics;
using System.Text;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>
/// Poly1305 with 64-bit limbs against two references: the previous 26-bit implementation (kept for 32-bit processes, and run explicitly
/// here on every machine) and the definition itself, computed with <see cref="BigInteger"/>. The cases cover every message length up to 1,100 bytes, long messages,
/// the RFC 8439 vectors, and the edge cases of the carries and the final reduction: the largest clamped r, accumulators just below and
/// above p and 2^130, and an s that carries out of 2^128.
/// </summary>
public class Poly1305Tests
{
    private static readonly BigInteger P = (BigInteger.One << 130) - 5;
    private static readonly BigInteger TwoTo128 = BigInteger.One << 128;
    private static readonly BigInteger Clamp = BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff", System.Globalization.NumberStyles.HexNumber, null);

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    /// <summary>The 64-bit code (limbs of 44, 44 and 42 bits), whatever the process.</summary>
    private static string Tag(byte[] key, byte[] message)
    {
        var tag = new byte[16];
        Poly1305.ComputeTag44(key, message, tag);
        return Hex(tag);
    }

    /// <summary>The 26-bit code: the previous implementation, kept for 32-bit processes.</summary>
    private static string ReferenceTag(byte[] key, byte[] message)
    {
        var tag = new byte[16];
        Poly1305.ComputeTag26(key, message, tag);
        return Hex(tag);
    }

    /// <summary>The public entry point, which picks one of the two for the process.</summary>
    private static string DispatchedTag(byte[] key, byte[] message)
    {
        var tag = new byte[16];
        Poly1305.ComputeTag(key, message, tag);
        return Hex(tag);
    }

    /// <summary>RFC 8439 section 2.5.1 as written: clamp r, then h = (h + block || 0x01) * r mod p per block, and the tag is h + s mod 2^128.</summary>
    private static string DefinitionTag(byte[] key, byte[] message)
    {
        var r = new BigInteger(key.AsSpan(0, 16), isUnsigned: true) & Clamp;
        var s = new BigInteger(key.AsSpan(16, 16), isUnsigned: true);
        var h = BigInteger.Zero;
        for (var offset = 0; offset < message.Length; offset += 16)
        {
            var block = message.AsSpan(offset, Math.Min(16, message.Length - offset));
            h = (h + new BigInteger([.. block, 1], isUnsigned: true)) * r % P;
        }

        return Hex(ToBytes((h + s) % TwoTo128));
    }

    private static byte[] ToBytes(BigInteger value)
    {
        var bytes = new byte[16];
        value.TryWriteBytes(bytes, out _, isUnsigned: true);
        return bytes;
    }

    private static async Task AssertMatchesBothReferences(byte[] key, byte[] message, string because)
    {
        var expected = DefinitionTag(key, message);
        await Assert.That(ReferenceTag(key, message)).IsEqualTo(expected).Because(because);
        await Assert.That(Tag(key, message)).IsEqualTo(expected).Because(because);
        await Assert.That(DispatchedTag(key, message)).IsEqualTo(expected).Because(because);
    }

    [Test]
    public async Task EveryLengthUpTo1100_WithRandomKeys_MatchesBothReferences()
    {
        var rng = new Random(301);
        for (var length = 0; length <= 1100; length++)
        {
            var key = new byte[32];
            var message = new byte[length];
            rng.NextBytes(key);
            rng.NextBytes(message);
            await AssertMatchesBothReferences(key, message, $"length {length}");
        }
    }

    [Test]
    public async Task LongMessages_MatchBothReferences()
    {
        var rng = new Random(302);
        foreach (var length in new[] { 16 * 1024, 32 * 1024 + 5, 35000, 256 * 1024 + 15 })
        {
            var key = new byte[32];
            var message = new byte[length];
            rng.NextBytes(key);
            rng.NextBytes(message);
            await AssertMatchesBothReferences(key, message, $"length {length}");
        }
    }

    [Test]
    public async Task LargestClampedR_WithAllOnesMessages_MatchesBothReferences()
    {
        // Every bit of r that clamping leaves is set, and every message bit too: the largest limbs and products the code can meet.
        // Each length ends in a whole block or in a partial one, after many blocks so the accumulator is as full as it gets.
        var rng = new Random(303);
        foreach (var s in new[] { new byte[16], Enumerable.Repeat((byte)0xff, 16).ToArray(), RandomBytes(rng, 16) })
        {
            byte[] key = [.. Enumerable.Repeat((byte)0xff, 16), .. s];
            foreach (var length in new[] { 1, 15, 16, 17, 31, 32, 33, 160, 1024, 1031, 4096, 16 * 1024 })
            {
                await AssertMatchesBothReferences(key, Enumerable.Repeat((byte)0xff, length).ToArray(), $"length {length}");
            }

            await AssertMatchesBothReferences(key, RandomBytes(rng, 999), "random message");
        }

        // The clamped r itself, whatever the masked-off bits held.
        await Assert.That(Tag([.. Enumerable.Repeat((byte)0xff, 16), .. new byte[16]], [1]))
            .IsEqualTo(Tag([.. H("ffffff0ffcffff0ffcffff0ffcffff0f"), .. new byte[16]], [1]));
    }

    [Test]
    public async Task AccumulatorsAroundPAnd2To130_AreReducedCorrectly()
    {
        // With r = 1, h is the sum of the blocks (each with 2^128 added) and is never reduced before the end, so these messages end with
        // h exactly at the target: just below p (no subtraction), at and above p (subtract p), up to 2^130 - 1, and from 2^130 on (the
        // carry out of the top limb comes back as 5).
        var rng = new Random(304);
        foreach (var delta in new[] { -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 9, 255 })
        {
            var target = P + delta;
            foreach (var s in new[] { new byte[16], Enumerable.Repeat((byte)0xff, 16).ToArray(), RandomBytes(rng, 16) })
            {
                byte[] key = [1, .. new byte[15], .. s];
                var message = MessageSummingTo(target, 3);
                await Assert.That(DefinitionTag(key, message)).IsEqualTo(Hex(ToBytes(((target % P) + new BigInteger(s, isUnsigned: true)) % TwoTo128)));
                await AssertMatchesBothReferences(key, message, $"h = p + {delta}");
            }
        }

        // The same with a random r: a random first block, and a second one chosen so that the result lands on the target modulo p (a
        // block has to be below 2^128, so a few tries are needed for each target). The accumulator's limbs before the final reduction
        // then hold the target or the target plus p.
        foreach (var delta in new[] { -2, -1, 0, 1, 4, 5, 6 })
        {
            var target = P + delta;
            var found = 0;
            for (var attempt = 0; found < 4; attempt++)
            {
                await Assert.That(attempt).IsLessThan(1000);
                var key = RandomBytes(rng, 32);
                var first = RandomBytes(rng, 16);
                var r = new BigInteger(key.AsSpan(0, 16), isUnsigned: true) & Clamp;
                if (r.IsZero)
                {
                    continue;
                }

                // h = ((first + 2^128) * r + second + 2^128) * r, solved for second.
                var second = ((target * BigInteger.ModPow(r, P - 2, P)) - ((new BigInteger(first, isUnsigned: true) + TwoTo128) * r) - TwoTo128) % P;
                second = second.Sign < 0 ? second + P : second;
                if (second >= TwoTo128)
                {
                    continue;
                }

                found++;
                byte[] message = [.. first, .. ToBytes(second)];
                await Assert.That(DefinitionTag(key, message))
                    .IsEqualTo(Hex(ToBytes(((target % P) + new BigInteger(key.AsSpan(16), isUnsigned: true)) % TwoTo128)));
                await AssertMatchesBothReferences(key, message, $"h = p + {delta}, random r");
            }
        }
    }

    [Test]
    public async Task SCarriesOutOf2To128()
    {
        // h + s above 2^128 must wrap: s = 2^128 - 1 with h = 1, 2 and p - 1 (whose low 128 bits are all ones but the last two).
        var rng = new Random(305);
        var s = Enumerable.Repeat((byte)0xff, 16).ToArray();
        foreach (var target in new[] { BigInteger.One + (3 * TwoTo128), 2 + (3 * TwoTo128), P - 1, P - 2 + TwoTo128 })
        {
            byte[] key = [1, .. new byte[15], .. s];
            var message = MessageSummingTo(target, 3);
            await AssertMatchesBothReferences(key, message, $"target {target}");
        }

        for (var i = 0; i < 64; i++)
        {
            byte[] key = [.. RandomBytes(rng, 16), .. s];
            await AssertMatchesBothReferences(key, RandomBytes(rng, rng.Next(1, 200)), "s = 2^128 - 1");
        }
    }

    [Test]
    public async Task Rfc8439_Section252_Vector()
    {
        var key = H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var message = "Cryptographic Forum Research Group"u8.ToArray();
        await Assert.That(Tag(key, message)).IsEqualTo("a8061dc1305136c6c22b8baf0c0127a9");
        await AssertMatchesBothReferences(key, message, "RFC 8439 2.5.2");
    }

    [Test]
    [MethodDataSource(nameof(AppendixA3))]
    public async Task Rfc8439_AppendixA3_Vectors(int number, string key, string message, string expected)
    {
        await Assert.That(Tag(H(key), H(message))).IsEqualTo(expected).Because($"#{number}");
        await AssertMatchesBothReferences(H(key), H(message), $"#{number}");
    }

    /// <summary>RFC 8439 appendix A.3, test vectors #1 to #11.</summary>
    public static IEnumerable<(int Number, string Key, string Message, string Expected)> AppendixA3()
    {
        var ietf = Convert.ToHexString(Encoding.ASCII.GetBytes(
            "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and " +
            "any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include " +
            "oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are " +
            "addressed to"));
        var jabberwocky = Convert.ToHexString(Encoding.ASCII.GetBytes(
            "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe."));
        var zero16 = new string('0', 32);
        var ones16 = new string('f', 32);
        var two = "02" + new string('0', 62);
        var one = "01" + new string('0', 62);
        var r10 = "0100000000000000040000000000000000000000000000000000000000000000";
        var m11 = "e33594d7505e43b90000000000000000" + "3394d7505e4379cd0100000000000000" + zero16;
        var m10 = m11 + "01" + new string('0', 30);

        yield return (1, new string('0', 64), new string('0', 128), zero16);
        yield return (2, zero16 + "36e5f6b5c5e06070f0efca96227a863e", ietf, "36e5f6b5c5e06070f0efca96227a863e");
        yield return (3, "36e5f6b5c5e06070f0efca96227a863e" + zero16, ietf, "f3477e7cd95417af89a6b8794c310cf0");
        yield return (4, "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", jabberwocky, "4541669a7eaaee61e708dc7cbcc5eb62");
        yield return (5, two, ones16, "03" + new string('0', 30));
        yield return (6, "02" + new string('0', 30) + ones16, "02" + new string('0', 30), "03" + new string('0', 30));
        yield return (7, one, ones16 + "f0" + new string('f', 30) + "11" + new string('0', 30), "05" + new string('0', 30));
        yield return (8, one, ones16 + "fb" + string.Concat(Enumerable.Repeat("fe", 15)) + string.Concat(Enumerable.Repeat("01", 16)), zero16);
        yield return (9, two, "fd" + new string('f', 30), "fa" + new string('f', 30));
        yield return (10, r10, m10, "14000000000000005500000000000000");
        yield return (11, r10, m11,"13000000000000000000000000000000");
    }

    /// <summary>A message of <paramref name="blocks"/> whole blocks whose values (each with 2^128 added) sum to <paramref name="target"/>.</summary>
    private static byte[] MessageSummingTo(BigInteger target, int blocks)
    {
        var rest = target - (blocks * TwoTo128);
        var message = new byte[16 * blocks];
        for (var i = 0; i < blocks; i++)
        {
            var part = BigInteger.Min(rest, TwoTo128 - 1);
            ToBytes(part).CopyTo(message, 16 * i);
            rest -= part;
        }

        return rest.IsZero && target >= blocks * TwoTo128 ? message : throw new ArgumentOutOfRangeException(nameof(target));
    }

    private static byte[] RandomBytes(Random rng, int length)
    {
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        return bytes;
    }
}
