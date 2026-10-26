using System.Text;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>BLAKE2b (RFC 7693) and Argon2 (RFC 9106) against the published test vectors.</summary>
public class Argon2Tests
{
    [Test]
    public async Task Blake2b512_Abc_Rfc7693AppendixA()
    {
        var hash = new byte[64];
        Blake2b.Hash("abc"u8, hash);
        await Assert.That(Convert.ToHexString(hash)).IsEqualTo(
            "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923");
    }

    [Test]
    public async Task Blake2b_EmptyInput_AndInputsAcrossBlockBoundaries()
    {
        var empty = new byte[64];
        Blake2b.Hash([], empty);
        await Assert.That(Convert.ToHexString(empty)).IsEqualTo(
            "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE");

        // Feeding the same 300 bytes in pieces of different sizes gives the same digest as one call.
        var data = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();
        var whole = new byte[32];
        Blake2b.Hash(data, whole);
        foreach (var piece in new[] { 1, 7, 64, 127, 128, 129 })
        {
            var blake = new Blake2b(32);
            for (var offset = 0; offset < data.Length; offset += piece)
            {
                blake.Update(data.AsSpan(offset, Math.Min(piece, data.Length - offset)));
            }

            var pieces = new byte[32];
            blake.Finish(pieces);
            await Assert.That(pieces).IsEquivalentTo(whole);
        }
    }

    // RFC 9106 section 5: m = 32 KiB, t = 3, p = 4, P = 32 x 0x01, S = 16 x 0x02, K = 8 x 0x03, X = 12 x 0x04, T = 32.
    [Test]
    [Arguments(0, "512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB")]
    [Arguments(1, "C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8")]
    [Arguments(2, "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659")]
    public async Task Rfc9106TestVectors(int type, string expected)
    {
        var tag = new byte[32];
        Argon2.Hash((Argon2Type)type, Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 16).ToArray(), memoryKiB: 32, passes: 3,
            parallelism: 4, tag, secret: Enumerable.Repeat((byte)3, 8).ToArray(), associatedData: Enumerable.Repeat((byte)4, 12).ToArray());
        await Assert.That(Convert.ToHexString(tag)).IsEqualTo(expected);
    }

    [Test]
    public async Task LongOutputs_UseTheChainedHash_AndInvalidParametersAreRefused()
    {
        // 80 bytes (what PuTTY derives: key, IV and MAC key) exercises H' beyond 64 bytes.
        var passphrase = Encoding.UTF8.GetBytes(TestSecrets.New());
        var output = new byte[80];
        Argon2.Hash(Argon2Type.Argon2id, passphrase, new byte[16], memoryKiB: 64, passes: 1, parallelism: 1, output);
        await Assert.That(output.Any(b => b != 0)).IsTrue();
        var again = new byte[80];
        Argon2.Hash(Argon2Type.Argon2id, passphrase, new byte[16], memoryKiB: 64, passes: 1, parallelism: 1, again);
        await Assert.That(again).IsEquivalentTo(output);

        await Assert.That(() => Argon2.Hash(Argon2Type.Argon2id, [], new byte[16], 4, 1, 1, new byte[32])).Throws<ArgumentException>();
        await Assert.That(() => Argon2.Hash(Argon2Type.Argon2id, [], new byte[4], 64, 1, 1, new byte[32])).Throws<ArgumentException>();
    }
}
