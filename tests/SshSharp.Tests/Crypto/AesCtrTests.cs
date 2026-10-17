using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class AesCtrTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private const string Sp800_38aPlaintext =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    /// <summary>NIST SP 800-38A appendix F.5.1, F.5.3 and F.5.5 (aes128-ctr, aes192-ctr, aes256-ctr): all four blocks, so the counter increments too.</summary>
    [Test]
    [Arguments("2b7e151628aed2a6abf7158809cf4f3c",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee")]
    [Arguments("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050")]
    [Arguments("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")]
    public async Task Sp800_38a_F5(string key, string expected)
    {
        using var ctr = new AesCtr(H(key), H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
        var data = H(Sp800_38aPlaintext);
        ctr.Transform(data);
        await Assert.That(Hex(data)).IsEqualTo(expected);
    }

    private static byte[] ReferenceCtr(byte[] key, byte[] counter, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        var block = (byte[])counter.Clone();
        var result = (byte[])data.Clone();
        for (var offset = 0; offset < data.Length; offset += 16)
        {
            var keystream = aes.EncryptEcb(block, PaddingMode.None);
            for (var i = 0; i < Math.Min(16, data.Length - offset); i++)
            {
                result[offset + i] ^= keystream[i];
            }

            for (var i = 15; i >= 0 && ++block[i] == 0; i--)
            {
            }
        }

        return result;
    }

    [Test]
    public async Task MatchesAnIndependentReference_ForManyLengths_AndContinuesAcrossCalls()
    {
        var rng = new Random(31);
        var key = new byte[32];
        rng.NextBytes(key);
        var counter = new byte[16];
        rng.NextBytes(counter);

        foreach (var length in new[] { 0, 1, 15, 16, 17, 255, 256, 257, 1000 })
        {
            var data = new byte[length];
            rng.NextBytes(data);
            using var ctr = new AesCtr(key, counter);
            var actual = (byte[])data.Clone();
            ctr.Transform(actual);
            await Assert.That(Hex(actual)).IsEqualTo(Hex(ReferenceCtr(key, counter, data)));
        }

        // Whole-block continuation: two calls of 48 + 64 bytes equal one call of 112.
        var big = new byte[112];
        rng.NextBytes(big);
        var whole = (byte[])big.Clone();
        using (var one = new AesCtr(key, counter))
        {
            one.Transform(whole);
        }

        var split = (byte[])big.Clone();
        using (var two = new AesCtr(key, counter))
        {
            two.Transform(split.AsSpan(0, 48));
            two.Transform(split.AsSpan(48));
        }

        await Assert.That(Hex(split)).IsEqualTo(Hex(whole));
    }

    [Test]
    public async Task CounterCarriesAcrossAllBytes()
    {
        var key = new byte[16];
        var counter = H("00000000000000000000000000ffffff");
        var data = new byte[48];
        using var ctr = new AesCtr(key, counter);
        ctr.Transform(data);
        await Assert.That(Hex(data)).IsEqualTo(Hex(ReferenceCtr(key, counter, new byte[48])));
    }

    [Test]
    public async Task CounterWrapsAround()
    {
        var key = new byte[16];
        var counter = H("ffffffffffffffffffffffffffffffff");
        var data = new byte[32];
        using var ctr = new AesCtr(key, counter);
        ctr.Transform(data);
        await Assert.That(Hex(data)).IsEqualTo(Hex(ReferenceCtr(key, counter, new byte[32])));
    }

    [Test]
    public async Task RejectsBadCounterSize()
    {
        await Assert.That(() => new AesCtr(new byte[16], new byte[15])).Throws<ArgumentException>();
    }

    /// <summary>
    /// Peeking (how encrypt-and-MAC learns the encrypted packet length) shows the next keystream block, after some has been used too, and
    /// does not advance the counter: what follows decrypts exactly as without the peek.
    /// </summary>
    [Test]
    public async Task PeekKeystream_ShowsTheNextBlock_WithoutAdvancing()
    {
        var key = H("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var reference = ReferenceCtr(key, counter, new byte[64]);
        using var ctr = new AesCtr(key, counter);

        foreach (var block in new[] { 0, 1, 3 })
        {
            var full = new byte[16];
            ctr.PeekKeystream(full);
            var start = new byte[4];
            ctr.PeekKeystream(start);
            await Assert.That(Hex(full)).IsEqualTo(Hex(reference[(block * 16)..((block + 1) * 16)]));
            await Assert.That(Hex(start)).IsEqualTo(Hex(reference[(block * 16)..((block * 16) + 4)]));

            var used = new byte[block == 1 ? 32 : 16];
            ctr.Transform(used);
            await Assert.That(Hex(used)).IsEqualTo(Hex(reference[(block * 16)..((block * 16) + used.Length)]));
        }

        await Assert.That(() => ctr.PeekKeystream(new byte[17])).Throws<ArgumentException>();
    }
}