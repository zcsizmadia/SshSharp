using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class AesCtrTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [Test]
    [Arguments("2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "6bc1bee22e409f96e93d7e117393172a", "874d6191b620e3261bef6864990db6ce")]
    [Arguments("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "6bc1bee22e409f96e93d7e117393172a", "601ec313775789a5b7a7f504bbf3d228")]
    public async Task Sp800_38a_FirstBlock(string key, string counter, string plain, string expected)
    {
        using var ctr = new AesCtr(H(key), H(counter));
        var data = H(plain);
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
}