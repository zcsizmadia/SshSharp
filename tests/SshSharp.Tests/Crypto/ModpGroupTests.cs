using System.Numerics;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class ModpGroupTests
{
    // Deterministic Miller-Rabin with fixed small bases (plenty to expose a wrongly derived constant).
    private static bool IsProbablePrime(BigInteger n, int[]? bases = null)
    {
        if (n < 2)
        {
            return false;
        }

        foreach (var small in new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 })
        {
            if (n == small)
            {
                return true;
            }

            if (n % small == 0)
            {
                return false;
            }
        }

        var d = n - 1;
        var r = 0;
        while (d.IsEven)
        {
            d >>= 1;
            r++;
        }

        foreach (var a in bases ?? [2, 3, 5, 7])
        {
            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
            {
                continue;
            }

            var composite = true;
            for (var i = 1; i < r; i++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    composite = false;
                    break;
                }
            }

            if (composite)
            {
                return false;
            }
        }

        return true;
    }

    private static string Hex(BigInteger value) => Convert.ToHexString(value.ToByteArray(isUnsigned: true, isBigEndian: true));

    [Test]
    public async Task ScaledPi_MatchesKnownDigits()
    {
        await Assert.That(ModpGroup.ScaledPi(8)).IsEqualTo((BigInteger)804);        // floor(pi * 256)
        await Assert.That(ModpGroup.ScaledPi(16)).IsEqualTo((BigInteger)205887);    // floor(pi * 65536)
        await Assert.That(Hex(ModpGroup.ScaledPi(64)).TrimStart('0')).IsEqualTo("3243F6A8885A308D3"); // pi = 3.243F6A8885A308D3...
    }

    [Test]
    public async Task Group14_HasTheRfc3526Shape_AndIsASafePrime()
    {
        var p = ModpGroup.Group14.Prime;
        var hex = Hex(p);
        await Assert.That(hex.Length).IsEqualTo(512);
        await Assert.That(hex).StartsWith("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
        await Assert.That(hex).EndsWith("8AACAA68FFFFFFFFFFFFFFFF");
        await Assert.That(IsProbablePrime(p)).IsTrue();
        await Assert.That(IsProbablePrime((p - 1) / 2)).IsTrue();
        await Assert.That(ModpGroup.Group14.Bits).IsEqualTo(2048);
        await Assert.That(ModpGroup.Group14.Name).IsEqualTo("group14");
        await Assert.That(ModpGroup.Generator).IsEqualTo((BigInteger)2);
    }

    [Test]
    public async Task Group16_HasTheRfc3526Shape_AndIsASafePrime()
    {
        var p = ModpGroup.Group16.Prime;
        var hex = Hex(p);
        await Assert.That(hex.Length).IsEqualTo(1024);
        await Assert.That(hex).StartsWith("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
        await Assert.That(hex).EndsWith("FFFFFFFFFFFFFFFF");
        await Assert.That(IsProbablePrime(p)).IsTrue();
        await Assert.That(IsProbablePrime((p - 1) / 2)).IsTrue();
        await Assert.That(ModpGroup.Group16.ExponentBits).IsEqualTo(768);
    }

    [Test]
    public async Task Group18_HasTheRfc3526Shape_AndIsASafePrime()
    {
        var p = ModpGroup.Group18.Prime;
        var hex = Hex(p);
        await Assert.That(hex.Length).IsEqualTo(2048);
        await Assert.That(hex).StartsWith("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");

        // RFC 3526 section 7 ends the prime with "60C980DD 98EDD3DF FFFFFFFF FFFFFFFF".
        await Assert.That(hex).EndsWith("60C980DD98EDD3DFFFFFFFFFFFFFFFFF");
        await Assert.That(ModpGroup.Group18.Bits).IsEqualTo(8192);
        await Assert.That(ModpGroup.Group18.ExponentBits).IsEqualTo(1024);
        await Assert.That(ModpGroup.Group18.Name).IsEqualTo("group18");

        // One base each: a full-size exponentiation at 8192 bits takes most of a second.
        await Assert.That(IsProbablePrime(p, [2])).IsTrue();
        await Assert.That(IsProbablePrime((p - 1) / 2, [2])).IsTrue();
    }

    [Test]
    public async Task AWrongOffsetWouldNotGiveASafePrime()
    {
        // Guards the guard: the safe-prime check really does discriminate.
        var p = ModpGroup.Group14.Prime + (BigInteger.One << 64);
        await Assert.That(IsProbablePrime(p) && IsProbablePrime((p - 1) / 2)).IsFalse();
    }
}