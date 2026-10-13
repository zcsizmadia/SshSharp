using System.Numerics;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>The field arithmetic against <see cref="BigInteger"/>, on random values and on the edges of the limb representation.</summary>
public class Field25519Tests
{
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;

    private static readonly BigInteger[] Edges =
    [
        0, 1, 2, 18, 19, 20, P - 2, P - 1, P, P + 1, P + 18, (BigInteger.One << 255) - 1,
        (BigInteger.One << 51) - 1, BigInteger.One << 51, (BigInteger.One << 102) - 1, (BigInteger.One << 204) + 7,
        P / 2, (P + 1) / 2,
    ];

    private static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;

    private static long[] Element(BigInteger value)
    {
        // Through Unpack, so values from p up to 2^255 - 1 arrive in their non-canonical form.
        var bytes = new byte[32];
        value.TryWriteBytes(bytes, out _, isUnsigned: true);
        var element = new long[Field25519.Limbs];
        Field25519.Unpack(element, bytes);
        return element;
    }

    private static BigInteger Value(long[] element)
    {
        var bytes = new byte[32];
        Field25519.Pack(bytes, element);
        return new BigInteger(bytes, isUnsigned: true);
    }

    private static IEnumerable<BigInteger> Values()
    {
        var random = new Random(25519);
        var bytes = new byte[32];
        foreach (var edge in Edges)
        {
            yield return edge;
        }

        for (var i = 0; i < 300; i++)
        {
            random.NextBytes(bytes);
            bytes[31] &= 0x7f;
            yield return new BigInteger(bytes, isUnsigned: true);
        }
    }

    [Test]
    public async Task PackAndUnpack_GiveTheCanonicalValue()
    {
        foreach (var value in Values())
        {
            await Assert.That(Value(Element(value))).IsEqualTo(Mod(value));
        }
    }

    [Test]
    public async Task Operations_MatchBigInteger()
    {
        var values = Values().ToArray();
        var result = new long[Field25519.Limbs];
        for (var i = 0; i < values.Length; i++)
        {
            var a = values[i];
            var b = values[(i * 7 + 3) % values.Length];
            Field25519.Add(result, Element(a), Element(b));
            await Assert.That(Value(result)).IsEqualTo(Mod(a + b));
            Field25519.Sub(result, Element(a), Element(b));
            await Assert.That(Value(result)).IsEqualTo(Mod(a - b));
            Field25519.Multiply(result, Element(a), Element(b));
            await Assert.That(Value(result)).IsEqualTo(Mod(a * b));
            Field25519.Square(result, Element(a));
            await Assert.That(Value(result)).IsEqualTo(Mod(a * a));
        }
    }

    [Test]
    public async Task InvertAndPow2523_MatchBigInteger()
    {
        var result = new long[Field25519.Limbs];
        foreach (var value in Values().Take(60))
        {
            Field25519.Invert(result, Element(value));
            await Assert.That(Value(result)).IsEqualTo(BigInteger.ModPow(Mod(value), P - 2, P));
            Field25519.Pow2523(result, Element(value));
            await Assert.That(Value(result)).IsEqualTo(BigInteger.ModPow(Mod(value), (P - 5) / 8, P));
        }
    }

    [Test]
    public async Task LongChains_StayInRange()
    {
        // Results feed straight into the next operation, as in the ladder: limbs must never outgrow what each operation accepts.
        var random = new Random(7748);
        var x = Element((BigInteger.One << 255) - 1);
        var y = Element(P - 1);
        var expectedX = Mod((BigInteger.One << 255) - 1);
        var expectedY = P - 1;
        for (var i = 0; i < 5000; i++)
        {
            switch (random.Next(4))
            {
                case 0:
                    Field25519.Add(x, x, y);
                    expectedX = Mod(expectedX + expectedY);
                    break;
                case 1:
                    Field25519.Sub(y, x, y);
                    expectedY = Mod(expectedX - expectedY);
                    break;
                case 2:
                    Field25519.Multiply(x, x, y);
                    expectedX = Mod(expectedX * expectedY);
                    break;
                default:
                    Field25519.Square(y, x);
                    expectedY = Mod(expectedX * expectedX);
                    break;
            }

            foreach (var limb in x.Concat(y))
            {
                await Assert.That(limb).IsGreaterThanOrEqualTo(0L).And.IsLessThan(1L << 52);
            }
        }

        await Assert.That(Value(x)).IsEqualTo(expectedX);
        await Assert.That(Value(y)).IsEqualTo(expectedY);
    }
}
