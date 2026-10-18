using System.Numerics;

namespace SshSharp.Crypto;

/// <summary>
/// A MODP Diffie-Hellman group from RFC 3526. The primes are not pasted in as constants: they are computed from their definition,
/// <c>p = 2^n - 2^(n-64) - 1 + 2^64 * ( floor(2^(n-130) * pi) + offset )</c>, and the tests check that the result is a safe prime.
/// </summary>
internal sealed class ModpGroup
{
    private ModpGroup(string name, int bits, int offset, int exponentBits)
    {
        Name = name;
        Bits = bits;
        ExponentBits = exponentBits;
        var scaledPi = ScaledPi(bits - 130);
        Prime = (BigInteger.One << bits) - (BigInteger.One << (bits - 64)) - 1 + ((scaledPi + offset) << 64);
    }

    /// <summary>RFC 3526 group 14 (2048 bits).</summary>
    public static ModpGroup Group14 { get; } = new("group14", 2048, 124476, 512);

    /// <summary>RFC 3526 group 16 (4096 bits).</summary>
    public static ModpGroup Group16 { get; } = new("group16", 4096, 240904, 768);

    /// <summary>RFC 3526 group 18 (8192 bits).</summary>
    public static ModpGroup Group18 { get; } = new("group18", 8192, 4743158, 1024);

    public string Name { get; }

    public int Bits { get; }

    /// <summary>The size of the private exponent in bits: well above twice the group's security strength.</summary>
    public int ExponentBits { get; }

    public BigInteger Prime { get; }

    public static BigInteger Generator => 2;

    /// <summary>floor(pi * 2^fractionBits), by Machin's formula in fixed point with guard bits.</summary>
    internal static BigInteger ScaledPi(int fractionBits)
    {
        const int guard = 64;
        var scale = BigInteger.One << (fractionBits + guard);
        var pi = (16 * ArctanInverse(5, scale)) - (4 * ArctanInverse(239, scale));
        return pi >> guard;
    }

    // arctan(1/x) * scale = scale * (1/x - 1/(3x^3) + 1/(5x^5) - ...)
    private static BigInteger ArctanInverse(int x, BigInteger scale)
    {
        var xSquared = (BigInteger)x * x;
        var term = scale / x;
        var sum = term;
        for (var n = 3; !term.IsZero; n += 2)
        {
            term /= xSquared;
            sum += ((n / 2) % 2 == 1 ? -1 : 1) * (term / n);
        }

        return sum;
    }
}