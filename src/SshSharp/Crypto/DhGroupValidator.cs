using System.Numerics;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// Checks a Diffie-Hellman group that a server chose (<c>diffie-hellman-group-exchange-sha256</c>, RFC 4419) before the client uses it.
/// </summary>
/// <remarks>
/// <para>
/// The group is covered by the exchange hash, which the server signs with its host key, so a man in the middle cannot substitute one:
/// only the server itself picks it. These checks catch a server with a broken or weak group (a corrupt moduli file, a short or composite
/// modulus), which would leave the session open to an eavesdropper. They are not meant to stop a malicious server, which already holds
/// the session keys.
/// </para>
/// <para>
/// OpenSSH's client checks only the prime's size. This adds, in order of cost: p odd, and 3 mod 4 as every safe prime above 7 is ((p-1)/2
/// odd); the generator's range; no odd factor below <see cref="SieveLimit"/> in p or in (p-1)/2 (a cheap partial safe-prime check); and
/// one Miller-Rabin round on p with a random base. That round is a full-size modular exponentiation, about 0.65 s for an 8192-bit group
/// with <see cref="BigInteger.ModPow"/>; proving (p-1)/2 prime as well would cost as much again, on every connection.
/// </para>
/// </remarks>
internal static class DhGroupValidator
{
    /// <summary>Trial division covers the odd numbers below this.</summary>
    public const int SieveLimit = 4096;

    /// <summary>Throws unless <paramref name="p"/> and <paramref name="g"/> make a usable group of <paramref name="minBits"/> to <paramref name="maxBits"/> bits.</summary>
    /// <exception cref="SshException">The group is unacceptable (<see cref="SshFailureReason.KeyExchangeFailed"/>).</exception>
    public static void Validate(BigInteger p, BigInteger g, int minBits, int maxBits)
    {
        var bits = p.GetBitLength();
        if (bits < minBits || bits > maxBits)
        {
            throw Fail($"The server's group exchange prime has {bits} bits, outside the {minBits} to {maxBits} requested.");
        }

        if (p.IsEven)
        {
            throw Fail("The server's group exchange modulus is even, so not prime.");
        }

        // A safe prime p = 2q + 1 above 7 has q odd, so p = 3 mod 4.
        if ((int)(p % 4) != 3)
        {
            throw Fail("The server's group exchange modulus is not a safe prime: it is not 3 mod 4.");
        }

        // 1 and p-1 generate subgroups of order 1 and 2. In a safe prime group every other element has order q or 2q.
        if (g < 2 || g > p - 2)
        {
            throw Fail("The server's group exchange generator is out of range.");
        }

        // p = 0 mod d: d divides p. p = 1 mod d: d divides p - 1, and so (p-1)/2, as d is odd.
        for (var d = 3; d < SieveLimit; d += 2)
        {
            var remainder = (int)(p % d);
            if (remainder == 0)
            {
                throw Fail($"The server's group exchange modulus is not prime: it is divisible by {d}.");
            }

            if (remainder == 1)
            {
                throw Fail($"The server's group exchange modulus is not a safe prime: (p-1)/2 is divisible by {d}.");
            }
        }

        if (!IsStrongProbablePrime(p, RandomBase(p)))
        {
            throw Fail("The server's group exchange modulus is not prime.");
        }
    }

    /// <summary>
    /// One Miller-Rabin round for p = 3 mod 4 (p - 1 = 2 * q with q odd, so a single step): a prime p gives a^q = 1 or -1 mod p for
    /// every base a in [2, p-2]. A composite p passes for at most a quarter of the bases, and for a random-looking composite of 2048 bits
    /// or more, the chance a random base lets it through is below 2^-64 (Damgard, Landrock and Pomerance, 1993).
    /// </summary>
    internal static bool IsStrongProbablePrime(BigInteger p, BigInteger a)
    {
        var x = BigInteger.ModPow(a, (p - 1) / 2, p);
        return x.IsOne || x == p - 1;
    }

    /// <summary>A uniformly random base in [2, p-2] (up to a bias of 2^-64 from the extra random bytes).</summary>
    internal static BigInteger RandomBase(BigInteger p)
    {
        var bytes = RandomNumberGenerator.GetBytes(p.GetByteCount(isUnsigned: true) + 8);
        return (new BigInteger(bytes, isUnsigned: true) % (p - 3)) + 2;
    }

    private static SshException Fail(string message) => new(SshFailureReason.KeyExchangeFailed, message);
}
