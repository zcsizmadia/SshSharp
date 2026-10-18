using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class DhGroupValidatorTests
{
    private static readonly BigInteger P14 = ModpGroup.Group14.Prime;

    // RFC 2409 group 2 (Oakley 1024-bit MODP): a safe prime, too small for group exchange.
    private static readonly BigInteger Oakley1024 = (BigInteger.One << 1024) - (BigInteger.One << 960) - 1 + ((ModpGroup.ScaledPi(894) + 129093) << 64);

    private static SshException Rejects(BigInteger p, BigInteger g, string message)
    {
        var ex = Assert.Throws<SshException>(() => DhGroupValidator.Validate(p, g, 2048, 8192));
        if (ex.Reason != SshFailureReason.KeyExchangeFailed || ex.Message != message)
        {
            throw new InvalidOperationException($"Expected KeyExchangeFailed \"{message}\", got {ex.Reason} \"{ex.Message}\".");
        }

        return ex;
    }

    /// <summary>
    /// A random n = <paramref name="modulus"/> * m + <paramref name="residue"/> of at least 2048 bits that is 3 mod 4 and passes trial
    /// division (no odd d gives n = 0 or 1 mod d) for every odd d below <paramref name="sieveUpTo"/>.
    /// </summary>
    private static BigInteger Candidate(BigInteger modulus, int residue, int sieveUpTo)
    {
        for (var attempt = 0; attempt < 100_000; attempt++)
        {
            var m = new BigInteger(RandomNumberGenerator.GetBytes(264 - (int)(modulus.GetBitLength() / 8)), isUnsigned: true, isBigEndian: true);
            var n = (modulus * m) + residue;
            if (n % 4 != 3 || n.GetBitLength() < 2048)
            {
                continue;
            }

            var ok = true;
            for (var d = 3; d < sieveUpTo && ok; d += 2)
            {
                var r = (int)(n % d);
                ok = r != 0 && r != 1;
            }

            if (ok)
            {
                return n;
            }
        }

        throw new InvalidOperationException("No candidate found.");
    }

    [Test]
    public async Task AcceptsTheRfc3526Groups_WithEitherCommonGenerator()
    {
        // Repeated: the primality round uses a random base, and a broken check would reject a prime only for some bases.
        for (var i = 0; i < 20; i++)
        {
            DhGroupValidator.Validate(P14, 2, 2048, 8192);
        }

        DhGroupValidator.Validate(P14, 5, 2048, 2048);
        DhGroupValidator.Validate(P14, P14 - 2, 2048, 4096);
        DhGroupValidator.Validate(ModpGroup.Group16.Prime, 2, 4096, 4096);
        DhGroupValidator.Validate(ModpGroup.Group18.Prime, 2, 2048, 8192);
        await Assert.That(() => DhGroupValidator.Validate(ModpGroup.Group16.Prime, 2, 2048, 8192)).ThrowsNothing();
    }

    [Test]
    public async Task RejectsAPrimeOutsideTheRequestedSize()
    {
        Rejects(Oakley1024, 2, "The server's group exchange prime has 1024 bits, outside the 2048 to 8192 requested.");
        Rejects((ModpGroup.Group18.Prime << 1) + 1, 2, "The server's group exchange prime has 8193 bits, outside the 2048 to 8192 requested.");

        // Both bounds are inclusive.
        var ex = Assert.Throws<SshException>(() => DhGroupValidator.Validate(P14, 2, 2049, 8192));
        await Assert.That(ex.Message).Contains("2048 bits, outside the 2049 to 8192");
        ex = Assert.Throws<SshException>(() => DhGroupValidator.Validate(ModpGroup.Group16.Prime, 2, 2048, 4095));
        await Assert.That(ex.Message).Contains("4096 bits, outside the 2048 to 4095");
    }

    [Test]
    public async Task RejectsAnEvenModulus_AndOneThatIsNot3Mod4()
    {
        var even = Rejects(P14 + 1, 2, "The server's group exchange modulus is even, so not prime.");
        await Assert.That(even.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        Rejects(P14 + 2, 2, "The server's group exchange modulus is not a safe prime: it is not 3 mod 4.");
        Rejects(P14 - 2, 2, "The server's group exchange modulus is not a safe prime: it is not 3 mod 4.");
    }

    [Test]
    public async Task RejectsAGeneratorOfOrderOneOrTwo_OrOutOfRange()
    {
        foreach (var g in new[] { BigInteger.Zero, BigInteger.One, P14 - 1, P14, P14 + 1 })
        {
            Rejects(P14, g, "The server's group exchange generator is out of range.");
        }

        await Assert.That(P14 % 4).IsEqualTo((BigInteger)3);
    }

    [Test]
    public async Task RejectsAModulusWithASmallFactor()
    {
        Rejects(Candidate(3, 0, 3), 2, "The server's group exchange modulus is not prime: it is divisible by 3.");

        // 4093 is the largest prime below the sieve limit; the candidate passes every smaller divisor.
        var n = Candidate(4093, 0, 4093);
        Rejects(n, 2, "The server's group exchange modulus is not prime: it is divisible by 4093.");
        await Assert.That(n % 4093).IsEqualTo(BigInteger.Zero);
    }

    [Test]
    public async Task RejectsAModulusWhoseHalfHasASmallFactor()
    {
        Rejects(Candidate(3, 1, 3), 2, "The server's group exchange modulus is not a safe prime: (p-1)/2 is divisible by 3.");
        var n = Candidate(4093, 1, 4093);
        Rejects(n, 2, "The server's group exchange modulus is not a safe prime: (p-1)/2 is divisible by 4093.");
        await Assert.That(n % 4093).IsEqualTo(BigInteger.One);
    }

    [Test]
    public async Task RejectsACompositeModulus_ThatPassesTheSieve()
    {
        // A multiple of a 2048-bit prime with no factor below the sieve limit, as p and as (p-1)/2: only the primality round catches it.
        var composite = Candidate(P14, 0, DhGroupValidator.SieveLimit);
        await Assert.That(composite % P14).IsEqualTo(BigInteger.Zero);
        Rejects(composite, 2, "The server's group exchange modulus is not prime.");
    }

    [Test]
    public async Task TheStrongProbablePrimeRound_SeparatesPrimesFromComposites()
    {
        // For a prime p = 3 mod 4, a^((p-1)/2) is 1 for a quadratic residue (4 = 2^2) and -1 for a non-residue (p-1 itself).
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(P14, 4)).IsTrue();
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(P14, P14 - 1)).IsTrue();
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(P14, 2)).IsTrue();
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(P14, 3)).IsTrue();

        // 77 = 7 * 11: 2^38 is 4 mod 7 and 3 mod 11, so neither 1 nor -1. 23 is prime and 5^11 = -1 mod 23.
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(77, 2)).IsFalse();
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(P14 * 3, 2)).IsFalse();
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(23, 5)).IsTrue();

        // The exponent is exactly (p-1)/2: for 15 = 3 * 5, 4^7 = 4 mod 15, while 4^14 and 4^28 are 1 and 4^8 is 1.
        await Assert.That(DhGroupValidator.IsStrongProbablePrime(15, 4)).IsFalse();
    }

    [Test]
    public async Task TheRandomBase_StaysWithin2AndPMinus2()
    {
        // With p = 7 the range is [2, 5]: every value turns up, and nothing outside it.
        var seen = new HashSet<BigInteger>();
        for (var i = 0; i < 400; i++)
        {
            var a = DhGroupValidator.RandomBase(7);
            await Assert.That(a >= 2 && a <= 5).IsTrue();
            seen.Add(a);
        }

        await Assert.That(seen.Count).IsEqualTo(4);

        var large = DhGroupValidator.RandomBase(P14);
        await Assert.That(large >= 2 && large <= P14 - 2).IsTrue();
        await Assert.That(large.GetBitLength()).IsGreaterThan(1900);
    }
}
