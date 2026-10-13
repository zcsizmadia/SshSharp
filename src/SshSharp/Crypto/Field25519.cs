using System.Globalization;
using System.Numerics;

namespace SshSharp.Crypto;

/// <summary>
/// Arithmetic in GF(2^255 - 19) with 16 limbs of 16 bits held in <c>long</c>s (the TweetNaCl representation). All operations are
/// branch-free on secret data. Elements are <c>Span&lt;long&gt;</c> of length 16; callers own the storage.
/// </summary>
internal static class Field25519
{
    public const int Limbs = 16;

    private static readonly BigInteger Prime = (BigInteger.One << 255) - 19;

    // Curve constants, derived from their definitions instead of hard-coded limbs.
    public static readonly long[] One = FromBigInteger(BigInteger.One);

    /// <summary>(A - 2) / 4 = 121665, the constant of the Montgomery ladder.</summary>
    public static readonly long[] A24 = FromBigInteger(121665);

    /// <summary>d = -121665 / 121666 (the Edwards curve constant).</summary>
    public static readonly long[] D = FromBigInteger(Mod(-121665 * ModInverse(121666)));

    /// <summary>2d.</summary>
    public static readonly long[] D2 = FromBigInteger(Mod(2 * Mod(-121665 * ModInverse(121666))));

    /// <summary>The base point's x coordinate (RFC 8032 section 5.1).</summary>
    public static readonly long[] BaseX = FromBigInteger(BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202", CultureInfo.InvariantCulture));

    /// <summary>The base point's y coordinate, 4/5.</summary>
    public static readonly long[] BaseY = FromBigInteger(Mod(4 * ModInverse(5)));

    /// <summary>sqrt(-1) = 2^((p-1)/4).</summary>
    public static readonly long[] SqrtMinusOne = FromBigInteger(BigInteger.ModPow(2, (Prime - 1) / 4, Prime));

    private static BigInteger Mod(BigInteger value) => ((value % Prime) + Prime) % Prime;

    private static BigInteger ModInverse(BigInteger value) => BigInteger.ModPow(value, Prime - 2, Prime);

    private static long[] FromBigInteger(BigInteger value)
    {
        var limbs = new long[Limbs];
        for (var i = 0; i < Limbs; i++)
        {
            limbs[i] = (long)((value >> (16 * i)) & 0xFFFF);
        }

        return limbs;
    }

    public static void Set(Span<long> result, ReadOnlySpan<long> a) => a.CopyTo(result);

    public static void Zero(Span<long> result) => result.Clear();

    public static void Add(Span<long> result, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (var i = 0; i < Limbs; i++)
        {
            result[i] = a[i] + b[i];
        }
    }

    public static void Sub(Span<long> result, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (var i = 0; i < Limbs; i++)
        {
            result[i] = a[i] - b[i];
        }
    }

    public static void Carry(Span<long> o)
    {
        for (var i = 0; i < Limbs; i++)
        {
            o[i] += 1L << 16;
            var c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + (37 * (c - 1) * (i == 15 ? 1 : 0));
            o[i] -= c << 16;
        }
    }

    /// <summary>Constant-time conditional swap: swaps <paramref name="p"/> and <paramref name="q"/> when <paramref name="bit"/> is 1.</summary>
    public static void ConditionalSwap(Span<long> p, Span<long> q, int bit)
    {
        var mask = ~(long)(bit - 1);
        for (var i = 0; i < Limbs; i++)
        {
            var t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    public static void Multiply(Span<long> result, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        Span<long> t = stackalloc long[31];
        for (var i = 0; i < Limbs; i++)
        {
            for (var j = 0; j < Limbs; j++)
            {
                t[i + j] += a[i] * b[j];
            }
        }

        for (var i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }

        t[..Limbs].CopyTo(result);
        Carry(result);
        Carry(result);
    }

    public static void Square(Span<long> result, ReadOnlySpan<long> a) => Multiply(result, a, a);

    public static void Invert(Span<long> result, ReadOnlySpan<long> input)
    {
        Span<long> c = stackalloc long[Limbs];
        input.CopyTo(c);
        for (var a = 253; a >= 0; a--)
        {
            Square(c, c);
            if (a != 2 && a != 4)
            {
                Multiply(c, c, input);
            }
        }

        c.CopyTo(result);
    }

    /// <summary>Computes input^((p-5)/8) = input^(2^252 - 3).</summary>
    public static void Pow2523(Span<long> result, ReadOnlySpan<long> input)
    {
        Span<long> c = stackalloc long[Limbs];
        input.CopyTo(c);
        for (var a = 250; a >= 0; a--)
        {
            Square(c, c);
            if (a != 1)
            {
                Multiply(c, c, input);
            }
        }

        c.CopyTo(result);
    }

    /// <summary>Writes the canonical 32-byte little-endian encoding.</summary>
    public static void Pack(Span<byte> output, ReadOnlySpan<long> n)
    {
        Span<long> t = stackalloc long[Limbs];
        Span<long> m = stackalloc long[Limbs];
        n.CopyTo(t);
        Carry(t);
        Carry(t);
        Carry(t);
        for (var j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }

            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            var b = (int)((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            ConditionalSwap(t, m, 1 - b);
        }

        for (var i = 0; i < Limbs; i++)
        {
            output[2 * i] = (byte)(t[i] & 0xff);
            output[(2 * i) + 1] = (byte)(t[i] >> 8);
        }
    }

    /// <summary>Reads a 32-byte little-endian value, ignoring the top bit.</summary>
    public static void Unpack(Span<long> result, ReadOnlySpan<byte> n)
    {
        for (var i = 0; i < Limbs; i++)
        {
            result[i] = n[2 * i] + ((long)n[(2 * i) + 1] << 8);
        }

        result[15] &= 0x7fff;
    }

    /// <summary>Parity (low bit) of the canonical encoding.</summary>
    public static int Parity(ReadOnlySpan<long> a)
    {
        Span<byte> d = stackalloc byte[32];
        Pack(d, a);
        return d[0] & 1;
    }

    /// <summary>Constant-time comparison of canonical encodings: true when the elements differ.</summary>
    public static bool NotEqual(ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        Span<byte> c = stackalloc byte[32];
        Span<byte> d = stackalloc byte[32];
        Pack(c, a);
        Pack(d, b);
        return !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(c, d);
    }
}