using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace SshSharp.Crypto;

/// <summary>
/// Arithmetic in GF(2^255 - 19) with 5 limbs of 51 bits (the ref10 / curve25519-donna 64-bit representation), multiplied through 128-bit
/// products. All operations are branch-free on secret data. Elements are <c>Span&lt;long&gt;</c> of length <see cref="Limbs"/> holding
/// non-negative limbs; callers own the storage. Every operation leaves its result weakly reduced (each limb below 2^52), which is what
/// the next operation's input may be.
/// </summary>
internal static class Field25519
{
    public const int Limbs = 5;

    private const ulong Mask = (1UL << 51) - 1;

    // 2p, limb by limb: added before a subtraction so that no limb goes negative.
    private const ulong TwoP0 = 2 * ((1UL << 51) - 19);
    private const ulong TwoP = 2 * ((1UL << 51) - 1);

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
            limbs[i] = (long)((value >> (51 * i)) & Mask);
        }

        return limbs;
    }

    public static void Set(Span<long> result, ReadOnlySpan<long> a) => a[..Limbs].CopyTo(result);

    public static void Zero(Span<long> result) => result[..Limbs].Clear();

    public static void Add(Span<long> result, ReadOnlySpan<long> a, ReadOnlySpan<long> b) => Reduce(
        result,
        (ulong)a[0] + (ulong)b[0],
        (ulong)a[1] + (ulong)b[1],
        (ulong)a[2] + (ulong)b[2],
        (ulong)a[3] + (ulong)b[3],
        (ulong)a[4] + (ulong)b[4]);

    public static void Sub(Span<long> result, ReadOnlySpan<long> a, ReadOnlySpan<long> b) => Reduce(
        result,
        (ulong)a[0] + TwoP0 - (ulong)b[0],
        (ulong)a[1] + TwoP - (ulong)b[1],
        (ulong)a[2] + TwoP - (ulong)b[2],
        (ulong)a[3] + TwoP - (ulong)b[3],
        (ulong)a[4] + TwoP - (ulong)b[4]);

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
        ulong a0 = (ulong)a[0], a1 = (ulong)a[1], a2 = (ulong)a[2], a3 = (ulong)a[3], a4 = (ulong)a[4];
        ulong b0 = (ulong)b[0], b1 = (ulong)b[1], b2 = (ulong)b[2], b3 = (ulong)b[3], b4 = (ulong)b[4];

        // 2^255 = 19 (mod p): the limbs that wrap past 2^255 come back multiplied by 19. Limbs below 2^52 keep every sum below 2^112.
        ulong b1x19 = b1 * 19, b2x19 = b2 * 19, b3x19 = b3 * 19, b4x19 = b4 * 19;
        var r0 = Mul(a0, b0) + Mul(a1, b4x19) + Mul(a2, b3x19) + Mul(a3, b2x19) + Mul(a4, b1x19);
        var r1 = Mul(a0, b1) + Mul(a1, b0) + Mul(a2, b4x19) + Mul(a3, b3x19) + Mul(a4, b2x19);
        var r2 = Mul(a0, b2) + Mul(a1, b1) + Mul(a2, b0) + Mul(a3, b4x19) + Mul(a4, b3x19);
        var r3 = Mul(a0, b3) + Mul(a1, b2) + Mul(a2, b1) + Mul(a3, b0) + Mul(a4, b4x19);
        var r4 = Mul(a0, b4) + Mul(a1, b3) + Mul(a2, b2) + Mul(a3, b1) + Mul(a4, b0);
        Reduce(result, r0, r1, r2, r3, r4);
    }

    public static void Square(Span<long> result, ReadOnlySpan<long> a)
    {
        ulong a0 = (ulong)a[0], a1 = (ulong)a[1], a2 = (ulong)a[2], a3 = (ulong)a[3], a4 = (ulong)a[4];
        ulong a0x2 = a0 * 2, a1x2 = a1 * 2, a1x38 = a1 * 38, a2x38 = a2 * 38, a3x38 = a3 * 38, a3x19 = a3 * 19, a4x19 = a4 * 19;
        var r0 = Mul(a0, a0) + Mul(a1x38, a4) + Mul(a2x38, a3);
        var r1 = Mul(a0x2, a1) + Mul(a2x38, a4) + Mul(a3x19, a3);
        var r2 = Mul(a0x2, a2) + Mul(a1, a1) + Mul(a3x38, a4);
        var r3 = Mul(a0x2, a3) + Mul(a1x2, a2) + Mul(a4x19, a4);
        var r4 = Mul(a0x2, a4) + Mul(a1x2, a3) + Mul(a2, a2);
        Reduce(result, r0, r1, r2, r3, r4);
    }

    /// <summary>Computes 1 / input = input^(p - 2) (zero for zero), with the usual addition chain: 254 squarings and 11 multiplications.</summary>
    public static void Invert(Span<long> result, ReadOnlySpan<long> input)
    {
        Span<long> z11 = stackalloc long[Limbs];
        Span<long> t = stackalloc long[Limbs];
        Pow2250Minus1(t, z11, input);
        SquareTimes(t, t, 5);
        Multiply(result, t, z11); // 2^255 - 21 = p - 2
    }

    /// <summary>Computes input^((p-5)/8) = input^(2^252 - 3).</summary>
    public static void Pow2523(Span<long> result, ReadOnlySpan<long> input)
    {
        Span<long> z11 = stackalloc long[Limbs];
        Span<long> t = stackalloc long[Limbs];
        Pow2250Minus1(t, z11, input);
        SquareTimes(t, t, 2);
        Multiply(result, t, input);
    }

    /// <summary>Writes the canonical 32-byte little-endian encoding.</summary>
    public static void Pack(Span<byte> output, ReadOnlySpan<long> n)
    {
        ulong t0 = (ulong)n[0], t1 = (ulong)n[1], t2 = (ulong)n[2], t3 = (ulong)n[3], t4 = (ulong)n[4];

        // Three carry passes leave every limb below 2^51, so the value is below 2^255 (< 2p).
        for (var pass = 0; pass < 3; pass++)
        {
            t1 += t0 >> 51;
            t0 &= Mask;
            t2 += t1 >> 51;
            t1 &= Mask;
            t3 += t2 >> 51;
            t2 &= Mask;
            t4 += t3 >> 51;
            t3 &= Mask;
            t0 += 19 * (t4 >> 51);
            t4 &= Mask;
        }

        // q = 1 exactly when the value is at least p (then value + 19 reaches 2^255); subtract p by adding 19 and dropping bit 255.
        var q = (t0 + 19) >> 51;
        q = (t1 + q) >> 51;
        q = (t2 + q) >> 51;
        q = (t3 + q) >> 51;
        q = (t4 + q) >> 51;
        t0 += 19 * q;
        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t4 &= Mask;

        BinaryPrimitives.WriteUInt64LittleEndian(output, t0 | (t1 << 51));
        BinaryPrimitives.WriteUInt64LittleEndian(output[8..], (t1 >> 13) | (t2 << 38));
        BinaryPrimitives.WriteUInt64LittleEndian(output[16..], (t2 >> 26) | (t3 << 25));
        BinaryPrimitives.WriteUInt64LittleEndian(output[24..], (t3 >> 39) | (t4 << 12));
    }

    /// <summary>Reads a 32-byte little-endian value, ignoring the top bit.</summary>
    public static void Unpack(Span<long> result, ReadOnlySpan<byte> n)
    {
        var w0 = BinaryPrimitives.ReadUInt64LittleEndian(n);
        var w1 = BinaryPrimitives.ReadUInt64LittleEndian(n[8..]);
        var w2 = BinaryPrimitives.ReadUInt64LittleEndian(n[16..]);
        var w3 = BinaryPrimitives.ReadUInt64LittleEndian(n[24..]);
        result[0] = (long)(w0 & Mask);
        result[1] = (long)(((w0 >> 51) | (w1 << 13)) & Mask);
        result[2] = (long)(((w1 >> 38) | (w2 << 26)) & Mask);
        result[3] = (long)(((w2 >> 25) | (w3 << 39)) & Mask);
        result[4] = (long)((w3 >> 12) & Mask);
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Wide Mul(ulong a, ulong b)
    {
        var high = Math.BigMul(a, b, out var low);
        return new Wide(low & Mask, (low >> 51) | (high << 13));
    }

    /// <summary>
    /// One carry pass over the 128-bit column sums of a product of weakly reduced inputs: limb 1 ends below 2^51 + 2^10, the others
    /// below 2^51.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Reduce(Span<long> result, Wide r0, Wide r1, Wide r2, Wide r3, Wide r4)
    {
        r1 += r0.Shift51();
        var t0 = r0.Low & Mask;
        r2 += r1.Shift51();
        var t1 = r1.Low & Mask;
        r3 += r2.Shift51();
        var t2 = r2.Low & Mask;
        r4 += r3.Shift51();
        var t3 = r3.Low & Mask;
        var carry = r4.Shift51(); // r4 has no factor of 19 and stays below 2^107: the carry is below 2^56, and 19 times it fits
        var t4 = r4.Low & Mask;
        t0 += carry * 19;
        t1 += t0 >> 51;
        t0 &= Mask;
        result[0] = (long)t0;
        result[1] = (long)t1;
        result[2] = (long)t2;
        result[3] = (long)t3;
        result[4] = (long)t4;
    }

    /// <summary>The same carry pass for 64-bit limb sums (additions and subtractions): limb 0 ends below 2^51 + 57, the others below 2^51.</summary>
    private static void Reduce(Span<long> result, ulong t0, ulong t1, ulong t2, ulong t3, ulong t4)
    {
        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t0 += 19 * (t4 >> 51);
        t4 &= Mask;
        result[0] = (long)t0;
        result[1] = (long)t1;
        result[2] = (long)t2;
        result[3] = (long)t3;
        result[4] = (long)t4;
    }

    /// <summary>
    /// A column sum of up to five products, held as High * 2^51 + Low: each product is split at bit 51 when it is made, so the two
    /// halves add up separately without ever overflowing 64 bits (products below 2^109 give High parts below 2^58 and Low parts below
    /// 2^51). Unlike <see cref="UInt128"/>, whose addition computes its carry with a comparison the JIT may turn into a branch, nothing
    /// here carries at all.
    /// </summary>
    private readonly struct Wide(ulong low, ulong high)
    {
        public ulong Low { get; } = low;

        public ulong High { get; } = high;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Wide operator +(Wide a, Wide b) => new(a.Low + b.Low, a.High + b.High);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Wide operator +(Wide a, ulong b) => new(a.Low + b, a.High);

        /// <summary>The value shifted right by 51 bits.</summary>
        public ulong Shift51() => High + (Low >> 51);
    }

    private static void SquareTimes(Span<long> result, ReadOnlySpan<long> input, int count)
    {
        Square(result, input);
        for (var i = 1; i < count; i++)
        {
            Square(result, result);
        }
    }

    /// <summary>Computes input^(2^250 - 1) into <paramref name="result"/>, and input^11 into <paramref name="z11"/> along the way.</summary>
    private static void Pow2250Minus1(Span<long> result, Span<long> z11, ReadOnlySpan<long> z)
    {
        Span<long> z2 = stackalloc long[Limbs];
        Span<long> t = stackalloc long[Limbs];
        Span<long> z9 = stackalloc long[Limbs];
        Span<long> x5 = stackalloc long[Limbs];
        Span<long> x10 = stackalloc long[Limbs];
        Span<long> x20 = stackalloc long[Limbs];
        Span<long> x50 = stackalloc long[Limbs];
        Span<long> x100 = stackalloc long[Limbs];

        Square(z2, z);              // 2
        SquareTimes(t, z2, 2);      // 8
        Multiply(z9, t, z);         // 9
        Multiply(z11, z9, z2);      // 11
        Square(t, z11);             // 22
        Multiply(x5, t, z9);        // 2^5 - 1
        SquareTimes(t, x5, 5);
        Multiply(x10, t, x5);       // 2^10 - 1
        SquareTimes(t, x10, 10);
        Multiply(x20, t, x10);      // 2^20 - 1
        SquareTimes(t, x20, 20);
        Multiply(t, t, x20);        // 2^40 - 1
        SquareTimes(t, t, 10);
        Multiply(x50, t, x10);      // 2^50 - 1
        SquareTimes(t, x50, 50);
        Multiply(x100, t, x50);     // 2^100 - 1
        SquareTimes(t, x100, 100);
        Multiply(t, t, x100);       // 2^200 - 1
        SquareTimes(t, t, 50);
        Multiply(result, t, x50);   // 2^250 - 1
    }
}
