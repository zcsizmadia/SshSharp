using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>Ed25519 signatures (RFC 8032 section 5.1), built on <see cref="Field25519"/> and SHA-512.</summary>
internal static class Ed25519
{
    public const int SeedSize = 32;
    public const int PublicKeySize = 32;
    public const int SignatureSize = 64;

    // The group order L, little-endian bytes, as longs for modL.
    private static readonly long[] L =
    [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// <summary>Derives the public key from a 32-byte seed.</summary>
    public static void GetPublicKey(ReadOnlySpan<byte> seed, Span<byte> publicKey)
    {
        RequireSizes(seed, SeedSize, publicKey, PublicKeySize);
        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(seed, h);
        Clamp(h);
        Span<long> p = stackalloc long[64];
        ScalarBase(p, h[..32]);
        Pack(publicKey, p);
        h.Clear();
    }

    /// <summary>Signs <paramref name="message"/> with the key derived from <paramref name="seed"/>.</summary>
    public static void Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, Span<byte> signature)
    {
        RequireSizes(seed, SeedSize, signature, SignatureSize);
        Span<byte> d = stackalloc byte[64];
        SHA512.HashData(seed, d);
        Clamp(d);

        Span<byte> publicKey = stackalloc byte[PublicKeySize];
        Span<long> p = stackalloc long[64];
        ScalarBase(p, d[..32]);
        Pack(publicKey, p);

        // r = H(prefix || M) mod L; R = r*B
        Span<byte> r = stackalloc byte[64];
        Hash(r, d[32..], message);
        Reduce(r);
        ScalarBase(p, r[..32]);
        Span<byte> encodedR = stackalloc byte[32];
        Pack(encodedR, p);

        // h = H(R || A || M) mod L; S = r + h*a mod L
        Span<byte> h = stackalloc byte[64];
        Hash(h, encodedR, publicKey, message);
        Reduce(h);
        Span<long> x = stackalloc long[64];
        for (var i = 0; i < 32; i++)
        {
            x[i] = r[i];
        }

        for (var i = 0; i < 32; i++)
        {
            for (var j = 0; j < 32; j++)
            {
                x[i + j] += h[i] * (long)d[j];
            }
        }

        encodedR.CopyTo(signature);
        ModL(signature[32..], x);
        d.Clear();
        r.Clear();
    }

    /// <summary>Verifies a signature. Rejects non-canonical S (S >= L) as RFC 8032 requires.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize || signature.Length != SignatureSize)
        {
            return false;
        }

        if (!ScalarIsCanonical(signature[32..]))
        {
            return false;
        }

        Span<long> q = stackalloc long[64];
        if (!UnpackNegated(q, publicKey))
        {
            return false;
        }

        Span<byte> h = stackalloc byte[64];
        Hash(h, signature[..32], publicKey, message);
        Reduce(h);

        Span<long> p = stackalloc long[64];
        ScalarMult(p, q, h[..32]);
        ScalarBase(q, signature[32..]);
        Add(p, q);
        Span<byte> check = stackalloc byte[32];
        Pack(check, p);
        return CryptographicOperations.FixedTimeEquals(check, signature[..32]);
    }

    private static void RequireSizes(ReadOnlySpan<byte> input, int inputSize, Span<byte> output, int outputSize)
    {
        if (input.Length != inputSize || output.Length != outputSize)
        {
            throw new ArgumentException($"Expected a {inputSize}-byte input and a {outputSize}-byte output.");
        }
    }

    private static void Clamp(Span<byte> h)
    {
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;
    }

    private static void Hash(Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> message)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(a);
        hash.AppendData(message);
        hash.GetCurrentHash(output);
    }

    private static void Hash(Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> message)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(a);
        hash.AppendData(b);
        hash.AppendData(message);
        hash.GetCurrentHash(output);
    }

    // ---- Points: extended coordinates (X, Y, Z, T) in four consecutive field elements ----

    private static Span<long> Coord(Span<long> point, int index) => point.Slice(index * Field25519.Limbs, Field25519.Limbs);

    private static void Add(Span<long> p, ReadOnlySpan<long> q)
    {
        Span<long> a = stackalloc long[16];
        Span<long> b = stackalloc long[16];
        Span<long> c = stackalloc long[16];
        Span<long> d = stackalloc long[16];
        Span<long> t = stackalloc long[16];
        Span<long> e = stackalloc long[16];
        Span<long> f = stackalloc long[16];
        Span<long> g = stackalloc long[16];
        Span<long> h = stackalloc long[16];
        var p0 = Coord(p, 0);
        var p1 = Coord(p, 1);
        var p2 = Coord(p, 2);
        var p3 = Coord(p, 3);
        var q0 = q.Slice(0, 16);
        var q1 = q.Slice(16, 16);
        var q2 = q.Slice(32, 16);
        var q3 = q.Slice(48, 16);

        Field25519.Sub(a, p1, p0);
        Field25519.Sub(t, q1, q0);
        Field25519.Multiply(a, a, t);
        Field25519.Add(b, p0, p1);
        Field25519.Add(t, q0, q1);
        Field25519.Multiply(b, b, t);
        Field25519.Multiply(c, p3, q3);
        Field25519.Multiply(c, c, Field25519.D2);
        Field25519.Multiply(d, p2, q2);
        Field25519.Add(d, d, d);
        Field25519.Sub(e, b, a);
        Field25519.Sub(f, d, c);
        Field25519.Add(g, d, c);
        Field25519.Add(h, b, a);
        Field25519.Multiply(p0, e, f);
        Field25519.Multiply(p1, h, g);
        Field25519.Multiply(p2, g, f);
        Field25519.Multiply(p3, e, h);
    }

    private static void ConditionalSwap(Span<long> p, Span<long> q, int bit)
    {
        for (var i = 0; i < 4; i++)
        {
            Field25519.ConditionalSwap(Coord(p, i), Coord(q, i), bit);
        }
    }

    private static void Pack(Span<byte> output, Span<long> p)
    {
        Span<long> tx = stackalloc long[16];
        Span<long> ty = stackalloc long[16];
        Span<long> zi = stackalloc long[16];
        Field25519.Invert(zi, Coord(p, 2));
        Field25519.Multiply(tx, Coord(p, 0), zi);
        Field25519.Multiply(ty, Coord(p, 1), zi);
        Field25519.Pack(output, ty);
        output[31] ^= (byte)(Field25519.Parity(tx) << 7);
    }

    private static void ScalarMult(Span<long> p, Span<long> q, ReadOnlySpan<byte> s)
    {
        Field25519.Zero(Coord(p, 0));
        Field25519.Set(Coord(p, 1), Field25519.One);
        Field25519.Set(Coord(p, 2), Field25519.One);
        Field25519.Zero(Coord(p, 3));
        for (var i = 255; i >= 0; i--)
        {
            var bit = (s[i / 8] >> (i & 7)) & 1;
            ConditionalSwap(p, q, bit);
            Add(q, p);
            Add(p, p);
            ConditionalSwap(p, q, bit);
        }
    }

    private static void ScalarBase(Span<long> p, ReadOnlySpan<byte> s)
    {
        Span<long> q = stackalloc long[64];
        Field25519.Set(Coord(q, 0), Field25519.BaseX);
        Field25519.Set(Coord(q, 1), Field25519.BaseY);
        Field25519.Set(Coord(q, 2), Field25519.One);
        Field25519.Multiply(Coord(q, 3), Field25519.BaseX, Field25519.BaseY);
        ScalarMult(p, q, s);
    }

    /// <summary>Decodes a point and negates it (so verification can compute S*B + h*(-A)). Returns false if it is not on the curve.</summary>
    private static bool UnpackNegated(Span<long> r, ReadOnlySpan<byte> p)
    {
        Span<long> t = stackalloc long[16];
        Span<long> chk = stackalloc long[16];
        Span<long> num = stackalloc long[16];
        Span<long> den = stackalloc long[16];
        Span<long> den2 = stackalloc long[16];
        Span<long> den4 = stackalloc long[16];
        Span<long> den6 = stackalloc long[16];
        var r0 = Coord(r, 0);
        var r1 = Coord(r, 1);
        var r2 = Coord(r, 2);
        var r3 = Coord(r, 3);

        Field25519.Set(r2, Field25519.One);
        Field25519.Unpack(r1, p);
        Field25519.Square(num, r1);
        Field25519.Multiply(den, num, Field25519.D);
        Field25519.Sub(num, num, r2);
        Field25519.Add(den, r2, den);

        Field25519.Square(den2, den);
        Field25519.Square(den4, den2);
        Field25519.Multiply(den6, den4, den2);
        Field25519.Multiply(t, den6, num);
        Field25519.Multiply(t, t, den);

        Field25519.Pow2523(t, t);
        Field25519.Multiply(t, t, num);
        Field25519.Multiply(t, t, den);
        Field25519.Multiply(t, t, den);
        Field25519.Multiply(r0, t, den);

        Field25519.Square(chk, r0);
        Field25519.Multiply(chk, chk, den);
        if (Field25519.NotEqual(chk, num))
        {
            Field25519.Multiply(r0, r0, Field25519.SqrtMinusOne);
        }

        Field25519.Square(chk, r0);
        Field25519.Multiply(chk, chk, den);
        if (Field25519.NotEqual(chk, num))
        {
            return false;
        }

        if (Field25519.Parity(r0) == (p[31] >> 7))
        {
            Span<long> zero = stackalloc long[16];
            Field25519.Sub(r0, zero, r0);
        }

        Field25519.Multiply(r3, r0, r1);
        return true;
    }

    // ---- Scalars modulo L ----

    private static bool ScalarIsCanonical(ReadOnlySpan<byte> s)
    {
        // s < L, comparing little-endian bytes from the most significant end, in constant time.
        var less = 0;
        var decided = 0;
        for (var i = 31; i >= 0; i--)
        {
            var diff = s[i] - (int)L[i];
            var isLess = (diff >> 31) & 1;
            var isGreater = ((-diff) >> 31) & 1;
            less |= isLess & ~decided & 1;
            decided |= (isLess | isGreater) & 1;
        }

        return less == 1;
    }

    private static void ModL(Span<byte> r, Span<long> x)
    {
        long carry;
        int i;
        int j;
        for (i = 63; i >= 32; --i)
        {
            carry = 0;
            for (j = i - 32; j < i - 12; ++j)
            {
                x[j] += carry - (16 * x[i] * L[j - (i - 32)]);
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }

            x[j] += carry;
            x[i] = 0;
        }

        carry = 0;
        for (j = 0; j < 32; j++)
        {
            x[j] += carry - ((x[31] >> 4) * L[j]);
            carry = x[j] >> 8;
            x[j] &= 255;
        }

        for (j = 0; j < 32; j++)
        {
            x[j] -= carry * L[j];
        }

        for (i = 0; i < 32; i++)
        {
            x[i + 1] += x[i] >> 8;
            r[i] = (byte)(x[i] & 255);
        }
    }

    private static void Reduce(Span<byte> r)
    {
        Span<long> x = stackalloc long[64];
        for (var i = 0; i < 64; i++)
        {
            x[i] = r[i];
            r[i] = 0;
        }

        ModL(r, x);
    }
}