using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>X25519 Diffie-Hellman (RFC 7748 section 5), a Montgomery ladder in constant time.</summary>
internal static class X25519
{
    public const int KeySize = 32;

    /// <summary>Derives the public key for a 32-byte private key (clamping is applied internally).</summary>
    public static void GetPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
    {
        Span<byte> basePoint = stackalloc byte[KeySize];
        basePoint[0] = 9;
        ScalarMult(publicKey, privateKey, basePoint);
    }

    /// <summary>
    /// Computes the shared secret. Returns false when the result is all zeros (the peer sent a low-order point), in which case
    /// the key exchange must be aborted (RFC 7748 section 6.1, RFC 8731 section 3.1).
    /// </summary>
    public static bool TryAgree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        ScalarMult(sharedSecret, privateKey, peerPublicKey);
        Span<byte> zero = stackalloc byte[KeySize];
        return !CryptographicOperations.FixedTimeEquals(sharedSecret[..KeySize], zero);
    }

    // The ladder runs once or twice per key exchange: fully optimized at the first call, see Field25519.Multiply.
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void ScalarMult(Span<byte> output, ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> point)
    {
        if (scalar.Length != KeySize || point.Length != KeySize || output.Length < KeySize)
        {
            throw new ArgumentException("X25519 keys must be 32 bytes.");
        }

        Span<byte> z = stackalloc byte[KeySize];
        scalar.CopyTo(z);
        z[31] = (byte)((scalar[31] & 127) | 64);
        z[0] &= 248;

        Span<long> x = stackalloc long[Field25519.Limbs];
        Span<long> a = stackalloc long[Field25519.Limbs];
        Span<long> b = stackalloc long[Field25519.Limbs];
        Span<long> c = stackalloc long[Field25519.Limbs];
        Span<long> d = stackalloc long[Field25519.Limbs];
        Span<long> e = stackalloc long[Field25519.Limbs];
        Span<long> f = stackalloc long[Field25519.Limbs];

        Field25519.Unpack(x, point);
        x.CopyTo(b);
        a.Clear();
        c.Clear();
        d.Clear();
        a[0] = 1;
        d[0] = 1;

        for (var i = 254; i >= 0; i--)
        {
            var bit = (z[i >> 3] >> (i & 7)) & 1;
            Field25519.ConditionalSwap(a, b, bit);
            Field25519.ConditionalSwap(c, d, bit);
            Field25519.Add(e, a, c);
            Field25519.Sub(a, a, c);
            Field25519.Add(c, b, d);
            Field25519.Sub(b, b, d);
            Field25519.Square(d, e);
            Field25519.Square(f, a);
            Field25519.Multiply(a, c, a);
            Field25519.Multiply(c, b, e);
            Field25519.Add(e, a, c);
            Field25519.Sub(a, a, c);
            Field25519.Square(b, a);
            Field25519.Sub(c, d, f);
            Field25519.Multiply(a, c, Field25519.A24);
            Field25519.Add(a, a, d);
            Field25519.Multiply(c, c, a);
            Field25519.Multiply(a, d, f);
            Field25519.Multiply(d, b, x);
            Field25519.Square(b, e);
            Field25519.ConditionalSwap(a, b, bit);
            Field25519.ConditionalSwap(c, d, bit);
        }

        Field25519.Invert(c, c);
        Field25519.Multiply(a, a, c);
        Field25519.Pack(output, a);
        z.Clear();
    }
}