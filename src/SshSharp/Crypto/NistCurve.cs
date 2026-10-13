using System.Numerics;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// A NIST prime curve (P-256, P-384, P-521) with an explicit on-curve check. Some platforms (notably Windows CNG) do not validate
/// a public point when a key is imported, which would allow invalid-curve attacks in ECDH, so points from the peer are always
/// checked here first. NIST prime curves have cofactor 1, so "on the curve" is all that is required of a non-infinity point.
/// </summary>
internal sealed class NistCurve
{
    private readonly BigInteger _p;
    private readonly BigInteger _a;
    private readonly BigInteger _b;

    private NistCurve(string name, ECCurve curve, int fieldSize)
    {
        Name = name;
        Curve = curve;
        FieldSize = fieldSize;

        // The curve constants are taken from the framework instead of being typed in.
        using var key = ECDsa.Create(curve);
        var explicitCurve = key.ExportExplicitParameters(false).Curve;
        _p = ToBigInteger(explicitCurve.Prime!);
        _a = ToBigInteger(explicitCurve.A!);
        _b = ToBigInteger(explicitCurve.B!);
    }

    public static NistCurve P256 { get; } = new("nistp256", ECCurve.NamedCurves.nistP256, 32);

    public static NistCurve P384 { get; } = new("nistp384", ECCurve.NamedCurves.nistP384, 48);

    public static NistCurve P521 { get; } = new("nistp521", ECCurve.NamedCurves.nistP521, 66);

    /// <summary>The SSH curve identifier (<c>nistp256</c> and so on).</summary>
    public string Name { get; }

    public ECCurve Curve { get; }

    /// <summary>The size of a coordinate in bytes.</summary>
    public int FieldSize { get; }

    /// <summary>The hash the SSH key exchange and signature schemes pair with this curve.</summary>
    public HashAlgorithmName Hash => FieldSize switch
    {
        32 => HashAlgorithmName.SHA256,
        48 => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    /// <summary>Whether the point (x, y), given as unsigned big-endian coordinates, is a valid point on this curve.</summary>
    public bool IsOnCurve(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        if (x.Length != FieldSize || y.Length != FieldSize)
        {
            return false;
        }

        var bx = ToBigInteger(x);
        var by = ToBigInteger(y);
        if (bx >= _p || by >= _p)
        {
            return false;
        }

        // y^2 = x^3 + a*x + b (mod p)
        var left = (by * by) % _p;
        var right = (((bx * bx % _p * bx) + (_a * bx) + _b) % _p + _p) % _p;
        return left == right;
    }

    public static NistCurve FromSshName(string name) => name switch
    {
        "nistp256" => P256,
        "nistp384" => P384,
        "nistp521" => P521,
        _ => throw new ArgumentException($"Unsupported curve '{name}'.", nameof(name)),
    };

    private static BigInteger ToBigInteger(ReadOnlySpan<byte> unsignedBigEndian) =>
        new(unsignedBigEndian, isUnsigned: true, isBigEndian: true);
}