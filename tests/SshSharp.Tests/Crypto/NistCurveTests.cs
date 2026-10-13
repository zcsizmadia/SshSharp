using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class NistCurveTests
{
    public static IEnumerable<string> Curves() => ["nistp256", "nistp384", "nistp521"];

    private static (byte[] X, byte[] Y) NewPoint(NistCurve curve)
    {
        using var key = ECDsa.Create(curve.Curve);
        var q = key.ExportParameters(false).Q;
        var x = new byte[curve.FieldSize];
        var y = new byte[curve.FieldSize];
        q.X!.CopyTo(x, curve.FieldSize - q.X.Length);
        q.Y!.CopyTo(y, curve.FieldSize - q.Y.Length);
        return (x, y);
    }

    [Test]
    [MethodDataSource(nameof(Curves))]
    public async Task GeneratedPointsAreOnTheCurve(string name)
    {
        var curve = NistCurve.FromSshName(name);
        for (var i = 0; i < 20; i++)
        {
            var (x, y) = NewPoint(curve);
            await Assert.That(curve.IsOnCurve(x, y)).IsTrue();
        }
    }

    [Test]
    [MethodDataSource(nameof(Curves))]
    public async Task ModifiedOrMalformedPointsAreRejected(string name)
    {
        var curve = NistCurve.FromSshName(name);
        var (x, y) = NewPoint(curve);

        var badY = (byte[])y.Clone();
        badY[^1] ^= 1;
        await Assert.That(curve.IsOnCurve(x, badY)).IsFalse();

        var badX = (byte[])x.Clone();
        badX[^1] ^= 1;
        await Assert.That(curve.IsOnCurve(badX, y)).IsFalse();

        await Assert.That(curve.IsOnCurve(new byte[curve.FieldSize], new byte[curve.FieldSize])).IsFalse();

        var tooBig = new byte[curve.FieldSize];
        Array.Fill(tooBig, (byte)0xff);
        await Assert.That(curve.IsOnCurve(tooBig, y)).IsFalse();
        await Assert.That(curve.IsOnCurve(x, tooBig)).IsFalse();

        await Assert.That(curve.IsOnCurve(x.AsSpan(1), y)).IsFalse();
        await Assert.That(curve.IsOnCurve(x, y.AsSpan(1))).IsFalse();
    }

    [Test]
    public async Task KnownGeneratorOfP256IsOnTheCurve()
    {
        var gx = Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        var gy = Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        await Assert.That(NistCurve.P256.IsOnCurve(gx, gy)).IsTrue();
        gy[0] ^= 0x80;
        await Assert.That(NistCurve.P256.IsOnCurve(gx, gy)).IsFalse();
    }

    [Test]
    public async Task NamesHashesAndSizes()
    {
        await Assert.That(NistCurve.P256.Hash).IsEqualTo(HashAlgorithmName.SHA256);
        await Assert.That(NistCurve.P384.Hash).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(NistCurve.P521.Hash).IsEqualTo(HashAlgorithmName.SHA512);
        await Assert.That(NistCurve.P521.FieldSize).IsEqualTo(66);
        await Assert.That(NistCurve.P384.Name).IsEqualTo("nistp384");
        await Assert.That(() => NistCurve.FromSshName("secp256k1")).Throws<ArgumentException>();
    }
}