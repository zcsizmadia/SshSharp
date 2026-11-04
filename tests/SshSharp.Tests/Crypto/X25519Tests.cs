using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class X25519Tests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Agree(string privateKey, string peerPublic)
    {
        var shared = new byte[32];
        X25519.TryAgree(H(privateKey), H(peerPublic), shared);
        return Convert.ToHexString(shared).ToLowerInvariant();
    }

    private static string PublicKey(string privateKey)
    {
        var pub = new byte[32];
        X25519.GetPublicKey(H(privateKey), pub);
        return Convert.ToHexString(pub).ToLowerInvariant();
    }

    [Test]
    [Arguments("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [Arguments("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public async Task Rfc7748_Section52_Vectors(string scalar, string u, string expected)
    {
        await Assert.That(Agree(scalar, u)).IsEqualTo(expected);
    }

    [Test]
    public async Task Rfc7748_Section52_FirstIteration()
    {
        // k = u = 9; one iteration of k = X25519(k, u).
        var nine = new byte[32];
        nine[0] = 9;
        var result = new byte[32];
        X25519.TryAgree(nine, nine, result);
        await Assert.That(Convert.ToHexString(result).ToLowerInvariant()).IsEqualTo("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }

    [Test]
    public async Task Rfc7748_Section52_ThousandIterations()
    {
        var k = new byte[32];
        var u = new byte[32];
        k[0] = 9;
        u[0] = 9;
        var result = new byte[32];
        for (var i = 0; i < 1000; i++)
        {
            X25519.TryAgree(k, u, result);
            k.CopyTo(u);
            result.CopyTo(k);
        }

        await Assert.That(Convert.ToHexString(k).ToLowerInvariant()).IsEqualTo("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }

    [Test]
    public async Task Rfc7748_Section61_AliceAndBob()
    {
        const string alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        const string alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        const string bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        const string bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        const string shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        await Assert.That(PublicKey(alicePrivate)).IsEqualTo(alicePublic);
        await Assert.That(PublicKey(bobPrivate)).IsEqualTo(bobPublic);
        await Assert.That(Agree(alicePrivate, bobPublic)).IsEqualTo(shared);
        await Assert.That(Agree(bobPrivate, alicePublic)).IsEqualTo(shared);
    }

    [Test]
    public async Task OpenSslVectors_PublicKeysAndSharedSecretsAgree()
    {
        var checkedVectors = 0;
        foreach (var line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "curve25519_openssl_vectors.txt")))
        {
            var f = line.Split(' ');
            if (f[0] != "x25519")
            {
                continue;
            }

            var (priv, peerPub, shared, pub) = (f[1], f[2], f[3], f[4]);
            await Assert.That(PublicKey(priv)).IsEqualTo(pub);
            await Assert.That(Agree(priv, peerPub)).IsEqualTo(shared);
            checkedVectors++;
        }

        await Assert.That(checkedVectors).IsEqualTo(6);
    }

    [Test]
    public async Task TryAgree_RejectsLowOrderPoints()
    {
        var shared = new byte[32];
        var priv = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

        var zero = new byte[32];
        await Assert.That(X25519.TryAgree(priv, zero, shared)).IsFalse();

        var one = new byte[32];
        one[0] = 1;
        await Assert.That(X25519.TryAgree(priv, one, shared)).IsFalse();

        // A point of order 8 (from RFC 7748's list of small-order points).
        var order8 = H("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        await Assert.That(X25519.TryAgree(priv, order8, shared)).IsFalse();

        await Assert.That(X25519.TryAgree(priv, H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), shared)).IsTrue();
    }

    [Test]
    public async Task Sizes_AreChecked()
    {
        var k = new byte[32];
        await Assert.That(() => X25519.GetPublicKey(new byte[31], new byte[32])).Throws<ArgumentException>();
        await Assert.That(() => X25519.GetPublicKey(k, new byte[31])).Throws<ArgumentException>();
        await Assert.That(() => X25519.TryAgree(k, new byte[33], new byte[32])).Throws<ArgumentException>().WithMessageContaining("X25519 keys must be 32 bytes.");
    }
}