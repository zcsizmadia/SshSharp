using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>
/// The key pair the key exchanges use: the platform's X25519 on .NET 11 (where the OS provides it) and the managed ladder elsewhere
/// must give the same public keys and secrets, and refuse the same low-order points.
/// </summary>
public class X25519KeyPairTests
{
    private const string AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    private const string AlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    private const string BobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    private const string BobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    private const string Shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static X25519KeyPair Pair(string privateKey, bool platform)
    {
        if (platform && !X25519KeyPair.UsesPlatform)
        {
            Skip.Test("The platform's X25519 needs .NET 11 on an OS that provides it.");
        }

        return X25519KeyPair.FromPrivateKey(H(privateKey), platform);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Rfc7748_Section61_AliceAndBob(bool platform)
    {
        using var alice = Pair(AlicePrivate, platform);
        using var bob = Pair(BobPrivate, platform);
        await Assert.That(alice.IsPlatform).IsEqualTo(platform);
        await Assert.That(Hex(alice.PublicKey)).IsEqualTo(AlicePublic);
        await Assert.That(Hex(bob.PublicKey)).IsEqualTo(BobPublic);

        var shared = new byte[32];
        await Assert.That(alice.TryAgree(H(BobPublic), shared)).IsTrue();
        await Assert.That(Hex(shared)).IsEqualTo(Shared);
        await Assert.That(bob.TryAgree(H(AlicePublic), shared)).IsTrue();
        await Assert.That(Hex(shared)).IsEqualTo(Shared);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OpenSslVectors_Agree(bool platform)
    {
        var checkedVectors = 0;
        foreach (var line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "curve25519_openssl_vectors.txt")))
        {
            var f = line.Split(' ');
            if (f[0] != "x25519")
            {
                continue;
            }

            using var pair = Pair(f[1], platform);
            var shared = new byte[32];
            await Assert.That(Hex(pair.PublicKey)).IsEqualTo(f[4]);
            await Assert.That(pair.TryAgree(H(f[2]), shared)).IsTrue();
            await Assert.That(Hex(shared)).IsEqualTo(f[3]);
            checkedVectors++;
        }

        await Assert.That(checkedVectors).IsEqualTo(6);
    }

    [Test]
    [Arguments(false, "0000000000000000000000000000000000000000000000000000000000000000")]
    [Arguments(true, "0000000000000000000000000000000000000000000000000000000000000000")]
    [Arguments(false, "0100000000000000000000000000000000000000000000000000000000000000")]
    [Arguments(true, "0100000000000000000000000000000000000000000000000000000000000000")]
    [Arguments(false, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    [Arguments(true, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    public async Task LowOrderPoints_AreRefused_AndLeaveNoSecret(bool platform, string peer)
    {
        using var pair = Pair(AlicePrivate, platform);
        var shared = new byte[32];
        Array.Fill(shared, (byte)0xAA);
        await Assert.That(pair.TryAgree(H(peer), shared)).IsFalse();
        await Assert.That(shared.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task GeneratedPairs_AgreeAcrossThePlatformAndManagedPaths()
    {
        using var generated = X25519KeyPair.Generate();
        await Assert.That(generated.IsPlatform).IsEqualTo(X25519KeyPair.UsesPlatform);

        using var managed = X25519KeyPair.FromPrivateKey(H(BobPrivate), platform: false);
        var a = new byte[32];
        var b = new byte[32];
        await Assert.That(generated.TryAgree(managed.PublicKey, a)).IsTrue();
        await Assert.That(managed.TryAgree(generated.PublicKey, b)).IsTrue();
        await Assert.That(Hex(a)).IsEqualTo(Hex(b));
    }

    [Test]
    public async Task Sizes_AreChecked()
    {
        await Assert.That(() => X25519KeyPair.FromPrivateKey(new byte[31], platform: false)).Throws<ArgumentException>();
        using var pair = X25519KeyPair.Generate();
        await Assert.That(() => pair.TryAgree(new byte[31], new byte[32])).Throws<ArgumentException>();
        await Assert.That(() => pair.TryAgree(new byte[32], new byte[31])).Throws<ArgumentException>();
    }
}
