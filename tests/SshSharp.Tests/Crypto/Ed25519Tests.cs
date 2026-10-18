using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

public class Ed25519Tests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] PublicKey(byte[] seed)
    {
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        return pub;
    }

    private static byte[] Sign(byte[] seed, byte[] message)
    {
        var sig = new byte[64];
        Ed25519.Sign(seed, message, sig);
        return sig;
    }

    [Test]
    public async Task Rfc8032_Test1_EmptyMessage()
    {
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pub = PublicKey(seed);
        await Assert.That(Hex(pub)).IsEqualTo("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        var sig = Sign(seed, []);
        await Assert.That(Hex(sig)).IsEqualTo("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        await Assert.That(Ed25519.Verify(pub, [], sig)).IsTrue();
    }

    [Test]
    public async Task Rfc8032_Test2_OneByteMessage()
    {
        var seed = H("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        var pub = PublicKey(seed);
        await Assert.That(Hex(pub)).IsEqualTo("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

        var sig = Sign(seed, [0x72]);
        await Assert.That(Hex(sig)).IsEqualTo("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        await Assert.That(Ed25519.Verify(pub, [0x72], sig)).IsTrue();
    }

    [Test]
    public async Task OpenSslVectors_KeysAndSignaturesMatch_AndVerify()
    {
        var count = 0;
        foreach (var line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "curve25519_openssl_vectors.txt")))
        {
            var f = line.Split(' ');
            if (f[0] != "ed25519")
            {
                continue;
            }

            var seed = H(f[1]);
            var expectedPub = H(f[2]);
            var message = H(f[3]);
            var expectedSig = H(f[4]);

            var pub = PublicKey(seed);
            await Assert.That(Hex(pub)).IsEqualTo(Hex(expectedPub));
            await Assert.That(Hex(Sign(seed, message))).IsEqualTo(Hex(expectedSig));
            await Assert.That(Ed25519.Verify(expectedPub, message, expectedSig)).IsTrue();
            count++;
        }

        await Assert.That(count).IsEqualTo(9);
    }

    [Test]
    public async Task Verify_RejectsTamperedInputs()
    {
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pub = PublicKey(seed);
        var message = "attack at dawn"u8.ToArray();
        var sig = Sign(seed, message);
        await Assert.That(Ed25519.Verify(pub, message, sig)).IsTrue();

        var wrongMessage = "attack at dusk"u8.ToArray();
        await Assert.That(Ed25519.Verify(pub, wrongMessage, sig)).IsFalse();

        for (var i = 0; i < 64; i += 9)
        {
            var bad = (byte[])sig.Clone();
            bad[i] ^= 1;
            await Assert.That(Ed25519.Verify(pub, message, bad)).IsFalse();
        }

        var otherPub = PublicKey(H("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
        await Assert.That(Ed25519.Verify(otherPub, message, sig)).IsFalse();
    }

    [Test]
    public async Task Verify_RejectsNonCanonicalS()
    {
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pub = PublicKey(seed);
        var sig = Sign(seed, "m"u8.ToArray());
        await Assert.That(Ed25519.Verify(pub, "m"u8.ToArray(), sig)).IsTrue();

        // S + L is the same scalar mod L, but a strict verifier must refuse it (RFC 8032 section 5.1.7).
        var l = H("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        var malleable = (byte[])sig.Clone();
        var carry = 0;
        for (var i = 0; i < 32; i++)
        {
            var sum = malleable[32 + i] + l[i] + carry;
            malleable[32 + i] = (byte)sum;
            carry = sum >> 8;
        }

        await Assert.That(Ed25519.Verify(pub, "m"u8.ToArray(), malleable)).IsFalse();

        // S = L exactly is also out of range.
        var equalToL = (byte[])sig.Clone();
        l.CopyTo(equalToL, 32);
        await Assert.That(Ed25519.Verify(pub, "m"u8.ToArray(), equalToL)).IsFalse();
    }

    [Test]
    public async Task Verify_RejectsSmallOrderAndNonCanonicalPublicKeys()
    {
        // With the identity as the public key, R = S·B satisfies the verification equation for any message: (R, S) = (identity, 0)
        // "verifies" without any private key. Small-order keys must be rejected for a fingerprint to mean one signer.
        var identity = new byte[32];
        identity[0] = 1;
        var forged = new byte[64];
        identity.CopyTo(forged, 0);
        await Assert.That(Ed25519.Verify(identity, "anything"u8.ToArray(), forged)).IsFalse();

        // The order-2 point (0, -1), and the order-4 point with y = 0.
        var order2 = H("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        await Assert.That(Ed25519.Verify(order2, "m"u8.ToArray(), forged)).IsFalse();
        await Assert.That(Ed25519.Verify(new byte[32], "m"u8.ToArray(), forged)).IsFalse();

        // y = p + 1 is a non-canonical encoding of y = 1; and x = 0 with the sign bit set is invalid (RFC 8032 5.1.3).
        var nonCanonical = H("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        await Assert.That(Ed25519.Verify(nonCanonical, "m"u8.ToArray(), forged)).IsFalse();
        var negativeZero = (byte[])identity.Clone();
        negativeZero[31] |= 0x80;
        await Assert.That(Ed25519.Verify(negativeZero, "m"u8.ToArray(), forged)).IsFalse();

        // Ordinary keys still verify.
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        await Assert.That(Ed25519.Verify(PublicKey(seed), "m"u8.ToArray(), Sign(seed, "m"u8.ToArray()))).IsTrue();
    }

    [Test]
    public async Task Verify_RejectsBadSizesAndInvalidPoints()
    {
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pub = PublicKey(seed);
        var sig = Sign(seed, []);

        await Assert.That(Ed25519.Verify(pub.AsSpan(0, 31), [], sig)).IsFalse();
        await Assert.That(Ed25519.Verify(pub, [], sig.AsSpan(0, 63))).IsFalse();

        // y = 2 is not the y coordinate of any curve point.
        var offCurve = new byte[32];
        offCurve[0] = 2;
        await Assert.That(Ed25519.Verify(offCurve, [], sig)).IsFalse();
    }

    [Test]
    public async Task SignAndGetPublicKey_CheckSizes()
    {
        await Assert.That(() => Ed25519.GetPublicKey(new byte[31], new byte[32])).Throws<ArgumentException>();
        await Assert.That(() => Ed25519.GetPublicKey(new byte[32], new byte[33])).Throws<ArgumentException>();
        await Assert.That(() => Ed25519.Sign(new byte[32], [], new byte[63])).Throws<ArgumentException>();
    }

    [Test]
    public async Task RoundTrip_ManyMessageLengths()
    {
        var seed = new byte[32];
        new Random(7).NextBytes(seed);
        var pub = PublicKey(seed);
        var rng = new Random(11);
        foreach (var length in new[] { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000 })
        {
            var message = new byte[length];
            rng.NextBytes(message);
            await Assert.That(Ed25519.Verify(pub, message, Sign(seed, message))).IsTrue();
        }
    }

    private static byte[] SignWithPublicKey(byte[] seed, byte[] publicKey, byte[] message)
    {
        var sig = new byte[64];
        Ed25519.Sign(seed, publicKey, message, sig);
        return sig;
    }

    [Test]
    public async Task SigningWithTheKnownPublicKey_MatchesTheRfc8032AndOpenSslVectors()
    {
        // RFC 8032 section 7.1, tests 1 to 3.
        (string Seed, string Message, string Signature)[] rfc =
        [
            ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ];
        foreach (var (seed, message, signature) in rfc)
        {
            await Assert.That(Hex(SignWithPublicKey(H(seed), PublicKey(H(seed)), H(message)))).IsEqualTo(signature);
        }

        var count = 0;
        foreach (var line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "curve25519_openssl_vectors.txt")))
        {
            var f = line.Split(' ');
            if (f[0] == "ed25519")
            {
                await Assert.That(Hex(SignWithPublicKey(H(f[1]), H(f[2]), H(f[3])))).IsEqualTo(f[4]);
                count++;
            }
        }

        await Assert.That(count).IsEqualTo(9);
    }

    [Test]
    public async Task SigningWithTheKnownPublicKey_ChecksItsSize()
    {
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pub = PublicKey(seed);
        await Assert.That(() => Ed25519.Sign(seed, pub.AsSpan(1), [], new byte[64])).Throws<ArgumentException>();
        await Assert.That(() => Ed25519.Sign(seed, [.. pub, 0], [], new byte[64])).Throws<ArgumentException>();
        await Assert.That(() => Ed25519.Sign(seed.AsSpan(1), pub, [], new byte[64])).Throws<ArgumentException>();
        await Assert.That(() => Ed25519.Sign(seed, pub, [], new byte[63])).Throws<ArgumentException>();
    }

    [Test]
    public async Task AMismatchedPublicKey_WouldGiveTheSecretScalarAway()
    {
        // Why only a key's own derived public key may be passed: the nonce depends on the seed and the message, not on the public key,
        // so two signatures of one message under two public keys share R, and S - S' = (h - h') * a gives away the scalar a. This
        // records the hazard that SshPrivateKey.Ed25519Key's derive-only public key (see SshPrivateKeyTests) guards against.
        var seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var message = "same message"u8.ToArray();
        var genuine = SignWithPublicKey(seed, PublicKey(seed), message);
        var mismatched = SignWithPublicKey(seed, PublicKey(H("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")), message);
        await Assert.That(Hex(mismatched[..32])).IsEqualTo(Hex(genuine[..32]));
        await Assert.That(Hex(mismatched[32..])).IsNotEqualTo(Hex(genuine[32..]));
        await Assert.That(Hex(genuine)).IsEqualTo(Hex(Sign(seed, message)));
    }

    [Test]
    public async Task Signing_IsDeterministic()
    {
        var seed = H("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        await Assert.That(Hex(Sign(seed, [1, 2, 3]))).IsEqualTo(Hex(Sign(seed, [1, 2, 3])));
    }
}