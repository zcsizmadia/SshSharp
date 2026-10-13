using System.Security.Cryptography;
using System.Text;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

public class SshPrivateKeyTests
{
    private static readonly byte[] Data = "data to sign"u8.ToArray();

    /// <summary>Every algorithm a key offers signs, and the signature verifies with the public key it reports.</summary>
    private static async Task AssertSignsAndVerifies(SshPrivateKey key, byte[] expectedPublicBlob)
    {
        await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(expectedPublicBlob);
        var publicKey = SshPublicKey.Parse(key.PublicKey.Span);
        await Assert.That(key.Fingerprint).IsEqualTo(publicKey.Fingerprint);
        foreach (var algorithm in key.SignatureAlgorithms)
        {
            var signature = key.Sign(algorithm, Data);
            await Assert.That(publicKey.VerifySignature(algorithm, signature, Data)).IsTrue();
            await Assert.That(publicKey.VerifySignature(algorithm, signature, "other"u8)).IsFalse();
        }
    }

    [Test]
    public async Task OpenSshFormat_Ed25519()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob, comment: "alice@laptop"));
        await Assert.That(key.KeyType).IsEqualTo("ssh-ed25519");
        await Assert.That(key.Comment).IsEqualTo("alice@laptop");
        await Assert.That(key.ToAuthorizedKeysLine()).IsEqualTo($"ssh-ed25519 {Convert.ToBase64String(blob)} alice@laptop");
        await AssertSignsAndVerifies(key, blob);
    }

    [Test]
    [Arguments("nistp256")]
    [Arguments("nistp384")]
    [Arguments("nistp521")]
    public async Task OpenSshFormat_Ecdsa(string curveName)
    {
        var curve = curveName switch { "nistp256" => ECCurve.NamedCurves.nistP256, "nistp384" => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEcdsa(curve, curveName, out var blob));
        await Assert.That(key.KeyType).IsEqualTo("ecdsa-sha2-" + curveName);
        await Assert.That(key.Comment).IsNull();
        await AssertSignsAndVerifies(key, blob);
    }

    [Test]
    public async Task OpenSshFormat_Rsa_SignsOnlyWithSha2()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var blob));
        await Assert.That(key.KeyType).IsEqualTo("ssh-rsa");
        await Assert.That(key.SignatureAlgorithms).IsEquivalentTo(new[] { "rsa-sha2-512", "rsa-sha2-256" });
        await AssertSignsAndVerifies(key, blob);
        await Assert.That(() => key.Sign("ssh-rsa", Data)).Throws<ArgumentException>();
    }

    [Test]
    public async Task Pem_Pkcs8_Pkcs1_Sec1_AndEncryptedPkcs8()
    {
        using var rsa = RSA.Create(2048);
        var rsaBlob = TestKeys.RsaPublicBlob(rsa);
        using (var key = SshPrivateKey.Parse(rsa.ExportPkcs8PrivateKeyPem()))
        {
            await AssertSignsAndVerifies(key, rsaBlob);
        }

        using (var key = SshPrivateKey.Parse(rsa.ExportRSAPrivateKeyPem()))
        {
            await AssertSignsAndVerifies(key, rsaBlob);
        }

        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000);
        using (var key = SshPrivateKey.Parse(rsa.ExportEncryptedPkcs8PrivateKeyPem("pass phrase", pbe), "pass phrase"))
        {
            await AssertSignsAndVerifies(key, rsaBlob);
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecBlob = TestKeys.EcdsaPublicBlob(ecdsa, "nistp384");
        using (var key = SshPrivateKey.Parse(ecdsa.ExportPkcs8PrivateKeyPem()))
        {
            await AssertSignsAndVerifies(key, ecBlob);
        }

        using (var key = SshPrivateKey.Parse(ecdsa.ExportECPrivateKeyPem()))
        {
            await AssertSignsAndVerifies(key, ecBlob);
        }

        using (var key = SshPrivateKey.Parse(ecdsa.ExportEncryptedPkcs8PrivateKeyPem("pw", pbe), "pw"))
        {
            await AssertSignsAndVerifies(key, ecBlob);
        }

        using (var key = SshPrivateKey.Parse(TestKeys.Pkcs8Ed25519(out var edBlob)))
        {
            await AssertSignsAndVerifies(key, edBlob);
        }
    }

    [Test]
    public async Task EncryptedPkcs8_NeedsTheRightPassphrase()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportEncryptedPkcs8PrivateKeyPem("right", new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 1000));
        await Assert.That(() => SshPrivateKey.Parse(pem)).Throws<FormatException>().WithMessageContaining("passphrase");
        await Assert.That(() => SshPrivateKey.Parse(pem, "wrong")).Throws<FormatException>().WithMessageContaining("passphrase");
    }

    [Test]
    public async Task WeakOrUnsupportedKeys_AreRefusedWithAClearMessage()
    {
        using var small = RSA.Create(1024);
        await Assert.That(() => SshPrivateKey.Parse(small.ExportPkcs8PrivateKeyPem())).Throws<FormatException>().WithMessageContaining("2048");
        await Assert.That(() => SshPrivateKey.Parse(TestKeys.OpenSshRsa(1024, out _))).Throws<FormatException>().WithMessageContaining("2048");

        await Assert.That(() => SshPrivateKey.Parse("PuTTY-User-Key-File-3: ssh-ed25519\n")).Throws<FormatException>().WithMessageContaining(".ppk");
        const string legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        await Assert.That(() => SshPrivateKey.Parse(legacy)).Throws<FormatException>().WithMessageContaining("Proc-Type");
        await Assert.That(() => SshPrivateKey.Parse("ssh-ed25519 AAAA user@host")).Throws<FormatException>();
    }

    [Test]
    public async Task CorruptOpenSshKeys_AreFormatErrors()
    {
        // Check values that differ mean a wrong passphrase or corruption; padding must be 1, 2, 3, ...
        await Assert.That(() => SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _, checkOverride: 7))).Throws<FormatException>().WithMessageContaining("check");
        await Assert.That(() => SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _, padding: [9]))).Throws<FormatException>().WithMessageContaining("padding");

        var text = TestKeys.OpenSshEd25519(out _);
        await Assert.That(() => SshPrivateKey.Parse(text.Replace("-----END OPENSSH PRIVATE KEY-----", string.Empty, StringComparison.Ordinal))).Throws<FormatException>();
        await Assert.That(() => SshPrivateKey.Parse(text.Insert(40, "!!"))).Throws<FormatException>();

        // A public key that does not match the private key.
        var other = TestKeys.OpenSshEd25519(out _);
        var a = Body(text);
        var b = Body(other);
        var mixed = Rewrap([.. a.AsSpan(0, PublicKeyEnd(a))[..^51], .. b.AsSpan(PublicKeyEnd(b) - 51, 51), .. a.AsSpan(PublicKeyEnd(a))]);
        await Assert.That(() => SshPrivateKey.Parse(mixed)).Throws<FormatException>().WithMessageContaining("does not match");
    }

    [Test]
    [Arguments("aes256-ctr")]
    [Arguments("aes256-gcm@openssh.com")]
    public async Task EncryptedOpenSshKeys_NeedTheRightPassphrase(string cipher)
    {
        var pem = TestKeys.OpenSshEd25519(out var blob, passphrase: "correct horse", cipher: cipher);
        using (var key = SshPrivateKey.Parse(pem, "correct horse"))
        {
            await AssertSignsAndVerifies(key, blob);
        }

        await Assert.That(() => SshPrivateKey.Parse(pem)).Throws<FormatException>().WithMessageContaining("passphrase is required");

        // A wrong passphrase shows up as differing check values (CTR) or a failed tag (GCM).
        var wrong = Assert.Throws<FormatException>(() => SshPrivateKey.Parse(pem, "battery staple"));
        await Assert.That(wrong.Message).Contains("passphrase");
    }

    [Test]
    [Arguments(2, "ssh-ed25519", null)]
    [Arguments(2, "ecdsa-sha2-nistp256", "pw")]
    [Arguments(2, "ssh-rsa", "pw")]
    [Arguments(3, "ssh-ed25519", "pw")]
    [Arguments(3, "ecdsa-sha2-nistp256", null)]
    [Arguments(3, "ssh-rsa", null)]
    public async Task PuttyKeys_Version2And3_PlainAndEncrypted(int version, string keyType, string? passphrase)
    {
        var ppk = TestKeys.Ppk(version, keyType, out var blob, passphrase);
        using (var key = SshPrivateKey.Parse(ppk, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo(keyType);
            await Assert.That(key.Comment).IsEqualTo("ppk-test");
            await AssertSignsAndVerifies(key, blob);
        }

        if (passphrase is not null)
        {
            await Assert.That(() => SshPrivateKey.Parse(ppk)).Throws<FormatException>().WithMessageContaining("passphrase is required");
            await Assert.That(() => SshPrivateKey.Parse(ppk, "wrong")).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        }

        // Windows line endings are fine; a changed MAC (or any edit) is not.
        using (var crlf = SshPrivateKey.Parse(ppk.Replace("\n", "\r\n", StringComparison.Ordinal), passphrase))
        {
            await Assert.That(crlf.PublicKey.ToArray()).IsEquivalentTo(blob);
        }

        var overflow = ppk.Replace("Public-Lines: ", "Public-Lines: 99999999999", StringComparison.Ordinal);
        await Assert.That(() => SshPrivateKey.Parse(overflow, passphrase)).Throws<FormatException>();

        var tampered = TestKeys.Ppk(version, keyType, out _, passphrase, corruptMac: true);
        await Assert.That(() => SshPrivateKey.Parse(tampered, passphrase)).Throws<FormatException>();
        await Assert.That(() => SshPrivateKey.Parse(ppk.Replace("Comment: ppk-test", "Comment: edited", StringComparison.Ordinal), passphrase)).Throws<FormatException>();
    }

    [Test]
    public async Task UnsupportedKeyCiphers_SayHowToConvert()
    {
        var body = Body(TestKeys.OpenSshEd25519(out _, passphrase: "pw"));
        var text = Encoding.Latin1.GetString(body).Replace("aes256-ctr", "aes256-xyz", StringComparison.Ordinal);
        await Assert.That(() => SshPrivateKey.Parse(Rewrap(Encoding.Latin1.GetBytes(text)), "pw")).Throws<FormatException>().WithMessageContaining("ssh-keygen -p");
    }

    [Test]
    public async Task Disposing_ClearsTheEd25519Seed()
    {
        var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        var seed = (byte[])typeof(SshPrivateKey.Ed25519Key).GetField("_seed", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(key)!;
        key.Dispose();
        await Assert.That(seed.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task LoadFileAsync_ReadsTheFile()
    {
        var path = Path.Combine(Path.GetTempPath(), "sshsharp-key-" + Guid.NewGuid().ToString("N"));
        try
        {
            await File.WriteAllTextAsync(path, TestKeys.OpenSshEd25519(out var blob));
            using var key = await SshPrivateKey.LoadFileAsync(path);
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] Body(string pem)
    {
        var lines = pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal));
        return Convert.FromBase64String(string.Concat(lines));
    }

    /// <summary>Offset just past the public key blob (magic, "none", "none", "", count, string public key).</summary>
    private static int PublicKeyEnd(byte[] body)
    {
        var offset = "openssh-key-v1\0"u8.Length + 8 + 8 + 4 + 4;
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(body.AsSpan(offset));
        return offset + 4 + length;
    }

    private static string Rewrap(byte[] body) =>
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(body) + "\n-----END OPENSSH PRIVATE KEY-----\n";
}
