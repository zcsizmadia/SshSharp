using System.Text;
using SshSharp.Keys;
using static SshSharp.Tests.Integration.KeyExportInteropTests;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Encrypted key files made by the real tools and read by SshSharp: traditional encrypted PEM (<c>Proc-Type: 4,ENCRYPTED</c>) from
/// <c>ssh-keygen -m PEM</c> and OpenSSL, and OpenSSH keys that <c>ssh-keygen -Z</c> encrypted with each AES cipher and with
/// <c>chacha20-poly1305@openssh.com</c>. The keys and passphrases are made per run, so none is written down. Each test is skipped
/// when its tool is not on the PATH.
/// </summary>
[Category("LocalTools")] // ssh-keygen and openssl only, no server: it runs with the unit tests
public class EncryptedKeyInteropTests
{
    private const string ChaCha = "chacha20-poly1305@openssh.com";

    [Test]
    [Arguments("rsa", 2048, "ssh-rsa")]
    [Arguments("ecdsa", 256, "ecdsa-sha2-nistp256")]
    [Arguments("ecdsa", 384, "ecdsa-sha2-nistp384")]
    [Arguments("ecdsa", 521, "ecdsa-sha2-nistp521")]
    public async Task SshKeygenPem_Encrypted_Reads(string type, int bits, string keyType)
    {
        if (Tool("ssh-keygen") is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        var passphrase = TestSecrets.New();
        var path = directory.NewPath("pem");
        var (exit, _, error) = await RunAsync(sshKeygen, "-q", "-t", type, "-b", bits.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-m", "PEM", "-N", passphrase, "-C", "pem@example", "-f", path);
        await Assert.That(exit).IsEqualTo(0).Because(error);

        var text = await File.ReadAllTextAsync(path);
        await Assert.That(text).Contains("Proc-Type: 4,ENCRYPTED");
        using (var key = SshPrivateKey.Parse(text, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo(keyType);
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(await PublicBlobAsync(path));
        }

        await Assert.That(() => SshPrivateKey.Parse(text, TestSecrets.New())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
    }

    [Test]
    [Arguments("ed25519", 0, "ssh-ed25519")]
    [Arguments("ecdsa", 256, "ecdsa-sha2-nistp256")]
    [Arguments("rsa", 2048, "ssh-rsa")]
    public async Task SshKeygenChaCha20Poly1305_Reads(string type, int bits, string keyType)
    {
        if (Tool("ssh-keygen") is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        var passphrase = TestSecrets.New();
        var path = directory.NewPath("chacha");
        string[] arguments = bits == 0
            ? ["-q", "-t", type, "-Z", ChaCha, "-N", passphrase, "-C", "chacha@example", "-f", path]
            : ["-q", "-t", type, "-b", bits.ToString(System.Globalization.CultureInfo.InvariantCulture), "-Z", ChaCha, "-N", passphrase, "-C", "chacha@example", "-f", path];
        var (exit, _, error) = await RunAsync(sshKeygen, arguments);
        await Assert.That(exit).IsEqualTo(0).Because(error);

        var text = await File.ReadAllTextAsync(path);
        var body = Body(text);
        await Assert.That(body.AsSpan().IndexOf(Encoding.ASCII.GetBytes(ChaCha))).IsGreaterThan(0);
        using (var key = SshPrivateKey.Parse(text, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo(keyType);
            await Assert.That(key.Comment).IsEqualTo("chacha@example");
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(await PublicBlobAsync(path));
        }

        await Assert.That(() => SshPrivateKey.Parse(text, TestSecrets.New())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");

        // A changed tag (the file's last 16 bytes) or encrypted section fails authentication.
        foreach (var offset in new[] { 1, 16, 17, 32 })
        {
            var tampered = (byte[])body.Clone();
            tampered[^offset] ^= 0x80;
            var rewrapped = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(tampered) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            await Assert.That(() => SshPrivateKey.Parse(rewrapped, passphrase)).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        }
    }

    [Test]
    [Arguments("aes128-ctr")]
    [Arguments("aes192-ctr")]
    [Arguments("aes256-ctr")]
    [Arguments("aes128-cbc")]
    [Arguments("aes192-cbc")]
    [Arguments("aes256-cbc")]
    [Arguments("aes128-gcm@openssh.com")]
    [Arguments("aes256-gcm@openssh.com")]
    public async Task SshKeygen_EachAesCipher_Reads(string cipher)
    {
        // The unit tests (Keys/SshPrivateKeyTests.cs) build these files themselves; here ssh-keygen encrypts them, so the decryption
        // is checked against another implementation's encryption.
        if (Tool("ssh-keygen") is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        var passphrase = TestSecrets.New();
        var path = directory.NewPath("key");
        var (exit, _, error) = await RunAsync(sshKeygen, "-q", "-t", "ed25519", "-Z", cipher, "-N", passphrase, "-C", "aes@example", "-f", path);
        await Assert.That(exit).IsEqualTo(0).Because(error);

        var text = await File.ReadAllTextAsync(path);
        await Assert.That(Body(text).AsSpan().IndexOf(Encoding.ASCII.GetBytes(cipher))).IsGreaterThan(0);
        using (var key = SshPrivateKey.Parse(text, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo("ssh-ed25519");
            await Assert.That(key.Comment).IsEqualTo("aes@example");
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(await PublicBlobAsync(path));
            var signature = key.Sign("ssh-ed25519", "data"u8.ToArray());
            await Assert.That(VerifyingKey.Parse(key.PublicKey.Span).VerifySignature("ssh-ed25519", signature, "data"u8)).IsTrue();
        }

        await Assert.That(() => SshPrivateKey.Parse(text, TestSecrets.New())).Throws<FormatException>().WithMessageContaining("passphrase");
    }

    [Test]
    [Arguments("RSA", "rsa_keygen_bits:2048", "-aes128", "AES-128-CBC")]
    [Arguments("RSA", "rsa_keygen_bits:2048", "-aes192", "AES-192-CBC")]
    [Arguments("RSA", "rsa_keygen_bits:2048", "-aes256", "AES-256-CBC")]
    [Arguments("EC", "ec_paramgen_curve:P-256", "-aes128", "AES-128-CBC")]
    [Arguments("EC", "ec_paramgen_curve:P-384", "-aes192", "AES-192-CBC")]
    [Arguments("EC", "ec_paramgen_curve:P-521", "-aes256", "AES-256-CBC")]
    public async Task OpenSslTraditionalPem_Encrypted_Reads(string algorithm, string option, string cipherOption, string dekCipher)
    {
        if (Tool("openssl") is not { } openssl)
        {
            Skip.Test("openssl is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        var (plainPath, encryptedPath, passphrase) = await OpenSslEncryptAsync(openssl, directory, algorithm, option, cipherOption);
        var text = await File.ReadAllTextAsync(encryptedPath);
        await Assert.That(text).Contains("Proc-Type: 4,ENCRYPTED");
        await Assert.That(text).Contains("DEK-Info: " + dekCipher + ",");

        using var expected = await SshPrivateKey.LoadAsync(plainPath);
        using (var key = SshPrivateKey.Parse(text, passphrase))
        {
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(expected.PublicKey.ToArray());
        }

        await Assert.That(() => SshPrivateKey.Parse(text, TestSecrets.New())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
    }

    [Test]
    [Arguments("ec_paramgen_curve:P-256", "ecdsa-sha2-nistp256")]
    [Arguments("ec_paramgen_curve:P-384", "ecdsa-sha2-nistp384")]
    [Arguments("ec_paramgen_curve:P-521", "ecdsa-sha2-nistp521")]
    public async Task OpenSslTraditionalPem_ExplicitCurveParameters_Reads(string option, string keyType)
    {
        if (Tool("openssl") is not { } openssl)
        {
            Skip.Test("openssl is not installed.");
            return;
        }

        // The curve written as explicit parameters, as macOS's ssh-keygen -m PEM (LibreSSL) writes it.
        using var directory = new TempDirectory();
        var (plainPath, encryptedPath, passphrase) = await OpenSslEncryptAsync(openssl, directory, "EC", option, "-aes128", explicitCurve: true);
        var text = await File.ReadAllTextAsync(encryptedPath);
        await Assert.That(text).Contains("Proc-Type: 4,ENCRYPTED");

        using var expected = await SshPrivateKey.LoadAsync(plainPath);
        using var key = SshPrivateKey.Parse(text, passphrase);
        await Assert.That(key.KeyType).IsEqualTo(keyType);
        await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(expected.PublicKey.ToArray());
    }

    [Test]
    public async Task OpenSslTraditionalPem_TripleDes_IsRefused()
    {
        if (Tool("openssl") is not { } openssl)
        {
            Skip.Test("openssl is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        var (_, encryptedPath, passphrase) = await OpenSslEncryptAsync(openssl, directory, "RSA", "rsa_keygen_bits:2048", "-des3");
        var text = await File.ReadAllTextAsync(encryptedPath);
        await Assert.That(text).Contains("DEK-Info: DES-EDE3-CBC,");
        await Assert.That(() => SshPrivateKey.Parse(text, passphrase)).Throws<FormatException>().WithMessageContaining("DES-EDE3-CBC");
    }

    /// <summary>
    /// Makes a key with OpenSSL and writes it encrypted in the traditional format. OpenSSL 3 writes PKCS#8 unless told
    /// <c>-traditional</c>; LibreSSL writes the traditional format already and may not know the option.
    /// </summary>
    private static async Task<(string Plain, string Encrypted, string Passphrase)> OpenSslEncryptAsync(string openssl, TempDirectory directory,
        string algorithm, string option, string cipherOption, bool explicitCurve = false)
    {
        var plain = directory.NewPath("plain");
        var (exit, _, error) = await RunAsync(openssl, "genpkey", "-algorithm", algorithm, "-pkeyopt", option, "-out", plain);
        await Assert.That(exit).IsEqualTo(0).Because(error);

        var passphrase = TestSecrets.New();
        var passphraseFile = directory.NewPath("phrase");
        await File.WriteAllTextAsync(passphraseFile, passphrase);
        var encrypted = directory.NewPath("encrypted");
        var command = algorithm == "RSA" ? "rsa" : "ec";
        string[] curveOptions = explicitCurve ? ["-param_enc", "explicit"] : [];
        (exit, _, error) = await RunAsync(openssl, [command, "-in", plain, .. curveOptions, cipherOption, "-traditional", "-passout", "file:" + passphraseFile, "-out", encrypted]);
        if (exit != 0)
        {
            (exit, _, error) = await RunAsync(openssl, [command, "-in", plain, .. curveOptions, cipherOption, "-passout", "file:" + passphraseFile, "-out", encrypted]);
        }

        await Assert.That(exit).IsEqualTo(0).Because(error);
        return (plain, encrypted, passphrase);
    }

    private static async Task<byte[]> PublicBlobAsync(string privatePath) =>
        Convert.FromBase64String((await File.ReadAllTextAsync(privatePath + ".pub")).Split(' ')[1]);

    private static byte[] Body(string pem) =>
        Convert.FromBase64String(string.Concat(pem.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n')
            .Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal))));
}
