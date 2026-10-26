using System.Security.Cryptography;
using System.Text;
using SshSharp.Keys;
using static SshSharp.Tests.Fuzz.FuzzHarness;

namespace SshSharp.Tests.Fuzz;

/// <summary>
/// Mutation fuzzing of encrypted private keys. It is apart from <see cref="ParserRobustnessTests"/> because every input runs a key
/// derivation: seconds in a normal run, but in a mutated build long enough for Stryker to mark the test dubious, and a dubious test is
/// run for every mutant of a scope and turns the ones the scope's fast tests miss into timeouts. Only the key reader scope takes it.
/// </summary>
public class EncryptedKeyRobustnessTests
{
    [Test]
    public async Task EncryptedKeyParsing_OnlyEverFailsWithAFormatError()
    {
        // Traditional encrypted PEM (headers and body as text), with the right passphrase, so an unmutated seed decrypts and the
        // mutations reach every step after the headers.
        var passphrase = TestSecrets.New();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = RSA.Create(2048);
        byte[][] pemSeeds =
        [
            Encoding.Latin1.GetBytes(Keys.TestKeys.LegacyEncryptedPem("EC PRIVATE KEY", ecdsa.ExportECPrivateKey(), passphrase)),
            Encoding.Latin1.GetBytes(Keys.TestKeys.LegacyEncryptedPem("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey(), passphrase, "AES-256-CBC")),
        ];
        var failures = Run(pemSeeds, input =>
        {
            using var key = SshPrivateKey.Parse(Encoding.Latin1.GetString(input), passphrase);
        }, FormatErrors, iterations: 1000);

        // A chacha20-poly1305 OpenSSH key: only what follows the bcrypt options is mutated, so no mutant asks for millions of rounds.
        var pem = Keys.TestKeys.OpenSshEd25519(out _, passphrase: passphrase, cipher: "chacha20-poly1305@openssh.com");
        var body = Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal))));
        var prefixLength = "openssh-key-v1\0"u8.Length + 4 + "chacha20-poly1305@openssh.com".Length + 4 + "bcrypt".Length + 4 + 4 + 16 + 4;
        var prefix = body[..prefixLength];
        failures.AddRange(Run([body[prefixLength..]], input =>
        {
            var text = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String([.. prefix, .. input]) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            using var key = SshPrivateKey.Parse(text, passphrase);
        }, FormatErrors, iterations: 50));
        await Assert.That(failures).IsEmpty();
    }
}
