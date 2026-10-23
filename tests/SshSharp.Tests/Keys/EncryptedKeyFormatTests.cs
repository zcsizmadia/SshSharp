using System.Security.Cryptography;
using System.Text;
using SshSharp.Keys;

namespace SshSharp.Tests.Keys;

/// <summary>
/// Traditional encrypted PEM keys (<c>Proc-Type: 4,ENCRYPTED</c>) and OpenSSH keys encrypted with <c>chacha20-poly1305@openssh.com</c>,
/// built here from fresh keys and passphrases. The LocalTools tests (Integration/EncryptedKeyInteropTests.cs) read files that OpenSSL
/// and ssh-keygen made.
/// </summary>
public class EncryptedKeyFormatTests
{
    private const string ChaCha = "chacha20-poly1305@openssh.com";

    // Generated per run, never written down.
    private static string NewPassphrase() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private static (string Pem, byte[] PublicBlob) LegacyRsa(string passphrase, string cipher = "AES-128-CBC", byte[]? iv = null)
    {
        using var rsa = RSA.Create(2048);
        return (TestKeys.LegacyEncryptedPem("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey(), passphrase, cipher, iv), TestKeys.RsaPublicBlob(rsa));
    }

    [Test]
    [Arguments("AES-128-CBC")]
    [Arguments("AES-192-CBC")]
    [Arguments("AES-256-CBC")]
    public async Task LegacyPem_Rsa_EachAesCipher(string cipher)
    {
        var passphrase = NewPassphrase();
        var (pem, blob) = LegacyRsa(passphrase, cipher);
        using (var key = SshPrivateKey.Parse(pem, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo("ssh-rsa");
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
            await Assert.That(key.Comment).IsNull();
        }

        // Windows line endings and a lower-case cipher name read the same.
        var crlf = pem.Replace("\n", "\r\n", StringComparison.Ordinal).Replace(cipher, cipher.ToLowerInvariant(), StringComparison.Ordinal);
        using (var key = SshPrivateKey.Parse(crlf, passphrase))
        {
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
        }
    }

    [Test]
    [Arguments("nistp256")]
    [Arguments("nistp384")]
    [Arguments("nistp521")]
    public async Task LegacyPem_Ecdsa(string curveName)
    {
        var curve = curveName switch { "nistp256" => ECCurve.NamedCurves.nistP256, "nistp384" => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
        using var ecdsa = ECDsa.Create(curve);
        var passphrase = NewPassphrase();
        var pem = TestKeys.LegacyEncryptedPem("EC PRIVATE KEY", ecdsa.ExportECPrivateKey(), passphrase, "AES-256-CBC");

        using var key = SshPrivateKey.Parse(pem, passphrase);
        await Assert.That(key.KeyType).IsEqualTo("ecdsa-sha2-" + curveName);
        await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(TestKeys.EcdsaPublicBlob(ecdsa, curveName));
    }

    [Test]
    public async Task LegacyPem_PassphraseMissingOrWrong()
    {
        var passphrase = NewPassphrase();
        var (pem, _) = LegacyRsa(passphrase);
        await Assert.That(() => SshPrivateKey.Parse(pem)).Throws<FormatException>().WithMessageContaining("passphrase is required");
        await Assert.That(() => SshPrivateKey.Parse(pem, string.Empty)).Throws<FormatException>().WithMessageContaining("passphrase is required");
        for (var i = 0; i < 20; i++)
        {
            await Assert.That(() => SshPrivateKey.Parse(pem, NewPassphrase())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        }
    }

    [Test]
    public async Task LegacyPem_DecryptedBytesThatAreNotOneKey_ReadAsAWrongPassphrase()
    {
        // About one wrong passphrase in 256 leaves valid padding; what it decrypts to is then not a key. Built directly, so the test does
        // not depend on luck: garbage, a key with bytes after it, and an RSA key labelled EC.
        var passphrase = NewPassphrase();
        using var rsa = RSA.Create(2048);
        var der = rsa.ExportRSAPrivateKey();
        foreach (var (label, body) in new[]
        {
            ("RSA PRIVATE KEY", RandomNumberGenerator.GetBytes(100)),
            ("RSA PRIVATE KEY", der.Append((byte)0).ToArray()),
            ("EC PRIVATE KEY", der),
        })
        {
            var pem = TestKeys.LegacyEncryptedPem(label, body, passphrase);
            await Assert.That(() => SshPrivateKey.Parse(pem, passphrase)).Throws<FormatException>().WithMessageContaining("passphrase is wrong, or the file is corrupt");
        }
    }

    [Test]
    [Arguments("DES-EDE3-CBC")]
    [Arguments("DES-EDE3-CFB")]
    [Arguments("DES-CBC")]
    [Arguments("des-ede3-cbc")]
    public async Task LegacyPem_Des_IsRefused_NamingTheCipherAndTheFix(string cipher)
    {
        // Refused before the passphrase is asked for: there is nothing to prompt for when the key cannot be read anyway.
        var pem = $"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: {cipher},0001020304050607\n\nAAAAAAAAAAA=\n-----END RSA PRIVATE KEY-----\n";
        foreach (var passphrase in new[] { null, NewPassphrase() })
        {
            var error = Assert.Throws<FormatException>(() => SshPrivateKey.Parse(pem, passphrase));
            await Assert.That(error.Message).Contains(cipher);
            await Assert.That(error.Message).Contains("ssh-keygen -p -f <file>");
            await Assert.That(error.Message).DoesNotContain("passphrase is required");
        }
    }

    [Test]
    [Arguments("AES-128-CTR")]
    [Arguments("AES-128-GCM")]
    [Arguments("CAMELLIA-256-CBC")]
    [Arguments("")]
    public async Task LegacyPem_OtherCiphers_AreUnsupported(string cipher)
    {
        var pem = $"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: {cipher},000102030405060708090A0B0C0D0E0F\n\nAAAAAAAAAAAAAAAAAAAAAA==\n-----END RSA PRIVATE KEY-----\n";
        await Assert.That(() => SshPrivateKey.Parse(pem, NewPassphrase())).Throws<FormatException>().WithMessageContaining("Unsupported cipher");
    }

    [Test]
    public async Task LegacyPem_MalformedHeaders_AreFormatErrors()
    {
        var passphrase = NewPassphrase();
        var (pem, _) = LegacyRsa(passphrase);
        var dekInfo = pem.Split('\n').Single(l => l.StartsWith("DEK-Info: ", StringComparison.Ordinal));
        var iv = dekInfo[(dekInfo.IndexOf(',', StringComparison.Ordinal) + 1)..];

        string With(string line) => pem.Replace(dekInfo, line, StringComparison.Ordinal);
        await Assert.That(() => SshPrivateKey.Parse(With("DEK-Info: AES-128-CBC"), passphrase)).Throws<FormatException>().WithMessageContaining("no IV");
        await Assert.That(() => SshPrivateKey.Parse(With("DEK-Info: AES-128-CBC," + iv[..^1] + "Z"), passphrase)).Throws<FormatException>().WithMessageContaining("hex");
        await Assert.That(() => SshPrivateKey.Parse(With("DEK-Info: AES-128-CBC," + iv[..30]), passphrase)).Throws<FormatException>().WithMessageContaining("16 bytes");
        await Assert.That(() => SshPrivateKey.Parse(With("DEK-Info: AES-128-CBC," + iv + "00"), passphrase)).Throws<FormatException>().WithMessageContaining("16 bytes");
        await Assert.That(() => SshPrivateKey.Parse(With("X-Other: 1"), passphrase)).Throws<FormatException>().WithMessageContaining("DEK-Info");
        await Assert.That(() => SshPrivateKey.Parse(pem.Replace("Proc-Type: 4,ENCRYPTED\n", "Proc-Type: 4,ENCRYPTED\nProc-Type: 4,MIC-ONLY\n", StringComparison.Ordinal), passphrase))
            .Throws<FormatException>().WithMessageContaining("Proc-Type");

        // An IV that is valid hex but not the one used decrypts the first block wrongly.
        var otherIv = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        await Assert.That(() => SshPrivateKey.Parse(With("DEK-Info: AES-128-CBC," + otherIv), passphrase)).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
    }

    [Test]
    public async Task LegacyPem_TruncatedOrDamagedBody_IsAFormatError()
    {
        var passphrase = NewPassphrase();
        var (pem, _) = LegacyRsa(passphrase);
        var lines = pem.Split('\n').ToList();
        var bodyStart = lines.IndexOf(string.Empty) + 1;
        var bodyEnd = lines.FindIndex(l => l.StartsWith("-----END", StringComparison.Ordinal));
        var body = Convert.FromBase64String(string.Concat(lines.GetRange(bodyStart, bodyEnd - bodyStart)));

        string WithBody(byte[] data) =>
            string.Join('\n', lines.Take(bodyStart)) + "\n" + Convert.ToBase64String(data) + "\n" + string.Join('\n', lines.Skip(bodyEnd));

        // Not a whole number of blocks, a whole block short (the padding no longer checks out), empty, and not base64.
        await Assert.That(() => SshPrivateKey.Parse(WithBody(body[..^5]), passphrase)).Throws<FormatException>().WithMessageContaining("invalid length");
        await Assert.That(() => SshPrivateKey.Parse(WithBody(body[..^16]), passphrase)).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        await Assert.That(() => SshPrivateKey.Parse(WithBody([]), passphrase)).Throws<FormatException>().WithMessageContaining("invalid length");
        await Assert.That(() => SshPrivateKey.Parse(WithBody(body).Replace(Convert.ToBase64String(body)[..8], "!!!!!!!!", StringComparison.Ordinal), passphrase))
            .Throws<FormatException>().WithMessageContaining("base64");
        await Assert.That(() => SshPrivateKey.Parse(pem[..pem.IndexOf("-----END", StringComparison.Ordinal)], passphrase))
            .Throws<FormatException>().WithMessageContaining("END");
    }

    [Test]
    public async Task LegacyPem_OtherKeyTypes_AndSmallRsa_AreRefused()
    {
        var passphrase = NewPassphrase();
        var dsa = "-----BEGIN DSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,000102030405060708090A0B0C0D0E0F\n\nAAAA\n-----END DSA PRIVATE KEY-----\n";
        await Assert.That(() => SshPrivateKey.Parse(dsa, passphrase)).Throws<FormatException>().WithMessageContaining("Only RSA and EC");

        using var small = RSA.Create(1024);
        var pem = TestKeys.LegacyEncryptedPem("RSA PRIVATE KEY", small.ExportRSAPrivateKey(), passphrase);
        await Assert.That(() => SshPrivateKey.Parse(pem, passphrase)).Throws<FormatException>().WithMessageContaining("2048");
    }

    [Test]
    [Arguments("nistp256")]
    [Arguments("nistp521")]
    public async Task Sec1_PrivateKeyWithoutLeadingZeros_AsLibreSslWritesIt_Reads(string curveName)
    {
        // LibreSSL (OpenSSH for Windows' ssh-keygen -m PEM) drops the private key's leading zero bytes, though RFC 5915 fixes its length.
        // A nistp521 key's first byte is 0 about half the time; a nistp256 one's 1 in 256. Keys are made until one starts with 0.
        var (curve, oid) = curveName == "nistp256" ? (ECCurve.NamedCurves.nistP256, "1.2.840.10045.3.1.7") : (ECCurve.NamedCurves.nistP521, "1.3.132.0.35");
        ECParameters parameters;
        byte[] blob;
        do
        {
            using var ecdsa = ECDsa.Create(curve);
            parameters = ecdsa.ExportParameters(true);
            blob = TestKeys.EcdsaPublicBlob(ecdsa, curveName);
        }
        while (parameters.D![0] != 0);

        var shortD = parameters.D.AsSpan().TrimStart((byte)0).ToArray();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteOctetString(shortD);
            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                writer.WriteObjectIdentifier(oid);
            }

            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 1, isConstructed: true)))
            {
                writer.WriteBitString([4, .. parameters.Q.X!, .. parameters.Q.Y!]);
            }
        }

        var der = writer.Encode();
        using (var key = SshPrivateKey.Parse(PemEncoding.WriteString("EC PRIVATE KEY", der)))
        {
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
        }

        var passphrase = NewPassphrase();
        using (var key = SshPrivateKey.Parse(TestKeys.LegacyEncryptedPem("EC PRIVATE KEY", der, passphrase), passphrase))
        {
            await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
        }

        // Trailing bytes after the key are still refused.
        byte[] trailing = [.. der, 0];
        await Assert.That(() => SshPrivateKey.Parse(PemEncoding.WriteString("EC PRIVATE KEY", trailing))).Throws<FormatException>();
    }

    [Test]
    public async Task Sec1_AfterAnEcParametersBlock_Reads()
    {
        // openssl ecparam -genkey writes the curve in its own block first.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pem = "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n" + PemEncoding.WriteString("EC PRIVATE KEY", ecdsa.ExportECPrivateKey());
        using var key = SshPrivateKey.Parse(pem);
        await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(TestKeys.EcdsaPublicBlob(ecdsa, "nistp384"));
    }

    [Test]
    public async Task EvpBytesToKey_MatchesTheDefinition_ForEachLength()
    {
        // D_1 = MD5(passphrase || salt), D_i = MD5(D_(i-1) || passphrase || salt); key = D_1 || D_2 || ... cut to length.
        var passphrase = Encoding.UTF8.GetBytes(NewPassphrase());
        var salt = RandomNumberGenerator.GetBytes(8);
#pragma warning disable CA5351 // the definition being checked is MD5's
        var d1 = MD5.HashData([.. passphrase, .. salt]);
        var d2 = MD5.HashData([.. d1, .. passphrase, .. salt]);
        var d3 = MD5.HashData([.. d2, .. passphrase, .. salt]);
#pragma warning restore CA5351
        byte[] expected = [.. d1, .. d2, .. d3];
        foreach (var length in new[] { 1, 16, 17, 24, 32, 48 })
        {
            var key = new byte[length];
            LegacyPemKeyDecryptor.DeriveKey(passphrase, salt, key);
            await Assert.That(Convert.ToHexString(key)).IsEqualTo(Convert.ToHexString(expected.AsSpan(0, length)));
        }
    }

    [Test]
    public async Task OpenSshChaCha20Poly1305_Decrypts()
    {
        var passphrase = NewPassphrase();
        var pem = TestKeys.OpenSshEd25519(out var blob, comment: "chacha@example", passphrase: passphrase, cipher: ChaCha);
        using var key = SshPrivateKey.Parse(pem, passphrase);
        await Assert.That(key.KeyType).IsEqualTo("ssh-ed25519");
        await Assert.That(key.PublicKey.ToArray()).IsEquivalentTo(blob);
        await Assert.That(key.Comment).IsEqualTo("chacha@example");

        await Assert.That(() => SshPrivateKey.Parse(pem)).Throws<FormatException>().WithMessageContaining("passphrase is required");
        await Assert.That(() => SshPrivateKey.Parse(pem, NewPassphrase())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
    }

    [Test]
    public async Task OpenSshChaCha20Poly1305_TamperedTagOrSection_FailsAuthentication()
    {
        var passphrase = NewPassphrase();
        var body = Body(TestKeys.OpenSshEd25519(out _, passphrase: passphrase, cipher: ChaCha));

        // The tag is the last 16 bytes, the encrypted section the bytes before it: any flipped bit is caught by the tag, never parsed.
        foreach (var offset in new[] { 1, 8, 16, 17, 20, 40 })
        {
            var tampered = (byte[])body.Clone();
            tampered[^offset] ^= 0x01;
            await Assert.That(() => SshPrivateKey.Parse(Rewrap(tampered), passphrase)).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        }

        // A missing or short tag is a malformed file.
        await Assert.That(() => SshPrivateKey.Parse(Rewrap(body[..^16]), passphrase)).Throws<FormatException>().WithMessageContaining("malformed");
        await Assert.That(() => SshPrivateKey.Parse(Rewrap(body[..^1]), passphrase)).Throws<FormatException>().WithMessageContaining("malformed");
    }

    [Test]
    public async Task OpenSshChaCha20Poly1305_SectionNotAMultipleOfItsBlockSize_IsRefused()
    {
        // chacha20-poly1305's block size is 8: a 16-byte multiple is not required, but an 8-byte one is.
        var passphrase = NewPassphrase();
        var aligned = TestKeys.OpenSshEd25519(out _, passphrase: passphrase, cipher: ChaCha);
        using (var key = SshPrivateKey.Parse(aligned, passphrase))
        {
            await Assert.That(key.KeyType).IsEqualTo("ssh-ed25519");
        }

        // Padding of 1..7 bytes for an 8-byte block, plus one more, is never a multiple of 8.
        var section = 4 + 4 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + "test@example".Length;
        var pad = Enumerable.Range(1, ((8 - (section % 8)) % 8) + 1).Select(i => (byte)i).ToArray();
        var misaligned = TestKeys.OpenSshEd25519(out _, padding: pad, passphrase: passphrase, cipher: ChaCha);
        await Assert.That(() => SshPrivateKey.Parse(misaligned, passphrase)).Throws<FormatException>().WithMessageContaining("invalid length");
    }

    private static byte[] Body(string pem) =>
        Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal))));

    private static string Rewrap(byte[] body) =>
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(body) + "\n-----END OPENSSH PRIVATE KEY-----\n";
}
