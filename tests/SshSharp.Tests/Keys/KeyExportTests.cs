using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SshSharp.Keys;
using SshSharp.Protocol;
using SshSharp.Tests.Agent;

namespace SshSharp.Tests.Keys;

/// <summary>
/// <see cref="SshPrivateKey.ToPkcs8PrivateKey"/>, <see cref="SshPrivateKey.ToPuttyPrivateKey"/> and the <c>SaveAsync</c> overloads that
/// take a format or bcrypt rounds (#266). What other tools make of the files is in <c>Integration/KeyExportInteropTests</c>.
/// </summary>
public class KeyExportTests
{
    public static IEnumerable<(SshKeyType Type, string KeyType, int Bits)> Types() => KeyGenerationTests.Types();

    public static IEnumerable<(SshKeyType Type, string KeyType, int Bits)> PlatformTypes() => Types().Where(t => t.Type != SshKeyType.Ed25519);

    // Generated per run, never written down.
    private static string NewPassphrase() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private static SshPrivateKey Generate(SshKeyType type, int bits, string? comment = null) =>
        SshPrivateKey.Generate(type, comment, bits == 0 ? 3072 : bits);

    private static void AssertSigns(SshPrivateKey key)
    {
        var data = RandomNumberGenerator.GetBytes(100);
        var algorithm = key.SignatureAlgorithms[0];
        if (!VerifyingKey.Parse(key.PublicKey.Span).VerifySignature(algorithm, key.Sign(algorithm, data), data))
        {
            throw new InvalidOperationException($"A {key.KeyType} signature did not verify.");
        }
    }

    // ---- PKCS#8 ----

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task Pkcs8_RoundTrips_Unencrypted(SshKeyType type, string keyType, int bits)
    {
        using var key = Generate(type, bits, "dropped@example");
        var text = key.ToPkcs8PrivateKey();

        await Assert.That(text).StartsWith("-----BEGIN PRIVATE KEY-----\n");
        await Assert.That(text).EndsWith("-----END PRIVATE KEY-----\n");
        using var parsed = SshPrivateKey.Parse(text);
        await Assert.That(parsed.KeyType).IsEqualTo(keyType);
        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(parsed.Comment).IsNull(); // PKCS#8 has no comment
        AssertSigns(parsed);
    }

    [Test]
    [MethodDataSource(nameof(PlatformTypes))]
    public async Task Pkcs8_RoundTrips_Encrypted_AndNeedsItsPassphrase(SshKeyType type, string keyType, int bits)
    {
        using var key = Generate(type, bits);
        var passphrase = NewPassphrase();
        var text = key.ToPkcs8PrivateKey(passphrase);

        await Assert.That(text).StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
        using var parsed = SshPrivateKey.Parse(text, passphrase);
        await Assert.That(parsed.KeyType).IsEqualTo(keyType);
        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        AssertSigns(parsed);
        await Assert.That(() => SshPrivateKey.Parse(text, NewPassphrase())).Throws<FormatException>();
        await Assert.That(() => SshPrivateKey.Parse(text)).Throws<FormatException>();
    }

    [Test]
    public async Task Pkcs8_IsWhatTheFrameworkReads()
    {
        var passphrase = NewPassphrase();
        using (var key = Generate(SshKeyType.Rsa, 2048))
        {
            using var plain = RSA.Create();
            plain.ImportFromPem(key.ToPkcs8PrivateKey());
            using var encrypted = RSA.Create();
            encrypted.ImportFromEncryptedPem(key.ToPkcs8PrivateKey(passphrase), passphrase);
            await Assert.That(SshPrivateKey.RsaKey.PublicBlob(plain)).IsEquivalentTo(key.PublicKey.ToArray());
            await Assert.That(SshPrivateKey.RsaKey.PublicBlob(encrypted)).IsEquivalentTo(key.PublicKey.ToArray());
        }

        using (var key = Generate(SshKeyType.EcdsaNistp384, 0))
        {
            using var plain = ECDsa.Create();
            plain.ImportFromPem(key.ToPkcs8PrivateKey());
            using var encrypted = ECDsa.Create();
            encrypted.ImportFromEncryptedPem(key.ToPkcs8PrivateKey(passphrase), passphrase);
            await Assert.That(SshPrivateKey.EcdsaKey.PublicBlob(global::SshSharp.Crypto.NistCurve.P384, plain)).IsEquivalentTo(key.PublicKey.ToArray());
            await Assert.That(SshPrivateKey.EcdsaKey.PublicBlob(global::SshSharp.Crypto.NistCurve.P384, encrypted)).IsEquivalentTo(key.PublicKey.ToArray());
        }
    }

    [Test]
    public async Task Pkcs8_EncryptsWithPbes2Aes256AndPbkdf2Sha256()
    {
        using var key = Generate(SshKeyType.EcdsaNistp256, 0);
        var text = key.ToPkcs8PrivateKey(NewPassphrase());
        var der = Convert.FromBase64String(string.Concat(text.Split('\n')[1..^2]));

        // EncryptedPrivateKeyInfo { AlgorithmIdentifier { PBES2, { { PBKDF2, { salt, iterations, ..., prf } }, { aes256-CBC, iv } } }, data }
        var info = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        var algorithm = info.ReadSequence();
        await Assert.That(algorithm.ReadObjectIdentifier()).IsEqualTo("1.2.840.113549.1.5.13"); // PBES2
        var parameters = algorithm.ReadSequence();
        var kdf = parameters.ReadSequence();
        await Assert.That(kdf.ReadObjectIdentifier()).IsEqualTo("1.2.840.113549.1.5.12"); // PBKDF2
        var kdfParameters = kdf.ReadSequence();
        await Assert.That(kdfParameters.ReadOctetString().Length).IsGreaterThanOrEqualTo(8);
        await Assert.That((int)kdfParameters.ReadInteger()).IsEqualTo(Pkcs8KeyWriter.Iterations);
        if (kdfParameters.PeekTag().TagValue == (int)System.Formats.Asn1.UniversalTagNumber.Integer)
        {
            kdfParameters.ReadInteger(); // key length, optional
        }

        await Assert.That(kdfParameters.ReadSequence().ReadObjectIdentifier()).IsEqualTo("1.2.840.113549.2.9"); // hmacWithSHA256
        await Assert.That(parameters.ReadSequence().ReadObjectIdentifier()).IsEqualTo("2.16.840.1.101.3.4.1.42"); // aes256-CBC
    }

    [Test]
    public async Task Pkcs8_Ed25519_IsTheRfc8410Encoding()
    {
        // RFC 8410 section 10.3.
        const string Rfc8410 = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
        using var key = SshPrivateKey.Parse(Rfc8410);

        await Assert.That(key.ToPkcs8PrivateKey()).IsEqualTo(Rfc8410);
    }

    [Test]
    public async Task Pkcs8_LinesAre64Characters()
    {
        using var key = Generate(SshKeyType.Rsa, 2048);
        var lines = key.ToPkcs8PrivateKey().Split('\n');

        await Assert.That(lines[1..^3].All(l => l.Length == 64)).IsTrue();
        await Assert.That(lines[^3].Length).IsBetween(1, 64);
        await Assert.That(lines[^1]).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Pkcs8_AnEncryptedEd25519Key_IsNotSupported_ButAnEmptyPassphraseMeansUnencrypted()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);

        await Assert.That(() => key.ToPkcs8PrivateKey(NewPassphrase())).Throws<NotSupportedException>().WithMessageContaining("OpenSSH or PuTTY");
        await Assert.That(key.ToPkcs8PrivateKey(string.Empty)).StartsWith("-----BEGIN PRIVATE KEY-----");
    }

    // ---- PuTTY ----

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task Putty_RoundTrips_Unencrypted(SshKeyType type, string keyType, int bits)
    {
        using var key = Generate(type, bits, "putty@example");
        var text = key.ToPuttyPrivateKey();

        await Assert.That(text).StartsWith($"PuTTY-User-Key-File-3: {keyType}\nEncryption: none\nComment: putty@example\n");
        await Assert.That(text).DoesNotContain("Key-Derivation");
        using var parsed = SshPrivateKey.Parse(text);
        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(parsed.Comment).IsEqualTo("putty@example");
        AssertSigns(parsed);
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task Putty_RoundTrips_Encrypted_AndNeedsItsPassphrase(SshKeyType type, string keyType, int bits)
    {
        using var key = Generate(type, bits, "putty@example");
        var passphrase = NewPassphrase();
        var text = key.ToPuttyPrivateKey(passphrase);

        using var parsed = SshPrivateKey.Parse(text, passphrase);
        await Assert.That(parsed.KeyType).IsEqualTo(keyType);
        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(parsed.Comment).IsEqualTo("putty@example");
        AssertSigns(parsed);
        await Assert.That(() => SshPrivateKey.Parse(text, NewPassphrase())).Throws<FormatException>().WithMessageContaining("passphrase is wrong");
        await Assert.That(() => SshPrivateKey.Parse(text)).Throws<FormatException>().WithMessageContaining("passphrase is required");
    }

    [Test]
    public async Task Putty_TheFile_IsLaidOutAsPuttygenWritesIt()
    {
        using var key = Generate(SshKeyType.Rsa, 2048, "layout@example");
        var text = key.ToPuttyPrivateKey(NewPassphrase());
        var lines = text.Split('\n');
        var headers = lines.Where(l => l.Contains(": ", StringComparison.Ordinal)).Select(l => l[..l.IndexOf(": ", StringComparison.Ordinal)]).ToArray();

        await Assert.That(headers).IsEquivalentTo(new[]
        {
            "PuTTY-User-Key-File-3", "Encryption", "Comment", "Public-Lines", "Key-Derivation", "Argon2-Memory", "Argon2-Passes",
            "Argon2-Parallelism", "Argon2-Salt", "Private-Lines", "Private-MAC",
        });
        string Value(string header) => lines.Single(l => l.StartsWith(header + ": ", StringComparison.Ordinal))[(header.Length + 2)..];
        await Assert.That(Value("Encryption")).IsEqualTo("aes256-cbc");
        await Assert.That(Value("Key-Derivation")).IsEqualTo("Argon2id");
        await Assert.That(Value("Argon2-Memory")).IsEqualTo(PuttyKeyWriter.Argon2MemoryKiB.ToString(System.Globalization.CultureInfo.InvariantCulture));
        await Assert.That(Value("Argon2-Passes")).IsEqualTo(PuttyKeyWriter.Argon2Passes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        await Assert.That(Value("Argon2-Parallelism")).IsEqualTo("1");

        // PuTTY compares the MAC as lowercase hex.
        await Assert.That(Value("Argon2-Salt")).Matches("^[0-9a-f]{32}$");
        await Assert.That(Value("Private-MAC")).Matches("^[0-9a-f]{64}$");

        // Base64 in lines of 64; the encrypted private blob is whole AES blocks.
        var privateStart = Array.FindIndex(lines, l => l.StartsWith("Private-Lines: ", StringComparison.Ordinal)) + 1;
        var privateLines = lines[privateStart..(privateStart + int.Parse(Value("Private-Lines"), System.Globalization.CultureInfo.InvariantCulture))];
        await Assert.That(privateLines[..^1].All(l => l.Length == 64)).IsTrue();
        await Assert.That(Convert.FromBase64String(string.Concat(privateLines)).Length % 16).IsEqualTo(0);
        await Assert.That(lines[^1]).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Putty_TwoExports_UseDifferentSalts()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var passphrase = NewPassphrase();

        await Assert.That(key.ToPuttyPrivateKey(passphrase)).IsNotEqualTo(key.ToPuttyPrivateKey(passphrase));
    }

    [Test]
    public async Task Putty_KeepsTheCommentAsItIs()
    {
        // PuTTY's MAC covers the comment as written, spaces included; the reader must not trim it.
        using var key = Generate(SshKeyType.Ed25519, 0, " spaced comment  ");
        using var parsed = SshPrivateKey.Parse(key.ToPuttyPrivateKey());

        await Assert.That(parsed.Comment).IsEqualTo(" spaced comment  ");
    }

    [Test]
    public async Task Putty_ACommentWithALineBreak_IsNotSupported()
    {
        using var key = Generate(SshKeyType.Ed25519, 0, "two\nlines");

        await Assert.That(() => key.ToPuttyPrivateKey()).Throws<NotSupportedException>().WithMessageContaining("line break");
    }

    [Test]
    public async Task Putty_ALoadedRsaKey_ExportsTheSameKey()
    {
        // PuTTY's iqmp is q^-1 mod p, as OpenSSH's; a mix-up would only show when the re-read key signs.
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out _));
        using var again = SshPrivateKey.Parse(key.ToPuttyPrivateKey());

        await Assert.That(again.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        AssertSigns(again);
    }

    // ---- Keys that cannot be exported ----

    [Test]
    public async Task KeysWithoutLocalPrivateMaterial_AreNotExported()
    {
        await using var agent = new FakeAgent();
        agent.Keys.Add((SshPrivateKey.Generate(SshKeyType.Ed25519), "in the agent"));
        var agentKey = (await new SshAgent(agent.Path).GetKeysAsync())[0];

        using var rsa = RSA.Create(2048);
        using var external = SshPrivateKey.FromRsa(rsa);

        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certified = key.WithCertificate(SshCertificate.FromBlob(TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User, ["me"])));

        foreach (var unexportable in new[] { agentKey, external, certified })
        {
            await Assert.That(() => unexportable.ToPkcs8PrivateKey()).Throws<NotSupportedException>();
            await Assert.That(() => unexportable.ToPkcs8PrivateKey(NewPassphrase())).Throws<NotSupportedException>();
            await Assert.That(() => unexportable.ToPuttyPrivateKey()).Throws<NotSupportedException>();
            await Assert.That(() => unexportable.ToPuttyPrivateKey(NewPassphrase())).Throws<NotSupportedException>();
        }
    }

    [Test]
    public async Task ADisposedKey_IsNotExported()
    {
        var key = Generate(SshKeyType.Ed25519, 0);
        key.Dispose();

        await Assert.That(() => key.ToPkcs8PrivateKey()).Throws<ObjectDisposedException>();
        await Assert.That(() => key.ToPuttyPrivateKey()).Throws<ObjectDisposedException>();
    }

    // ---- SaveAsync ----

    [Test]
    [Arguments(SshPrivateKeyFormat.OpenSsh, "-----BEGIN OPENSSH PRIVATE KEY-----")]
    [Arguments(SshPrivateKeyFormat.Pkcs8, "-----BEGIN ENCRYPTED PRIVATE KEY-----")]
    [Arguments(SshPrivateKeyFormat.Putty, "PuTTY-User-Key-File-3: ")]
    public async Task SaveAsync_WritesTheFormat_ReadableOnlyByItsOwner(SshPrivateKeyFormat format, string start)
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-keyexport-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_key");
            using var key = Generate(SshKeyType.EcdsaNistp256, 0, "saved@example");
            var passphrase = NewPassphrase();

            await key.SaveAsync(path, format, passphrase);

            await Assert.That(await File.ReadAllTextAsync(path)).StartsWith(start);
            using var loaded = await SshPrivateKey.LoadAsync(path, passphrase);
            await Assert.That(loaded.Fingerprint).IsEqualTo(key.Fingerprint);
            await Assert.That(await File.ReadAllTextAsync(path + ".pub")).IsEqualTo(key.ToAuthorizedKeysLine() + "\n");
            await AssertOwnerOnly(path);

            // Never overwritten.
            await Assert.That(async () => await key.SaveAsync(path, format)).Throws<IOException>();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public async Task SaveAsync_WithKdfRounds_WritesThem()
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-keyexport-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_ed25519");
            using var key = Generate(SshKeyType.Ed25519, 0);
            var passphrase = NewPassphrase();

            await key.SaveAsync(path, passphrase, kdfRounds: 20);

            var lines = (await File.ReadAllTextAsync(path)).Split('\n');
            var data = Convert.FromBase64String(string.Concat(lines[1..^2]));
            var reader = new SshReader(data.AsSpan(15));
            reader.ReadString(); // cipher
            reader.ReadString(); // kdf
            var options = new SshReader(reader.ReadString());
            options.ReadString(); // salt
            await Assert.That(options.ReadUInt32()).IsEqualTo(20u);
            using var loaded = await SshPrivateKey.LoadAsync(path, passphrase);
            await Assert.That(loaded.Fingerprint).IsEqualTo(key.Fingerprint);
            await AssertOwnerOnly(path);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public async Task SaveAsync_RejectsBadArguments_AndWritesNothing()
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-keyexport-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_key");
            using var key = Generate(SshKeyType.Ed25519, 0);

            await Assert.That(async () => await key.SaveAsync(path, "p", kdfRounds: 0)).Throws<ArgumentOutOfRangeException>();
            await Assert.That(async () => await key.SaveAsync(path, "p", kdfRounds: (1 << 16) + 1)).Throws<ArgumentOutOfRangeException>();
            await Assert.That(async () => await key.SaveAsync(path, (SshPrivateKeyFormat)99)).Throws<ArgumentOutOfRangeException>();
            await Assert.That(async () => await key.SaveAsync(" ", SshPrivateKeyFormat.Pkcs8)).Throws<ArgumentException>();

            // A format that cannot hold the key fails before any file is made.
            await Assert.That(async () => await key.SaveAsync(path, SshPrivateKeyFormat.Pkcs8, NewPassphrase())).Throws<NotSupportedException>();
            await Assert.That(Directory.GetFiles(directory.FullName)).IsEmpty();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static async Task AssertOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var rules = new FileInfo(path).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
            using var identity = WindowsIdentity.GetCurrent();
            await Assert.That(rules.Count).IsEqualTo(1);
            await Assert.That(rules[0].IdentityReference).IsEqualTo(identity.User!);
        }
        else
        {
            await Assert.That(File.GetUnixFileMode(path)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
