using System.Diagnostics;
using System.Text;

namespace SshSharp.Tests.Keys;

/// <summary>SSHSIG signatures (<c>ssh-keygen -Y sign/verify</c>) and allowed-signers files.</summary>
public class SshSignatureTests
{
    private static readonly byte[] Message = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A U Thor\n\nsigned commit\n"u8.ToArray();

    public static IEnumerable<Func<(SshKeyType Type, int Bits)>> Types()
    {
        yield return () => (SshKeyType.Ed25519, 0);
        yield return () => (SshKeyType.EcdsaNistp256, 0);
        yield return () => (SshKeyType.EcdsaNistp384, 0);
        yield return () => (SshKeyType.EcdsaNistp521, 0);
        yield return () => (SshKeyType.Rsa, 2048);
    }

    private static SshPrivateKey Generate(SshKeyType type, int bits) => SshPrivateKey.Generate(type, "signer@example", bits == 0 ? 3072 : bits);

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task ASignature_RoundTripsThroughItsText_AndVerifies(SshKeyType type, int bits)
    {
        using var key = Generate(type, bits);
        var signature = await SshSignature.SignAsync(key, Message, "git");

        var parsed = SshSignature.Parse(signature.ToString());
        await Assert.That(parsed.Namespace).IsEqualTo("git");
        await Assert.That(parsed.HashAlgorithm).IsEqualTo("sha512");
        await Assert.That(parsed.KeyType).IsEqualTo(key.KeyType);
        await Assert.That(parsed.Fingerprint).IsEqualTo(key.Fingerprint);
        await Assert.That(parsed.PublicKey.ToArray().SequenceEqual(key.PublicKey.ToArray())).IsTrue();
        await Assert.That(parsed.Certificate).IsNull();
        await Assert.That(parsed.Verify(Message, "git")).IsTrue();
        await Assert.That(await parsed.VerifyAsync(new MemoryStream(Message), "git")).IsTrue();

        // Another namespace, or one changed byte, and it no longer verifies.
        await Assert.That(parsed.Verify(Message, "file")).IsFalse();
        var tampered = (byte[])Message.Clone();
        tampered[^2] ^= 1;
        await Assert.That(parsed.Verify(tampered, "git")).IsFalse();
    }

    [Test]
    public async Task Sha256_AndStreams_AreSupported()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var signature = await SshSignature.SignAsync(key, new MemoryStream(Message), "file", "sha256");

        await Assert.That(signature.HashAlgorithm).IsEqualTo("sha256");
        await Assert.That(SshSignature.Parse(signature.ToString()).Verify(Message, "file")).IsTrue();
        await Assert.That(async () => await SshSignature.SignAsync(key, Message, "file", "sha1")).Throws<ArgumentException>();
        await Assert.That(async () => await SshSignature.SignAsync(key, Message, "")).Throws<ArgumentException>();
    }

    [Test]
    public async Task TheText_IsArmoredAsSshKeygenWritesIt()
    {
        using var key = Generate(SshKeyType.Rsa, 2048);
        var text = (await SshSignature.SignAsync(key, Message, "git")).ToString();
        var lines = text.Split('\n');

        await Assert.That(lines[0]).IsEqualTo("-----BEGIN SSH SIGNATURE-----");
        await Assert.That(lines[^2]).IsEqualTo("-----END SSH SIGNATURE-----");
        await Assert.That(lines[^1]).IsEmpty();
        await Assert.That(lines[1..^2].All(l => l.Length is > 0 and <= 70)).IsTrue();
        await Assert.That(lines[1..^3].All(l => l.Length == 70)).IsTrue();
        await Assert.That(Convert.FromBase64String(string.Concat(lines[1..^2])).AsSpan(0, 6).SequenceEqual("SSHSIG"u8)).IsTrue();

        // Parse tolerates CRLF line ends and surrounding text.
        await Assert.That(SshSignature.Parse("junk\r\n" + text.Replace("\n", "\r\n", StringComparison.Ordinal)).Verify(Message, "git")).IsTrue();
    }

    [Test]
    public async Task MalformedSignatures_AreRejected()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var good = (await SshSignature.SignAsync(key, Message, "git")).ToString();
        var blob = Convert.FromBase64String(string.Concat(good.Split('\n')[1..^2]));

        static string Armor(byte[] bytes) => $"-----BEGIN SSH SIGNATURE-----\n{Convert.ToBase64String(bytes)}\n-----END SSH SIGNATURE-----\n";

        await Assert.That(() => SshSignature.Parse("not a signature")).Throws<FormatException>();
        await Assert.That(() => SshSignature.Parse("-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----")).Throws<FormatException>();
        var badMagic = (byte[])blob.Clone();
        badMagic[0] = (byte)'X';
        await Assert.That(() => SshSignature.Parse(Armor(badMagic))).Throws<FormatException>();
        var badVersion = (byte[])blob.Clone();
        badVersion[9] = 2;
        await Assert.That(() => SshSignature.Parse(Armor(badVersion))).Throws<FormatException>().WithMessageContaining("version 2");
        await Assert.That(() => SshSignature.Parse(Armor([.. blob, 0]))).Throws<FormatException>();
        await Assert.That(() => SshSignature.Parse(Armor(blob[..^3]))).Throws<FormatException>();
    }

    [Test]
    public async Task ASignatureByAnotherKey_DoesNotVerifyAsThisKey()
    {
        using var signer = Generate(SshKeyType.Ed25519, 0);
        using var other = Generate(SshKeyType.Ed25519, 0);
        var signature = await SshSignature.SignAsync(signer, Message, "git");

        // Swap the claimed public key for another one: the signature no longer matches it.
        var blob = Convert.FromBase64String(string.Concat(signature.ToString().Split('\n')[1..^2]));
        var swapped = blob.AsSpan().ToArray();
        var publicKey = signer.PublicKey.ToArray();
        var at = swapped.AsSpan().IndexOf(publicKey);
        other.PublicKey.Span.CopyTo(swapped.AsSpan(at));
        var forged = SshSignature.Parse($"-----BEGIN SSH SIGNATURE-----\n{Convert.ToBase64String(swapped)}\n-----END SSH SIGNATURE-----\n");

        await Assert.That(forged.Fingerprint).IsEqualTo(other.Fingerprint);
        await Assert.That(forged.Verify(Message, "git")).IsFalse();
    }

    [Test]
    public async Task AllowedSigners_MatchPrincipalsAndNamespaces()
    {
        using var alice = Generate(SshKeyType.Ed25519, 0);
        using var bob = Generate(SshKeyType.EcdsaNistp256, 0);
        var signers = SshAllowedSigners.Parse($"""
            # team signing keys
            alice@example.com,*@admins.example.com {KeyText(alice)}

            "bob@example.com" namespaces="git,backup-*" {KeyText(bob)} bob's laptop
            """);
        var byAlice = await SshSignature.SignAsync(alice, Message, "git");
        var byBob = await SshSignature.SignAsync(bob, Message, "backup-nightly");

        await Assert.That(signers.Count).IsEqualTo(2);
        await Assert.That(signers.Verify(byAlice, "alice@example.com", Message, "git")).IsTrue();
        await Assert.That(signers.Verify(byAlice, "root@admins.example.com", Message, "git")).IsTrue();
        await Assert.That(await signers.VerifyAsync(byAlice, "alice@example.com", new MemoryStream(Message), "git")).IsTrue();

        // Principals are case-sensitive, and a key signs only as its own principals.
        await Assert.That(signers.Verify(byAlice, "Alice@example.com", Message, "git")).IsFalse();
        await Assert.That(signers.Verify(byAlice, "bob@example.com", Message, "git")).IsFalse();

        // namespaces= limits what bob's key may sign; the signature's own namespace must match too.
        await Assert.That(signers.Verify(byBob, "bob@example.com", Message, "backup-nightly")).IsTrue();
        await Assert.That(signers.Verify(byBob, "bob@example.com", Message, "git")).IsFalse();
        var bobFile = await SshSignature.SignAsync(bob, Message, "file");
        await Assert.That(bobFile.Verify(Message, "file")).IsTrue();
        await Assert.That(signers.Verify(bobFile, "bob@example.com", Message, "file")).IsFalse();

        await Assert.That(signers.FindPrincipals(byAlice)).IsEquivalentTo(["alice@example.com", "*@admins.example.com"]);
        await Assert.That(signers.FindPrincipals(byBob)).IsEquivalentTo(["bob@example.com"]);
    }

    [Test]
    public async Task AllowedSigners_NegatedPrincipals_AndTimes()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var signers = SshAllowedSigners.Parse(
            $"*@example.com,!intern@example.com valid-after=\"20260101\",valid-before=\"20261231235959Z\" {KeyText(key)}");
        var signature = await SshSignature.SignAsync(key, Message, "git");
        var inside = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

        await Assert.That(signers.Verify(signature, "dev@example.com", Message, "git", inside)).IsTrue();
        await Assert.That(signers.Verify(signature, "intern@example.com", Message, "git", inside)).IsFalse();
        await Assert.That(signers.Verify(signature, "dev@example.com", Message, "git", new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero))).IsFalse();
        await Assert.That(signers.Verify(signature, "dev@example.com", Message, "git", new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero))).IsFalse();
        await Assert.That(signers.FindPrincipals(signature, new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero))).IsEmpty();
    }

    [Test]
    public async Task AllowedSigners_CertificateAuthorities()
    {
        using var authority = Generate(SshKeyType.Ed25519, 0);
        using var otherAuthority = Generate(SshKeyType.Ed25519, 0);
        using var key = Generate(SshKeyType.EcdsaNistp256, 0);
        var signers = SshAllowedSigners.Parse($"*@example.com cert-authority {KeyText(authority)}\n");

        async Task<SshSignature> SignWith(SshPrivateKey ca, SshCertificateType type, DateTimeOffset? validBefore = null)
        {
            var blob = TestKeys.Certificate(ca, key.PublicKey.ToArray(), type, ["dev@example.com", "ops@other.org"], validBefore: validBefore);
            using var certified = type == SshCertificateType.User
                ? key.WithCertificate(SshCertificate.Parse(TestKeys.CertificateLine(blob)))
                : null;
            if (certified is not null)
            {
                return await SshSignature.SignAsync(certified, Message, "git");
            }

            // A host certificate cannot be paired with a key for signing; build the signature by swapping in its blob.
            var plain = (await SshSignature.SignAsync(key, Message, "git")).ToString();
            var raw = Convert.FromBase64String(string.Concat(plain.Split('\n')[1..^2]));
            var publicKey = key.PublicKey.ToArray();
            var at = raw.AsSpan().IndexOf(publicKey);
            byte[] swapped = [.. raw[..(at - 4)], .. Length(blob.Length), .. blob, .. raw[(at + publicKey.Length)..]];
            return SshSignature.Parse($"-----BEGIN SSH SIGNATURE-----\n{Convert.ToBase64String(swapped)}\n-----END SSH SIGNATURE-----\n");
        }

        var signature = await SignWith(authority, SshCertificateType.User);
        await Assert.That(signature.Certificate).IsNotNull();
        await Assert.That(signature.Fingerprint).IsEqualTo(key.Fingerprint);
        await Assert.That(signature.Verify(Message, "git")).IsTrue();
        await Assert.That(signers.Verify(signature, "dev@example.com", Message, "git")).IsTrue();

        // The principal must be in the certificate and allowed by the line.
        await Assert.That(signers.Verify(signature, "qa@example.com", Message, "git")).IsFalse();
        await Assert.That(signers.Verify(signature, "ops@other.org", Message, "git")).IsFalse();
        await Assert.That(signers.FindPrincipals(signature)).IsEquivalentTo(["dev@example.com"]);

        // Another authority, an expired certificate, or a host certificate is not accepted.
        await Assert.That(signers.Verify(await SignWith(otherAuthority, SshCertificateType.User), "dev@example.com", Message, "git")).IsFalse();
        var expired = await SignWith(authority, SshCertificateType.User, DateTimeOffset.UtcNow.AddDays(-1));
        await Assert.That(signers.Verify(expired, "dev@example.com", Message, "git")).IsFalse();
        await Assert.That(signers.Verify(await SignWith(authority, SshCertificateType.Host), "dev@example.com", Message, "git")).IsFalse();

        // Without cert-authority, the CA's key on the line does not vouch for its certificates.
        var plainLine = SshAllowedSigners.Parse($"*@example.com {KeyText(authority)}");
        await Assert.That(plainLine.Verify(signature, "dev@example.com", Message, "git")).IsFalse();
    }

    [Test]
    [Arguments("namespaces=\"git\",namespaces=\"file\"")]
    [Arguments("valid-after=\"20260101\",valid-after=\"20270101\"")]
    [Arguments("valid-before=\"20260101\",VALID-BEFORE=\"20270101\"")]
    [Arguments("cert-authority,cert-authority")]
    public async Task ARepeatedOption_RejectsTheFile_AsSshKeygenDoes(string options)
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        await Assert.That(() => SshAllowedSigners.Parse($"# first\nalice@example.com {options} {KeyText(key)}"))
            .Throws<FormatException>().WithMessageContaining("line 2");
    }

    [Test]
    public async Task FindPrincipals_AnswersFromTheFirstMatchingLine_AsSshKeygenDoes()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        using var other = Generate(SshKeyType.Ed25519, 0);
        var signers = SshAllowedSigners.Parse($"""
            nobody@example.com {KeyText(other)}
            old@example.com valid-before="20200101Z" {KeyText(key)}
            first@example.com,first-alias@example.com {KeyText(key)}
            second@example.com {KeyText(key)}
            """);
        var signature = await SshSignature.SignAsync(key, Message, "git");

        // The expired line is skipped; the first line that matches answers, the later one is not merged in.
        await Assert.That(signers.FindPrincipals(signature)).IsEquivalentTo(["first@example.com", "first-alias@example.com"]);
        await Assert.That(signers.FindPrincipals(signature, new DateTimeOffset(2019, 6, 1, 0, 0, 0, TimeSpan.Zero))).IsEquivalentTo(["old@example.com"]);

        // Verification still accepts every line's principals.
        await Assert.That(signers.Verify(signature, "second@example.com", Message, "git")).IsTrue();
    }

    [Test]
    public async Task MalformedAllowedSigners_AreRejected_WithTheLineNumber()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var line = KeyText(key);

        await Assert.That(() => SshAllowedSigners.Parse($"# ok\na@b {line}\nc@d bogus-option {line}")).Throws<FormatException>().WithMessageContaining("line 3");
        await Assert.That(() => SshAllowedSigners.Parse($"a@b valid-after=\"2026\" {line}")).Throws<FormatException>();
        await Assert.That(() => SshAllowedSigners.Parse($"a@b namespaces=\"git {line}")).Throws<FormatException>();
        await Assert.That(() => SshAllowedSigners.Parse("a@b ssh-ed25519 !!!")).Throws<FormatException>();
        await Assert.That(() => SshAllowedSigners.Parse($"a@b ssh-rsa {line.Split(' ')[1]}")).Throws<FormatException>();
        await Assert.That(() => SshAllowedSigners.Parse(line)).Throws<FormatException>();
        await Assert.That(SshAllowedSigners.Parse("\n# nothing\n\n").Count).IsEqualTo(0);
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task SshKeygen_VerifiesOurSignatures_AndWeVerifyItsSignatures(SshKeyType type, int bits)
    {
        var sshKeygen = FindSshKeygen();
        if (sshKeygen is null)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        var directory = Directory.CreateTempSubdirectory("sshsharp-sshsig-");
        try
        {
            using var key = Generate(type, bits);
            var keyPath = Path.Combine(directory.FullName, "id_key");
            await key.SaveAsync(keyPath);
            var allowed = Path.Combine(directory.FullName, "allowed_signers");
            await File.WriteAllTextAsync(allowed, $"signer@example.com namespaces=\"git\" {KeyText(key)}\n");
            var messagePath = Path.Combine(directory.FullName, "message");
            await File.WriteAllBytesAsync(messagePath, Message);

            // Ours, checked by ssh-keygen -Y verify (the message on standard input, as git passes it).
            var ours = Path.Combine(directory.FullName, "ours.sig");
            await File.WriteAllTextAsync(ours, (await SshSignature.SignAsync(key, Message, "git")).ToString());
            var (verified, output) = await RunAsync(sshKeygen, Message, "-Y", "verify", "-f", allowed, "-I", "signer@example.com", "-n", "git", "-s", ours);
            await Assert.That(verified).IsEqualTo(0).Because(output);
            await Assert.That(output).Contains("Good \"git\" signature for signer@example.com");

            var (found, principals) = await RunAsync(sshKeygen, null, "-Y", "find-principals", "-f", allowed, "-s", ours);
            await Assert.That(found).IsEqualTo(0).Because(principals);
            await Assert.That(principals.Trim()).IsEqualTo("signer@example.com");

            // Theirs (ssh-keygen -Y sign writes message.sig), checked here.
            var (signed, signOutput) = await RunAsync(sshKeygen, null, "-Y", "sign", "-f", keyPath, "-n", "git", messagePath);
            await Assert.That(signed).IsEqualTo(0).Because(signOutput);
            var theirs = SshSignature.Parse(await File.ReadAllTextAsync(messagePath + ".sig"));
            var signers = await SshAllowedSigners.LoadAsync(allowed);
            await Assert.That(signers.Verify(theirs, "signer@example.com", Message, "git")).IsTrue();
            await Assert.That(signers.Verify(theirs, "signer@example.com", Message.AsSpan(1), "git")).IsFalse();
            await Assert.That(theirs.ToString()).IsEqualTo(await File.ReadAllTextAsync(messagePath + ".sig"));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static string KeyText(SshPrivateKey key) => $"{key.KeyType} {Convert.ToBase64String(key.PublicKey.Span)}";

    private static byte[] Length(int length) => [(byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length];

    private static async Task<(int ExitCode, string Output)> RunAsync(string program, byte[]? input, params string[] arguments)
    {
        var start = new ProcessStartInfo(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        if (input is not null)
        {
            await process.StandardInput.BaseStream.WriteAsync(input);
        }

        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await output + await error);
    }

    private static string? FindSshKeygen()
    {
        var name = OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen";
        return (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, name))
            .FirstOrDefault(File.Exists);
    }
}
