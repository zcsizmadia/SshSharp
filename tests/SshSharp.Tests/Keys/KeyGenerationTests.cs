using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SshSharp.Protocol;
using SshSharp.Tests.Agent;

namespace SshSharp.Tests.Keys;

/// <summary><see cref="SshPrivateKey.Generate"/>, <see cref="SshPrivateKey.ToOpenSshPrivateKey"/> and <see cref="SshPrivateKey.SaveAsync(string, string?, CancellationToken)"/> (#117).</summary>
public class KeyGenerationTests
{
    public static IEnumerable<(SshKeyType Type, string KeyType, int Bits)> Types() =>
    [
        (SshKeyType.Ed25519, "ssh-ed25519", 0),
        (SshKeyType.EcdsaNistp256, "ecdsa-sha2-nistp256", 0),
        (SshKeyType.EcdsaNistp384, "ecdsa-sha2-nistp384", 0),
        (SshKeyType.EcdsaNistp521, "ecdsa-sha2-nistp521", 0),
        (SshKeyType.Rsa, "ssh-rsa", 2048),
    ];

    private static void AssertSigns(SshPrivateKey key)
    {
        var data = RandomNumberGenerator.GetBytes(100);
        var algorithm = key.SignatureAlgorithms[0];
        var signature = key.Sign(algorithm, data);
        if (!global::SshSharp.Keys.VerifyingKey.Parse(key.PublicKey.Span).VerifySignature(algorithm, signature, data))
        {
            throw new InvalidOperationException($"A {key.KeyType} signature did not verify.");
        }
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task AGeneratedKey_RoundTripsThroughTheOpenSshFormat(SshKeyType type, string keyType, int bits)
    {
        using var key = SshPrivateKey.Generate(type, "me@example", bits == 0 ? 3072 : bits);
        await Assert.That(key.KeyType).IsEqualTo(keyType);
        AssertSigns(key);

        using var parsed = SshPrivateKey.Parse(key.ToOpenSshPrivateKey());

        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(parsed.Comment).IsEqualTo("me@example");
        AssertSigns(parsed);
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task AnEncryptedKey_NeedsItsPassphrase(SshKeyType type, string keyType, int bits)
    {
        using var key = SshPrivateKey.Generate(type, rsaBits: bits == 0 ? 3072 : bits);
        var text = key.ToOpenSshPrivateKey("correct horse", kdfRounds: 4);

        using var parsed = SshPrivateKey.Parse(text, "correct horse");
        await Assert.That(parsed.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(parsed.KeyType).IsEqualTo(keyType);
        AssertSigns(parsed);
        await Assert.That(() => SshPrivateKey.Parse(text, "wrong")).Throws<FormatException>();
        await Assert.That(() => SshPrivateKey.Parse(text)).Throws<FormatException>();
    }

    [Test]
    public async Task TheFile_IsLaidOutAsSshKeygenWritesIt()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var text = key.ToOpenSshPrivateKey("pass", kdfRounds: 24);
        var lines = text.Split('\n');

        await Assert.That(lines[0]).IsEqualTo("-----BEGIN OPENSSH PRIVATE KEY-----");
        await Assert.That(lines[^2]).IsEqualTo("-----END OPENSSH PRIVATE KEY-----");
        await Assert.That(lines[^1]).IsEqualTo(string.Empty); // ends with a newline
        await Assert.That(lines[1..^3].All(l => l.Length == 70)).IsTrue();
        await Assert.That(lines[^3].Length).IsBetween(1, 70);

        var data = Convert.FromBase64String(string.Concat(lines[1..^2]));
        var header = ReadHeader(data);
        await Assert.That(header.Magic).IsTrue();
        await Assert.That(header.Cipher).IsEqualTo("aes256-ctr");
        await Assert.That(header.Kdf).IsEqualTo("bcrypt");
        await Assert.That(header.SaltLength).IsEqualTo(16);
        await Assert.That(header.Rounds).IsEqualTo(24u);
        await Assert.That(header.Keys).IsEqualTo(1u);
        await Assert.That(header.PublicKey).IsEquivalentTo(key.PublicKey.ToArray());
        await Assert.That(header.SectionLength % 16).IsEqualTo(0); // padded to the AES block
    }

    private static (bool Magic, string Cipher, string Kdf, int SaltLength, uint Rounds, uint Keys, byte[] PublicKey, int SectionLength) ReadHeader(byte[] data)
    {
        var reader = new SshReader(data.AsSpan(15));
        var cipher = reader.ReadUtf8String();
        var kdf = reader.ReadUtf8String();
        var options = new SshReader(reader.ReadString());
        var saltLength = options.ReadString().Length;
        var rounds = options.ReadUInt32();
        var keys = reader.ReadUInt32();
        var publicKey = reader.ReadString().ToArray();
        return (data.AsSpan(0, 15).SequenceEqual("openssh-key-v1\0"u8), cipher, kdf, saltLength, rounds, keys, publicKey, reader.ReadString().Length);
    }

    [Test]
    public async Task TwoGeneratedKeys_Differ_AndTwoExportsOfOneKeyUseDifferentSalts()
    {
        using var first = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var second = SshPrivateKey.Generate(SshKeyType.Ed25519);

        await Assert.That(first.Fingerprint).IsNotEqualTo(second.Fingerprint);
        await Assert.That(first.ToOpenSshPrivateKey("p", 1)).IsNotEqualTo(first.ToOpenSshPrivateKey("p", 1));
    }

    [Test]
    public async Task ALoadedRsaKey_ExportsTheSameKey()
    {
        // OpenSSH's iqmp is q^-1 mod p; a mix-up with p^-1 mod q would only show when the re-read key signs.
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out _));
        using var again = SshPrivateKey.Parse(key.ToOpenSshPrivateKey());

        await Assert.That(again.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
        AssertSigns(again);
    }

    [Test]
    public async Task AKeyPairedWithACertificate_IsNotExported()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User, ["me"]));
        var certified = key.WithCertificate(certificate);

        await Assert.That(() => certified.ToOpenSshPrivateKey()).Throws<NotSupportedException>();
    }

    [Test]
    public async Task AnAgentKey_IsNotExported()
    {
        await using var agent = new FakeAgent();
        agent.Keys.Add((SshPrivateKey.Generate(SshKeyType.Ed25519), "in the agent"));
        var keys = await new SshAgent(agent.Path).GetKeysAsync();

        await Assert.That(() => keys[0].ToOpenSshPrivateKey()).Throws<NotSupportedException>();
    }

    [Test]
    public async Task InvalidSizesAndRounds_AreRejected()
    {
        await Assert.That(() => SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 1024)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 3071)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => SshPrivateKey.Generate((SshKeyType)99)).Throws<ArgumentOutOfRangeException>();
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await Assert.That(() => key.ToOpenSshPrivateKey("p", 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => key.ToOpenSshPrivateKey("p", (1 << 16) + 1)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task SaveAsync_WritesBothFiles_WithThePrivateOneReadableOnlyByItsOwner()
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-keygen-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_ed25519");
            using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "saved@example");

            await key.SaveAsync(path, "secret");

            using var loaded = await SshPrivateKey.LoadAsync(path, "secret");
            await Assert.That(loaded.Fingerprint).IsEqualTo(key.Fingerprint);
            await Assert.That(await File.ReadAllTextAsync(path + ".pub")).IsEqualTo(key.ToAuthorizedKeysLine() + "\n");

            if (OperatingSystem.IsWindows())
            {
                var rules = new FileInfo(path).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
                using var identity = WindowsIdentity.GetCurrent();
                await Assert.That(rules.Count).IsEqualTo(1);
                await Assert.That(rules[0].IdentityReference).IsEqualTo(identity.User!);
                await Assert.That(rules[0].IsInherited).IsFalse();
            }
            else
            {
                await Assert.That(File.GetUnixFileMode(path)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public async Task SaveAsync_NeverOverwritesAKey()
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-keygen-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_ed25519");
            await File.WriteAllTextAsync(path + ".pub", "existing");
            using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);

            await Assert.That(async () => await key.SaveAsync(path)).Throws<IOException>();
            await Assert.That(File.Exists(path)).IsFalse();
            await Assert.That(await File.ReadAllTextAsync(path + ".pub")).IsEqualTo("existing");

            File.Delete(path + ".pub");
            await File.WriteAllTextAsync(path, "existing");
            await Assert.That(async () => await key.SaveAsync(path)).Throws<IOException>();
            await Assert.That(await File.ReadAllTextAsync(path)).IsEqualTo("existing");
            await Assert.That(File.Exists(path + ".pub")).IsFalse();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task SshKeygen_ReadsTheFiles(SshKeyType type, string keyType, int bits)
    {
        var sshKeygen = FindSshKeygen();
        if (sshKeygen is null)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        var directory = Directory.CreateTempSubdirectory("sshsharp-keygen-");
        try
        {
            var path = Path.Combine(directory.FullName, "id_key");
            using var key = SshPrivateKey.Generate(type, "interop@example", bits == 0 ? 3072 : bits);
            await key.SaveAsync(path, "interop passphrase");

            // -y prints the public key derived from the private key file, after decrypting it.
            var start = new ProcessStartInfo(sshKeygen) { RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { "-y", "-P", "interop passphrase", "-f", path })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)!;
            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            await Assert.That(process.ExitCode).IsEqualTo(0).Because(error);
            var fields = output.Trim().Split(' ');
            await Assert.That(fields[0]).IsEqualTo(keyType);
            await Assert.That(Convert.FromBase64String(fields[1])).IsEquivalentTo(key.PublicKey.ToArray());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
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
