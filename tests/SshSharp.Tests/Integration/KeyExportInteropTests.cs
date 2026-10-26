using System.Diagnostics;
using System.Security.Cryptography;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Exported keys (<see cref="SshPrivateKey.ToPkcs8PrivateKey"/>, <see cref="SshPrivateKey.ToPuttyPrivateKey"/>) as the real tools read
/// them: OpenSSL and <c>ssh-keygen</c> read PKCS#8, PuTTY's <c>puttygen</c> reads <c>.ppk</c>; and keys those tools made export to the
/// same bytes. Each test is skipped when its tool is not on the PATH (CI's interop job installs all three).
/// </summary>
[Category("LocalTools")] // ssh-keygen, openssl and puttygen only, no server: it runs with the unit tests
public class KeyExportInteropTests
{
    public static IEnumerable<(SshKeyType Type, string KeyType)> Types() =>
    [
        (SshKeyType.Ed25519, "ssh-ed25519"),
        (SshKeyType.EcdsaNistp256, "ecdsa-sha2-nistp256"),
        (SshKeyType.EcdsaNistp384, "ecdsa-sha2-nistp384"),
        (SshKeyType.EcdsaNistp521, "ecdsa-sha2-nistp521"),
        (SshKeyType.Rsa, "ssh-rsa"),
    ];

    // RFC 8410 section 10.3: an Ed25519 private key in PKCS#8.
    private const string Rfc8410Example = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";

    // Generated per run, never written down; tools read it from a file or an argument.
    private static SshPrivateKey Generate(SshKeyType type) => SshPrivateKey.Generate(type, "export@example", type == SshKeyType.Rsa ? 2048 : 3072);

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task SshKeygen_ReadsPkcs8(SshKeyType type, string keyType)
    {
        if (Tool("ssh-keygen") is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        if (type == SshKeyType.Ed25519)
        {
            // ssh-keygen reads Ed25519 PKCS#8 from OpenSSH 9.8p1 on, built with an OpenSSL that has Ed25519: 9.6p1 added the code, but
            // its configure check never enabled it until 9.8p1 fixed the check. So Ubuntu 24.04's 9.6p1, OpenSSH for Windows 9.5 and
            // macOS's own (LibreSSL) do not, and CI runs this on macOS with Homebrew's OpenSSH. RFC 8410's own example key, which the
            // unit tests show is what SshSharp writes, tells whether this one does.
            var probe = directory.NewPath("rfc8410");
            using var example = SshPrivateKey.Parse(Rfc8410Example);
            await example.SaveAsync(probe, SshPrivateKeyFormat.Pkcs8);
            if ((await RunAsync(sshKeygen, "-y", "-P", string.Empty, "-f", probe)).Exit != 0)
            {
                Skip.Test("This ssh-keygen does not read Ed25519 PKCS#8 keys, not even RFC 8410's example.");
                return;
            }
        }

        using var key = Generate(type);
        var passphrases = type == SshKeyType.Ed25519 ? [string.Empty] : new[] { string.Empty, TestSecrets.New() };
        foreach (var passphrase in passphrases)
        {
            var path = directory.NewPath("pkcs8");
            await key.SaveAsync(path, SshPrivateKeyFormat.Pkcs8, passphrase);

            // -y decrypts the private key and prints the public key it derives.
            var (exit, output, error) = await RunAsync(sshKeygen, "-y", "-P", passphrase, "-f", path);
            await Assert.That(exit).IsEqualTo(0).Because(error);
            var fields = output.Trim().Split(' ');
            await Assert.That(fields[0]).IsEqualTo(keyType);
            await Assert.That(Convert.FromBase64String(fields[1])).IsEquivalentTo(key.PublicKey.ToArray());
        }
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task OpenSsl_ReadsPkcs8(SshKeyType type, string keyType)
    {
        if (Tool("openssl") is not { } openssl)
        {
            Skip.Test("openssl is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        if (type == SshKeyType.Ed25519 && !await ReadsEd25519Async(openssl, directory))
        {
            Skip.Test("This openssl has no Ed25519.");
            return;
        }

        using var key = Generate(type);
        var passphrase = TestSecrets.New();
        var passphraseFile = directory.NewPath("phrase");
        await File.WriteAllTextAsync(passphraseFile, passphrase);
        var encrypted = type != SshKeyType.Ed25519;
        var path = directory.NewPath("pkcs8");
        await File.WriteAllTextAsync(path, encrypted ? key.ToPkcs8PrivateKey(passphrase) : key.ToPkcs8PrivateKey());

        // OpenSSL decrypts the file and writes the key unencrypted, which must be this key.
        var (exit, output, error) = await RunAsync(openssl, "pkey", "-in", path, "-passin", "file:" + passphraseFile);
        await Assert.That(exit).IsEqualTo(0).Because(error);
        using var decrypted = SshPrivateKey.Parse(output);
        await Assert.That(decrypted.KeyType).IsEqualTo(keyType);
        await Assert.That(decrypted.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());

        if (encrypted)
        {
            await File.WriteAllTextAsync(passphraseFile, TestSecrets.New());
            var (wrongExit, _, _) = await RunAsync(openssl, "pkey", "-in", path, "-passin", "file:" + passphraseFile);
            await Assert.That(wrongExit).IsNotEqualTo(0);
        }
    }

    [Test]
    [Arguments("RSA", "rsa_keygen_bits:2048")]
    [Arguments("EC", "ec_paramgen_curve:P-256")]
    [Arguments("ED25519", null)]
    public async Task KeysFromOpenSsl_ExportToTheSamePkcs8(string algorithm, string? option)
    {
        if (Tool("openssl") is not { } openssl)
        {
            Skip.Test("openssl is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        if (algorithm == "ED25519" && !await ReadsEd25519Async(openssl, directory))
        {
            Skip.Test("This openssl has no Ed25519.");
            return;
        }

        string[] arguments = option is null ? ["genpkey", "-algorithm", algorithm] : ["genpkey", "-algorithm", algorithm, "-pkeyopt", option];
        var (exit, output, error) = await RunAsync(openssl, arguments);
        await Assert.That(exit).IsEqualTo(0).Because(error);
        var pem = output.Replace("\r\n", "\n", StringComparison.Ordinal);

        using var key = SshPrivateKey.Parse(pem);
        var exported = key.ToPkcs8PrivateKey();
        if (algorithm != "RSA")
        {
            await Assert.That(exported).IsEqualTo(pem);
            return;
        }

        // RSA's private exponent has two valid values: OpenSSL writes e^-1 mod lcm(p-1, q-1), and some platforms (Windows CNG) keep
        // only the primes and export e^-1 mod (p-1)(q-1). Every other field, and the DER around them, must match.
        var expected = RsaFields(pem);
        var actual = RsaFields(exported);
        await Assert.That(actual.Length).IsEqualTo(9);
        foreach (var i in new[] { 0, 1, 2, 4, 5, 6, 7, 8 })
        {
            await Assert.That(actual[i]).IsEqualTo(expected[i]);
        }
    }

    /// <summary>The nine INTEGERs of the RSAPrivateKey (RFC 8017) in a PKCS#8 PEM, as hex: version, n, e, d, p, q, dP, dQ, qInv.</summary>
    private static string[] RsaFields(string pem)
    {
        var der = Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal))));
        var info = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        info.ReadInteger();
        info.ReadSequence();
        var rsa = new System.Formats.Asn1.AsnReader(info.ReadOctetString(), System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        var fields = new List<string>();
        while (rsa.HasData)
        {
            fields.Add(Convert.ToHexString(rsa.ReadIntegerBytes().Span));
        }

        return [.. fields];
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task Puttygen_ReadsPpk(SshKeyType type, string keyType)
    {
        if (Tool("puttygen") is not { } puttygen)
        {
            Skip.Test("puttygen is not installed.");
            return;
        }

        using var directory = new TempDirectory();
        using var key = Generate(type);
        var passphrase = TestSecrets.New();
        var passphraseFile = directory.NewPath("phrase");
        await File.WriteAllTextAsync(passphraseFile, passphrase);
        var emptyFile = directory.NewPath("empty");
        await File.WriteAllTextAsync(emptyFile, string.Empty);

        foreach (var encrypted in new[] { false, true })
        {
            var path = directory.NewPath("key.ppk");
            await key.SaveAsync(path, SshPrivateKeyFormat.Putty, encrypted ? passphrase : null);

            // Converting to an unencrypted OpenSSH key makes puttygen decrypt the file and check its MAC.
            var converted = directory.NewPath("converted");
            var (exit, _, error) = await RunAsync(puttygen, path, "--old-passphrase", encrypted ? passphraseFile : emptyFile,
                "--new-passphrase", emptyFile, "-O", "private-openssh-new", "-o", converted);
            await Assert.That(exit).IsEqualTo(0).Because(error);
            using var read = await SshPrivateKey.LoadAsync(converted);
            await Assert.That(read.KeyType).IsEqualTo(keyType);
            await Assert.That(read.PublicKey.ToArray()).IsEquivalentTo(key.PublicKey.ToArray());
            await Assert.That(read.Comment).IsEqualTo("export@example");
        }
    }

    [Test]
    [Arguments("ed25519", 0)]
    [Arguments("ecdsa", 256)]
    [Arguments("rsa", 2048)]
    public async Task KeysFromPuttygen_ExportToTheSamePpk(string type, int bits)
    {
        if (Tool("puttygen") is not { } puttygen)
        {
            Skip.Test("puttygen is not installed.");
            return;
        }

        // An unencrypted file has nothing random in it, so the export must match puttygen's byte for byte.
        using var directory = new TempDirectory();
        var emptyFile = directory.NewPath("empty");
        await File.WriteAllTextAsync(emptyFile, string.Empty);
        var path = directory.NewPath("key.ppk");
        string[] arguments = bits == 0
            ? ["-t", type, "--new-passphrase", emptyFile, "-o", path]
            : ["-t", type, "-b", bits.ToString(System.Globalization.CultureInfo.InvariantCulture), "--new-passphrase", emptyFile, "-o", path];
        var (exit, _, error) = await RunAsync(puttygen, arguments);
        await Assert.That(exit).IsEqualTo(0).Because(error);
        var ppk = (await File.ReadAllTextAsync(path)).Replace("\r\n", "\n", StringComparison.Ordinal);

        using var key = SshPrivateKey.Parse(ppk);
        await Assert.That(key.ToPuttyPrivateKey()).IsEqualTo(ppk);
    }

    /// <summary>Whether <paramref name="openssl"/> reads RFC 8410's example key (LibreSSL before 3.7 has no Ed25519).</summary>
    private static async Task<bool> ReadsEd25519Async(string openssl, TempDirectory directory)
    {
        var path = directory.NewPath("rfc8410");
        await File.WriteAllTextAsync(path, Rfc8410Example);
        return (await RunAsync(openssl, "pkey", "-in", path, "-noout")).Exit == 0;
    }

    internal static string? Tool(string name)
    {
        var file = OperatingSystem.IsWindows() ? name + ".exe" : name;
        return (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, file))
            .FirstOrDefault(File.Exists);
    }

    internal static async Task<(int Exit, string Output, string Error)> RunAsync(string tool, params string[] arguments)
    {
        var start = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        process.StandardInput.Close(); // never wait for a passphrase typed in
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await output, await error);
    }

    internal sealed class TempDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("sshsharp-keyexport-");
        private int _count;

        public string NewPath(string name) => Path.Combine(_directory.FullName, $"{Interlocked.Increment(ref _count)}-{name}");

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
