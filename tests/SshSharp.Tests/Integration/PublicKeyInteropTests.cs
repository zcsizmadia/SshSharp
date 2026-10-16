namespace SshSharp.Tests.Integration;

/// <summary>
/// Keys made by the real <c>ssh-keygen</c>. SSHSHARP_TEST_KEYDIR names a directory of private key files, each with its <c>.pub</c>
/// next to it (CI generates Ed25519, ECDSA and RSA keys in OpenSSH, PEM and PKCS#8 formats). With SSHSHARP_TEST_SSHD and
/// SSHSHARP_TEST_USER too, and the keys in that user's authorized_keys, each key is also used to log in. Skipped when not set.
/// </summary>
public class PublicKeyInteropTests
{
    private static string? KeyDirectory => Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? dir : null;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    /// <summary>Files with "encrypted" in their name are protected with SSHSHARP_TEST_KEY_PASSPHRASE.</summary>
    private static Task<SshPrivateKey> LoadAsync(string file) =>
        SshPrivateKey.LoadFileAsync(file, Path.GetFileName(file).Contains("encrypted", StringComparison.Ordinal)
            ? Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEY_PASSPHRASE")
            : null);

    private static IEnumerable<string> PrivateKeyFiles(string directory) =>
        Directory.EnumerateFiles(directory).Where(f => !f.EndsWith(".pub", StringComparison.Ordinal) && File.Exists(f + ".pub")).Order(StringComparer.Ordinal);

    [Test]
    public async Task KeysFromSshKeygen_ParseAndMatchTheirPublicKeys()
    {
        if (KeyDirectory is not { } directory)
        {
            Skip.Test("SSHSHARP_TEST_KEYDIR is not set.");
            return;
        }

        var files = PrivateKeyFiles(directory).ToList();
        await Assert.That(files).IsNotEmpty();
        foreach (var file in files)
        {
            using var key = await LoadAsync(file);
            var expected = (await File.ReadAllTextAsync(file + ".pub")).Split(' ');
            await Assert.That(key.KeyType).IsEqualTo(expected[0]);
            await Assert.That(Convert.ToBase64String(key.PublicKey.Span)).IsEqualTo(expected[1]);
        }
    }

    [Test]
    public async Task EachKeyLogsInToTheRealServer_WithoutAPassword()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (KeyDirectory is not { } directory || !RealServer.IsAvailable || string.IsNullOrEmpty(user))
        {
            Skip.Test("SSHSHARP_TEST_KEYDIR, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return;
        }

        var (host, port) = RealServer.Endpoint!.Value;
        foreach (var file in PrivateKeyFiles(directory))
        {
            using var key = await LoadAsync(file);
            var options = new SshClientOptions
            {
                UserName = user,
                PrivateKeys = [key],
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            };
            await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
            var result = await client.RunCommandAsync("echo key-ok", Timeout());
            await Assert.That(result.StandardOutputText).IsEqualTo("key-ok\n");
        }
    }

    [Test]
    public async Task EachKeyLogsIn_ThroughAnExternalSigner_WithItsSignaturesInBothEcdsaFormats()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (KeyDirectory is not { } directory || !RealServer.IsAvailable || string.IsNullOrEmpty(user))
        {
            Skip.Test("SSHSHARP_TEST_KEYDIR, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return;
        }

        // The key as a key vault would hold it: SshSharp sees only the public key and the signer's raw signatures (ECDSA as r || s and
        // as DER), and builds the SSH encoding the real server checks.
        var (host, port) = RealServer.Endpoint!.Value;
        foreach (var file in PrivateKeyFiles(directory))
        {
            using var key = await LoadAsync(file);
            foreach (var format in new[] { System.Security.Cryptography.DSASignatureFormat.IeeeP1363FixedFieldConcatenation, System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence })
            {
                if (format == System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence && !key.KeyType.StartsWith("ecdsa-", StringComparison.Ordinal))
                {
                    continue;
                }

                using var external = SshPrivateKey.FromSigner(new Keys.ExternalKeyTests.TestSigner(key) { Format = format });
                var options = new SshClientOptions
                {
                    UserName = user,
                    PrivateKeys = [external],
                    HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
                };
                await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
                await Assert.That((await client.RunCommandAsync("echo signer-ok", Timeout())).StandardOutputText).IsEqualTo("signer-ok\n");
            }
        }
    }
}
