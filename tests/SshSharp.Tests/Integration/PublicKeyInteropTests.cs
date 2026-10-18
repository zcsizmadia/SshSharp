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
        SshPrivateKey.LoadAsync(file, Path.GetFileName(file).Contains("encrypted", StringComparison.Ordinal)
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

    /// <summary>
    /// A key held in the process signs its first request, with no query before it (RFC 4252 section 7 allows both). Runs wherever the
    /// account has a password and a shell: the key goes into the account's authorized_keys for the test, so it also covers the servers of
    /// the interop matrix that read authorized_keys (Dropbear, OpenSSH of several eras, OpenSSH for Windows).
    /// </summary>
    [Test]
    [NotInParallel("authorized_keys")] // two tests editing the file at once could each drop the other's line
    public async Task ALocalKey_SignsStraightAway_AfterARefusedOne()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var trustAll = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true));
        using var refused = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);

        // A refused signed request is an ordinary failure, with the methods the server still accepts.
        var failed = await Assert.ThrowsAsync<SshAuthenticationException>(async () =>
            await SshClient.ConnectAsync(host, port, new SshClientOptions { UserName = user, PrivateKeys = [refused], HostKeyVerifier = trustAll }, Timeout()));
        if (!failed!.AllowedMethods.Contains("publickey"))
        {
            Skip.Test("The server does not offer publickey authentication.");
            return;
        }

        var marker = "sshsharp-direct-" + Guid.NewGuid().ToString("N");
        var line = $"{key.KeyType} {Convert.ToBase64String(key.PublicKey.Span)} {marker}";
        await using var admin = await SshClient.ConnectAsync(host, port, new SshClientOptions { UserName = user, Password = password, HostKeyVerifier = trustAll }, Timeout());
        var install = $"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{line}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys";
        await Assert.That((await admin.RunCommandAsync(install, Timeout())).ExitStatus).IsEqualTo(0);
        try
        {
            await using var client = await SshClient.ConnectAsync(host, port,
                new SshClientOptions { UserName = user, PrivateKeys = [refused, key], HostKeyVerifier = trustAll }, Timeout());
            await Assert.That((await client.RunCommandAsync("echo direct-ok", Timeout())).StandardOutputText.Trim()).IsEqualTo("direct-ok");
        }
        finally
        {
            await admin.RunCommandAsync($"sed -i '/{marker}/d' ~/.ssh/authorized_keys", Timeout());
        }
    }
}
