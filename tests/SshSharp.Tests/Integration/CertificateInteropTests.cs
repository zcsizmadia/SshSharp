namespace SshSharp.Tests.Integration;

/// <summary>
/// Certificates made by the real <c>ssh-keygen -s</c>. SSHSHARP_TEST_CERTDIR holds <c>ca.pub</c> (the authority sshd trusts for users,
/// and that signed sshd's HostCertificate), <c>user</c> (a key that is NOT in authorized_keys) and <c>user-cert.pub</c> (its user
/// certificate for SSHSHARP_TEST_USER). With SSHSHARP_TEST_SSHD too; skipped otherwise.
/// </summary>
public sealed class CertificateInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-certi-" + Guid.NewGuid().ToString("N"));

    public CertificateInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string? CertDirectory => Environment.GetEnvironmentVariable("SSHSHARP_TEST_CERTDIR") is { Length: > 0 } dir ? dir : null;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    [Test]
    public async Task HostCertificate_UserCertificate_AgainstOpenSsh()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (CertDirectory is not { } dir || RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user))
        {
            Skip.Test("SSHSHARP_TEST_CERTDIR, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return;
        }

        // Trust only the authority: no plain host key anywhere, and StrictHostKeyChecking yes.
        var ca = (await File.ReadAllTextAsync(Path.Combine(dir, "ca.pub"))).Trim().Split(' ');
        var knownHosts = Path.Combine(_dir, "known_hosts");
        await File.WriteAllTextAsync(knownHosts, $"@cert-authority * {ca[0]} {ca[1]}\n");

        using var key = await SshPrivateKey.LoadAsync(Path.Combine(dir, "user"));
        var certificate = SshCertificate.Parse(await File.ReadAllTextAsync(Path.Combine(dir, "user-cert.pub")));
        var options = new SshClientOptions
        {
            UserName = user,
            PrivateKeys = [key.WithCertificate(certificate)], // the plain key alone is not authorized
            HostKeyVerifier = new KnownHostsVerifier([knownHosts]) { Policy = SshSharp.Config.StrictHostKeyChecking.Yes },
        };

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await Assert.That(client.HostKey.Certificate).IsNotNull();
        await Assert.That(client.HostKey.Certificate!.Type).IsEqualTo(SshCertificateType.Host);
        await Assert.That(client.HostKey.Algorithm).EndsWith("-cert-v01@openssh.com");
        var result = await client.RunCommandAsync("echo certified", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("certified\n");

        // The same key without its certificate is refused: the certificate is what authenticated.
        var plain = new SshClientOptions
        {
            UserName = user,
            PrivateKeys = [key],
            HostKeyVerifier = new KnownHostsVerifier([knownHosts]) { Policy = SshSharp.Config.StrictHostKeyChecking.Yes },
        };
        await Assert.That(async () => await SshClient.ConnectAsync(host, port, plain, Timeout())).Throws<SshAuthenticationException>();
    }

    /// <summary>
    /// SshSharp as the certificate authority: user certificates issued by <see cref="SshCertificateBuilder"/> with the CA key that sshd
    /// trusts (<c>TrustedUserCAKeys</c>, <c>ca</c> in SSHSHARP_TEST_CERTDIR), for fresh keys of each type that are in no authorized_keys.
    /// </summary>
    [Test]
    [Arguments(SshKeyType.Ed25519)]
    [Arguments(SshKeyType.EcdsaNistp256)]
    [Arguments(SshKeyType.Rsa)]
    public async Task CertificatesSshSharpIssues_AuthenticateWithOpenSsh(SshKeyType keyType)
    {
        if (await IssuingSetupAsync() is not var (authority, user, host, port))
        {
            return;
        }

        using (authority)
        {
            using var key = SshPrivateKey.Generate(keyType, rsaBits: 2048);
            var builder = new SshCertificateBuilder(key.GetPublicKey(), SshCertificateType.User, "sshsharp-interop")
            {
                Serial = 7,
                Principals = { user },
                ValidBefore = DateTimeOffset.UtcNow.AddMinutes(10),
            };
            var certificate = await builder.SignAsync(authority, Timeout());

            await using var client = await SshClient.ConnectAsync(host, port, Options(user, key.WithCertificate(certificate)), Timeout());
            var result = await client.RunCommandAsync("echo issued", Timeout());
            await Assert.That(result.StandardOutputText).IsEqualTo("issued\n");
        }
    }

    [Test]
    public async Task CriticalOptionsSshSharpWrites_AreEnforcedByOpenSsh()
    {
        if (await IssuingSetupAsync() is not var (authority, user, host, port))
        {
            return;
        }

        using (authority)
        {
            using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
            SshCertificateBuilder Builder() => new(key.GetPublicKey(), SshCertificateType.User, "sshsharp-options")
            {
                Principals = { user },
                ValidBefore = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            // force-command replaces the command asked for; source-address admits the loopback client.
            var forced = Builder();
            forced.CriticalOptions[SshCertificateBuilder.ForceCommand] = "echo forced";
            forced.CriticalOptions[SshCertificateBuilder.SourceAddress] = "127.0.0.0/8,::1";
            var certificate = await forced.SignAsync(authority, Timeout());
            await using (var client = await SshClient.ConnectAsync(host, port, Options(user, key.WithCertificate(certificate)), Timeout()))
            {
                var result = await client.RunCommandAsync("echo asked", Timeout());
                await Assert.That(result.StandardOutputText).IsEqualTo("forced\n");
            }

            // sshd refuses a certificate for another user, from another address, or outside its validity window.
            var otherUser = Builder();
            otherUser.Principals[0] = user + "-other";
            var elsewhere = Builder();
            elsewhere.CriticalOptions[SshCertificateBuilder.SourceAddress] = "198.51.100.0/24";
            var expired = Builder();
            expired.ValidAfter = DateTimeOffset.UtcNow.AddHours(-2);
            expired.ValidBefore = DateTimeOffset.UtcNow.AddHours(-1);
            foreach (var refused in new[] { otherUser, elsewhere, expired })
            {
                var cert = await refused.SignAsync(authority, Timeout());
                await Assert.That(async () => await SshClient.ConnectAsync(host, port, Options(user, key.WithCertificate(cert)), Timeout()))
                    .Throws<SshAuthenticationException>();
            }
        }
    }

    private static SshClientOptions Options(string user, SshPrivateKey key) => new()
    {
        UserName = user,
        PrivateKeys = [key],
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)), // the host is not what is tested here
    };

    /// <summary>The CA key sshd trusts for users, the user, and the server; null (and the test skipped) when they are not configured.</summary>
    private static async Task<(SshPrivateKey Authority, string User, string Host, int Port)?> IssuingSetupAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (CertDirectory is not { } dir || !File.Exists(Path.Combine(dir, "ca")) || RealServer.Endpoint is not var (host, port)
            || string.IsNullOrEmpty(user))
        {
            Skip.Test("SSHSHARP_TEST_CERTDIR (with the CA's private key, ca), SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return null;
        }

        return (await SshPrivateKey.LoadAsync(Path.Combine(dir, "ca")), user, host, port);
    }
}
