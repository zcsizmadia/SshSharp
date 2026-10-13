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

        using var key = await SshPrivateKey.LoadFileAsync(Path.Combine(dir, "user"));
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
}
