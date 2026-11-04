using SshSharp.Config;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>OpenSSH certificates: parsing and checks, host certificates against @cert-authority, and user certificates for authentication.</summary>
public sealed class CertificateTests : IDisposable
{
    private const string Host = "srv.example.com";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-cert-" + Guid.NewGuid().ToString("N"));
    private readonly SshPrivateKey _authority = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));

    public CertificateTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        _authority.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private string AuthorityLine(string patterns, string marker = "@cert-authority") =>
        $"{marker} {patterns} {_authority.KeyType} {Convert.ToBase64String(_authority.PublicKey.Span)}\n";

    // ---- the certificate itself ----

    [Test]
    public async Task ACertificate_ParsesBackToWhatWasSigned()
    {
        var key = FakeHostKey.Ed25519();
        var after = DateTimeOffset.UtcNow.AddHours(-1);
        var before = DateTimeOffset.UtcNow.AddDays(1);
        var blob = TestKeys.Certificate(_authority, key.Blob, SshCertificateType.Host, [Host, "10.0.0.5"], after, before, keyId: "web-1", serial: 42);
        var certificate = SshCertificate.Parse(TestKeys.CertificateLine(blob));

        await Assert.That(certificate.Algorithm).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
        await Assert.That(certificate.KeyType).IsEqualTo("ssh-ed25519");
        await Assert.That(certificate.PublicKey.ToArray()).IsEquivalentTo(key.Blob);
        await Assert.That(certificate.Fingerprint).IsEqualTo(key.Fingerprint);
        await Assert.That(certificate.Type).IsEqualTo(SshCertificateType.Host);
        await Assert.That(certificate.KeyId).IsEqualTo("web-1");
        await Assert.That(certificate.Serial).IsEqualTo(42ul);
        await Assert.That(certificate.Principals).IsEquivalentTo(new[] { Host, "10.0.0.5" });
        await Assert.That(certificate.ValidAfter.ToUnixTimeSeconds()).IsEqualTo(after.ToUnixTimeSeconds());
        await Assert.That(certificate.ValidBefore.ToUnixTimeSeconds()).IsEqualTo(before.ToUnixTimeSeconds());
        await Assert.That(certificate.Extensions).IsEquivalentTo(new[] { "permit-pty" });
        await Assert.That(certificate.AuthorityFingerprint).IsEqualTo(_authority.Fingerprint);
        await Assert.That(certificate.VerifySignature()).IsTrue();

        // "Forever" maps to MaxValue rather than overflowing.
        var forever = SshCertificate.FromBlob(TestKeys.Certificate(_authority, key.Blob, SshCertificateType.Host));
        await Assert.That(forever.ValidBefore).IsEqualTo(DateTimeOffset.MaxValue);
    }

    [Test]
    public async Task TamperedOrMalformedCertificates_AreCaught()
    {
        var key = FakeHostKey.Ed25519();
        var blob = TestKeys.Certificate(_authority, key.Blob, SshCertificateType.Host, [Host]);

        // Change one byte of the key id: the authority's signature no longer verifies.
        var tampered = (byte[])blob.Clone();
        var index = Array.IndexOf(tampered, (byte)'t', 120);
        tampered[index] ^= 1;
        await Assert.That(SshCertificate.FromBlob(tampered).VerifySignature()).IsFalse();

        // An authority whose key is itself a certificate is refused.
        var authorityCertificate = SshCertificate.FromBlob(TestKeys.Certificate(_authority, _authority.PublicKey.ToArray(), SshCertificateType.User));
        var certifiedAuthority = _authority.WithCertificate(authorityCertificate);
        var nested = TestKeys.Certificate(certifiedAuthority, key.Blob, SshCertificateType.Host);
        await Assert.That(() => SshCertificate.Parse(TestKeys.CertificateLine(nested))).Throws<FormatException>().WithMessageContaining("cannot itself be a certificate");

        // Lines that are not certificates, and a type field that does not match the blob.
        await Assert.That(() => SshCertificate.Parse("ssh-ed25519 AAAA")).Throws<FormatException>();
        await Assert.That(() => SshCertificate.Parse("ssh-ed25519-cert-v01@openssh.com !!!")).Throws<FormatException>();
        await Assert.That(() => SshCertificate.Parse($"ecdsa-sha2-nistp256-cert-v01@openssh.com {Convert.ToBase64String(blob)}")).Throws<FormatException>();
    }

    [Test]
    [Arguments("", null)]
    [Arguments("RequiredRSASize 3072", 3072)]
    [Arguments("RequiredRSASize 1024", 1024)]
    [Arguments("RequiredRSASize 512", null)] // below ssh's floor: ignored
    [Arguments("RequiredRSASize lots", null)]
    public async Task RequiredRsaSize_IsReadFromSshConfig(string line, int? expected)
    {
        var host = SshSharp.Config.SshConfig.Parse($"Host *\n {line}\n").Resolve("h", new SshSharp.Config.SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h" });
        await Assert.That(host.RequiredRsaSize).IsEqualTo(expected);
    }

    [Test]
    public async Task HostChecks_TypeValidityPrincipalsAndCriticalOptions()
    {
        var key = FakeHostKey.Ed25519();
        var now = DateTimeOffset.UtcNow;
        SshCertificate Make(SshCertificateType type = SshCertificateType.Host, string[]? principals = null, DateTimeOffset? after = null,
            DateTimeOffset? before = null, (string, string)[]? options = null) =>
            SshCertificate.FromBlob(TestKeys.Certificate(_authority, key.Blob, type, principals ?? [Host], after, before, options));

        await Assert.That(Make().CheckForHost(Host, now)).IsNull();
        await Assert.That(Make().CheckForHost("SRV.EXAMPLE.COM", now)).IsNull();
        // No principals: no host's, as OpenSSH's client has it ("Certificate lacks principal list"), not any host's.
        await Assert.That(Make(principals: []).CheckForHost("anything", now)).Contains("no principals");

        // Principals are patterns for host certificates (OpenSSH 10.3 made that consistent).
        await Assert.That(Make(principals: ["*.example.com"]).CheckForHost(Host, now)).IsNull();
        await Assert.That(Make(principals: ["srv?.example.com"]).CheckForHost("srv1.example.com", now)).IsNull();
        await Assert.That(Make(principals: ["*.example.com"]).CheckForHost("example.org", now)).Contains("not issued for");
        await Assert.That(Make(principals: ["other.example.com", "*.example.com"]).CheckForHost(Host, now)).IsNull();
        await Assert.That(Make(type: SshCertificateType.User).CheckForHost(Host, now)).Contains("user certificate");
        await Assert.That(Make(principals: ["other.example.com"]).CheckForHost(Host, now)).Contains("not issued for");
        await Assert.That(Make(before: now.AddMinutes(-1)).CheckForHost(Host, now)).Contains("valid only");
        await Assert.That(Make(after: now.AddMinutes(5)).CheckForHost(Host, now)).Contains("valid only");
        await Assert.That(Make(options: [("force-command", "/bin/true")]).CheckForHost(Host, now)).Contains("critical options");
        await Assert.That(Make(options: [("force-command", "/bin/true"), ("source-address", "192.0.2.0/24")]).CheckForHost(Host, now))
            .Contains("(force-command, source-address)");
    }

    [Test]
    public async Task ALineThatIsNotACertificate_OrDoesNotMatchItsBlob_SaysWhich()
    {
        var key = FakeHostKey.Ed25519();
        var blob = TestKeys.Certificate(_authority, key.Blob, SshCertificateType.Host, [Host]);

        await Assert.That(() => SshCertificate.Parse(null!)).ThrowsExactly<ArgumentNullException>();
        foreach (var line in new[] { "ssh-ed25519-cert-v01@openssh.com", $"ssh-ed25519 {Convert.ToBase64String(blob)}" })
        {
            await Assert.That(() => SshCertificate.Parse(line)).ThrowsExactly<FormatException>().WithMessageContaining("Not an OpenSSH certificate line");
        }

        await Assert.That(() => SshCertificate.Parse($"ecdsa-sha2-nistp256-cert-v01@openssh.com {Convert.ToBase64String(blob)}"))
            .ThrowsExactly<FormatException>().WithMessageContaining("The certificate's type does not match the line's type field.");
        await Assert.That(() => SshCertificate.FromBlob([.. blob, 0])).ThrowsExactly<SshProtocolException>().WithMessageContaining("Trailing data");
    }

    [Test]
    public async Task TheCertifiedKeyIsRead_OnlyFromATypeSshSharpAccepts()
    {
        foreach (var type in new[] { "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa", "sk-ssh-ed25519", "sk-ecdsa-sha2-nistp256" })
        {
            await Assert.That(SshCertificate.IsAcceptedCertificateKeyType(type + "-cert-v01@openssh.com")).IsTrue().Because(type);
        }

        await Assert.That(SshCertificate.IsAcceptedCertificateKeyType("ssh-dss-cert-v01@openssh.com")).IsFalse();
        var dss = TestKeys.Blob(w => w.WriteString("ssh-dss-cert-v01@openssh.com"));
        await Assert.That(() => SshCertificate.ReadCertifiedKey(dss)).ThrowsExactly<SshProtocolException>().WithMessageContaining("not of a type SshSharp accepts");
    }

    // ---- host certificates in a connection ----

    private async Task<SshClient> ConnectAsync(FakeSessionServer server, StrictHostKeyChecking policy = StrictHostKeyChecking.Yes)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = policy },
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private FakeServerOptions WithHostCertificate(FakeHostKey key, string[]? principals = null, DateTimeOffset? before = null, string? algorithm = null) => new()
    {
        HostKey = key,
        HostCertificate = FakeHostKey.Certified(key, TestKeys.Certificate(_authority, key.Blob, SshCertificateType.Host, principals ?? [Host], validBefore: before)),
        HostCertificateAlgorithm = algorithm,
    };

    [Test]
    public async Task AHostCertificateFromATrustedAuthority_IsAccepted_WithoutAnyKnownHostsEntryForTheKey()
    {
        File.WriteAllText(KnownHosts, AuthorityLine("*.example.com"));
        await using var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Ed25519()));
        await using var client = await ConnectAsync(server);

        await Assert.That(client.HostKey.Certificate).IsNotNull();
        await Assert.That(client.HostKey.Algorithm).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
        await Assert.That(client.HostKey.Certificate!.AuthorityFingerprint).IsEqualTo(_authority.Fingerprint);
        await Assert.That(File.ReadAllLines(KnownHosts).Length).IsEqualTo(1); // nothing recorded
    }

    [Test]
    public async Task ACertificateOnlyHostKeyList_ConnectsToAHostWhoseAuthorityIsTrusted()
    {
        // The list names only the certificate algorithm: it used to be emptied (and the connection fail) once the authority was trusted.
        File.WriteAllText(KnownHosts, AuthorityLine("*.example.com"));
        await using var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Ed25519()));
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]),
            HostKeyAlgorithms = SshAlgorithmList.Only("ssh-ed25519-cert-v01@openssh.com"),
        }, leaveOpen: true, Timeout());
        await Assert.That(client.HostKey.Algorithm).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
    }

    [Test]
    public async Task RsaHostCertificates_UseTheSha2CertificateAlgorithms()
    {
        File.WriteAllText(KnownHosts, AuthorityLine("*"));
        await using var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Rsa(2048), algorithm: "rsa-sha2-512-cert-v01@openssh.com"));
        await using var client = await ConnectAsync(server);
        await Assert.That(client.HostKey.Algorithm).IsEqualTo("rsa-sha2-512-cert-v01@openssh.com");
        await Assert.That(client.HostKey.KeyType).IsEqualTo("ssh-rsa");
    }

    [Test]
    public async Task ATrustedAuthority_ButAWrongPrincipalOrAnExpiredCertificate_IsRefused()
    {
        File.WriteAllText(KnownHosts, AuthorityLine("*.example.com"));
        await using (var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Ed25519(), principals: ["other.example.com"])))
        {
            var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await ConnectAsync(server));
            await Assert.That(ex!.Message).Contains("not issued for srv.example.com");
        }

        await using (var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Ed25519(), before: DateTimeOffset.UtcNow.AddMinutes(-5))))
        {
            var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await ConnectAsync(server));
            await Assert.That(ex!.Message).Contains("valid only");
        }
    }

    [Test]
    public async Task ARevokedAuthority_IsRefused()
    {
        File.WriteAllText(KnownHosts, AuthorityLine("*.example.com") + AuthorityLine("*", "@revoked"));
        await using var server = new FakeSessionServer(WithHostCertificate(FakeHostKey.Ed25519()));
        var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await ConnectAsync(server, StrictHostKeyChecking.No));
        await Assert.That(ex!.Message).Contains("@revoked");
    }

    [Test]
    public async Task WithoutATrustedAuthority_ThePlainKeyIsUsed_AsSshFallsBack()
    {
        // No @cert-authority for the host: the client does not ask for certificates, and the plain key is checked as usual.
        var key = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, $"{Host} {key.KeyType} {Convert.ToBase64String(key.Blob)}\n{AuthorityLine("*.other.org")}");
        await using var server = new FakeSessionServer(WithHostCertificate(key));
        await using var client = await ConnectAsync(server);
        await Assert.That(client.HostKey.Certificate).IsNull();
        await Assert.That(client.HostKey.Algorithm).IsEqualTo("ssh-ed25519");
    }

    // ---- user certificates ----

    [Test]
    public async Task AUserCertificate_AuthenticatesWhereOnlyTheAuthorityIsTrusted()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(_authority, blob, SshCertificateType.User, ["tester"]));
        var certified = key.WithCertificate(certificate);
        await Assert.That(certified.KeyType).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
        await Assert.That(certified.Certificate).IsEqualTo(certificate);

        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], TrustedUserAuthority = _authority.PublicKey.ToArray() };
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [certified],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        await using var client = await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
        string[] attempts;
        lock (server.AuthAttempts)
        {
            attempts = [.. server.AuthAttempts];
        }

        await Assert.That(attempts).Contains("publickey-signed:ssh-ed25519-cert-v01@openssh.com");

        // The certificate's key is held here, so it signs straight away, without offering the certificate first.
        string[] requests;
        lock (server.PublicKeyRequests)
        {
            requests = [.. server.PublicKeyRequests];
        }

        await Assert.That(requests).IsEquivalentTo(new[] { "signed:ssh-ed25519-cert-v01@openssh.com" });
    }

    [Test]
    public async Task WithCertificate_RefusesHostCertificatesAndOtherKeys()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var host = SshCertificate.FromBlob(TestKeys.Certificate(_authority, blob, SshCertificateType.Host));
        await Assert.That(() => key.WithCertificate(host)).Throws<ArgumentException>();

        TestKeys.OpenSshEd25519(out var otherBlob);
        var other = SshCertificate.FromBlob(TestKeys.Certificate(_authority, otherBlob, SshCertificateType.User));
        await Assert.That(() => key.WithCertificate(other)).Throws<ArgumentException>();
    }

    [Test]
    public async Task ConfigConnect_FindsTheCertificateNextToTheIdentityFile()
    {
        var keyPath = Path.Combine(_dir, "id_ed25519");
        File.WriteAllText(keyPath, TestKeys.OpenSshEd25519(out var blob));
        File.WriteAllText(keyPath + "-cert.pub", TestKeys.CertificateLine(TestKeys.Certificate(_authority, blob, SshCertificateType.User, ["tester"])));

        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], TrustedUserAuthority = _authority.PublicKey.ToArray() };
        await using var client = await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse($"Host srv\n User tester\n IdentityFile \"{keyPath}\"\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir },
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }
}
