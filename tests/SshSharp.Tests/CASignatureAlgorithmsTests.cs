using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <c>CASignatureAlgorithms</c> (and <see cref="SshClientOptions.CASignatureAlgorithms"/>): the signature algorithms a certificate
/// authority may have signed a host certificate with. The list can only narrow SshSharp's set, and a certificate signed with an
/// algorithm it leaves out is unusable, so its key is checked as a plain key, as ssh does.
/// </summary>
public sealed class CASignatureAlgorithmsTests : IDisposable
{
    private const string Host = "srv.example.com";

    private static readonly string[] BuiltIn =
        ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"];

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-casig-" + Guid.NewGuid().ToString("N"));

    public CASignatureAlgorithmsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private static SshHostConfig ResolveWith(string lines) =>
        SshConfig.Parse($"Host *\n{lines}").Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h" });

    private static IReadOnlyList<string> FromConfig(string lines) => AlgorithmPreferences.FromConfig(ResolveWith(lines)).CASignatures;

    private static string AuthorityLine(SshPrivateKey authority) =>
        $"@cert-authority * {authority.KeyType} {Convert.ToBase64String(authority.PublicKey.Span)}\n";

    /// <summary>A host key with a valid certificate for <see cref="Host"/> from <paramref name="authority"/>.</summary>
    private static SshHostKey CertifiedKey(SshPrivateKey authority, SshPrivateKey host, string? authorityAlgorithm = null)
    {
        var blob = host.PublicKey.ToArray();
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, blob, SshCertificateType.Host, [Host], keyId: "web-1",
            authorityAlgorithm: authorityAlgorithm));
        return new SshHostKey(certificate.Algorithm, host.KeyType, host.Fingerprint, blob, 256) { Certificate = certificate };
    }

    // ---- the list: ssh_config's forms, cut back to SshSharp's set ----

    [Test]
    public async Task TheDirective_IsReadFromSshConfig()
    {
        await Assert.That(ResolveWith(string.Empty).CASignatureAlgorithms).IsNull();
        await Assert.That(ResolveWith(" CASignatureAlgorithms ssh-ed25519,ecdsa-sha2-nistp256\n").CASignatureAlgorithms)
            .IsEqualTo("ssh-ed25519,ecdsa-sha2-nistp256");
        await Assert.That(ResolveWith(" casignaturealgorithms -rsa*\n").CASignatureAlgorithms).IsEqualTo("-rsa*"); // keywords have no case
    }

    [Test]
    [Arguments("", new[] { "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256" })]
    [Arguments("ssh-ed25519", new[] { "ssh-ed25519" })]
    [Arguments("ecdsa-sha2-nistp384,ssh-ed25519", new[] { "ecdsa-sha2-nistp384", "ssh-ed25519" })]
    [Arguments("-ecdsa*", new[] { "ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256" })]
    [Arguments("-rsa-sha2-256,ssh-ed25519", new[] { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512" })]
    [Arguments("^rsa-sha2-256", new[] { "rsa-sha2-256", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512" })]
    [Arguments("ecdsa*", new[] { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" })]
    // Names SshSharp does not accept are dropped: a typo, and what ssh's own defaults have but SshSharp refuses (SHA-1, security keys).
    [Arguments("ssh-ed25519,ssh-ed448,ssh-dss", new[] { "ssh-ed25519" })]
    [Arguments("ssh-ed25519,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com", new[] { "ssh-ed25519" })]
    public async Task AList_IsAppliedToSshSharpsSet_AsSshAppliesIt(string specification, string[] expected)
    {
        var lines = specification.Length == 0 ? string.Empty : $" CASignatureAlgorithms {specification}\n";
        await Assert.That(FromConfig(lines)).IsEquivalentTo(expected, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }

    [Test]
    [Arguments("+ssh-rsa")]
    [Arguments("+ssh-rsa,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com")]
    [Arguments("^ssh-rsa")]
    [Arguments("+*")]
    public async Task AddingWhatSshSharpRefuses_LeavesItsSet_TheListCannotWidenIt(string specification)
    {
        // +ssh-rsa is the usual way back to SHA-1 authorities in ssh; here it changes nothing.
        await Assert.That(FromConfig($" CASignatureAlgorithms {specification}\n")).IsEquivalentTo(BuiltIn);
        await Assert.That(AlgorithmPreferences.CASignaturesFromConfig(specification)).IsEquivalentTo(BuiltIn);
    }

    [Test]
    [Arguments("ssh-rsa")]
    [Arguments("sk-ssh-ed25519@openssh.com,ssh-rsa")]
    [Arguments("-*")]
    [Arguments("bogus")]
    public async Task AListThatLeavesNothing_IsAConfigurationError_NamingTheDirective(string specification)
    {
        var host = ResolveWith($" CASignatureAlgorithms {specification}\n");
        var error = await Assert.That(() => AlgorithmPreferences.FromConfig(host)).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.Message).IsEqualTo("ssh_config's CASignatureAlgorithms leaves no CA signature algorithm that SshSharp can use.");

        // The verifier made from the same configuration says the same.
        var fromVerifier = await Assert.That(() => KnownHostsVerifier.FromConfig(host)).Throws<SshException>();
        await Assert.That(fromVerifier!.Message).IsEqualTo(error.Message);
    }

    [Test]
    public async Task UnsetOrEmpty_TheVerifierFromConfigUsesSshSharpsSet()
    {
        await Assert.That(KnownHostsVerifier.FromConfig(ResolveWith(string.Empty)).CASignatureAlgorithms).IsNull();
        await Assert.That(AlgorithmPreferences.CASignaturesFromConfig("  ")).IsNull();
        await Assert.That(KnownHostsVerifier.FromConfig(ResolveWith(" CASignatureAlgorithms -ecdsa*,rsa*\n")).CASignatureAlgorithms)
            .IsEquivalentTo(new[] { "ssh-ed25519" });
    }

    [Test]
    public async Task TheOption_TakesOnlyNamesSshSharpAccepts_AndCannotLeaveNothing()
    {
        SshClientOptions Options(SshAlgorithmList? list) => new()
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            CASignatureAlgorithms = list,
        };

        await Assert.That(AlgorithmPreferences.FromOptions(Options(null)).CASignatures).IsEquivalentTo(BuiltIn);
        await Assert.That(AlgorithmPreferences.FromOptions(Options(SshAlgorithmList.Only("ssh-ed25519"))).CASignatures).IsEquivalentTo(new[] { "ssh-ed25519" });
        await Assert.That(AlgorithmPreferences.FromOptions(Options(SshAlgorithmList.Remove("rsa-*"))).CASignatures)
            .IsEquivalentTo(new[] { "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" });
        await Assert.That(Options(SshAlgorithmList.Parse("-ecdsa*")).CASignatureAlgorithms!.ToString()).IsEqualTo("-ecdsa*");

        // A name SshSharp never accepts from an authority is an error when the option is set, as for the other typed lists.
        foreach (var refused in new[] { "ssh-rsa", "sk-ssh-ed25519@openssh.com", "ssh-ed25519-cert-v01@openssh.com", "bogus" })
        {
            var error = await Assert.That(() => Options(SshAlgorithmList.Append(refused))).Throws<ArgumentException>();
            await Assert.That(error!.Message).Contains($"'{refused}' is not a CA signature algorithm SshSharp supports");
        }

        // FIPS mode narrows it as it narrows the host keys: no Ed25519 authority.
        string[] fips = ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"];
        await Assert.That(AlgorithmPreferences.FromOptions(new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            FipsMode = true,
        }).CASignatures).IsEquivalentTo(fips);
        await Assert.That(AlgorithmPreferences.Fips().CASignatures).IsEquivalentTo(fips);

        var empty = await Assert.That(() => AlgorithmPreferences.FromOptions(Options(SshAlgorithmList.Remove("*")))).Throws<ArgumentException>();
        await Assert.That(empty!.Message).Contains("SshClientOptions.CASignatureAlgorithms leaves no CA signature algorithm");
    }

    // ---- host certificates: one signed with an algorithm not allowed is unusable, and its key is checked as a plain key ----

    [Test]
    public async Task ACertificateFromAnEcdsaAuthority_IsTrustedByDefault_ButNotWhenTheListAllowsOnlyEd25519()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var key = CertifiedKey(authority, host);
        File.WriteAllText(KnownHosts, AuthorityLine(authority));
        var verifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes };

        var byDefault = await verifier.VerifyAsync(new SshHostKeyContext(Host, 22, null, key), default);
        await Assert.That(byDefault.IsAccepted).IsTrue();

        // As ssh: the certificate cannot be used ("Certificate signed with disallowed algorithm"), and with no plain line for the key,
        // StrictHostKeyChecking yes refuses it, saying why the certificate did not help.
        var log = new ListLogger();
        var narrowed = new SshHostKeyContext(Host, 22, null, key) { Logger = log, CASignatureAlgorithms = ["ssh-ed25519"] };
        var refused = await verifier.VerifyAsync(narrowed, default);
        await Assert.That(refused.IsAccepted).IsFalse();
        await Assert.That(refused.Reason).Contains("not in known_hosts, and StrictHostKeyChecking is yes").And.Contains("could not be used either")
            .And.Contains("its authority signed it with ecdsa-sha2-nistp256, which is not allowed here");

        // The warning names the keys and the algorithm, never the host or the key id.
        var (level, message) = log.Entries.Single();
        await Assert.That(level).IsEqualTo(LogLevel.Warning);
        await Assert.That(message).Contains(authority.Fingerprint).And.Contains("ecdsa-sha2-nistp256");
        await Assert.That(message).DoesNotContain(Host).And.DoesNotContain("web-1");

        // A plain known_hosts line for the key accepts it, as for any unusable certificate.
        File.AppendAllText(KnownHosts, $"{Host} {host.KeyType} {Convert.ToBase64String(host.PublicKey.Span)}\n");
        await Assert.That((await verifier.VerifyAsync(narrowed, default)).IsAccepted).IsTrue();
    }

    [Test]
    public async Task OnlyTheAlgorithmTheAuthoritySignedWith_Counts()
    {
        // An RSA authority signs with rsa-sha2-512 or rsa-sha2-256: the list decides by the signature, not by the authority's key type.
        using var authority = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        File.WriteAllText(KnownHosts, AuthorityLine(authority));
        var verifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes };

        async Task<SshHostKeyVerdict> VerifyAsync(string signedWith, params string[] allowed) =>
            await verifier.VerifyAsync(new SshHostKeyContext(Host, 22, null, CertifiedKey(authority, host, signedWith)) { CASignatureAlgorithms = allowed }, default);

        await Assert.That((await VerifyAsync("rsa-sha2-512", "rsa-sha2-512")).IsAccepted).IsTrue();
        await Assert.That((await VerifyAsync("rsa-sha2-256", "rsa-sha2-512")).Reason).Contains("signed it with rsa-sha2-256");
        await Assert.That((await VerifyAsync("rsa-sha2-256", "ssh-ed25519", "rsa-sha2-256")).IsAccepted).IsTrue();
    }

    [Test]
    public async Task TheConfigurationsListAndTheConnectionsList_EachNarrowTheOther()
    {
        using var ed25519Authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var ecdsaAuthority = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        File.WriteAllText(KnownHosts, AuthorityLine(ed25519Authority) + AuthorityLine(ecdsaAuthority));
        var verifier = KnownHostsVerifier.FromConfig(ResolveWith(
            $" StrictHostKeyChecking yes\n UserKnownHostsFile \"{KnownHosts}\"\n CASignatureAlgorithms ssh-ed25519,ecdsa-sha2-nistp256\n"));

        async Task<bool> AcceptsAsync(SshPrivateKey authority, params string[] connection) =>
            (await verifier.VerifyAsync(new SshHostKeyContext(Host, 22, null, CertifiedKey(authority, host)) { CASignatureAlgorithms = connection }, default))
            .IsAccepted;

        await Assert.That(await AcceptsAsync(ecdsaAuthority, BuiltIn)).IsTrue();
        await Assert.That(await AcceptsAsync(ed25519Authority, BuiltIn)).IsTrue();
        await Assert.That(await AcceptsAsync(ecdsaAuthority, "ssh-ed25519")).IsFalse();
        await Assert.That(await AcceptsAsync(ed25519Authority, "ecdsa-sha2-nistp256", "rsa-sha2-512")).IsFalse();
    }

    [Test]
    public async Task ASha1SignedCertificate_StaysRefused_AsAnInvalidSignature()
    {
        // ssh-rsa is never in the list; a certificate an RSA authority signed with SHA-1 fails as it always has, and the reason does not
        // repeat a name the certificate chose.
        using var authority = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(authority.ToPkcs8PrivateKey());
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);

        // SshSharp never signs with SHA-1, so the rsa-sha2-256 signature (string "rsa-sha2-256", string of 256 bytes) is replaced.
        var sha2 = TestKeys.Certificate(authority, host.PublicKey.ToArray(), SshCertificateType.Host, [Host], authorityAlgorithm: "rsa-sha2-256");
        var signed = sha2[..^(4 + 4 + "rsa-sha2-256".Length + 4 + 256)];
        var sha1 = TestKeys.Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteString(rsa.SignData(signed, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
        });
        var certificate = SshCertificate.FromBlob([.. signed, .. TestKeys.Blob(w => w.WriteString(sha1))]);
        await Assert.That(certificate.SignatureAlgorithm).IsEqualTo("ssh-rsa");
        await Assert.That(certificate.CheckForHost(Host, DateTimeOffset.UtcNow, BuiltIn)).IsEqualTo("its authority's signature is invalid");
        await Assert.That(certificate.CheckForHost(Host, DateTimeOffset.UtcNow)).IsEqualTo("its authority's signature is invalid");
    }

    [Test]
    public async Task CheckForHost_SaysWhichAlgorithmIsNotAllowed_BeforeTheOtherChecks()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.EcdsaNistp384);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var now = DateTimeOffset.UtcNow;
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, host.PublicKey.ToArray(), SshCertificateType.Host, [Host],
            validBefore: now.AddMinutes(-1)));

        await Assert.That(certificate.SignatureAlgorithm).IsEqualTo("ecdsa-sha2-nistp384");
        await Assert.That(certificate.CheckForHost(Host, now, ["ssh-ed25519", "ecdsa-sha2-nistp256"]))
            .IsEqualTo("its authority signed it with ecdsa-sha2-nistp384, which is not allowed here (CASignatureAlgorithms, or FIPS mode)");
        await Assert.That(certificate.CheckForHost(Host, now, ["ecdsa-sha2-nistp384"])).Contains("valid only");
        await Assert.That(certificate.CheckForHost(Host, now.AddMinutes(-2), ["ecdsa-sha2-nistp384"])).IsNull();
    }

    // ---- in a connection ----

    private static FakeServerOptions WithCertificate(SshPrivateKey authority)
    {
        var key = FakeHostKey.Ed25519();
        return new()
        {
            HostKey = key,
            HostCertificate = FakeHostKey.Certified(key, TestKeys.Certificate(authority, key.Blob, SshCertificateType.Host, [Host])),
        };
    }

    [Test]
    public async Task TheOption_RefusesAHostCertificateFromAnEcdsaAuthority_WhenItAllowsOnlyEd25519()
    {
        using var ecdsaAuthority = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        using var ed25519Authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        File.WriteAllText(KnownHosts, AuthorityLine(ecdsaAuthority) + AuthorityLine(ed25519Authority));

        async Task<SshClient> ConnectAsync(FakeSessionServer server, SshAlgorithmList? list)
        {
            _ = server.StartAsync();
            return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = TestSecrets.Password,
                HostKeyAlias = Host,
                HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes },
                CASignatureAlgorithms = list,
            }, leaveOpen: true, Timeout());
        }

        await using (var server = new FakeSessionServer(WithCertificate(ecdsaAuthority)))
        {
            await using var byDefault = await ConnectAsync(server, null);
            await Assert.That(byDefault.HostKey.Certificate!.AuthorityFingerprint).IsEqualTo(ecdsaAuthority.Fingerprint);
        }

        await using (var server = new FakeSessionServer(WithCertificate(ecdsaAuthority)))
        {
            var error = await Assert.That(async () => await ConnectAsync(server, SshAlgorithmList.Only("ssh-ed25519"))).Throws<SshHostKeyException>();
            await Assert.That(error!.Message).Contains("ecdsa-sha2-nistp256, which is not allowed here");
        }

        await using (var server = new FakeSessionServer(WithCertificate(ed25519Authority)))
        {
            await using var ed25519 = await ConnectAsync(server, SshAlgorithmList.Only("ssh-ed25519"));
            await Assert.That(ed25519.HostKey.Certificate!.AuthorityFingerprint).IsEqualTo(ed25519Authority.Fingerprint);
        }
    }

    [Test]
    public async Task InFipsMode_ACertificateFromAnEd25519Authority_CannotBeUsed_AndItsKeyIsCheckedAsAPlainKey()
    {
        // FIPS mode accepts no Ed25519 host key, so no Ed25519 authority either: an ECDSA host key's certificate it signed proves nothing
        // there, and the connection stands or falls with the plain key, as for any certificate that cannot be used.
        using var ed25519Authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var hostKey = FakeHostKey.Ecdsa(256);
        FakeServerOptions Server() => new()
        {
            HostKey = hostKey,
            HostCertificate = FakeHostKey.Certified(hostKey, TestKeys.Certificate(ed25519Authority, hostKey.Blob, SshCertificateType.Host, [Host])),
            Kex = SshAlgorithms.EcdhNistp256,
            Cipher = "aes256-gcm@openssh.com",
        };

        async Task<SshClient> ConnectAsync(FakeSessionServer server)
        {
            _ = server.StartAsync();
            return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = TestSecrets.Password,
                HostKeyAlias = Host,
                HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes },
                FipsMode = true,
            }, leaveOpen: true, Timeout());
        }

        File.WriteAllText(KnownHosts, AuthorityLine(ed25519Authority));
        await using (var server = new FakeSessionServer(Server()))
        {
            var error = await Assert.That(async () => await ConnectAsync(server)).Throws<SshHostKeyException>();
            await Assert.That(error!.Message).Contains("ssh-ed25519, which is not allowed here");
        }

        File.AppendAllText(KnownHosts, $"{Host} {hostKey.KeyType} {Convert.ToBase64String(hostKey.Blob)}\n");
        await using (var server = new FakeSessionServer(Server()))
        {
            await using var client = await ConnectAsync(server);
            await Assert.That(client.HostKey.Certificate).IsNotNull();
        }
    }

    [Test]
    [Arguments(null, true)]
    [Arguments("ssh-ed25519", false)]
    [Arguments("-ecdsa-sha2-nistp256", false)]
    [Arguments("+ssh-rsa", true)]
    [Arguments("ecdsa*", true)]
    public async Task TheDirective_AppliesWhenConnectingByAlias(string? specification, bool accepted)
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        File.WriteAllText(KnownHosts, AuthorityLine(authority));
        await using var server = new FakeSessionServer(WithCertificate(authority));
        var config = $"Host srv\n HostName {Host}\n User tester\n StrictHostKeyChecking yes\n UserKnownHostsFile \"{KnownHosts}\"\n"
            + (specification is null ? string.Empty : $" CASignatureAlgorithms {specification}\n");

        Task<SshClient> ConnectAsync() => SshClient.ConnectAsync("srv", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir, LocalHostName = "box" },
            Password = TestSecrets.Password,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());

        if (accepted)
        {
            await using var client = await ConnectAsync();
            await Assert.That(client.HostKey.Certificate).IsNotNull();
        }
        else
        {
            var error = await Assert.That(async () => await ConnectAsync()).Throws<SshHostKeyException>();
            await Assert.That(error!.Message).Contains("is not allowed here");
        }
    }

    [Test]
    public async Task ADirectiveThatLeavesNothing_FailsTheConnectionBeforeAnythingIsSent()
    {
        var connected = false;
        var error = await Assert.That(async () => await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host srv\n User tester\n UserKnownHostsFile none\n CASignatureAlgorithms ssh-rsa\n"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir, LocalHostName = "box" },
            TcpConnector = (_, _, _, _) =>
            {
                connected = true;
                throw new SshException(SshFailureReason.ConnectFailed, "No network in this test.");
            },
        }, Timeout())).Throws<SshException>();

        await Assert.That(error!.Message).Contains("CASignatureAlgorithms leaves no CA signature algorithm");
        await Assert.That(connected).IsFalse();
    }

    /// <summary>Collects log entries.</summary>
    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
