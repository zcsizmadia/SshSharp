using SshSharp.Config;
using SshSharp.Keys;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <c>PubkeyAcceptedAlgorithms</c> (ssh_config, and <see cref="SshClientOptions.PubkeyAcceptedAlgorithms"/>): which keys are offered and
/// with which signature algorithm. Also how ssh_config algorithm lists resolve (wildcards, <c>+</c>, empty results) and which host key
/// lists the client may reorder for a trusted certificate authority.
/// </summary>
public sealed class PubkeyAcceptedAlgorithmsTests : IDisposable
{
    private readonly SshPrivateKey _authority = SshPrivateKey.Generate(SshKeyType.Ed25519);

    public void Dispose() => _authority.Dispose();

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static SshHostConfig Config(string text) => SshConfig.Parse(text).Resolve("h", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = "/h" });

    private static readonly Dictionary<string, string> BothRsa = new() { ["server-sig-algs"] = "ssh-ed25519,rsa-sha2-256,rsa-sha2-512" };

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }

    // ---- resolution ----

    [Test]
    public async Task NotConfigured_RestrictsNothing()
    {
        await Assert.That(AlgorithmPreferences.FromConfig(Config("User x\n")).PublicKeys).IsNull();
        await Assert.That(AlgorithmPreferences.FromOptions(Options()).PublicKeys).IsNull();
    }

    [Test]
    [Arguments("PubkeyAcceptedAlgorithms ssh-ed25519", "ssh-ed25519")]
    [Arguments("PubkeyAcceptedKeyTypes ssh-ed25519,ssh-rsa,ssh-dss", "ssh-ed25519")] // the old name; SHA-1 ssh-rsa is never used
    [Arguments("PubkeyAcceptedAlgorithms ssh-ed25519*", "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519")] // wildcards, as ssh expands them
    [Arguments("PubkeyAcceptedAlgorithms rsa-sha2-256,rsa-sha2-512", "rsa-sha2-256,rsa-sha2-512")]
    [Arguments("PubkeyAcceptedAlgorithms -*-cert-v01@openssh.com,sk-*,ecdsa-*", "ssh-ed25519,rsa-sha2-512,rsa-sha2-256")]
    [Arguments("PubkeyAcceptedAlgorithms ^rsa-sha2-256", "rsa-sha2-256,ssh-ed25519-cert-v01@openssh.com")]
    public async Task TheConfigListResolves_AsSshAssemblesIt(string line, string expected)
    {
        var resolved = AlgorithmPreferences.FromConfig(Config(line + "\n")).PublicKeys!;
        await Assert.That(string.Join(",", resolved.Take(expected.Count(c => c == ',') + 1))).IsEqualTo(expected);
    }

    [Test]
    public async Task Plus_KeepsTheDefaults_AndADefaultWhereItIs()
    {
        var resolved = AlgorithmPreferences.FromConfig(Config("PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519\n")).PublicKeys!;
        await Assert.That(string.Join(",", resolved)).IsEqualTo(string.Join(",", SshAlgorithms.PublicKeySignatures));
    }

    [Test]
    [Arguments("PubkeyAcceptedAlgorithms ssh-rsa,ssh-dss")]
    [Arguments("PubkeyAcceptedKeyTypes ssh-rsa")] // common in older configurations
    public async Task AConfigListThatLeavesNothing_OffersNoKey_ButIsNoError(string line)
    {
        // Unlike the other lists: an empty one means no key is offered, and the other methods still work (as they did in 1.0, before
        // the list was applied). The connection logs a warning naming the directive.
        var preferences = AlgorithmPreferences.FromConfig(Config(line + "\n"));
        await Assert.That(preferences.PublicKeys!).IsEmpty();
        await Assert.That(preferences.NoPublicKeyAlgorithm).IsTrue();
        await Assert.That(AlgorithmPreferences.FromConfig(Config("User x\n")).NoPublicKeyAlgorithm).IsFalse();
    }

    /// <summary>Records each entry's level and message.</summary>
    private sealed class TestLogger : Microsoft.Extensions.Logging.ILogger
    {
        public List<(Microsoft.Extensions.Logging.LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
            {
                Entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }

    private static SshConfigConnectOptions LegacyConfigOptions(FakeSessionServer server, SshPrivateKey key, string? password, TestLogger logger) => new()
    {
        Config = SshConfig.Parse("Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n PubkeyAcceptedKeyTypes ssh-rsa\n"),
        ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = Path.GetTempPath() },
        UseAgent = false,
        PrivateKeys = [key],
        Password = password,
        Logger = logger,
        TcpConnector = (_, _, _, _) =>
        {
            _ = server.StartAsync();
            return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
        },
    };

    [Test]
    public async Task PubkeyAcceptedKeyTypesSshRsa_StillLogsInWithAPassword()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        var password = Guid.NewGuid().ToString("N");
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"], AuthorizedKeys = [rsaBlob], Password = password };
        var logger = new TestLogger();
        await using var client = await SshClient.ConnectAsync("target.example.com", LegacyConfigOptions(server, rsa, password, logger), Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "password" }); // the key, which the server would take, was not offered

        // One warning, naming the directive, and neither the host nor the user.
        var warnings = logger.Entries.Where(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning).Select(e => e.Message).ToList();
        await Assert.That(warnings.Count).IsEqualTo(1);
        await Assert.That(warnings[0]).Contains("PubkeyAcceptedAlgorithms leaves no public key signature algorithm");
        await Assert.That(warnings[0]).DoesNotContain("target");
        await Assert.That(warnings[0]).DoesNotContain("tester");
    }

    [Test]
    public async Task PubkeyAcceptedKeyTypesSshRsa_WithOnlyKeys_ReportsEachKeyAsNoAcceptedAlgorithm()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [rsaBlob] };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(async () =>
            await SshClient.ConnectAsync("target.example.com", LegacyConfigOptions(server, rsa, password: null, new TestLogger()), Timeout()));

        await Assert.That(error!.Attempts.Single().Outcome).IsEqualTo(SshAuthenticationOutcome.NoAcceptedAlgorithm);
        await Assert.That(error.Attempts.Single().KeyFingerprint).IsEqualTo(rsa.Fingerprint);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none" });
    }

    [Test]
    public async Task AnUnusableAlgorithmList_FailsBeforeAnythingIsSent()
    {
        var connected = false;
        var error = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("target.example.com", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse("Host *\n User tester\n Ciphers aes128-cbc\n"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = Path.GetTempPath() },
            UseAgent = false,
            TcpConnector = (_, _, _, _) =>
            {
                connected = true;
                throw new SshException(SshFailureReason.ConnectFailed, "Not reached.");
            },
        }, Timeout()));

        await Assert.That(error!.Message).Contains("Ciphers leaves no cipher algorithm");
        await Assert.That(connected).IsFalse();
    }

    [Test]
    public async Task TheTypedList_IsChecked_AndCannotLeaveNothing()
    {
        await Assert.That(Options(SshAlgorithmList.Only("ssh-ed25519")).PubkeyAcceptedAlgorithms!.ToString()).IsEqualTo("ssh-ed25519");
        var unknown = await Assert.That(() => Options(SshAlgorithmList.Only("ssh-rsa"))).Throws<ArgumentException>();
        await Assert.That(unknown!.Message).Contains("public key signature algorithm");

        var error = await Assert.That(() => AlgorithmPreferences.FromOptions(Options(SshAlgorithmList.Remove("*")))).Throws<ArgumentException>();
        await Assert.That(error!.Message).Contains("SshClientOptions.PubkeyAcceptedAlgorithms leaves no public key signature algorithm");
    }

    [Test]
    public async Task FipsMode_DoesNotRestrictTheClientsKeys()
    {
        var preferences = AlgorithmPreferences.FromConfig(Config("PubkeyAcceptedAlgorithms ssh-ed25519\n"), fipsMode: true);
        await Assert.That(preferences.PublicKeys!).IsEquivalentTo(new[] { "ssh-ed25519" });
    }

    private static SshClientOptions Options(SshAlgorithmList? accepted = null) => new()
    {
        UserName = "tester",
        HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
        PubkeyAcceptedAlgorithms = accepted,
    };

    // ---- choosing the signature algorithm ----

    [Test]
    public async Task AnRsaKey_SignsWithTheFirstAllowedAlgorithmTheServerTakes()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out _));
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, BothRsa)).IsEqualTo("rsa-sha2-512"); // the key's own order
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, BothRsa, ["rsa-sha2-256", "rsa-sha2-512"])).IsEqualTo("rsa-sha2-256");
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, new Dictionary<string, string> { ["server-sig-algs"] = "rsa-sha2-512" },
            ["rsa-sha2-256", "rsa-sha2-512"])).IsEqualTo("rsa-sha2-512");
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, new Dictionary<string, string>(), ["rsa-sha2-256"])).IsEqualTo("rsa-sha2-256");
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, BothRsa, ["ssh-ed25519"])).IsNull();
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(rsa, new Dictionary<string, string>(), ["ssh-ed25519"])).IsNull(); // and without server-sig-algs
    }

    [Test]
    public async Task ACertifiedKey_NeedsItsCertificateAlgorithm()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var certified = key.WithCertificate(SshCertificate.FromBlob(TestKeys.Certificate(_authority, blob, SshCertificateType.User, ["tester"])));
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(certified, BothRsa, ["ssh-ed25519"])).IsNull();
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(certified, BothRsa, ["ssh-ed25519-cert-v01@openssh.com"]))
            .IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(key, BothRsa, ["ssh-ed25519-cert-v01@openssh.com"])).IsNull();
    }

    // ---- end to end ----

    [Test]
    public async Task OnlyKeysTheListAllows_AreOffered()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        using var ed25519 = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var edBlob));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [rsaBlob, edBlob] };
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [rsa, ed25519], // the RSA key, which the server would take, first
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            PubkeyAcceptedAlgorithms = SshAlgorithmList.Only("ssh-ed25519"),
        };
        await using var client = await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey-signed:ssh-ed25519" });
        await Assert.That(client.AcceptedKeys.Single()).IsSameReferenceAs(ed25519);
    }

    [Test]
    public async Task AKeyTheListRulesOut_IsReported_AndNotSent()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [rsaBlob] };
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [rsa],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            PubkeyAcceptedAlgorithms = SshAlgorithmList.Remove("rsa-*"),
        };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(async () =>
            await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout()));
        await Assert.That(error!.Attempts.Single(a => a.Method == "publickey").Outcome).IsEqualTo(SshAuthenticationOutcome.NoAcceptedAlgorithm);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none" });
    }

    [Test]
    public async Task FromSshConfig_TheListPicksTheRsaAlgorithm()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [rsaBlob] };
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse("Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n PubkeyAcceptedAlgorithms rsa-sha2-256,ssh-ed25519\n"),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = Path.GetTempPath() },
            UseAgent = false,
            PrivateKeys = [rsa],
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await Assert.That(Attempts(server)).Contains("publickey-signed:rsa-sha2-256");
        await Assert.That(Attempts(server)).DoesNotContain("publickey-signed:rsa-sha2-512");
    }

    // ---- other ssh_config algorithm lists ----

    [Test]
    [Arguments("Ciphers aes*-ctr", "aes256-ctr,aes192-ctr,aes128-ctr")]
    [Arguments("Ciphers ^aes128*", "aes128-gcm@openssh.com,aes128-ctr")]
    [Arguments("KexAlgorithms curve25519-sha256*", "curve25519-sha256,curve25519-sha256@libssh.org")]
    [Arguments("HostKeyAlgorithms ecdsa-sha2-nistp256*", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com")]
    public async Task WildcardsInAnyForm_StandForTheNamesTheyMatch(string line, string expectedStart)
    {
        var preferences = AlgorithmPreferences.FromConfig(Config(line + "\n"));
        var list = line.Split(' ')[0] switch
        {
            "Ciphers" => preferences.Ciphers,
            "KexAlgorithms" => preferences.Kex,
            _ => preferences.HostKeys,
        };
        await Assert.That(string.Join(",", list).StartsWith(expectedStart, StringComparison.Ordinal)).IsTrue();
        await Assert.That(list.Any(n => n.Contains('*', StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    [Arguments("Ciphers 3des-cbc,aes128-cbc", "Ciphers leaves no cipher algorithm")]
    [Arguments("KexAlgorithms -*", "KexAlgorithms leaves no key exchange algorithm")]
    [Arguments("MACs hmac-md5", "MACs leaves no MAC algorithm")]
    [Arguments("HostKeyAlgorithms ssh-dss", "HostKeyAlgorithms leaves no host key algorithm")]
    public async Task AConfigListThatLeavesNothing_FailsBeforeConnecting(string line, string message)
    {
        var error = await Assert.That(() => AlgorithmPreferences.FromConfig(Config(line + "\n"))).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.Message).Contains(message);
    }

    [Test]
    public async Task InFipsMode_TheErrorSaysSo()
    {
        var error = await Assert.That(() => AlgorithmPreferences.FromConfig(Config("Ciphers chacha20-poly1305@openssh.com\n"), fipsMode: true)).Throws<SshException>();
        await Assert.That(error!.Message).Contains("in FIPS mode");
    }

    // ---- host key algorithms with a trusted certificate authority ----

    private const string Ed25519Cert = "ssh-ed25519-cert-v01@openssh.com";

    [Test]
    public async Task ACertificateOnlyList_IsKeptAsWritten()
    {
        var fromConfig = AlgorithmPreferences.FromConfig(Config($"HostKeyAlgorithms {Ed25519Cert}\n")).WithCertificateHostKeysFirst();
        await Assert.That(fromConfig.HostKeys).IsEquivalentTo(new[] { Ed25519Cert });

        var typed = AlgorithmPreferences.FromOptions(new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            HostKeyAlgorithms = SshAlgorithmList.Only(Ed25519Cert),
        }).WithCertificateHostKeysFirst();
        await Assert.That(typed.HostKeys).IsEquivalentTo(new[] { Ed25519Cert });
    }

    [Test]
    public async Task AnExplicitOrder_IsNotRewritten()
    {
        var plain = AlgorithmPreferences.FromConfig(Config("HostKeyAlgorithms rsa-sha2-256,ssh-ed25519\n")).WithCertificateHostKeysFirst();
        await Assert.That(string.Join(",", plain.HostKeys)).IsEqualTo("rsa-sha2-256,ssh-ed25519");

        var mixed = AlgorithmPreferences.FromConfig(Config($"HostKeyAlgorithms ssh-ed25519,{Ed25519Cert}\n")).WithCertificateHostKeysFirst();
        await Assert.That(string.Join(",", mixed.HostKeys)).IsEqualTo($"ssh-ed25519,{Ed25519Cert}");

        var first = AlgorithmPreferences.FromConfig(Config("HostKeyAlgorithms ^rsa-sha2-256\n")).WithCertificateHostKeysFirst();
        await Assert.That(first.HostKeys[0]).IsEqualTo("rsa-sha2-256");
        await Assert.That(first.HostKeys.Any(SshCertificate.IsCertificateAlgorithm)).IsFalse();
    }

    [Test]
    public async Task TheDefaultsAndPlusOrMinusChanges_AskForCertificatesFirst()
    {
        var defaults = AlgorithmPreferences.FromConfig(Config("User x\n")).WithCertificateHostKeysFirst();
        await Assert.That(defaults.HostKeys[0]).IsEqualTo(Ed25519Cert);

        // As in ssh, whose defaults hold the certificate algorithms: '-ssh-ed25519' removes that name only, not its certificate algorithm.
        var removed = AlgorithmPreferences.FromConfig(Config("HostKeyAlgorithms -ssh-ed25519\n")).WithCertificateHostKeysFirst();
        await Assert.That(removed.HostKeys[0]).IsEqualTo(Ed25519Cert);
        await Assert.That(removed.HostKeys.Contains("ssh-ed25519")).IsFalse();

        var both = AlgorithmPreferences.FromConfig(Config($"HostKeyAlgorithms -ssh-ed25519,{Ed25519Cert}\n")).WithCertificateHostKeysFirst();
        await Assert.That(both.HostKeys.Contains(Ed25519Cert)).IsFalse();
        await Assert.That(both.HostKeys[0]).IsEqualTo("ecdsa-sha2-nistp256-cert-v01@openssh.com");

        // A '-' pattern removes certificate algorithms too, as it would from ssh's defaults, which hold them.
        var noCertificates = AlgorithmPreferences.FromConfig(Config("HostKeyAlgorithms -*-cert-v01@openssh.com\n")).WithCertificateHostKeysFirst();
        await Assert.That(noCertificates.HostKeys.Any(SshCertificate.IsCertificateAlgorithm)).IsFalse();

        var added = AlgorithmPreferences.FromConfig(Config("HostKeyAlgorithms +rsa-sha2-256\n")).WithCertificateHostKeysFirst();
        await Assert.That(added.HostKeys[0]).IsEqualTo(Ed25519Cert);
    }

    [Test]
    public async Task InFipsMode_AnApprovedCertificateAlgorithm_IsKept()
    {
        var preferences = AlgorithmPreferences.FromOptions(new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            HostKeyAlgorithms = SshAlgorithmList.Only("ecdsa-sha2-nistp256-cert-v01@openssh.com", Ed25519Cert),
            FipsMode = true,
        });
        await Assert.That(preferences.HostKeys).IsEquivalentTo(new[] { "ecdsa-sha2-nistp256-cert-v01@openssh.com" });

        // Certificate algorithms added for a trusted authority are approved ones too: no Ed25519 certificate after a '-' list.
        var removal = AlgorithmPreferences.FromOptions(new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            HostKeyAlgorithms = SshAlgorithmList.Remove("rsa-sha2-256"),
            FipsMode = true,
        }).WithCertificateHostKeysFirst();
        await Assert.That(removal.HostKeys.Contains(Ed25519Cert)).IsFalse();
        await Assert.That(removal.HostKeys.Contains("rsa-sha2-256-cert-v01@openssh.com")).IsTrue();
        await Assert.That(AlgorithmPreferences.Fips().WithCertificateHostKeysFirst().HostKeys.Contains(Ed25519Cert)).IsFalse();
    }
}
