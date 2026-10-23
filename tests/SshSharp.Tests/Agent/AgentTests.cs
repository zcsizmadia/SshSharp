using System.Buffers;
using System.Security.Cryptography;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>Keys held by an SSH agent: listing them, authenticating with them, and how config connect picks them.</summary>
public sealed class AgentTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-agent-" + Guid.NewGuid().ToString("N"));

    public AgentTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, IReadOnlyList<SshPrivateKey> keys)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = keys,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private static string[] SignedAttempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts.Where(a => a.StartsWith("publickey-signed", StringComparison.Ordinal))];
        }
    }

    private static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    [Test]
    public async Task TheAgentsKeys_AreListedWithTheirComments_AndUnsupportedTypesLeftOut()
    {
        await using var agent = new FakeAgent();
        using var ed25519 = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var ecdsa = SshPrivateKey.Parse(TestKeys.OpenSshEcdsa(ECCurve.NamedCurves.nistP384, "nistp384", out _));
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out _));
        agent.Keys.AddRange([(ed25519, "laptop"), (ecdsa, "yubikey slot"), (rsa, "old rsa")]);
        agent.RawIdentities.Add(Blob(w => { w.WriteString("ssh-dss"); w.WriteString(new byte[20]); }));
        agent.RawIdentities.Add(Blob(w => w.WriteString("sk-ssh-ed25519@openssh.com")));
        agent.RawIdentities.Add([1, 2]); // not even a key type

        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());
        await Assert.That(keys.Select(k => k.KeyType)).IsEquivalentTo(new[] { "ssh-ed25519", "ecdsa-sha2-nistp384", "ssh-rsa", "sk-ssh-ed25519@openssh.com" });
        await Assert.That(keys.Select(k => k.Comment ?? "")).IsEquivalentTo(new[] { "laptop", "yubikey slot", "old rsa", "raw" });
        await Assert.That(keys[0].Fingerprint).IsEqualTo(ed25519.Fingerprint);
        await Assert.That(() => keys[0].ToAuthorizedKeysLine()).ThrowsNothing();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task QueryExtensions_ListsWhatTheAgentSupports(bool replyWithSuccess)
    {
        // RFC 9987 section 5.8.1; older OpenSSH agents answer with SSH_AGENT_SUCCESS instead of SSH_AGENT_EXTENSION_RESPONSE.
        await using var agent = new FakeAgent
        {
            Extensions = ["session-bind@openssh.com", "query"],
            QueryRepliesWithSuccess = replyWithSuccess,
        };
        var extensions = await new SshAgent(agent.Path).QueryExtensionsAsync(Timeout());
        await Assert.That(extensions).IsEquivalentTo(new[] { "session-bind@openssh.com", "query" });
    }

    [Test]
    public async Task QueryExtensions_IsEmpty_ForAnAgentWithoutIt()
    {
        await using var agent = new FakeAgent(); // answers SSH_AGENT_FAILURE, as RFC 9987 requires for unknown extensions
        await Assert.That(await new SshAgent(agent.Path).QueryExtensionsAsync(Timeout())).IsEmpty();
    }

    [Test]
    public async Task SecurityKeyCertificates_AreOfferedAsTheyAre_UnderTheirCertificateAlgorithm()
    {
        // The agent and the key's touch make the signature and the server checks the certificate, so the client passes it on unopened.
        await using var agent = new FakeAgent();
        agent.RawIdentities.Add(Blob(w => { w.WriteString("sk-ssh-ed25519-cert-v01@openssh.com"); w.WriteString(new byte[32]); }));
        agent.RawIdentities.Add(Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"); w.WriteString(new byte[32]); }));

        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());
        await Assert.That(keys.Select(k => k.KeyType)).IsEquivalentTo(new[]
        {
            "sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        });

        // server-sig-algs lists the plain security-key algorithms, which keep their @openssh.com domain.
        var extensions = new Dictionary<string, string> { ["server-sig-algs"] = "ssh-ed25519,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com" };
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(keys[0], extensions)).IsEqualTo("sk-ssh-ed25519-cert-v01@openssh.com");
        await Assert.That(SshUserAuth.ChooseSignatureAlgorithm(keys[1], extensions)).IsEqualTo("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com");
    }

    [Test]
    [Arguments("sk-ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519@openssh.com")]
    [Arguments("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")]
    public async Task ASecurityKeyCertificate_SignsThroughTheAgent_UnderItsPlainAlgorithm(string certificateType, string plainAlgorithm)
    {
        // The agent signs with the certificate's plain security-key algorithm (the name keeps its @openssh.com domain); the client must
        // ask for that and accept it. Before the name mapping was fixed, it expected "sk-ssh-ed25519" and every such signature failed.
        var blob = Blob(w => { w.WriteString(certificateType); w.WriteString(new byte[32]); });
        await using var agent = new FakeAgent { ClaimAlgorithm = plainAlgorithm };
        agent.RawIdentities.Add(blob);
        var key = (await new SshAgent(agent.Path).GetKeysAsync(Timeout())).Single();

        var signature = await key.SignAsync(new SshSignRequest(certificateType, new byte[] { 1, 2, 3 }, SshSignaturePurpose.Authentication), null, Timeout());
        await Assert.That(new SshReader(signature).ReadUtf8String()).IsEqualTo(plainAlgorithm);
        await Assert.That(agent.LastSignedBlob).IsEquivalentTo(blob); // the certificate itself was sent to the agent

        // An agent that signs with anything else is caught here, not by the server.
        agent.ClaimAlgorithm = "ssh-ed25519";
        var error = await Assert.ThrowsAsync<SshException>(async () => await key.SignAsync(new SshSignRequest(certificateType, new byte[] { 1, 2, 3 }, SshSignaturePurpose.Authentication), null, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);
    }

    [Test]
    [Arguments("ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519")]
    [Arguments("rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-512")]
    [Arguments("sk-ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519@openssh.com")]
    [Arguments("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")]
    public async Task CertificateAlgorithms_MapToTheirPlainAlgorithm_AndBack(string certificate, string plain)
    {
        await Assert.That(SshCertificate.BaseAlgorithm(certificate)).IsEqualTo(plain);
        var expectedKeyType = plain.StartsWith("rsa-", StringComparison.Ordinal) ? "ssh-rsa-cert-v01@openssh.com" : certificate;
        await Assert.That(SshCertificate.CertificateKeyType(certificate)).IsEqualTo(expectedKeyType);
    }

    [Test]
    public async Task EachKeyType_AuthenticatesThroughTheAgent_RsaWithSha512()
    {
        await using var agent = new FakeAgent();
        using var ed25519 = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var edBlob));
        using var ecdsa = SshPrivateKey.Parse(TestKeys.OpenSshEcdsa(ECCurve.NamedCurves.nistP256, "nistp256", out var ecBlob));
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var rsaBlob));
        agent.Keys.AddRange([(ed25519, "a"), (ecdsa, "b"), (rsa, "c")]);
        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());

        foreach (var (blob, expected) in new[] { (edBlob, "ssh-ed25519"), (ecBlob, "ecdsa-sha2-nistp256"), (rsaBlob, "rsa-sha2-512") })
        {
            await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };
            await using var client = await ConnectAsync(server, keys);
            await Assert.That(SignedAttempts(server)).IsEquivalentTo(new[] { "publickey-signed:" + expected });
        }

        // The RSA request asked for SHA-512 (SSH_AGENT_RSA_SHA2_512); the others carried no flags.
        await Assert.That(agent.SignFlags).IsEquivalentTo(new uint[] { 0, 0, 4 });
    }

    [Test]
    public async Task ACertificateInTheAgent_OrAFileCertificateForAnAgentKey_Authenticates()
    {
        using var authority = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, blob, SshCertificateType.User, ["tester"]));

        // ssh-add adds id_ed25519-cert.pub along with the key: the agent lists the certificate.
        await using (var agent = new FakeAgent())
        {
            agent.Keys.Add((key.WithCertificate(certificate), "cert"));
            var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());
            await Assert.That(keys.Single().Certificate).IsNotNull();
            await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], TrustedUserAuthority = authority.PublicKey.ToArray() };
            await using var client = await ConnectAsync(server, keys);
            await Assert.That(SignedAttempts(server)).IsEquivalentTo(new[] { "publickey-signed:ssh-ed25519-cert-v01@openssh.com" });
        }

        // The agent has only the key; the certificate comes from a file.
        await using (var agent = new FakeAgent())
        {
            agent.Keys.Add((key, "plain"));
            var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());
            await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], TrustedUserAuthority = authority.PublicKey.ToArray() };
            await using var client = await ConnectAsync(server, [keys.Single().WithCertificate(certificate)]);
            await Assert.That(SignedAttempts(server)).IsEquivalentTo(new[] { "publickey-signed:ssh-ed25519-cert-v01@openssh.com" });
        }
    }

    [Test]
    public async Task AKeyTheAgentWillNotSignWith_IsSkipped_AndTheNextOneTried()
    {
        await using var agent = new FakeAgent();
        using var declined = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var declinedBlob));
        using var fine = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var fineBlob));
        agent.Keys.AddRange([(declined, "confirm"), (fine, "ok")]);
        agent.RefuseToSign.Add(declined.Fingerprint);
        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());

        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [declinedBlob, fineBlob] };
        await using var client = await ConnectAsync(server, keys);
        await Assert.That(SignedAttempts(server).Length).IsEqualTo(1);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AnAgentThatSignsWithTheWrongAlgorithm_IsCaught()
    {
        // An old agent that ignores the SHA-2 flags signs RSA with SHA-1, which the server would refuse.
        await using var agent = new FakeAgent { ClaimAlgorithm = "ssh-rsa" };
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var blob));
        agent.Keys.Add((rsa, "rsa"));
        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());

        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };
        await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, keys));
        await Assert.That(SignedAttempts(server)).IsEmpty();
    }

    [Test]
    public async Task AgentKeys_SignOnlyAsynchronously_AndOnlyWithTheirOwnAlgorithms()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        agent.Keys.Add((key, "k"));
        var held = (await new SshAgent(agent.Path).GetKeysAsync(Timeout())).Single();
        await Assert.That(() => held.Sign("ssh-ed25519", [1])).Throws<NotSupportedException>();
        await Assert.That(async () => await held.SignAsync(new SshSignRequest("rsa-sha2-256", new byte[] { 1 }, SshSignaturePurpose.Authentication), null, Timeout())).Throws<ArgumentException>();
        held.Dispose(); // nothing to clear; the agent keeps the key
        await Assert.That((await held.SignAsync(new SshSignRequest("ssh-ed25519", new byte[] { 1 }, SshSignaturePurpose.Authentication), null, Timeout())).Length).IsGreaterThan(64);
    }

    [Test]
    public async Task NoAgent_OrABrokenOne_FailsWithAgentFailed()
    {
        var missing = new SshAgent(Path.Combine(_dir, "no-such-socket"));
        var error = await Assert.ThrowsAsync<SshException>(() => missing.GetKeysAsync(Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);

        // Longer than any platform allows for a socket path (macOS: 104 bytes): reported the same way, not as an argument error.
        var tooLong = new SshAgent(Path.Combine(_dir, new string('a', 120)));
        error = await Assert.ThrowsAsync<SshException>(() => tooLong.GetKeysAsync(Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);

        // A pipe that does not exist fails at once (on other systems, pipes are not a transport at all).
        var pipe = new SshAgent(@"\\.\pipe\sshsharp-no-such-agent-" + Guid.NewGuid().ToString("N"));
        var started = System.Diagnostics.Stopwatch.StartNew();
        error = await Assert.ThrowsAsync<SshException>(() => pipe.GetKeysAsync(Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);
        await Assert.That(started.Elapsed).IsLessThan(TimeSpan.FromSeconds(2));

        // The messages, which the client logs, never name the socket or pipe: its path can hold the user's name (Pageant's does).
        foreach (var agent in new[] { missing, tooLong, pipe })
        {
            error = await Assert.ThrowsAsync<SshException>(() => agent.GetKeysAsync(Timeout()));
            await Assert.That(error!.Message).DoesNotContain(Path.GetFileName(agent.Path));
            await Assert.That(error.Message).DoesNotContain(_dir);
        }

        byte[][] brokenReplies =
        [
            [0, 0, 0, 1, 5], // SSH_AGENT_FAILURE to the listing
            [0, 0, 0, 0], // an empty message
            [0, 0x10, 0, 0], // a 1 MiB message
            [0, 0, 0, 5, 12, 0, 0, 0x08, 0x01], // 2049 keys
            [0, 0, 0, 9, 12, 0, 0, 0, 1, 0, 0, 0, 9], // a key blob cut short
            [0, 0, 0, 2], // the connection ends mid-message
        ];
        foreach (var reply in brokenReplies)
        {
            await using var agent = new FakeAgent { RawReply = reply };
            error = await Assert.ThrowsAsync<SshException>(() => new SshAgent(agent.Path).GetKeysAsync(Timeout()));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);
        }
    }

    [Test]
    public async Task TheAgentFromTheEnvironment_IsSshAuthSock_OrTheWindowsService()
    {
        await Assert.That(SshAgent.FromSocketVariable("/tmp/ssh-x/agent.1", windows: false)!.Path).IsEqualTo("/tmp/ssh-x/agent.1");
        await Assert.That(SshAgent.FromSocketVariable(null, windows: false)).IsNull();
        await Assert.That(SshAgent.FromSocketVariable("", windows: true)!.Path).IsEqualTo(@"\\.\pipe\openssh-ssh-agent");
        await Assert.That(() => new SshAgent("")).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(null, "env")]
    [Arguments("IdentityAgent SSH_AUTH_SOCK\n", "env")]
    [Arguments("IdentityAgent none\n", null)]
    [Arguments("IdentityAgent /run/agent.sock\n", "/run/agent.sock")]
    public async Task ConfigConnect_PicksTheAgentLikeSsh(string? config, string? expected)
    {
        var hostConfig = SshConfig.Parse(config ?? "").Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir });
        var fromEnvironment = new SshAgent("env");
        await Assert.That((await SshClient.ResolveAgentAsync(hostConfig, new SshConfigConnectOptions(), () => ValueTask.FromResult<SshAgent?>(fromEnvironment)))?.Path).IsEqualTo(expected);
        await Assert.That(await SshClient.ResolveAgentAsync(hostConfig, new SshConfigConnectOptions { UseAgent = false }, () => ValueTask.FromResult<SshAgent?>(fromEnvironment))).IsNull();
        await Assert.That((await SshClient.ResolveAgentAsync(hostConfig, new SshConfigConnectOptions { Agent = new SshAgent("given") }, () => ValueTask.FromResult<SshAgent?>(fromEnvironment)))!.Path).IsEqualTo("given");
    }

    [Test]
    public async Task ConfigConnect_UsesTheAgentForAnEncryptedIdentityFile_AndIdentitiesOnlyLeavesOtherAgentKeysOut()
    {
        // id_ed25519 is encrypted and there is no passphrase provider, but the agent holds the key: no passphrase is needed.
        using var identity = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var identityBlob));
        using var other = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var otherBlob));
        var identityPath = Path.Combine(_dir, "id_ed25519");
        File.WriteAllText(identityPath, "-----BEGIN OPENSSH PRIVATE KEY-----\nnot readable without the agent\n-----END OPENSSH PRIVATE KEY-----\n");
        File.WriteAllText(identityPath + ".pub", identity.ToAuthorizedKeysLine());

        await using var agent = new FakeAgent();
        agent.Keys.AddRange([(other, "other"), (identity, "identity")]);

        async Task<FakeSessionServer> ConnectByConfigAsync(bool identitiesOnly)
        {
            var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [identityBlob] };
            var config = $"Host *\n User tester\n IdentityFile \"{identityPath}\"\n IdentityAgent \"{agent.Path}\"\n IdentitiesOnly {(identitiesOnly ? "yes" : "no")}\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
            await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse(config),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                TcpConnector = (_, _, _, _) =>
                {
                    _ = server.StartAsync();
                    return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                },
            }, Timeout());
            return server;
        }

        // The identity file's key is offered first, so it is the only one the server is asked about.
        await using (var server = await ConnectByConfigAsync(identitiesOnly: false))
        {
            await Assert.That(SignedAttempts(server).Length).IsEqualTo(1);
            await Assert.That(server.AuthAttempts.Count(a => a == "publickey")).IsEqualTo(2);
        }

        // With IdentitiesOnly the other agent key is never offered, even where the identity is refused.
        var refusing = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [otherBlob] };
        await using (refusing)
        {
            var config = $"Host *\n User tester\n IdentityFile \"{identityPath}\"\n IdentityAgent \"{agent.Path}\"\n IdentitiesOnly yes\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
            await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse(config),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                TcpConnector = (_, _, _, _) =>
                {
                    _ = refusing.StartAsync();
                    return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((refusing.ClientStream, null));
                },
            }, Timeout()));
            await Assert.That(refusing.AuthAttempts.Count(a => a == "publickey")).IsEqualTo(1);
        }

        // Without IdentitiesOnly the same server accepts the other agent key.
        var accepting = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [otherBlob] };
        await using (accepting)
        {
            var config = $"Host *\n User tester\n IdentityFile \"{identityPath}\"\n IdentityAgent \"{agent.Path}\"\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
            await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse(config),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                TcpConnector = (_, _, _, _) =>
                {
                    _ = accepting.StartAsync();
                    return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((accepting.ClientStream, null));
                },
            }, Timeout());
            await Assert.That(SignedAttempts(accepting).Length).IsEqualTo(1);
        }
    }

    [Test]
    public async Task ConfigConnect_CarriesOnWithoutAnAgent()
    {
        await using var server = new FakeSessionServer();
        var config = $"Host *\n User tester\n IdentityAgent \"{Path.Combine(_dir, "nothing-here")}\"\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = TestSecrets.Password,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }
}
