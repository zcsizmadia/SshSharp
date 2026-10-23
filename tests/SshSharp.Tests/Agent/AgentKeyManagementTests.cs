using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>Adding, removing and locking agent keys (ssh-add), and AddKeysToAgent.</summary>
public sealed class AgentKeyManagementTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-agentkeys-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    public static IEnumerable<Func<SshKeyType>> Types() =>
        [() => SshKeyType.Ed25519, () => SshKeyType.EcdsaNistp256, () => SshKeyType.EcdsaNistp384, () => SshKeyType.EcdsaNistp521, () => SshKeyType.Rsa];

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task AnAddedKey_IsListed_AndSignsThroughTheAgent(SshKeyType type)
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var key = SshPrivateKey.Generate(type, "added@example", 2048);

        await agent.AddKeyAsync(key, cancellationToken: Timeout());

        var held = (await agent.GetKeysAsync(Timeout())).Single();
        await Assert.That(held.PublicKey.ToArray().SequenceEqual(key.PublicKey.ToArray())).IsTrue();
        await Assert.That(held.Comment).IsEqualTo("added@example");
        var signature = await SshSignature.SignAsync(held, "through the agent"u8.ToArray(), "file", cancellationToken: Timeout());
        await Assert.That(signature.Verify("through the agent"u8, "file")).IsTrue();
        await Assert.That(fake.AddRequests.Single().LifetimeSeconds).IsNull();
        await Assert.That(fake.AddRequests.Single().Confirm).IsFalse();
    }

    [Test]
    public async Task Constraints_AreSent()
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);

        await agent.AddKeyAsync(key, new SshAgentKeyConstraints { Lifetime = TimeSpan.FromMinutes(90), Confirm = true }, Timeout());

        await Assert.That(fake.AddRequests.Single().LifetimeSeconds).IsEqualTo(5400u);
        await Assert.That(fake.AddRequests.Single().Confirm).IsTrue();
        await Assert.That(() => new SshAgentKeyConstraints { Lifetime = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(SshKeyType.Ed25519, 2)]
    [Arguments(SshKeyType.EcdsaNistp256, 1)]
    [Arguments(SshKeyType.Rsa, 4)]
    public async Task AKeyWithACertificate_IsAddedAsTheCertificateAndTheFieldsItLacks(SshKeyType type, int privateFields)
    {
        await using var fake = new FakeAgent();
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(type, rsaBits: 2048);
        var certificate = SshCertificate.Parse(TestKeys.CertificateLine(
            TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User, ["tester"])));
        using var certified = key.WithCertificate(certificate);

        await new SshAgent(fake.Path).AddKeyAsync(certified, cancellationToken: Timeout());

        // PROTOCOL.certkeys: string certificate, then only the private fields (Ed25519: ENC(A) and k || ENC(A); ECDSA: d; RSA: d, iqmp, p, q).
        var added = fake.AddRequests.Single();
        await Assert.That(added.KeyType).IsEqualTo(certificate.Algorithm);
        static (bool CertificateFirst, bool NothingLeft) Layout(byte[] fields, byte[] certificateBlob, int count)
        {
            var reader = new SshReader(fields);
            var first = reader.ReadString().SequenceEqual(certificateBlob);
            for (var i = 0; i < count; i++)
            {
                reader.ReadString();
            }

            return (first, reader.IsEmpty);
        }

        var (certificateFirst, nothingLeft) = Layout(added.Fields, certificate.Blob.ToArray(), privateFields);
        await Assert.That(certificateFirst).IsTrue();
        await Assert.That(nothingLeft).IsTrue();
    }

    [Test]
    public async Task Remove_RemoveAll_Lock_AndUnlock()
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var first = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var second = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        await agent.AddKeyAsync(first, cancellationToken: Timeout());
        await agent.AddKeyAsync(second, cancellationToken: Timeout());

        await agent.RemoveKeyAsync(first, Timeout());
        await Assert.That((await agent.GetKeysAsync(Timeout())).Count).IsEqualTo(1);
        await Assert.That(async () => await agent.RemoveKeyAsync(first, Timeout())).Throws<SshException>();

        // Locked, the agent lists nothing and takes no keys; the wrong passphrase does not unlock it.
        var lockPassphrase = TestSecrets.New();
        await agent.LockAsync(lockPassphrase, Timeout());
        await Assert.That(await agent.GetKeysAsync(Timeout())).IsEmpty();
        await Assert.That(async () => await agent.AddKeyAsync(first, cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(async () => await agent.UnlockAsync(TestSecrets.New(), Timeout())).Throws<SshException>();
        await agent.UnlockAsync(lockPassphrase, Timeout());
        await Assert.That((await agent.GetKeysAsync(Timeout())).Count).IsEqualTo(1);

        await agent.RemoveAllKeysAsync(Timeout());
        await Assert.That(await agent.GetKeysAsync(Timeout())).IsEmpty();
    }

    [Test]
    public async Task AKeyHeldByAnAgent_CannotBeAddedAgain()
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await agent.AddKeyAsync(key, cancellationToken: Timeout());
        var held = (await agent.GetKeysAsync(Timeout())).Single();

        await Assert.That(async () => await agent.AddKeyAsync(held, cancellationToken: Timeout())).Throws<NotSupportedException>();
    }

    [Test]
    [Arguments("yes", true, false, null)]
    [Arguments("Yes", true, false, null)]
    [Arguments("confirm", true, true, null)]
    [Arguments("confirm 1h", true, true, 3600)]
    [Arguments("yes 30m", true, false, 1800)]
    [Arguments("1h30m", true, false, 5400)]
    [Arguments("no", false, false, null)]
    [Arguments("ask", false, false, null)]
    [Arguments("maybe", false, false, null)]
    [Arguments("yes nonsense", false, false, null)]
    public async Task AddKeysToAgent_IsParsedAsSshConfigHasIt(string value, bool add, bool confirm, int? seconds)
    {
        var host = SshConfig.Parse($"Host *\n AddKeysToAgent {value}\n").Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir });

        await Assert.That(host.AddKeysToAgent is not null).IsEqualTo(add);
        if (host.AddKeysToAgent is { } constraints)
        {
            await Assert.That(constraints.Confirm).IsEqualTo(confirm);
            await Assert.That(constraints.Lifetime).IsEqualTo(seconds is { } s ? TimeSpan.FromSeconds(s) : null);
        }
    }

    [Test]
    public async Task AddKeysToAgent_AddsTheIdentityFileKeyTheServerAccepted()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "deploy@example");
        var identity = Path.Combine(_dir, "id_ed25519");
        await key.SaveAsync(identity);
        await using var fake = new FakeAgent();
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [key.PublicKey.ToArray()] };
        var config = $"Host *\n User tester\n IdentityFile \"{identity}\"\n IdentityAgent \"{fake.Path}\"\n AddKeysToAgent confirm 1h\n"
            + " StrictHostKeyChecking no\n UserKnownHostsFile none\n";

        await using (var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout()))
        {
            await Assert.That(client.IsConnected).IsTrue();
        }

        var added = fake.AddRequests.Single();
        await Assert.That(added.Confirm).IsTrue();
        await Assert.That(added.LifetimeSeconds).IsEqualTo(3600u);
        await Assert.That(fake.Keys.Single().Key.PublicKey.ToArray().SequenceEqual(key.PublicKey.ToArray())).IsTrue();
    }

    [Test]
    public async Task AddKeysToAgent_LeavesTheCallersOwnKeysAlone()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "in-memory@example");
        await using var fake = new FakeAgent();
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [key.PublicKey.ToArray()] };
        var config = $"Host *\n User tester\n IdentityAgent \"{fake.Path}\"\n AddKeysToAgent yes\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";

        await using (var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            PrivateKeys = [key],
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout()))
        {
            await Assert.That(client.IsConnected).IsTrue();
        }

        await Assert.That(fake.AddRequests).IsEmpty();
    }

    [Test]
    public async Task AnAgentKeyWithACertificate_CannotBeAdded()
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await agent.AddKeyAsync(key, cancellationToken: Timeout());
        var held = (await agent.GetKeysAsync(Timeout())).Single();
        var certificate = SshCertificate.Parse(TestKeys.CertificateLine(
            TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User, ["tester"])));

        await Assert.That(async () => await agent.AddKeyAsync(held.WithCertificate(certificate), cancellationToken: Timeout())).Throws<NotSupportedException>();
    }
}
