using System.Security.Cryptography;
using SshSharp.Tests.Agent;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Public-key authentication end to end against the fake server, which verifies signatures like sshd.</summary>
public class PublicKeyAuthTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, IReadOnlyList<SshPrivateKey> keys, string? password = null)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = password,
            PrivateKeys = keys,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    public static IEnumerable<Func<(string Pem, byte[] Blob)>> Keys()
    {
        yield return () => (TestKeys.OpenSshEd25519(out var blob), blob);
        yield return () => (TestKeys.OpenSshEcdsa(ECCurve.NamedCurves.nistP256, "nistp256", out var blob), blob);
        yield return () => (TestKeys.OpenSshEcdsa(ECCurve.NamedCurves.nistP521, "nistp521", out var blob), blob);
        yield return () => (TestKeys.OpenSshRsa(2048, out var blob), blob);
    }

    [Test]
    [MethodDataSource(nameof(Keys))]
    public async Task EachKeyTypeAuthenticates_SigningStraightAway((string Pem, byte[] Blob) generated)
    {
        using var key = SshPrivateKey.Parse(generated.Pem);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [generated.Blob] };
        await using var client = await ConnectAsync(server, [key]);
        var result = await client.RunCommandAsync("whoami", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);

        // none, then the signed request at once: a key held in this process is not offered first. RSA uses SHA-512 when the server
        // offers it.
        var algorithm = key.KeyType == "ssh-rsa" ? "rsa-sha2-512" : key.KeyType;
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey-signed:" + algorithm });
        await Assert.That(Requests(server)).IsEquivalentTo(new[] { "signed:" + algorithm });
    }

    [Test]
    public async Task RefusedLocalKeys_FallThroughToTheNextKey_ThenThePassword()
    {
        using var stranger = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var known = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var knownBlob));

        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"], AuthorizedKeys = [knownBlob] })
        {
            await using var client = await ConnectAsync(server, [stranger, known]);
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey", "publickey-signed:ssh-ed25519" });
            await Assert.That(Requests(server)).IsEquivalentTo(new[] { "signed:ssh-ed25519", "signed:ssh-ed25519" });
        }

        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"] })
        {
            await using var client = await ConnectAsync(server, [stranger], password: "secret");
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "password" });
        }
    }

    [Test]
    public async Task AgentKeys_AreOfferedFirst_AndSignOnlyWhenAccepted()
    {
        // An agent's key may ask the user to confirm, or need a touch: it signs only for a key the server said it would take.
        await using var agent = new FakeAgent();
        using var stranger = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var known = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var knownBlob));
        agent.Keys.Add((stranger, "stranger"));
        agent.Keys.Add((known, "known"));
        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [knownBlob] };

        await using var client = await ConnectAsync(server, keys);

        await Assert.That(Requests(server)).IsEquivalentTo(new[] { "query:ssh-ed25519", "query:ssh-ed25519", "signed:ssh-ed25519" });
        await Assert.That(agent.SignFlags.Count).IsEqualTo(1);
    }

    [Test]
    public async Task SignerKeys_AreOfferedFirst_AndSignOnlyWhenAccepted()
    {
        // A key service (KMS, HSM) costs a remote call or a PIN per signature: none for a key the server would refuse.
        using var stranger = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var known = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var knownBlob));
        var strangerSigner = new AgentServerTests.KeySigner(stranger);
        var knownSigner = new AgentServerTests.KeySigner(known);
        using var strangerKey = SshPrivateKey.FromSigner(strangerSigner);
        using var knownKey = SshPrivateKey.FromSigner(knownSigner);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [knownBlob] };

        await using var client = await ConnectAsync(server, [strangerKey, knownKey]);

        await Assert.That(Requests(server)).IsEquivalentTo(new[] { "query:ssh-ed25519", "query:ssh-ed25519", "signed:ssh-ed25519" });
        await Assert.That(strangerSigner.Requests).IsEmpty();
        await Assert.That(knownSigner.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ALocalKey_SignsHostBoundStraightAway()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var hostBound = new FakeServerOptions { ExtraExtensions = new Dictionary<string, string> { ["publickey-hostbound@openssh.com"] = "0" } };
        await using var server = new FakeSessionServer(hostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };

        await using var client = await ConnectAsync(server, [key]);

        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey-hostbound-v00@openssh.com", "publickey-hostbound-signed:ssh-ed25519" });
        await Assert.That(Requests(server)).IsEquivalentTo(new[] { "signed:ssh-ed25519" });
        await Assert.That(server.HostBoundKeys.Single()).IsEquivalentTo(client.HostKey.PublicKey.ToArray());
    }

    [Test]
    public async Task RsaFallsBackToSha256_AndIsSkippedWhenTheServerTakesNeither()
    {
        using var rsa = SshPrivateKey.Parse(TestKeys.OpenSshRsa(2048, out var blob));
        await using (var server = new FakeSessionServer(new FakeServerOptions { ServerSigAlgs = "ssh-ed25519,rsa-sha2-256" }) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] })
        {
            await using var client = await ConnectAsync(server, [rsa]);
            await Assert.That(Attempts(server).Last()).IsEqualTo("publickey-signed:rsa-sha2-256");
        }

        // Only SHA-1 "ssh-rsa": the key is never offered, and authentication fails cleanly with the server's methods.
        await using (var server = new FakeSessionServer(new FakeServerOptions { ServerSigAlgs = "ssh-ed25519,ssh-rsa" }) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] })
        {
            var ex = await Assert.ThrowsAsync<SshAuthenticationException>(async () => await ConnectAsync(server, [rsa]));
            await Assert.That(ex!.AllowedMethods).IsEquivalentTo(new[] { "publickey" });
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none" });
        }
    }

    [Test]
    public async Task PartialSuccess_KeyThenPassword()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob], RequirePasswordAfterPublicKey = true };
        await using var client = await ConnectAsync(server, [key], password: "secret");
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey-signed:ssh-ed25519", "password" });
    }

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }

    private static string[] Requests(FakeSessionServer server)
    {
        lock (server.PublicKeyRequests)
        {
            return [.. server.PublicKeyRequests];
        }
    }
}
