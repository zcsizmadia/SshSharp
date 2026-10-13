using System.Security.Cryptography;
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
    public async Task EachKeyTypeAuthenticates_AfterAskingFirst((string Pem, byte[] Blob) generated)
    {
        using var key = SshPrivateKey.Parse(generated.Pem);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [generated.Blob] };
        await using var client = await ConnectAsync(server, [key]);
        var result = await client.RunCommandAsync("whoami", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);

        // none, then a query without signature, then the signed request; RSA uses SHA-512 when the server offers it.
        var attempts = Attempts(server);
        await Assert.That(attempts[0]).IsEqualTo("none");
        await Assert.That(attempts.Count(a => a == "publickey")).IsEqualTo(2);
        await Assert.That(attempts.Last()).IsEqualTo("publickey-signed:" + (key.KeyType == "ssh-rsa" ? "rsa-sha2-512" : key.KeyType));
    }

    [Test]
    public async Task RefusedKeysAreSkippedWithoutSigning_ThenTheNextKey_ThenThePassword()
    {
        using var stranger = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        using var known = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var knownBlob));

        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"], AuthorizedKeys = [knownBlob] })
        {
            await using var client = await ConnectAsync(server, [stranger, known]);
            var attempts = Attempts(server);
            await Assert.That(attempts.Count(a => a.StartsWith("publickey-signed", StringComparison.Ordinal))).IsEqualTo(1);
        }

        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"] })
        {
            await using var client = await ConnectAsync(server, [stranger], password: "secret");
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "password" });
        }
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
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey", "publickey-signed:ssh-ed25519", "password" });
    }

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }
}
