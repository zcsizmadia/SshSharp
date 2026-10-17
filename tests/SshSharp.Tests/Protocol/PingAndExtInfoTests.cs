using Microsoft.Extensions.Time.Testing;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>OpenSSH's transport ping (ping@openssh.com) and EXT_INFO during authentication (ext-info-in-auth@openssh.com).</summary>
public class PingAndExtInfoTests
{
    private static readonly Dictionary<string, string> PingExtension = new() { ["ping@openssh.com"] = "0" };

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions? options = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options ?? new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    [Test]
    public async Task TheClient_AnnouncesExtInfoInAuth_AfterItsFirstNewKeys()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await Assert.That(server.Raw.ClientExtensions).ContainsKey("ext-info-in-auth@openssh.com");
        await Assert.That(server.Raw.ClientExtensions["ext-info-in-auth@openssh.com"]).IsEqualTo("0");
    }

    [Test]
    public async Task ServerSigAlgs_SentAgainDuringAuthentication_AreUsed()
    {
        // The first EXT_INFO allows only rsa-sha2-256; the one during authentication (a Match block for this user, say) only rsa-sha2-512.
        using var key = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        await using var server = new FakeSessionServer(new FakeServerOptions { ServerSigAlgs = "rsa-sha2-256" })
        {
            AuthorizedKeys = [key.PublicKey.ToArray()],
            AdvertisedMethods = ["publickey"],
            ExtInfoDuringAuth = new Dictionary<string, string> { ["server-sig-algs"] = "rsa-sha2-512" },
        };
        await using var client = await ConnectAsync(server, new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        });

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.PublicKeyAlgorithms).IsNotEmpty();
        await Assert.That(server.PublicKeyAlgorithms[^1]).IsEqualTo("rsa-sha2-512");
    }

    [Test]
    public async Task APingTheServerDropsDuringAKeyExchange_IsSentAgainAfterIt()
    {
        // OpenSSH never answers a PING that arrives while it re-keys; the client used to wait for that pong forever.
        await using var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = PingExtension }) { DropNextPingAndRekey = true };
        await using var client = await ConnectAsync(server);

        var roundTrip = await client.PingAsync(Timeout());

        await Assert.That(roundTrip).IsLessThan(TimeSpan.FromSeconds(30));
        await Assert.That(server.PingsReceived).IsEqualTo(2);
        await Assert.That(server.Raw.KeyExchangeCount).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task PingAsync_UsesTheTransportPing_WhereTheServerHasIt()
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = PingExtension });
        await using var client = await ConnectAsync(server);

        var pings = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => client.PingAsync(Timeout())));

        await Assert.That(pings.All(t => t >= TimeSpan.Zero)).IsTrue();
        await Assert.That(server.PingsReceived).IsEqualTo(5);
        await Assert.That(server.GlobalRequests).DoesNotContain("keepalive@openssh.com");
    }

    [Test]
    public async Task PingAsync_FallsBackToAKeepAliveRequest_Elsewhere()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await client.PingAsync(Timeout());

        await Assert.That(server.PingsReceived).IsEqualTo(0);
        await Assert.That(server.GlobalRequests).Contains("keepalive@openssh.com");
    }

    [Test]
    public async Task APendingPing_FailsWhenTheConnectionEnds()
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = PingExtension }) { AnswerPings = false };
        var client = await ConnectAsync(server);

        var ping = client.PingAsync(Timeout());
        await Task.Delay(100);
        await client.DisposeAsync();

        await Assert.That(async () => await ping).Throws<Exception>();
    }

    [Test]
    public async Task KeepAlive_ProbesWithPings_AndAServerThatStopsAnsweringIsDeclaredDead()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = PingExtension });
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KeepAliveInterval = TimeSpan.FromSeconds(30),
            KeepAliveCountMax = 2,
            TimeProvider = time,
        }, leaveOpen: true, Timeout());
        server.AnswerPings = false;

        // Silent intervals until the first probe reaches the server, before time runs on: under load the client could otherwise give up
        // while its pings still sit in the outbox, and the server would count none. The keep-alive loop starts on the thread pool, so
        // an advance before it has set its timer does nothing (seen on windows-11-arm): advance again until a ping arrives. An advance
        // while a ping is still on its way counts one missed probe, which CountMax = 2 allows.
        for (var i = 0; i < 20 && server.PingsReceived == 0 && client.IsConnected; i++)
        {
            time.Advance(TimeSpan.FromSeconds(30));
            for (var waited = 0; server.PingsReceived == 0 && waited < 20; waited++)
            {
                await Task.Delay(50);
            }
        }

        await Assert.That(server.PingsReceived).IsGreaterThanOrEqualTo(1);
        for (var i = 0; i < 100 && client.IsConnected; i++)
        {
            time.Advance(TimeSpan.FromSeconds(30));
            await Task.Delay(50);
        }

        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(((SshException)client.ConnectionError!).Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(server.GlobalRequests).DoesNotContain("keepalive@openssh.com");
    }
}
