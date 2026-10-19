using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="SshClientOptions.JumpHosts"/> and <see cref="SshProxy.FromConnector"/>, against chained fake servers: the first network
/// connection goes through a custom proxy that reaches fake servers by name, later hops through <c>direct-tcpip</c> channels.
/// </summary>
public sealed class JumpHostTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A password made for the test run: never written in the source.</summary>
    private static readonly string TargetPassword = Guid.NewGuid().ToString("N");

    /// <summary>The key the first jump host accepts.</summary>
    private static readonly SshPrivateKey JumpKey = SshPrivateKey.Generate(SshKeyType.Ed25519);

    /// <summary>A custom proxy that "connects" to fake servers by host name, and records what it was asked for.</summary>
    private static SshProxy Network(List<string> asked, params (string Host, FakeSessionServer Server)[] servers) =>
        SshProxy.FromConnector((host, port, cancellationToken) =>
        {
            lock (asked)
            {
                asked.Add($"{host}:{port}");
            }

            var server = servers.FirstOrDefault(s => s.Host == host).Server ?? throw new IOException("No route to the host.");
            _ = server.StartAsync();
            return ValueTask.FromResult(server.ClientStream);
        });

    private static Func<string, int, Stream?> Routes(params (string Host, FakeSessionServer Server)[] servers) =>
        (host, port) =>
        {
            if (servers.FirstOrDefault(s => s.Host == host && port == 22).Server is not { } server)
            {
                return null;
            }

            _ = server.StartAsync();
            return server.ClientStream;
        };

    /// <summary>A verifier that trusts one fingerprint and records which hosts it was asked about.</summary>
    private static SshHostKeyVerifier Expect(string fingerprint, List<string> asked) => SshHostKeyVerifier.FromDelegate((context, _) =>
    {
        lock (asked)
        {
            asked.Add($"{context.Host}:{context.Port}");
        }

        return ValueTask.FromResult(context.HostKey.Fingerprint == fingerprint);
    });

    /// <summary>
    /// Two jump hosts and a target, each with its own host key, user and credentials: the first hop takes a key, the second its own
    /// password, the target another password. All three would take any password offered, so one offered to the wrong host is seen.
    /// </summary>
    private sealed class Chain : IAsyncDisposable
    {
        public Chain()
        {
            Jump1 = new FakeSessionServer(new FakeServerOptions { HostKey = Keys[0] })
            {
                UserName = "jump",
                AuthorizedKeys = [JumpKey.PublicKey.ToArray()],
                AdvertisedMethods = ["publickey", "password"],
                Password = TargetPassword,
            };
            Jump2 = new FakeSessionServer(new FakeServerOptions { HostKey = Keys[1] })
            {
                UserName = "relay",
                AdvertisedMethods = ["publickey", "password"],
                Password = Jump2Password,
            };
            Target = new FakeSessionServer(new FakeServerOptions { HostKey = Keys[2] })
            {
                UserName = "deploy",
                AdvertisedMethods = ["publickey", "password"],
                Password = TargetPassword,
            };
            Jump1.DirectTcpIp = Routes(("j2.internal", Jump2));
            Jump2.DirectTcpIp = Routes(("target.internal", Target));
        }

        public static readonly FakeHostKey[] Keys = [FakeHostKey.Ed25519(), FakeHostKey.Ed25519(), FakeHostKey.Ed25519()];

        public static readonly string Jump2Password = Guid.NewGuid().ToString("N");

        public FakeSessionServer Jump1 { get; }

        public FakeSessionServer Jump2 { get; }

        public FakeSessionServer Target { get; }

        public List<string> Connected { get; } = [];

        public List<string> Verified { get; } = [];

        public SshClientOptions Options(TimeSpan? connectTimeout = null, SshClientOptions? jump2 = null) => new()
        {
            UserName = "deploy",
            Password = TargetPassword,
            HostKeyVerifier = Expect(Keys[2].Fingerprint, Verified),
            Proxy = Network(Connected, ("j1.example.com", Jump1)),
            ConnectTimeout = connectTimeout,
            JumpHosts =
            [
                new SshJumpHost("j1.example.com", 22, new SshClientOptions
                {
                    UserName = "jump",
                    PrivateKeys = [JumpKey],
                    HostKeyVerifier = Expect(Keys[0].Fingerprint, Verified),
                }),
                new SshJumpHost("j2.internal", 22, jump2 ?? new SshClientOptions
                {
                    UserName = "relay",
                    Password = Jump2Password,
                    HostKeyVerifier = Expect(Keys[1].Fingerprint, Verified),
                }),
            ],
        };

        public async ValueTask DisposeAsync()
        {
            await Jump1.DisposeAsync();
            await Jump2.DisposeAsync();
            await Target.DisposeAsync();
        }
    }

    [Test]
    public async Task TwoJumpHosts_ReachTheTarget_EachWithItsOwnUserCredentialsAndVerifier()
    {
        await using var chain = new Chain();
        await using var client = await SshClient.ConnectAsync("target.internal", 22, chain.Options(), Timeout());

        var result = await client.RunCommandAsync("hostname", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(chain.Target.Commands).IsEquivalentTo(new[] { "hostname" });

        // The custom proxy made the first network connection, to the first hop; the others went through the hops.
        await Assert.That(chain.Connected).IsEquivalentTo(new[] { "j1.example.com:22" });
        await Assert.That(chain.Jump1.DirectTcpIpRequests).IsEquivalentTo(new[] { "j2.internal:22" });
        await Assert.That(chain.Jump2.DirectTcpIpRequests).IsEquivalentTo(new[] { "target.internal:22" });

        // Each host was checked by its own verifier (a wrong key fails its Expect), in order, under its own name.
        await Assert.That(chain.Verified).IsEquivalentTo(new[] { "j1.example.com:22", "j2.internal:22", "target.internal:22" });

        // Credentials stayed with their host: the first hop logged in with its key and was never offered a password, the second with its
        // own password, and only the target was offered the target's.
        await Assert.That(chain.Jump1.AuthAttempts).DoesNotContain("password");
        await Assert.That(chain.Jump2.AuthAttempts).Contains("password");
        await Assert.That(chain.Target.AuthAttempts).Contains("password");
        await Assert.That(chain.Target.AuthAttempts.Any(a => a.StartsWith("publickey", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task DisposingTheClient_ClosesEveryHop()
    {
        await using var chain = new Chain();
        var client = await SshClient.ConnectAsync("target.internal", 22, chain.Options(), Timeout());
        await client.DisposeAsync();
        await Assert.That(client.IsConnected).IsFalse();
        await Task.WhenAll(chain.Jump1.Finished, chain.Jump2.Finished, chain.Target.Finished).WaitAsync(Timeout());
    }

    [Test]
    public async Task AHopsUntrustedHostKey_FailsTheChain_BeforeTheTargetIsReached_AndClosesTheHopsBefore()
    {
        await using var chain = new Chain();
        var verified = new List<string>();
        var options = chain.Options(jump2: new SshClientOptions
        {
            UserName = "relay",
            Password = Chain.Jump2Password,
            HostKeyVerifier = Expect("SHA256:somethingelse", verified),
        });

        await Assert.That(async () => await SshClient.ConnectAsync("target.internal", 22, options, Timeout())).Throws<SshHostKeyException>();
        await Assert.That(verified).IsEquivalentTo(new[] { "j2.internal:22" });
        await Assert.That(chain.Jump2.DirectTcpIpRequests).IsEmpty();
        await Assert.That(chain.Target.Commands).IsEmpty();
        await chain.Jump1.Finished.WaitAsync(Timeout());
    }

    [Test]
    public async Task AJumpHostThatCannotReachTheNextHost_FailsWithConnectFailed_AndIsClosed()
    {
        await using var chain = new Chain();
        chain.Jump2.DirectTcpIp = (_, _) => null; // the target refuses (or the hop is not allowed to forward)
        var error = await Assert.That(async () => await SshClient.ConnectAsync("target.internal", 22, chain.Options(), Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Task.WhenAll(chain.Jump1.Finished, chain.Jump2.Finished).WaitAsync(Timeout());
    }

    [Test]
    public async Task TheDestinationsConnectTimeout_SpansTheWholeChain()
    {
        // The second hop never answers: the destination's limit ends the attempt, as a Timeout with a TimeoutException inside.
        await using var chain = new Chain();
        var silent = new FakeSessionServer(); // never started: it says nothing
        chain.Jump1.DirectTcpIp = (_, _) => silent.ClientStream;
        var error = await Assert.That(async () =>
            await SshClient.ConnectAsync("target.internal", 22, chain.Options(TimeSpan.FromMilliseconds(500)), Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(error.InnerException).IsTypeOf<TimeoutException>();
        await chain.Jump1.Finished.WaitAsync(Timeout());
        await silent.DisposeAsync();
    }

    [Test]
    public async Task AHopsOwnConnectTimeout_BoundsThatHop()
    {
        await using var chain = new Chain();
        var silent = new FakeSessionServer();
        chain.Jump1.DirectTcpIp = (_, _) => silent.ClientStream;
        var options = chain.Options(jump2: new SshClientOptions
        {
            UserName = "relay",
            Password = Chain.Jump2Password,
            HostKeyVerifier = Expect(Chain.Keys[1].Fingerprint, []),
            ConnectTimeout = TimeSpan.FromMilliseconds(300),
        });
        var error = await Assert.That(async () => await SshClient.ConnectAsync("target.internal", 22, options, Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await chain.Jump1.Finished.WaitAsync(Timeout());
        await silent.DisposeAsync();
    }

    [Test]
    public async Task CancellingTheConnection_EndsTheChain_AsACancellation()
    {
        await using var chain = new Chain();
        var silent = new FakeSessionServer();
        chain.Jump1.DirectTcpIp = (_, _) => silent.ClientStream;
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.That(async () => await SshClient.ConnectAsync("target.internal", 22, chain.Options(), cancel.Token))
            .Throws<OperationCanceledException>();
        await chain.Jump1.Finished.WaitAsync(Timeout());
        await silent.DisposeAsync();
    }

    [Test]
    public async Task AJumpHostsAlgorithmOptions_AreCheckedBeforeTheNetworkIsTouched()
    {
        var connected = new List<string>();
        var options = new SshClientOptions
        {
            UserName = "deploy",
            HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            Proxy = Network(connected),
            JumpHosts =
            [
                new SshJumpHost("j1.example.com", 22, new SshClientOptions
                {
                    UserName = "jump",
                    HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
                    FipsMode = true,
                    Ciphers = SshAlgorithmList.Only("chacha20-poly1305@openssh.com"), // FIPS mode leaves nothing of this
                }),
            ],
        };
        await Assert.That(async () => await SshClient.ConnectAsync("target.internal", 22, options, Timeout())).Throws<ArgumentException>();
        await Assert.That(connected).IsEmpty();
    }

    [Test]
    public async Task AJumpHostsOptions_CannotNestJumpHostsOrSetTheNetworkSettings()
    {
        var verifier = SshHostKeyVerifier.Pinned("SHA256:unused");
        var hop = new SshJumpHost("j1.example.com", 22, new SshClientOptions { UserName = "jump", HostKeyVerifier = verifier });
        await Assert.That(() => new SshJumpHost("j2.example.com", 22, new SshClientOptions { UserName = "jump", HostKeyVerifier = verifier, JumpHosts = [hop] }))
            .Throws<ArgumentException>();
        await Assert.That(() => new SshJumpHost("j2.example.com", 22, new SshClientOptions
        {
            UserName = "jump", HostKeyVerifier = verifier, Proxy = SshProxy.Socks5("proxy.example.com", 1080),
        })).Throws<ArgumentException>();
        await Assert.That(() => new SshJumpHost("j2.example.com", 22, new SshClientOptions
        {
            UserName = "jump", HostKeyVerifier = verifier, LocalEndPoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0),
        })).Throws<ArgumentException>();
        await Assert.That(() => new SshJumpHost("", 22, new SshClientOptions { UserName = "jump", HostKeyVerifier = verifier })).Throws<ArgumentException>();
        await Assert.That(() => new SshJumpHost("j2.example.com", 0, new SshClientOptions { UserName = "jump", HostKeyVerifier = verifier }))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshClientOptions { UserName = "deploy", HostKeyVerifier = verifier, JumpHosts = [hop, null!] }).Throws<ArgumentException>();
    }

    // ---- SshProxy.FromConnector ----

    [Test]
    public async Task ACustomProxy_CarriesADirectConnection()
    {
        await using var server = new FakeSessionServer { Password = TargetPassword };
        var connected = new List<string>();
        var proxy = Network(connected, ("app.example.com", server));
        await Assert.That(proxy.Type).IsEqualTo(SshProxyType.Custom);
        await Assert.That(proxy.ToString()).IsEqualTo("Custom proxy");

        await using var client = await SshClient.ConnectAsync("app.example.com", 2222, new SshClientOptions
        {
            UserName = "tester",
            Password = TargetPassword,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Proxy = proxy,
        }, Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(connected).IsEquivalentTo(new[] { "app.example.com:2222" });
    }

    [Test]
    public async Task ACustomProxysFailure_IsAConnectFailure_WithTheCauseInside()
    {
        var proxy = SshProxy.FromConnector((_, _, _) => throw new IOException("tunnel refused"));
        var error = await Assert.That(async () => await proxy.ConnectAsync("app.example.com", 22, Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.InnerException).IsTypeOf<IOException>();
        await Assert.That(error.Message).DoesNotContain("app.example.com");

        // An SshException passes as it is; so does a null stream's failure, as ConnectFailed.
        var own = SshProxy.FromConnector((_, _, _) => throw new SshException(SshFailureReason.Timeout, "the tunnel timed out"));
        var passed = await Assert.That(async () => await own.ConnectAsync("app.example.com", 22, Timeout())).Throws<SshException>();
        await Assert.That(passed!.Reason).IsEqualTo(SshFailureReason.Timeout);
        var empty = SshProxy.FromConnector((_, _, _) => ValueTask.FromResult<Stream>(null!));
        var none = await Assert.That(async () => await empty.ConnectAsync("app.example.com", 22, Timeout())).Throws<SshException>();
        await Assert.That(none!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
    }

    [Test]
    public async Task ACustomProxy_SeesTheCallersCancellation_AsACancellation()
    {
        using var cancel = new CancellationTokenSource();
        var proxy = SshProxy.FromConnector(async (_, _, token) =>
        {
            await cancel.CancelAsync();
            token.ThrowIfCancellationRequested();
            return Stream.Null;
        });
        await Assert.That(async () => await proxy.ConnectAsync("app.example.com", 22, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(() => SshProxy.FromConnector(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task ACustomProxy_CarriesTheFirstProxyJumpHost_FromSshConfig()
    {
        await using var jump = new FakeSessionServer
        {
            AuthorizedKeys = [JumpKey.PublicKey.ToArray()],
            AdvertisedMethods = ["publickey"],
        };
        await using var target = new FakeSessionServer { Password = TargetPassword };
        jump.DirectTcpIp = Routes(("app.internal", target));
        var connected = new List<string>();
        await using var client = await SshClient.ConnectAsync("app", new SshConfigConnectOptions
        {
            Agent = SshAgent.FromKeys(JumpKey), // the hop's key (PrivateKeys is the destination's only); also keeps the developer's agent out
            Config = SshConfig.Parse("""
                Host app
                  HostName app.internal
                  ProxyJump bastion
                Host bastion
                  HostName bastion.example.com
                Host *
                  User tester
                  StrictHostKeyChecking no
                  UserKnownHostsFile none
                """),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = Path.GetTempPath(), LocalHostName = "box" },
            Password = TargetPassword,
            Proxy = Network(connected, ("bastion.example.com", jump)),
        }, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(connected).IsEquivalentTo(new[] { "bastion.example.com:22" });
        await Assert.That(jump.DirectTcpIpRequests).IsEquivalentTo(new[] { "app.internal:22" });
    }
}
