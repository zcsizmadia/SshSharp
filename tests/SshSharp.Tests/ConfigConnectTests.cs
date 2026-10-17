using SshSharp.Config;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Connecting by ssh_config alias: hops, identity files, known_hosts, timeouts and ProxyCommand, all against fake servers.</summary>
public sealed class ConfigConnectTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-cfg-" + Guid.NewGuid().ToString("N"));

    public ConfigConnectTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    /// <summary>The key the jump hosts accept: a hop is never offered the destination's password.</summary>
    private static readonly SshPrivateKey HopKey = SshPrivateKey.Generate(SshKeyType.Ed25519);

    /// <summary>A jump host that takes <see cref="HopKey"/>, and the password too, so a password offered to it would be accepted and seen.</summary>
    private static FakeSessionServer JumpHost(FakeHostKey? hostKey = null) =>
        new(new FakeServerOptions { HostKey = hostKey ?? FakeHostKey.Ed25519() })
        {
            AuthorizedKeys = [HopKey.PublicKey.ToArray()],
            AdvertisedMethods = ["publickey", "password"],
        };

    private SshConfigResolveOptions Resolve => new() { LocalUser = "local", HomeDirectory = _dir, LocalHostName = "box" };

    /// <summary>"TCP" that reaches fake servers by host name.</summary>
    private static Func<string, int, SshAddressFamily, CancellationToken, ValueTask<(Stream, IAsyncDisposable?)>> Network(params (string Host, FakeSessionServer Server)[] servers) =>
        (host, port, _, _) =>
        {
            var server = servers.FirstOrDefault(s => s.Host == host).Server ?? throw new SshException(SshFailureReason.ConnectFailed, $"No route to {host}.");
            _ = server.StartAsync();
            return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
        };

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

    [Test]
    public async Task ATwoHopProxyJump_ReachesTheTarget_AndRecordsEveryHostKey()
    {
        // Each fake server takes one connection; the second round uses new servers with the same host keys.
        var keys = new[] { FakeHostKey.Ed25519(), FakeHostKey.Ed25519(), FakeHostKey.Ed25519() };
        (FakeSessionServer Jump1, FakeSessionServer Jump2, FakeSessionServer Target) Chain()
        {
            var jump1 = JumpHost(keys[0]);
            var jump2 = JumpHost(keys[1]);
            var target = new FakeSessionServer(new FakeServerOptions { HostKey = keys[2] });
            jump1.DirectTcpIp = Routes(("j2.internal", jump2));
            jump2.DirectTcpIp = Routes(("target.internal", target));
            return (jump1, jump2, target);
        }

        string Config(string policy) => $"""
            Host target
              HostName target.internal
              ProxyJump j1,j2
            Host j1
              HostName j1.example.com
            Host j2
              HostName j2.internal
            Host *
              User tester
              StrictHostKeyChecking {policy}
              UserKnownHostsFile "{KnownHosts}"
            """;

        var (jump1, jump2, target) = Chain();
        await using var j1 = jump1;
        await using var j2 = jump2;
        await using var t = target;
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse(Config("accept-new")),
            ResolveOptions = Resolve,
            Password = "secret",
            PrivateKeys = [HopKey],
            TcpConnector = Network(("j1.example.com", jump1)),
        }, Timeout());

        var result = await client.RunCommandAsync("hostname", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(target.Commands).IsEquivalentTo(new[] { "hostname" });
        await Assert.That(jump1.DirectTcpIpRequests).IsEquivalentTo(new[] { "j2.internal:22" });
        await Assert.That(jump2.DirectTcpIpRequests).IsEquivalentTo(new[] { "target.internal:22" });

        // The password went to the destination only: the jump hosts, which would have taken it, were never offered it.
        await Assert.That(jump1.AuthAttempts).DoesNotContain("password");
        await Assert.That(jump2.AuthAttempts).DoesNotContain("password");
        await Assert.That(target.AuthAttempts).Contains("password");

        // accept-new recorded each hop under its HostName.
        var known = KnownHostsFile.Load(KnownHosts);
        foreach (var host in new[] { "j1.example.com", "j2.internal", "target.internal" })
        {
            await Assert.That(known.Find(host).Count()).IsEqualTo(1);
        }

        // Disposing the client tears down the whole chain: every hop's connection ends, the first one too (it used to be left open).
        await client.DisposeAsync();
        await Task.WhenAll(jump1.Finished, jump2.Finished, target.Finished).WaitAsync(Timeout());

        // A second connection now trusts all three hosts even with StrictHostKeyChecking yes.
        var (again1, again2, againTarget) = Chain();
        await using var a1 = again1;
        await using var a2 = again2;
        await using var at = againTarget;
        await using var again = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse(Config("yes")),
            ResolveOptions = Resolve,
            Password = "secret",
            PrivateKeys = [HopKey],
            TcpConnector = Network(("j1.example.com", again1)),
        }, Timeout());
        await Assert.That(again.IsConnected).IsTrue();
    }

    [Test]
    public async Task AJumpHost_IsNeverOfferedTheDestinationsPassword()
    {
        // A jump host that takes passwords only (and would take this one): it must not be offered it, so the chain fails there.
        await using var jump = new FakeSessionServer { AdvertisedMethods = ["password"] };
        await using var target = new FakeSessionServer();
        jump.DirectTcpIp = Routes(("t", target));
        var answered = 0;

        var error = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse("Host t\n ProxyJump j\nHost *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
            ResolveOptions = Resolve,
            Password = "secret",
            KeyboardInteractive = (_, _) =>
            {
                Interlocked.Increment(ref answered);
                return ValueTask.FromResult<IReadOnlyList<string>?>(["secret"]);
            },
            TcpConnector = Network(("j", jump)),
        }, Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(jump.AuthAttempts).DoesNotContain("password");
        await Assert.That(answered).IsEqualTo(0);
        await Assert.That(target.Commands).IsEmpty();
    }

    [Test]
    public async Task DisposingTheClient_ClosesTheJumpHostsToo()
    {
        await using var jump = JumpHost();
        await using var target = new FakeSessionServer();
        jump.DirectTcpIp = Routes(("t", target));
        var client = await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse("Host t\n ProxyJump j\nHost *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
            ResolveOptions = Resolve,
            Password = "secret",
            PrivateKeys = [HopKey],
            TcpConnector = Network(("j", jump)),
        }, Timeout());

        await client.DisposeAsync();
        await Assert.That(client.IsConnected).IsFalse();
        for (var i = 0; i < 200 && jump.Channels.Any(c => !c.CloseReceived); i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(jump.Channels.All(c => c.CloseReceived)).IsTrue();
    }

    [Test]
    public async Task IdentityFiles_AreUsed_IncludingEncryptedOnesThroughThePassphraseProvider()
    {
        File.WriteAllText(Path.Combine(_dir, "plain"), TestKeys.OpenSshEd25519(out var plainBlob));
        File.WriteAllText(Path.Combine(_dir, "locked"), TestKeys.OpenSshEd25519(out var lockedBlob, passphrase: "pw"));

        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [plainBlob] })
        {
            await using var client = await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
            {
                UseAgent = false, // the developer's own agent must not change the outcome
                Config = SshConfig.Parse("Host srv\n User tester\n IdentityFile ~/missing\n IdentityFile ~/plain\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
                ResolveOptions = Resolve,
                TcpConnector = Network(("srv", server)),
            }, Timeout());
            await Assert.That(client.IsConnected).IsTrue();
        }

        var asked = new List<string>();
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [lockedBlob] })
        {
            await using var client = await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
            {
                UseAgent = false, // the developer's own agent must not change the outcome
                Config = SshConfig.Parse("Host srv\n User tester\n IdentityFile ~/locked\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
                ResolveOptions = Resolve,
                PassphraseProvider = (path, _) => { asked.Add(Path.GetFileName(path)); return ValueTask.FromResult<string?>("pw"); },
                TcpConnector = Network(("srv", server)),
            }, Timeout());
            await Assert.That(asked).IsEquivalentTo(new[] { "locked" });
        }

        // BatchMode never asks, so the encrypted key is skipped and authentication fails.
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [lockedBlob] })
        {
            asked.Clear();
            await Assert.That(async () => await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
            {
                UseAgent = false, // the developer's own agent must not change the outcome
                Config = SshConfig.Parse("Host srv\n User tester\n IdentityFile ~/locked\n BatchMode yes\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
                ResolveOptions = Resolve,
                PassphraseProvider = (path, _) => { asked.Add(path); return ValueTask.FromResult<string?>("pw"); },
                TcpConnector = Network(("srv", server)),
            }, Timeout())).Throws<SshAuthenticationException>();
            await Assert.That(asked).IsEmpty();
        }
    }

    [Test]
    public async Task StrictHostKeyCheckingYes_RefusesAnUnknownHost_AndTheUserCanBeGivenInTheDestination()
    {
        var config = SshConfig.Parse($"Host srv\n User nobody\n UserKnownHostsFile \"{KnownHosts}\"\n");
        await using (var refusing = new FakeSessionServer { UserName = "alice" })
        {
            // StrictHostKeyChecking defaults to ask, and nobody answers: refused.
            await Assert.That(async () => await SshClient.ConnectAsync("alice@srv", new SshConfigConnectOptions
            {
                UseAgent = false, // the developer's own agent must not change the outcome
                Config = config,
                ResolveOptions = Resolve,
                Password = "secret",
                TcpConnector = Network(("srv", refusing)),
            }, Timeout())).Throws<SshHostKeyException>();
        }

        // Asked and accepted: the destination's user (alice) overrides the config's.
        await using var server = new FakeSessionServer { UserName = "alice" };
        await using var client = await SshClient.ConnectAsync("alice@srv", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = config,
            ResolveOptions = Resolve,
            Password = "secret",
            AskHostKey = (_, _) => ValueTask.FromResult(true),
            TcpConnector = Network(("srv", server)),
        }, Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(KnownHostsFile.Load(KnownHosts).Find("srv").Count()).IsEqualTo(1);
    }

    [Test]
    public async Task ConnectTimeout_StopsAConnectThatHangs()
    {
        var started = DateTime.UtcNow;
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("slow", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse("Host slow\n ConnectTimeout 1\n User u\n"),
            ResolveOptions = Resolve,
            TcpConnector = async (_, _, _, ct) =>
            {
                await Task.Delay(System.Threading.Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            },
        }, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>(); // as SshClientOptions.ConnectTimeout reports it
        await Assert.That(DateTime.UtcNow - started).IsLessThan(TimeSpan.FromSeconds(20));
    }

    [Test]
    public async Task ConnectTimeout_CallersCancellation_StaysACancellation()
    {
        using var cancel = new CancellationTokenSource();
        var connecting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempt = SshClient.ConnectAsync("slow", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse("Host slow\n ConnectTimeout 300\n User u\n"),
            ResolveOptions = Resolve,
            TcpConnector = async (_, _, _, ct) =>
            {
                connecting.TrySetResult();
                await Task.Delay(System.Threading.Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            },
        }, cancel.Token);
        await connecting.Task.WaitAsync(Timeout());
        await cancel.CancelAsync();

        await Assert.That(async () => await attempt).Throws<OperationCanceledException>();
    }

    [Test]
    [Arguments("", SshAddressFamily.Any)]
    [Arguments(" AddressFamily inet\n", SshAddressFamily.Inet)]
    [Arguments(" AddressFamily inet6\n", SshAddressFamily.Inet6)]
    public async Task AddressFamily_InSshConfig_ReachesTheConnection(string line, SshAddressFamily expected)
    {
        SshAddressFamily? seen = null;
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = SshConfig.Parse("Host box\n User u\n" + line),
            ResolveOptions = Resolve,
            TcpConnector = (_, _, family, _) =>
            {
                seen = family;
                throw new SshException(SshFailureReason.ConnectFailed, "No route.");
            },
        }, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(seen).IsEqualTo(expected);
    }

    [Test]
    public async Task ProxyCommand_RunsTheCommandAndTalksOverItsOutput_UnlessDisallowed()
    {
        // The command prints a server identification and exits: the client must have read it from the process (a protocol error about
        // the missing key exchange follows), rather than failing to start or connecting anywhere else.
        var command = OperatingSystem.IsWindows() ? "echo SSH-2.0-ProxyCommandTest" : "echo SSH-2.0-ProxyCommandTest";
        var config = SshConfig.Parse($"Host p\n User u\n ProxyCommand {command}\n StrictHostKeyChecking no\n UserKnownHostsFile none\n");
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("p", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = config,
            ResolveOptions = Resolve,
            TcpConnector = (_, _, _, _) => throw new InvalidOperationException("TCP must not be used with a ProxyCommand."),
        }, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);

        var refused = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("p", new SshConfigConnectOptions
        {
            UseAgent = false, // the developer's own agent must not change the outcome
            Config = config,
            ResolveOptions = Resolve,
            AllowProxyCommand = false,
        }, Timeout()));
        await Assert.That(refused!.Message).Contains("AllowProxyCommand");
    }

    [Test]
    [Arguments("host", null, "host", null)]
    [Arguments("bob@host", "bob", "host", null)]
    [Arguments("host:2200", null, "host", 2200)]
    [Arguments("bob@host:2200", "bob", "host", 2200)]
    [Arguments("ssh://bob@host:2201", "bob", "host", 2201)]
    [Arguments("ssh://host", null, "host", null)]
    [Arguments("[fe80::1]:2222", null, "fe80::1", 2222)]
    [Arguments("ssh://[::1]:22", null, "::1", 22)]
    [Arguments("user.name@corp@host", "user.name@corp", "host", null)]
    public async Task Destinations_ParseLikeSshAndProxyJump(string destination, string? user, string host, int? port)
    {
        var parsed = SshClient.ParseDestination(destination);
        await Assert.That(parsed.User).IsEqualTo(user);
        await Assert.That(parsed.Host).IsEqualTo(host);
        await Assert.That(parsed.Port).IsEqualTo(port);
    }

    [Test]
    [Arguments("")]
    [Arguments("@host")]
    [Arguments("host:0")]
    [Arguments("host:70000")]
    public async Task BadDestinations_AreRefused(string destination)
    {
        await Assert.That(() => SshClient.ParseDestination(destination)).Throws<Exception>();
    }
}
