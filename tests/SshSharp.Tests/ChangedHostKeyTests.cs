using System.Net;
using SshSharp.Config;
using SshSharp.Tests.Agent;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;
using Round = SshSharp.Tests.Protocol.FakeSessionServer.KeyboardRound;

namespace SshSharp.Tests;

/// <summary>
/// A host key that differs from the one in known_hosts, accepted with StrictHostKeyChecking no: as in ssh, the connection goes on, but
/// the server may be a man in the middle, so it gets no password or keyboard-interactive answers, no forwarded agent and no port
/// forwardings. A key that is unknown or matches is not affected.
/// </summary>
public sealed class ChangedHostKeyTests : IDisposable
{
    private const string Host = "server.example.com";

    private static readonly Round PasswordRound = new("", "", [("Password: ", false)], [TestSecrets.Password]);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-changed-" + Guid.NewGuid().ToString("N"));

    public ChangedHostKeyTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private static string Line(string host, FakeHostKey key) => $"{host} {key.KeyType} {Convert.ToBase64String(key.Blob)}\n";

    /// <summary>What known_hosts holds for the host, against the key the server presents.</summary>
    public enum Recorded
    {
        /// <summary>Another key of the same type: "the host key has changed".</summary>
        Changed,

        /// <summary>Nothing: a host seen for the first time.</summary>
        Unknown,

        /// <summary>The server's own key.</summary>
        Matching,
    }

    /// <summary>A server presenting <paramref name="presented"/>, with known_hosts set up as <paramref name="recorded"/> says.</summary>
    private FakeSessionServer Server(Recorded recorded, FakeHostKey presented, Func<FakeSessionServer>? create = null)
    {
        var line = recorded switch
        {
            Recorded.Changed => Line(Host, FakeHostKey.Ed25519()),
            Recorded.Matching => Line(Host, presented),
            _ => string.Empty,
        };
        File.WriteAllText(KnownHosts, line);
        return create?.Invoke() ?? new FakeSessionServer(new FakeServerOptions { HostKey = presented });
    }

    private static Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions options)
    {
        _ = server.StartAsync();
        return SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private SshClientOptions Options(string? password = null, IReadOnlyList<SshPrivateKey>? keys = null, SshAgent? forwardAgent = null,
        Func<SshPasswordPrompt, CancellationToken, ValueTask<string?>>? provider = null,
        Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>>? keyboard = null,
        Func<SshPasswordChangeRequest, CancellationToken, ValueTask<string?>>? changePassword = null) => new()
    {
        // Password first, so a password that is withheld is seen as withheld rather than as not needed.
        PreferredAuthentications = ["password", "keyboard-interactive", "publickey"],
        UserName = "tester",
        Password = password,
        PasswordProvider = provider,
        KeyboardInteractive = keyboard,
        ChangePassword = changePassword,
        PrivateKeys = keys ?? [],
        ForwardAgent = forwardAgent,
        HostKeyAlias = Host,
        HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.No },
    };

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }

    private static string[] SessionRequests(FakeSessionServer server) =>
        [.. server.Channels.SelectMany(c =>
        {
            lock (c.Requests)
            {
                return c.Requests.Select(r => r.Type).ToArray();
            }
        })];

    [Test]
    public async Task AChangedKey_UnderNo_SendsNoPassword_AsksNoProvider_AndSaysWhy()
    {
        var presented = FakeHostKey.Ed25519();
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            Password = TestSecrets.New(),
        });
        var asked = 0;
        var changes = 0;
        var options = Options(password: server.Password, provider: (_, _) =>
        {
            Interlocked.Increment(ref asked);
            return ValueTask.FromResult<string?>(server.Password);
        }, changePassword: (_, _) =>
        {
            Interlocked.Increment(ref changes);
            return ValueTask.FromResult<string?>(null);
        });

        var ex = await Assert.ThrowsAsync<SshAuthenticationException>(async () => await ConnectAsync(server, options));

        // The server, which may be a man in the middle, saw no password request at all: nothing to capture, nothing to change.
        await Assert.That(Attempts(server)).DoesNotContain("password");
        await Assert.That(server.PasswordsReceived).IsEmpty();
        await Assert.That(asked).IsEqualTo(0);
        await Assert.That(changes).IsEqualTo(0);
        await Assert.That(ex!.Message).Contains("disabled because the host key has changed and StrictHostKeyChecking is no");
        await Assert.That(ex.Attempts).Contains(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Unavailable));
    }

    [Test]
    public async Task AChangedKey_UnderNo_AnswersNoKeyboardInteractiveQuestion()
    {
        var presented = FakeHostKey.Ed25519();
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            AdvertisedMethods = ["keyboard-interactive"],
            KeyboardInteractiveRounds = [PasswordRound],
        });
        var asked = 0;
        var options = Options(password: TestSecrets.Password, keyboard: (_, _) =>
        {
            Interlocked.Increment(ref asked);
            return ValueTask.FromResult<IReadOnlyList<string>?>([TestSecrets.Password]);
        });

        var ex = await Assert.ThrowsAsync<SshAuthenticationException>(async () => await ConnectAsync(server, options));

        // Neither the callback nor the password (which would answer a single password prompt) was used.
        await Assert.That(Attempts(server)).DoesNotContain("keyboard-interactive");
        await Assert.That(server.KeyboardInteractiveAnswers).IsEmpty();
        await Assert.That(asked).IsEqualTo(0);
        await Assert.That(ex!.Attempts).Contains(new SshAuthenticationAttempt("keyboard-interactive", SshAuthenticationOutcome.Unavailable));
    }

    [Test]
    public async Task AChangedKey_UnderNo_StillLogsInWithAKey_ButForwardsNoAgentAndNoPorts()
    {
        var presented = FakeHostKey.Ed25519();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            AdvertisedMethods = ["password", "publickey"],
            AuthorizedKeys = [blob],
        });
        using var agentKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var agent = SshAgent.FromKeys(agentKey);
        await using var client = await ConnectAsync(server, Options(password: server.Password, keys: [key], forwardAgent: agent));

        // The password comes first in the order, yet was never offered: the key got in.
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.PasswordsReceived).IsEmpty();

        // No agent: not asked for on a session, and refused when the server opens an agent channel anyway.
        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(SessionRequests(server)).DoesNotContain("auth-agent-req@openssh.com");
        await Assert.That(await server.OpenAgentChannelAsync()).IsNull();

        // No port forwarding asked for now, either: each refusal says why, and nothing listens or reaches the server.
        var loopback = new IPEndPoint(IPAddress.Loopback, 0);
        var socketPath = Path.Combine(_dir, "l.sock");
        var refusals = new List<Func<Task>>
        {
            async () => await client.ForwardLocalPortAsync(loopback, "db.example.com", 5432, Timeout()),
            async () => await client.ForwardLocalPortAsync(loopback, "/run/db.sock", Timeout()),
            async () => await client.ForwardLocalUnixSocketAsync(socketPath, "db.example.com", 5432, Timeout()),
            async () => await client.ForwardLocalUnixSocketAsync(socketPath, "/run/db.sock", Timeout()),
            async () => await client.ForwardDynamicPortAsync(loopback, Timeout()),
            async () => await client.ForwardDynamicPortAsync(loopback, new NetworkCredential("socks", TestSecrets.New()), Timeout()),
            async () => await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", 3000, Timeout()),
            async () => await client.ForwardRemotePortAsync("localhost", 0, (_, _) => Task.CompletedTask, cancellationToken: Timeout()),
            async () => await client.ForwardRemoteDynamicPortAsync("localhost", 0, cancellationToken: Timeout()),
            async () => await client.ForwardRemoteUnixSocketAsync("/run/r.sock", "127.0.0.1", 3000, Timeout()),
            async () => await client.ForwardRemoteUnixSocketAsync("/run/r.sock", socketPath, Timeout()),
            async () => await client.ForwardRemoteUnixSocketAsync("/run/r.sock", (_, _) => Task.CompletedTask, cancellationToken: Timeout()),
        };
        foreach (var refused in refusals)
        {
            var ex = await Assert.ThrowsAsync<SshHostKeyException>(refused);
            await Assert.That(ex!.Message).Contains("Port forwarding is disabled to avoid man-in-the-middle attacks");
            await Assert.That(ex.HostKey!.Fingerprint).IsEqualTo(presented.Fingerprint);
        }

        await Assert.That(File.Exists(socketPath)).IsFalse();
        await Assert.That(server.GlobalRequests.Where(r => r.Contains("forward", StringComparison.Ordinal))).IsEmpty();
        await Assert.That(client.IsConnected).IsTrue(); // the refusals do not end the connection
    }

    [Test]
    public async Task AChangedKey_UnderNo_StillOpensTunnels_AsSshDashWDoes()
    {
        // ssh -W, which ProxyJump uses, still works with a changed key: a tunnel listens nowhere and is used by this process only.
        var presented = FakeHostKey.Ed25519();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            AdvertisedMethods = ["publickey"],
            AuthorizedKeys = [blob],
            DirectTcpIp = (_, _) => DuplexStream.CreatePair().A,
        });
        await using var client = await ConnectAsync(server, Options(keys: [key]));
        await using var tunnel = await client.OpenTcpTunnelAsync("db.example.com", 5432, Timeout());
        await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.example.com:5432" });
    }

    [Test]
    [Arguments(Recorded.Unknown)]
    [Arguments(Recorded.Matching)]
    public async Task AnUnknownOrMatchingKey_UnderNo_IsTrusted_PasswordAgentAndForwardingWork(Recorded recorded)
    {
        var presented = FakeHostKey.Ed25519();
        await using var server = Server(recorded, presented);
        using var agentKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var agent = SshAgent.FromKeys(agentKey);
        await using var client = await ConnectAsync(server, Options(password: server.Password, forwardAgent: agent));

        await Assert.That(server.PasswordsReceived).IsEquivalentTo(new[] { server.Password });
        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(SessionRequests(server)).Contains("auth-agent-req@openssh.com");

        await using var local = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "db.example.com", 5432, Timeout());
        await using var remote = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", 3000, Timeout());
        await Assert.That(server.GlobalRequests).Contains("tcpip-forward");
    }

    /// <summary>Connects by alias through ssh_config, with StrictHostKeyChecking no and the given lines, to a server presenting a changed key.</summary>
    private async Task<SshClient> ConnectByConfigAsync(FakeSessionServer server, string agentPath, SshPrivateKey key, string lines)
    {
        var config = $"Host target\n User tester\n HostKeyAlias {Host}\n StrictHostKeyChecking no\n UserKnownHostsFile \"{KnownHosts}\"\n"
            + $" ForwardAgent yes\n IdentityAgent \"{agentPath}\"\n PreferredAuthentications password,publickey\n{lines}";
        return await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = server.Password,
            PrivateKeys = [key],
            StartForwardings = true,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
    }

    [Test]
    public async Task AChangedKey_FromSshConfig_StartsNoConfiguredForwarding_AndForwardsNoAgent()
    {
        var presented = FakeHostKey.Ed25519();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            AdvertisedMethods = ["password", "publickey"],
            AuthorizedKeys = [blob],
        });
        await using var agent = new FakeAgent();
        await using var client = await ConnectByConfigAsync(server, agent.Path, key,
            " LocalForward 0 db.example.com:5432\n RemoteForward 0 127.0.0.1:3000\n DynamicForward 127.0.0.1:0\n");

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.PasswordsReceived).IsEmpty();
        await Assert.That(client.LocalForwardings).IsEmpty();
        await Assert.That(client.RemoteForwardings).IsEmpty();
        await Assert.That(client.DynamicForwardings).IsEmpty();
        await Assert.That(server.GlobalRequests.Where(r => r.Contains("forward", StringComparison.Ordinal))).IsEmpty();

        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());
        await Assert.That(SessionRequests(server)).DoesNotContain("auth-agent-req@openssh.com");
    }

    [Test]
    public async Task AChangedKey_FromSshConfig_WithExitOnForwardFailure_FailsTheConnection()
    {
        var presented = FakeHostKey.Ed25519();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = Server(Recorded.Changed, presented, () => new FakeSessionServer(new FakeServerOptions { HostKey = presented })
        {
            AdvertisedMethods = ["publickey"],
            AuthorizedKeys = [blob],
        });
        await using var agent = new FakeAgent();

        var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () =>
            await ConnectByConfigAsync(server, agent.Path, key, " LocalForward 0 db.example.com:5432\n ExitOnForwardFailure yes\n"));
        await Assert.That(ex!.Message).Contains("Port forwarding is disabled");
    }

    [Test]
    public async Task AJumpHostsChangedKey_WithholdsItsPassword_NotTheDestinations()
    {
        // Each hop is verified on its own: a hop whose key changed (StrictHostKeyChecking no) gets no password, and the destination,
        // whose key matches, still gets its own.
        var hopKey = FakeHostKey.Ed25519();
        var targetKey = FakeHostKey.Ed25519();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var target = new FakeSessionServer(new FakeServerOptions { HostKey = targetKey }) { Password = TestSecrets.New() };
        await using var hop = new FakeSessionServer(new FakeServerOptions { HostKey = hopKey })
        {
            AdvertisedMethods = ["password", "publickey"],
            AuthorizedKeys = [blob],
            Password = TestSecrets.New(),
            DirectTcpIp = (host, port) =>
            {
                if (host != "target.example.com" || port != 22)
                {
                    return null;
                }

                _ = target.StartAsync();
                return target.ClientStream;
            },
        };
        File.WriteAllText(KnownHosts, Line("hop.example.com", FakeHostKey.Ed25519()) + Line("target.example.com", targetKey));
        var verifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.No };
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = target.Password,
            HostKeyVerifier = verifier,
            Proxy = SshProxy.FromConnector((_, _, _) =>
            {
                _ = hop.StartAsync();
                return ValueTask.FromResult(hop.ClientStream);
            }),
            JumpHosts =
            [
                new SshJumpHost("hop.example.com", 22, new SshClientOptions
                {
                    UserName = "tester",
                    Password = hop.Password,
                    PrivateKeys = [key],
                    PreferredAuthentications = ["password", "publickey"],
                    HostKeyVerifier = verifier,
                }),
            ],
        };

        await using var client = await SshClient.ConnectAsync("target.example.com", 22, options, Timeout());
        await Assert.That(hop.PasswordsReceived).IsEmpty();
        await Assert.That(target.PasswordsReceived).IsEquivalentTo(new[] { target.Password });
    }
}
