using System.Buffers.Binary;
using SshSharp.Config;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>Agent forwarding (ssh -A): sessions ask for it, and agent channels the server opens reach the local agent.</summary>
public sealed class AgentForwardingTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-fwd-" + Guid.NewGuid().ToString("N"));

    public AgentForwardingTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshAgent? forward)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ForwardAgent = forward,
        }, leaveOpen: true, Timeout());
    }

    /// <summary>A shell that stays up until its input ends.</summary>
    private static async Task IdleAsync(ExecScript script)
    {
        while (await script.ReadInputAsync() is not null)
        {
        }

        await script.FinishAsync(0);
    }

    /// <summary>What a program on the server gets when it asks the forwarded agent for its keys (SSH_AGENTC_REQUEST_IDENTITIES).</summary>
    private static async Task<(byte Type, uint Count)> ListKeysAsync(Stream agentChannel)
    {
        await agentChannel.WriteAsync(new byte[] { 0, 0, 0, 1, 11 }, Timeout());
        var header = new byte[4];
        await agentChannel.ReadExactlyAsync(header, Timeout());
        var reply = new byte[BinaryPrimitives.ReadUInt32BigEndian(header)];
        await agentChannel.ReadExactlyAsync(reply, Timeout());
        return (reply[0], BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(1)));
    }

    private static FakeSessionServer.ChannelRequestRecord[] Requests(FakeSessionServer server)
    {
        var channel = server.Channels.First(c => c.Requests.Count > 0);
        lock (channel.Requests)
        {
            return [.. channel.Requests];
        }
    }

    [Test]
    public async Task ASessionAsksForForwarding_AndTheServersAgentRequestsReachTheLocalAgent()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        agent.Keys.Add((key, "laptop"));
        await using var server = new FakeSessionServer { OnShell = IdleAsync };
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path));
        await using var shell = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions() }, Timeout());

        // Asked for after the terminal and before the shell, without waiting for a reply, as ssh does.
        var requests = Requests(server);
        await Assert.That(requests.Select(r => r.Type)).IsEquivalentTo(new[] { "pty-req", "auth-agent-req@openssh.com", "shell" });
        await Assert.That(requests[1].WantReply).IsFalse();

        // A program on the server (ssh, git) uses the forwarded agent: twice, each over its own channel.
        for (var i = 0; i < 2; i++)
        {
            await using var channel = await server.OpenAgentChannelAsync();
            await Assert.That(channel).IsNotNull();
            await Assert.That(await ListKeysAsync(channel!)).IsEqualTo(((byte)12, 1u)); // SSH_AGENT_IDENTITIES_ANSWER, one key
        }

        await shell.CloseInputAsync(Timeout());
        await shell.WaitForExitAsync(Timeout());
    }

    [Test]
    public async Task AServerAnnouncingAgentForward_GetsTheRfc9987Names()
    {
        // RFC 9987 section 7: "agent-req" and "agent-connect" are used only when the server announces "agent-forward" in EXT_INFO.
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        agent.Keys.Add((key, "laptop"));
        var options = new FakeServerOptions { ExtraExtensions = new Dictionary<string, string> { ["agent-forward"] = "0" } };
        await using var server = new FakeSessionServer(options) { OnShell = IdleAsync };
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path));
        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());

        await Assert.That(Requests(server).Select(r => r.Type)).IsEquivalentTo(new[] { "agent-req", "shell" });
        await using (var channel = await server.OpenAgentChannelAsync("agent-connect"))
        {
            await Assert.That(channel).IsNotNull();
            await Assert.That(await ListKeysAsync(channel!)).IsEqualTo(((byte)12, 1u));
        }

        // A server that still opens the channel under OpenSSH's name is served too.
        await using (var channel = await server.OpenAgentChannelAsync("auth-agent@openssh.com"))
        {
            await Assert.That(channel).IsNotNull();
        }

        await shell.CloseInputAsync(Timeout());
        await shell.WaitForExitAsync(Timeout());
    }

    [Test]
    public async Task WithoutForwarding_NothingIsAsked_AndAgentChannelsAreRefused()
    {
        await using var server = new FakeSessionServer { OnShell = IdleAsync };
        await using var client = await ConnectAsync(server, forward: null);
        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());
        await Assert.That(Requests(server).Select(r => r.Type)).IsEquivalentTo(new[] { "shell" });
        await Assert.That(await server.OpenAgentChannelAsync()).IsNull();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AnAgentThatIsNotRunning_ClosesTheForwardedChannel()
    {
        await using var server = new FakeSessionServer { OnShell = IdleAsync };
        await using var client = await ConnectAsync(server, new SshAgent(Path.Combine(_dir, "no-agent")));
        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());
        await using var channel = await server.OpenAgentChannelAsync();
        await Assert.That(channel).IsNotNull();
        using var received = new MemoryStream();
        await channel!.CopyToAsync(received, Timeout()); // ends: the client closed the channel
        await Assert.That(received.Length).IsEqualTo(0);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments("yes", true)]
    [Arguments("no", false)]
    public async Task ConfigConnect_FollowsForwardAgent(string forwardAgent, bool expected)
    {
        await using var agent = new FakeAgent();
        await using var server = new FakeSessionServer { OnShell = IdleAsync };
        var config = $"Host *\n User tester\n ForwardAgent {forwardAgent}\n IdentityAgent \"{agent.Path}\"\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = "secret",
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());
        await Assert.That(Requests(server).Any(r => r.Type == "auth-agent-req@openssh.com")).IsEqualTo(expected);
    }
}
