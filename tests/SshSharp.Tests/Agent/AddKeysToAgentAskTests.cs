using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary><c>AddKeysToAgent ask</c>: an accepted identity-file key goes to the agent only once <see cref="SshConfigConnectOptions.ConfirmAddKeyToAgent"/> says yes.</summary>
public sealed class AddKeysToAgentAskTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-agentask-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private async Task<(SshPrivateKey Key, string Path)> IdentityAsync()
    {
        var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "deploy@example");
        var path = Path.Combine(_dir, "id_ed25519");
        await key.SaveAsync(path);
        return (key, path);
    }

    /// <summary>Connects with <paramref name="directives"/> through a fake server that accepts <paramref name="key"/>, then disconnects.</summary>
    private async Task ConnectAsync(SshPrivateKey key, string identity, FakeAgent agent, string directives,
        Func<SshAddKeyToAgentPrompt, CancellationToken, ValueTask<bool>>? confirm)
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [key.PublicKey.ToArray()] };
        var config = $"Host target\n HostName target.example.com\n User tester\n IdentityFile \"{identity}\"\n IdentityAgent \"{agent.Path}\"\n"
            + $" StrictHostKeyChecking no\n UserKnownHostsFile none\n{directives}";
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            ConfirmAddKeyToAgent = confirm,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AConfirmedKey_IsAdded_WithNoConstraints_AndThePromptSaysWhichKey()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            var prompts = new List<SshAddKeyToAgentPrompt>();
            await ConnectAsync(key, identity, agent, " AddKeysToAgent ask\n", (prompt, _) =>
            {
                prompts.Add(prompt);
                return ValueTask.FromResult(true);
            });

            var prompt = prompts.Single();
            await Assert.That(prompt.IdentityFile).IsEqualTo(identity);
            await Assert.That(prompt.Fingerprint).IsEqualTo(key.Fingerprint);
            await Assert.That(prompt.Comment).IsEqualTo("deploy@example");
            await Assert.That(prompt.Host).IsEqualTo("target.example.com");

            var added = agent.AddRequests.Single();
            await Assert.That(added.Confirm).IsFalse();
            await Assert.That(added.LifetimeSeconds).IsNull();
            await Assert.That(agent.Keys.Single().Key.PublicKey.ToArray().SequenceEqual(key.PublicKey.ToArray())).IsTrue();
        }
    }

    [Test]
    public async Task ADeclinedKey_IsNotAdded()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            var asked = 0;
            await ConnectAsync(key, identity, agent, " AddKeysToAgent ask\n", (_, _) =>
            {
                Interlocked.Increment(ref asked);
                return ValueTask.FromResult(false);
            });

            await Assert.That(asked).IsEqualTo(1);
            await Assert.That(agent.AddRequests).IsEmpty();
        }
    }

    [Test]
    public async Task WithoutAWayToAsk_NothingIsAdded()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            await ConnectAsync(key, identity, agent, " AddKeysToAgent ask\n", confirm: null);
            await Assert.That(agent.AddRequests).IsEmpty();
        }
    }

    [Test]
    public async Task InBatchMode_TheCallbackIsNotAsked_AndNothingIsAdded()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            var asked = false;
            await ConnectAsync(key, identity, agent, " AddKeysToAgent ask\n BatchMode yes\n", (_, _) =>
            {
                asked = true;
                return ValueTask.FromResult(true);
            });

            await Assert.That(asked).IsFalse();
            await Assert.That(agent.AddRequests).IsEmpty();
        }
    }

    [Test]
    public async Task WithoutAsk_TheCallbackIsNotAsked()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            var asked = false;
            await ConnectAsync(key, identity, agent, " AddKeysToAgent confirm 10m\n", (_, _) =>
            {
                asked = true;
                return ValueTask.FromResult(false);
            });

            await Assert.That(asked).IsFalse();
            var added = agent.AddRequests.Single();
            await Assert.That(added.Confirm).IsTrue();
            await Assert.That(added.LifetimeSeconds).IsEqualTo(600u);
        }
    }

    [Test]
    public async Task WhatTheCallbackThrows_FailsTheConnection_AndClosesIt()
    {
        var (key, identity) = await IdentityAsync();
        using (key)
        {
            await using var agent = new FakeAgent();
            await Assert.That(async () => await ConnectAsync(key, identity, agent, " AddKeysToAgent ask\n",
                (_, _) => throw new InvalidOperationException("the prompt failed"))).Throws<InvalidOperationException>();
            await Assert.That(agent.AddRequests).IsEmpty();
        }
    }
}
