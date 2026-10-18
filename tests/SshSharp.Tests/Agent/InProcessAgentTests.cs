using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>
/// An agent served in-process from keys and signers (SshAgent.FromKeys), used for authentication and forwarded to the server, and the
/// filter for forwarded requests (ForwardAgentFilter) over it and over a real agent (#275).
/// </summary>
public sealed class InProcessAgentTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-inproc-" + Guid.NewGuid().ToString("N"));

    // The fake server's password: generated, never written down.
    private readonly string _password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));

    public InProcessAgentTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static readonly FakeServerOptions HostBound = new()
    {
        ExtraExtensions = new Dictionary<string, string> { ["publickey-hostbound@openssh.com"] = "0" },
    };

    private FakeSessionServer NewServer() => new() { Password = _password };

    /// <summary>Connects with the password and forwards <paramref name="agent"/>; one command runs, so the server may open agent channels.</summary>
    private async Task<SshClient> ConnectAsync(FakeSessionServer server, SshAgent agent, Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? filter = null)
    {
        _ = server.StartAsync();
        var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = _password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ForwardAgent = agent,
            ForwardAgentFilter = filter,
        }, leaveOpen: true, Timeout());
        await client.RunCommandAsync("true", Timeout());
        return client;
    }

    /// <summary>One request over a forwarded agent channel, as a program on the server sends it, and its reply.</summary>
    private static async Task<byte[]> RequestAsync(Stream channel, byte[] message)
    {
        var frame = new byte[4 + message.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)message.Length);
        message.CopyTo(frame, 4);
        await channel.WriteAsync(frame, Timeout());
        return await ReadReplyAsync(channel);
    }

    private static async Task<byte[]> ReadReplyAsync(Stream channel)
    {
        var header = new byte[4];
        await channel.ReadExactlyAsync(header, Timeout());
        var reply = new byte[BinaryPrimitives.ReadUInt32BigEndian(header)];
        await channel.ReadExactlyAsync(reply, Timeout());
        return reply;
    }

    private static async Task<int> ListCountAsync(Stream channel)
    {
        var reply = await RequestAsync(channel, [11]);
        return reply[0] == 12 ? (int)BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(1)) : -1;
    }

    private static byte[] SignRequest(SshPrivateKey key, byte[] data, uint flags = 0) => TestKeys.Blob(w =>
    {
        w.WriteByte(13);
        w.WriteString(key.PublicKey.Span);
        w.WriteString(data);
        w.WriteUInt32(flags);
    });

    /// <summary>Whether the channel was closed by the client: reading ends without data.</summary>
    private static async Task<bool> ClosedAsync(Stream channel)
    {
        using var received = new MemoryStream();
        await channel.CopyToAsync(received, Timeout());
        return received.Length == 0;
    }

    [Test]
    public async Task AnInProcessAgent_AuthenticatesLikeARealOne_HostBoundToo()
    {
        using var ed25519 = SshPrivateKey.Generate(SshKeyType.Ed25519, "laptop");
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        var agent = SshAgent.FromKeys(ed25519, rsa);
        await Assert.That(agent.IsInProcess).IsTrue();
        await Assert.That(agent.Path).IsEqualTo("(in-process)");
        await Assert.That(new SshAgent(Path.Combine(_dir, "agent.sock")).IsInProcess).IsFalse();

        var keys = await agent.GetKeysAsync(Timeout());
        await Assert.That(keys.Select(k => k.Fingerprint)).IsEquivalentTo(new[] { ed25519.Fingerprint, rsa.Fingerprint });
        await Assert.That(keys[0].Comment).IsEqualTo("laptop");

        // The server accepts only the RSA key: the agent signs with rsa-sha2-512 over the session the connection is bound to.
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [rsa.PublicKey.ToArray()] };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = keys,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        string[] attempts;
        lock (server.AuthAttempts)
        {
            attempts = [.. server.AuthAttempts];
        }

        await Assert.That(attempts).Contains("publickey-hostbound-signed:rsa-sha2-512");
    }

    [Test]
    public async Task AnInProcessAgent_SignsFiles_AndAnswersTheQuery()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.EcdsaNistp384);
        var agent = SshAgent.FromKeys(key);
        var agentKey = (await agent.GetKeysAsync(Timeout())).Single();
        var data = Encoding.UTF8.GetBytes("release notes");

        var signature = await SshSignature.SignAsync(agentKey, data, "file", cancellationToken: Timeout());

        await Assert.That(signature.Verify(data, "file")).IsTrue();
        await Assert.That(signature.GetPublicKey()).IsEqualTo(key.GetPublicKey());
        await Assert.That(await agent.QueryExtensionsAsync(Timeout())).IsEquivalentTo(new[] { "query", "session-bind@openssh.com" });
    }

    [Test]
    public async Task AnInProcessAgent_IsReadOnly()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var agent = SshAgent.FromKeys(key);
        var passphrase = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12));

        await AssertRefusedAsync(() => agent.AddKeyAsync(other, cancellationToken: Timeout()));
        await AssertRefusedAsync(() => agent.RemoveKeyAsync(key, Timeout()));
        await AssertRefusedAsync(() => agent.RemoveAllKeysAsync(Timeout()));
        await AssertRefusedAsync(() => agent.LockAsync(passphrase, Timeout()));
        await AssertRefusedAsync(() => agent.UnlockAsync(passphrase, Timeout()));
        await Assert.That((await agent.GetKeysAsync(Timeout())).Count).IsEqualTo(1);

        static async Task AssertRefusedAsync(Func<Task> call)
        {
            var exception = await Assert.That(call).Throws<SshException>();
            await Assert.That(exception!.Reason).IsEqualTo(SshFailureReason.AgentFailed);
        }
    }

    [Test]
    public async Task AnInProcessAgent_WithAKmsSigner_AuthenticatesAndIsForwarded()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var signer = new AgentServerTests.KeySigner(inner);
        using var kmsKey = SshPrivateKey.FromSigner(signer, "kms");
        var agent = SshAgent.FromKeys(kmsKey);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, agent);

        await using var channel = await server.OpenAgentChannelAsync();
        var data = AgentServerTests.Login(kmsKey, "ssh-ed25519");
        var reply = await RequestAsync(channel!, SignRequest(kmsKey, data));

        await Assert.That(reply[0]).IsEqualTo((byte)14);
        var blob = new SshReader(reply.AsSpan(1)).ReadString().ToArray();
        await Assert.That(kmsKey.GetPublicKey().VerifySignature(data, blob)).IsTrue();
        await Assert.That(signer.Requests.Single().Purpose).IsEqualTo(SshSignaturePurpose.Authentication);
    }

    [Test]
    public async Task AForwardedInProcessAgent_ListsAndSigns_ForTheServersPrograms()
    {
        using var ed25519 = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(ed25519, rsa));

        await using var channel = await server.OpenAgentChannelAsync();
        await Assert.That(channel).IsNotNull();
        await Assert.That(await ListCountAsync(channel!)).IsEqualTo(2);

        var data = AgentServerTests.Login(rsa, "rsa-sha2-256");
        var reply = await RequestAsync(channel!, SignRequest(rsa, data, flags: 2));
        await Assert.That(reply[0]).IsEqualTo((byte)14);
        var blob = new SshReader(reply.AsSpan(1)).ReadString().ToArray();
        await Assert.That(new SshReader(blob).ReadUtf8String()).IsEqualTo("rsa-sha2-256");
        await Assert.That(rsa.GetPublicKey().VerifySignature(data, blob)).IsTrue();

        // Never SHA-1, and the agent cannot be changed from the server.
        await Assert.That(await RequestAsync(channel!, SignRequest(rsa, data))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await RequestAsync(channel!, [19])).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await ListCountAsync(channel!)).IsEqualTo(2);
    }

    [Test]
    public async Task ForwardedChannels_AreServedConcurrently()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(key));

        var channels = new List<Stream>();
        for (var i = 0; i < 8; i++)
        {
            channels.Add((await server.OpenAgentChannelAsync())!);
        }

        try
        {
            var results = await Task.WhenAll(channels.Select(async channel =>
            {
                var replies = new List<byte>();
                for (var round = 0; round < 5; round++)
                {
                    replies.Add((await RequestAsync(channel, SignRequest(key, AgentServerTests.SshSig("file"))))[0]);
                    replies.Add((byte)await ListCountAsync(channel));
                }

                return replies;
            }));

            foreach (var replies in results)
            {
                await Assert.That(replies).IsEquivalentTo(new byte[] { 14, 1, 14, 1, 14, 1, 14, 1, 14, 1 });
            }
        }
        finally
        {
            foreach (var channel in channels)
            {
                await channel.DisposeAsync();
            }
        }
    }

    [Test]
    public async Task RequestsSplitOrJoinedOnTheChannel_AreEachAnswered()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(key));
        await using var channel = (await server.OpenAgentChannelAsync())!;

        // One request a byte at a time.
        foreach (var b in new byte[] { 0, 0, 0, 1, 11 })
        {
            await channel.WriteAsync(new[] { b }, Timeout());
            await channel.FlushAsync(Timeout());
        }

        await Assert.That((await ReadReplyAsync(channel))[0]).IsEqualTo((byte)12);

        // Three requests in one write: three replies, in order.
        await channel.WriteAsync(new byte[] { 0, 0, 0, 1, 11, 0, 0, 0, 1, 17, 0, 0, 0, 1, 11 }, Timeout());
        await Assert.That((await ReadReplyAsync(channel))[0]).IsEqualTo((byte)12);
        await Assert.That((await ReadReplyAsync(channel))[0]).IsEqualTo((byte)5);
        await Assert.That((await ReadReplyAsync(channel))[0]).IsEqualTo((byte)12);
    }

    [Test]
    public async Task AMalformedRequest_IsRefused_AndTheChannelCarriesOn()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(key));
        await using var channel = (await server.OpenAgentChannelAsync())!;

        await Assert.That(await RequestAsync(channel, [13, 0, 0, 0, 200, 1, 2])).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await RequestAsync(channel, [27, 0, 0, 0, 3, 0xC3, 0x28, 0x41])).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await ListCountAsync(channel)).IsEqualTo(1);
    }

    [Test]
    [Arguments(0u)]
    [Arguments(256u * 1024 + 1)]
    [Arguments(uint.MaxValue)]
    public async Task AnEmptyOrOversizedMessage_ClosesTheChannel_NotTheConnection(uint length)
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(key));

        await using (var channel = (await server.OpenAgentChannelAsync())!)
        {
            var header = new byte[5];
            BinaryPrimitives.WriteUInt32BigEndian(header, length);
            await channel.WriteAsync(header, Timeout());
            await Assert.That(await ClosedAsync(channel)).IsTrue();
        }

        await Assert.That(client.IsConnected).IsTrue();
        await using var next = (await server.OpenAgentChannelAsync())!;
        await Assert.That(await ListCountAsync(next)).IsEqualTo(1);
    }

    [Test]
    public async Task AMessageAtTheLimit_IsReadAndAnswered()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(key));
        await using var channel = (await server.OpenAgentChannelAsync())!;

        var message = new byte[256 * 1024];
        message[0] = 13; // a signing request whose fields do not parse
        await Assert.That(await RequestAsync(channel, message)).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await ListCountAsync(channel)).IsEqualTo(1);
    }

    [Test]
    public async Task TheFilter_HidesKeys_RefusesSignatures_AndCanAskTheUser()
    {
        using var shown = SshPrivateKey.Generate(SshKeyType.Ed25519, "shown");
        using var hidden = SshPrivateKey.Generate(SshKeyType.Ed25519, "hidden");
        var confirm = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var asked = new List<SshAgentRequest>();
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, SshAgent.FromKeys(shown, hidden), async (request, cancellationToken) =>
        {
            lock (asked)
            {
                asked.Add(request);
            }

            if (request.Operation == SshAgentOperation.ListKeys)
            {
                return request.Key.Comment == "shown";
            }

            // A confirmation, as ssh-add -c asks: the user answers later.
            return request.Key.Comment == "shown" && await confirm.Task.WaitAsync(cancellationToken);
        });
        await using var channel = (await server.OpenAgentChannelAsync())!;

        await Assert.That(await ListCountAsync(channel)).IsEqualTo(1);
        await Assert.That(await RequestAsync(channel, SignRequest(hidden, AgentServerTests.SshSig("file")))).IsEquivalentTo(new byte[] { 5 });

        var signing = RequestAsync(channel, SignRequest(shown, AgentServerTests.SshSig("file")));
        await Task.Delay(100);
        await Assert.That(signing.IsCompleted).IsFalse();
        confirm.SetResult(true);
        await Assert.That((await signing)[0]).IsEqualTo((byte)14);

        // The first hop is this connection's server, known from this client's own key exchange.
        await Assert.That(asked.Last().ForwardingHostKeys).IsEquivalentTo(new[] { client.HostKey.GetPublicKey() });
    }

    [Test]
    public async Task WithAFilter_ARealAgentsRequestsAreCheckedOneByOne()
    {
        await using var agent = new FakeAgent();
        using var allowed = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var refused = SshPrivateKey.Generate(SshKeyType.Ed25519);
        agent.Keys.Add((allowed, "allowed"));
        agent.Keys.Add((refused, "refused"));
        var asked = new List<SshAgentRequest>();
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path), (request, _) =>
        {
            lock (asked)
            {
                asked.Add(request);
            }

            return ValueTask.FromResult(request.Key.Comment != "refused" && request.Key != refused.GetPublicKey());
        });
        await using var channel = (await server.OpenAgentChannelAsync())!;

        await Assert.That(await ListCountAsync(channel)).IsEqualTo(1);

        // The agent connection was bound to this session as a forwarding one first, as without a filter.
        await Assert.That(agent.Bindings.Single().IsForwarding).IsTrue();
        await Assert.That(await RequestAsync(channel, SignRequest(refused, AgentServerTests.SshSig("git")))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(agent.LastSignedData).IsNull(); // refused here: the agent never saw it

        var data = AgentServerTests.SshSig("git");
        await Assert.That((await RequestAsync(channel, SignRequest(allowed, data)))[0]).IsEqualTo((byte)14);
        await Assert.That(agent.LastSignedData).IsEquivalentTo(data);

        // Read-only: nothing reaches the agent that would change it.
        var lockRequest = TestKeys.Blob(w => { w.WriteByte(22); w.WriteString(Convert.ToBase64String(RandomNumberGenerator.GetBytes(12))); });
        await Assert.That(await RequestAsync(channel, lockRequest)).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await RequestAsync(channel, [19])).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(agent.LockPassphrase).IsNull();
        await Assert.That(agent.Keys.Count).IsEqualTo(2);

        await Assert.That(asked.Select(r => r.Operation)).IsEquivalentTo(new[]
        {
            SshAgentOperation.ListKeys, SshAgentOperation.ListKeys, SshAgentOperation.Sign, SshAgentOperation.Sign,
        });
        await Assert.That(asked.Last().Namespace).IsEqualTo("git");
        await Assert.That(asked.Last().ForwardingHostKeys).IsEquivalentTo(new[] { client.HostKey.GetPublicKey() });
    }

    [Test]
    public async Task WithAFilter_ARealAgentsRefusal_IsPassedOn()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        agent.Keys.Add((key, "declined"));
        agent.RefuseToSign.Add(key.Fingerprint); // the agent's own confirmation, declined
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path), (_, _) => ValueTask.FromResult(true));
        await using var channel = (await server.OpenAgentChannelAsync())!;

        await Assert.That(await RequestAsync(channel, SignRequest(key, AgentServerTests.SshSig("file")))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(agent.LastSignedData).IsNotNull();
    }

    [Test]
    public async Task WithAFilter_ARealAgentThatGoesAway_ClosesTheChannel()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        agent.Keys.Add((key, "laptop"));
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path), (_, _) => ValueTask.FromResult(true));
        await using var channel = (await server.OpenAgentChannelAsync())!;
        await Assert.That(await ListCountAsync(channel)).IsEqualTo(1);

        agent.RawReply = [0, 0, 0, 0]; // a broken agent: an empty reply, then it hangs up
        await channel.WriteAsync(new byte[] { 0, 0, 0, 1, 11 }, Timeout());
        await Assert.That(await ClosedAsync(channel)).IsTrue();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task WithoutAFilter_ARealAgentIsRelayedByteForByte()
    {
        // The relay is as before: even a request that changes the agent reaches it (a filter makes the forwarded agent read-only).
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        agent.Keys.Add((key, "laptop"));
        await using var server = NewServer();
        await using var client = await ConnectAsync(server, new SshAgent(agent.Path));
        await using var channel = (await server.OpenAgentChannelAsync())!;

        var passphrase = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12));
        await Assert.That(await RequestAsync(channel, TestKeys.Blob(w => { w.WriteByte(22); w.WriteString(passphrase); }))).IsEquivalentTo(new byte[] { 6 });
        await Assert.That(agent.LockPassphrase).IsEqualTo(passphrase);

        // And no request is judged: an RSA-less, arbitrary signing request goes to the agent as it is.
        await RequestAsync(channel, TestKeys.Blob(w => { w.WriteByte(13); w.WriteString(key.PublicKey.Span); w.WriteString("anything"u8); w.WriteUInt32(0); }));
        await Assert.That(agent.LastSignedData).IsEquivalentTo("anything"u8.ToArray());
    }

    [Test]
    public async Task ConfigConnect_ForwardsAnInProcessAgent_ThroughTheFilter()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var asked = 0;
        await using var server = NewServer();
        var config = "Host *\n User tester\n ForwardAgent yes\n StrictHostKeyChecking no\n UserKnownHostsFile none\n";
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = _password,
            Agent = SshAgent.FromKeys(key),
            ForwardAgentFilter = (_, _) =>
            {
                Interlocked.Increment(ref asked);
                return ValueTask.FromResult(false);
            },
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        await client.RunCommandAsync("true", Timeout());

        await using var channel = (await server.OpenAgentChannelAsync())!;
        await Assert.That(await ListCountAsync(channel)).IsEqualTo(0);
        await Assert.That(asked).IsEqualTo(1);
    }
}
