using System.Buffers.Binary;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>
/// Destination-constrained agent keys (#91): agent connections are bound to the SSH session (session-bind@openssh.com), and public key
/// authentication is host-bound (publickey-hostbound-v00@openssh.com) when the server offers it.
/// </summary>
public class SessionBindTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static readonly FakeServerOptions HostBound = new()
    {
        ExtraExtensions = new Dictionary<string, string> { ["publickey-hostbound@openssh.com"] = "0" },
    };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, IReadOnlyList<SshPrivateKey> keys, SshAgent? forward = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = keys,
            Password = forward is null ? null : TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ForwardAgent = forward,
        }, leaveOpen: true, Timeout());
    }

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts.Where(a => a.StartsWith("publickey", StringComparison.Ordinal))];
        }
    }

    [Test]
    public async Task AnAgentSignature_IsMadeOnAConnectionBoundToTheSession()
    {
        await using var agent = new FakeAgent { RequireBinding = true }; // as for a key added with ssh-add -h
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        agent.Keys.Add((key, "constrained"));
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };
        var keys = await new SshAgent(agent.Path).GetKeysAsync(Timeout());

        await using var client = await ConnectAsync(server, keys);

        var binding = agent.Bindings.Single();
        await Assert.That(binding.SignatureValid).IsTrue(); // the host key's signature over the session id, as the agent verifies it
        await Assert.That(binding.IsForwarding).IsFalse();
        await Assert.That(binding.SessionId).IsEquivalentTo(server.SessionId!);
        await Assert.That(binding.HostKey).IsEquivalentTo(client.HostKey.PublicKey.ToArray());
        await Assert.That(Attempts(server)).Contains("publickey-hostbound-signed:ssh-ed25519");
    }

    [Test]
    public async Task HostBoundAuthentication_SignsTheServersHostKey()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        agent.Keys.Add((key, "laptop"));
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };

        await using var client = await ConnectAsync(server, await new SshAgent(agent.Path).GetKeysAsync(Timeout()));

        // What the agent signed: session id, then the request with the host-bound method and, last, the server's host key.
        var (method, hostKey) = ParseSignedRequest(agent.LastSignedData!);
        await Assert.That(method).IsEqualTo("publickey-hostbound-v00@openssh.com");
        await Assert.That(hostKey).IsEquivalentTo(client.HostKey.PublicKey.ToArray());
        await Assert.That(server.HostBoundKeys.Count).IsEqualTo(2); // the query, then the signed request
    }

    private static (string Method, byte[] HostKey) ParseSignedRequest(byte[] data)
    {
        var reader = new SshReader(data);
        reader.ReadString(); // session id
        reader.ReadByte(); // SSH_MSG_USERAUTH_REQUEST
        reader.ReadString(); // user
        reader.ReadString(); // service
        var method = reader.ReadUtf8String();
        reader.ReadBoolean();
        reader.ReadString(); // algorithm
        reader.ReadString(); // public key
        return (method, reader.ReadString().ToArray());
    }

    [Test]
    public async Task ALocalKey_UsesHostBoundAuthenticationToo()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };

        await using var client = await ConnectAsync(server, [key]);

        await Assert.That(Attempts(server)).Contains("publickey-hostbound-signed:ssh-ed25519");
    }

    [Test]
    public async Task WithoutTheServerExtension_PlainPublicKeyIsUsed_AndTheAgentConnectionIsStillBound()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        agent.Keys.Add((key, "laptop"));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };

        await using var client = await ConnectAsync(server, await new SshAgent(agent.Path).GetKeysAsync(Timeout()));

        await Assert.That(Attempts(server)).Contains("publickey-signed:ssh-ed25519");
        await Assert.That(server.HostBoundKeys).IsEmpty();
        await Assert.That(agent.Bindings.Single().SignatureValid).IsTrue();
    }

    [Test]
    public async Task AnAgentWithoutSessionBind_StillSigns()
    {
        // OpenSSH before 8.9, the Windows agent of older releases, and other agents refuse the extension; the signature goes ahead.
        await using var agent = new FakeAgent { RejectBinding = true };
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        agent.Keys.Add((key, "laptop"));
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [blob] };

        await using var client = await ConnectAsync(server, await new SshAgent(agent.Path).GetKeysAsync(Timeout()));

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(agent.Bindings).IsEmpty();
    }

    [Test]
    public async Task EachSignature_BindsItsOwnAgentConnection()
    {
        // The agent refuses a second binding on one connection, so every signature needs a fresh, freshly bound connection.
        await using var agent = new FakeAgent { RequireBinding = true };
        using var first = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var refusedBlob));
        using var second = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var acceptedBlob));
        agent.Keys.Add((first, "first"));
        agent.Keys.Add((second, "second"));
        await using var server = new FakeSessionServer(HostBound) { AdvertisedMethods = ["publickey"], AuthorizedKeys = [acceptedBlob] };

        await using var client = await ConnectAsync(server, await new SshAgent(agent.Path).GetKeysAsync(Timeout()));

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(agent.Bindings.Count).IsEqualTo(1); // only the accepted key was signed with (the first was refused in the query)
        await Assert.That(refusedBlob).IsNotEquivalentTo(acceptedBlob);
    }

    [Test]
    public async Task AForwardedAgentConnection_IsBoundAsForwarding()
    {
        await using var agent = new FakeAgent();
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        agent.Keys.Add((key, "laptop"));
        await using var server = new FakeSessionServer { OnShell = IdleAsync };
        await using var client = await ConnectAsync(server, [], new SshAgent(agent.Path));
        await using var shell = await client.StartShellAsync(cancellationToken: Timeout());

        await using (var channel = await server.OpenAgentChannelAsync())
        {
            // A program on the server lists the keys: the relay starts after the binding, and its reply is not mixed into the stream.
            await channel!.WriteAsync(new byte[] { 0, 0, 0, 1, 11 }, Timeout());
            var header = new byte[4];
            await channel.ReadExactlyAsync(header, Timeout());
            var reply = new byte[BinaryPrimitives.ReadUInt32BigEndian(header)];
            await channel.ReadExactlyAsync(reply, Timeout());
            await Assert.That(reply[0]).IsEqualTo((byte)12);
        }

        var binding = agent.Bindings.Single();
        await Assert.That(binding.IsForwarding).IsTrue();
        await Assert.That(binding.SignatureValid).IsTrue();
        await Assert.That(binding.SessionId).IsEquivalentTo(server.SessionId!);

        await shell.CloseInputAsync(Timeout());
        await shell.WaitForExitAsync(Timeout());
    }

    private static async Task IdleAsync(ExecScript script)
    {
        while (await script.ReadInputAsync() is not null)
        {
        }

        await script.FinishAsync(0);
    }
}
