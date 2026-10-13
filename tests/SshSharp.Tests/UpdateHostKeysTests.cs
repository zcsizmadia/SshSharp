using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>OpenSSH's UpdateHostKeys (PROTOCOL 2.5): new host keys are recorded only after the server proves it holds them.</summary>
public sealed class UpdateHostKeysTests : IDisposable
{
    private const string Host = "rotating.example.com";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-uhk-" + Guid.NewGuid().ToString("N"));

    public UpdateHostKeysTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private static string Line(FakeHostKey key) => $"{Host} {key.KeyType} {Convert.ToBase64String(key.Blob)}\n";

    private async Task<SshClient> ConnectAsync(FakeSessionServer server, bool update)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes, UpdateHostKeys = update },
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>The recorded lines; the update appends from a background task, so a read can meet the file mid-write.</summary>
    private string[] Recorded()
    {
        try
        {
            using var stream = new FileStream(KnownHosts, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var text = reader.ReadToEnd();
            return text.EndsWith('\n') ? [.. text.Split('\n').Where(l => l.Length > 0)] : [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    [Test]
    public async Task AProvenNewKey_IsRecorded_AndKnownOnesAreNotDuplicated()
    {
        var current = FakeHostKey.Ed25519();
        var added = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] };
        await using var client = await ConnectAsync(server, update: true);

        string[] expected = [Line(current).TrimEnd(), Line(added).TrimEnd()];
        for (var i = 0; i < 500 && !Recorded().SequenceEqual(expected); i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(Recorded()).IsEquivalentTo(expected);
        int proveRequests;
        lock (server.GlobalRequests)
        {
            proveRequests = server.GlobalRequests.Count(r => r == "hostkeys-prove-00@openssh.com");
        }

        await Assert.That(proveRequests).IsEqualTo(1);

        // The new key is now trusted with StrictHostKeyChecking yes: a server presenting it is accepted.
        await using var rotated = new FakeSessionServer(new FakeServerOptions { HostKey = added });
        await using var next = await ConnectAsync(rotated, update: false);
        await Assert.That(next.HostKey.KeyType).IsEqualTo("ecdsa-sha2-nistp256");
    }

    [Test]
    public async Task Sha1ProofsForRsaKeys_LeaveOnlyThatKeyOut()
    {
        // Older OpenSSH proves RSA keys with SHA-1 when the connection's host key is not RSA (found by the interop matrix).
        var current = FakeHostKey.Ed25519();
        var rsa = FakeHostKey.Rsa(2048);
        var ecdsa = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current })
        {
            AnnouncedHostKeys = [current, rsa, ecdsa],
            ProveRsaWithSha1 = true,
        };
        await using var client = await ConnectAsync(server, update: true);

        string[] expected = [Line(current).TrimEnd(), Line(ecdsa).TrimEnd()];
        for (var i = 0; i < 500 && !Recorded().SequenceEqual(expected); i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(Recorded()).IsEquivalentTo(expected);
    }

    [Test]
    public async Task InvalidProofs_RecordNothing()
    {
        var current = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current })
        {
            AnnouncedHostKeys = [current, FakeHostKey.Ed25519()],
            CorruptHostKeyProofs = true,
        };
        await using var client = await ConnectAsync(server, update: true);

        for (var i = 0; i < 300 && !Proved(server); i++)
        {
            await Task.Delay(10);
        }

        await Task.Delay(100);
        await Assert.That(Proved(server)).IsTrue();
        await Assert.That(Recorded().Length).IsEqualTo(1);
        await Assert.That(client.IsConnected).IsTrue(); // a failed update does not end the connection
    }

    [Test]
    public async Task WithUpdateHostKeysOff_NothingIsAskedOrRecorded()
    {
        var current = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, FakeHostKey.Ed25519()] };
        await using var client = await ConnectAsync(server, update: false);
        await client.RunCommandAsync("sync", Timeout());
        await Task.Delay(100);
        await Assert.That(Proved(server)).IsFalse();
        await Assert.That(Recorded().Length).IsEqualTo(1);
    }

    [Test]
    public async Task SshConfig_UpdateHostKeysYes_TurnsItOn_AskDoesNot()
    {
        var resolve = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir };
        await Assert.That(KnownHostsVerifier.FromConfig(SshConfig.Parse("UpdateHostKeys yes\n").Resolve("h", resolve)).UpdateHostKeys).IsTrue();
        await Assert.That(KnownHostsVerifier.FromConfig(SshConfig.Parse("UpdateHostKeys ask\n").Resolve("h", resolve)).UpdateHostKeys).IsFalse();
        await Assert.That(KnownHostsVerifier.FromConfig(SshConfig.Parse("Port 22\n").Resolve("h", resolve)).UpdateHostKeys).IsFalse();
    }

    private static bool Proved(FakeSessionServer server)
    {
        lock (server.GlobalRequests)
        {
            return server.GlobalRequests.Contains("hostkeys-prove-00@openssh.com");
        }
    }
}
