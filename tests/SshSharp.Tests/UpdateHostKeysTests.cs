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
            Password = TestSecrets.Password,
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
    public async Task AChangedKeyAcceptedWithStrictHostKeyCheckingNo_UpdatesNothing()
    {
        // A man in the middle presents its own key; StrictHostKeyChecking no lets the connection through, but its announcement must not
        // add its keys or have the real one removed as stale.
        var real = FakeHostKey.Ed25519();
        var impostor = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, Line(real));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = impostor }) { AnnouncedHostKeys = [impostor, FakeHostKey.Ecdsa(256)] };
        _ = server.StartAsync();
        var skipped = new SkipLogger();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.No, UpdateHostKeys = true },
            Logger = skipped,
        }, leaveOpen: true, Timeout());

        await skipped.Reason.Task.WaitAsync(Timeout());
        await Assert.That(skipped.Reason.Task.Result).Contains("not in known_hosts");
        await Assert.That(Recorded()).IsEquivalentTo([Line(real).TrimEnd()]);
        await Assert.That(Proved(server)).IsFalse();
    }

    /// <summary>Completes when the client logs why it skipped a host key update.</summary>
    private sealed class SkipLogger : Microsoft.Extensions.Logging.ILogger
    {
        public TaskCompletionSource<string> Reason { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            if (message.StartsWith("Host key update skipped", StringComparison.Ordinal))
            {
                Reason.TrySetResult(message);
            }
        }
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

    private async Task<SshClient> ConnectAsync(FakeSessionServer server, Func<SshHostKeyUpdate, CancellationToken, ValueTask<bool>>? confirm)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.Yes, UpdateHostKeys = true, ConfirmHostKeyUpdate = confirm },
        }, leaveOpen: true, Timeout());
    }

    /// <summary>All lines of the file once it has the expected number, read safely while the update may still be writing.</summary>
    private async Task<string[]> WaitForLinesAsync(Func<string[], bool> done)
    {
        string[] lines = [];
        for (var i = 0; i < 500; i++)
        {
            try
            {
                using var stream = new FileStream(KnownHosts, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                lines = [.. (await reader.ReadToEndAsync()).Split('\n').Where(l => l.Length > 0)];
                if (done(lines))
                {
                    return lines;
                }
            }
            catch (IOException)
            {
                // Mid-replace.
            }

            await Task.Delay(10);
        }

        return lines;
    }

    [Test]
    public async Task KeysTheServerNoLongerAnnounces_AreRemoved_AndOtherLinesKept()
    {
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var added = FakeHostKey.Rsa(2048);
        var wildcardKey = FakeHostKey.Ecdsa(384);
        File.WriteAllText(KnownHosts, string.Join(string.Empty,
            "# keys for the rotating host\n",
            Line(current),
            Line(retired),
            $"*.example.com {wildcardKey.KeyType} {Convert.ToBase64String(wildcardKey.Blob)}\n", // also about other hosts: kept
            $"@revoked {Host} {retired.KeyType} {Convert.ToBase64String(retired.Blob)}\n", // a marker line: kept
            $"{KnownHostsEntry.HashHost(Host, 22)} {retired.KeyType} {Convert.ToBase64String(retired.Blob)}\n")); // hashed, this host: removed
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] };
        await using var client = await ConnectAsync(server, update: true);

        var lines = await WaitForLinesAsync(l => l.Any(x => x.Contains(added.KeyType, StringComparison.Ordinal)) && l.Length == 5);
        await Assert.That(lines).IsEquivalentTo(new[]
        {
            "# keys for the rotating host",
            Line(current).TrimEnd(),
            $"*.example.com {wildcardKey.KeyType} {Convert.ToBase64String(wildcardKey.Blob)}",
            $"@revoked {Host} {retired.KeyType} {Convert.ToBase64String(retired.Blob)}",
            Line(added).TrimEnd(),
        });
    }

    [Test]
    public async Task TheKeyInUse_IsKept_EvenWhenTheServerLeavesItOut()
    {
        var current = FakeHostKey.Ed25519();
        var other = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current) + Line(other));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [other] };
        await using var client = await ConnectAsync(server, update: true);
        await client.RunCommandAsync("sync", Timeout());
        await Task.Delay(200);
        await Assert.That(Recorded()).IsEquivalentTo(new[] { Line(current).TrimEnd(), Line(other).TrimEnd() });
    }

    [Test]
    public async Task AnUpdate_WaitsForConfirmation_WithTheFingerprints()
    {
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var added = FakeHostKey.Ecdsa(384);
        var original = Line(current) + Line(retired);

        // Declined: nothing changes.
        File.WriteAllText(KnownHosts, original);
        var asked = new TaskCompletionSource<SshHostKeyUpdate>();
        await using (var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] })
        await using (var client = await ConnectAsync(server, (update, _) =>
        {
            asked.TrySetResult(update);
            return ValueTask.FromResult(false);
        }))
        {
            var update = await asked.Task.WaitAsync(Timeout());
            await Assert.That(update.Host).IsEqualTo(Host);
            await Assert.That(update.Port).IsEqualTo(22);
            await Assert.That(update.Added.Single()).IsEqualTo($"ecdsa-sha2-nistp384 {Fingerprint(added)}");
            await Assert.That(update.Removed.Single()).IsEqualTo($"ecdsa-sha2-nistp256 {Fingerprint(retired)}");
            await Task.Delay(200);
            await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
        }

        // Confirmed: applied.
        await using (var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] })
        await using (var client = await ConnectAsync(server, (_, _) => ValueTask.FromResult(true)))
        {
            var lines = await WaitForLinesAsync(l => l.Length == 2 && l.Any(x => x.Contains("nistp384", StringComparison.Ordinal)));
            await Assert.That(lines).IsEquivalentTo(new[] { Line(current).TrimEnd(), Line(added).TrimEnd() });
        }
    }

    [Test]
    public async Task AnAnnouncementWithNothingUsable_ChangesNothing()
    {
        var current = FakeHostKey.Ed25519();
        var other = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current) + Line(other));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [] };
        await using var client = await ConnectAsync(server, update: true);
        await client.RunCommandAsync("sync", Timeout());
        await Task.Delay(200);
        await Assert.That(Recorded().Length).IsEqualTo(2);
    }

    [Test]
    public async Task SshConfig_UpdateHostKeysAsk_IsOnOnlyWithAConfirmation()
    {
        var resolve = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = _dir };
        var config = SshConfig.Parse("UpdateHostKeys ask\n").Resolve("h", resolve);
        await Assert.That(KnownHostsVerifier.FromConfig(config, ask: null, confirmUpdate: null).UpdateHostKeys).IsFalse();
        var withConfirm = KnownHostsVerifier.FromConfig(config, ask: null, confirmUpdate: (_, _) => ValueTask.FromResult(true));
        await Assert.That(withConfirm.UpdateHostKeys).IsTrue();
        await Assert.That(withConfirm.ConfirmHostKeyUpdate is not null).IsTrue();

        // With "yes", a confirmation callback is not used: yes means without asking.
        var yes = KnownHostsVerifier.FromConfig(SshConfig.Parse("UpdateHostKeys yes\n").Resolve("h", resolve), ask: null, confirmUpdate: (_, _) => ValueTask.FromResult(false));
        await Assert.That(yes.UpdateHostKeys).IsTrue();
        await Assert.That(yes.ConfirmHostKeyUpdate is null).IsTrue();
    }

    private static string Fingerprint(FakeHostKey key) =>
        "SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(key.Blob)).TrimEnd('=');

    private static bool Proved(FakeSessionServer server)
    {
        lock (server.GlobalRequests)
        {
            return server.GlobalRequests.Contains("hostkeys-prove-00@openssh.com");
        }
    }
}
