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
        // add its keys or have the real one removed as stale. A key logs in: the connection gives such a server no password.
        var real = FakeHostKey.Ed25519();
        var impostor = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, Line(real));
        using var key = SshPrivateKey.Parse(Keys.TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = impostor })
        {
            AnnouncedHostKeys = [impostor, FakeHostKey.Ecdsa(256)],
            AuthorizedKeys = [blob],
            AdvertisedMethods = ["publickey"],
        };
        _ = server.StartAsync();
        var skipped = new SkipLogger();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [key],
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = StrictHostKeyChecking.No, UpdateHostKeys = true },
            Logger = skipped,
        }, leaveOpen: true, Timeout());

        // The untrusted connection is turned away before the known_hosts checks, which would refuse it too (its key is in no user file).
        await skipped.Reason.Task.WaitAsync(Timeout());
        await Assert.That(skipped.Reason.Task.Result).Contains("is not trusted");
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
        var otherHostKey = FakeHostKey.Ecdsa(384);
        File.WriteAllText(KnownHosts, string.Join(string.Empty,
            "# keys for the rotating host\n",
            Line(current),
            Line(retired),
            LineFor("other.example.com", otherHostKey), // another host: kept
            $"{KnownHostsEntry.HashHost(Host, 22)} {retired.KeyType} {Convert.ToBase64String(retired.Blob)}\n")); // hashed, this host: removed
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] };
        await using var client = await ConnectAsync(server, update: true);

        var lines = await WaitForLinesAsync(l => l.Any(x => x.Contains(added.KeyType, StringComparison.Ordinal)) && l.Length == 4);
        await Assert.That(lines).IsEquivalentTo(new[]
        {
            "# keys for the rotating host",
            Line(current).TrimEnd(),
            LineFor("other.example.com", otherHostKey).TrimEnd(),
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

    // ssh's gates on the update (OpenSSH 9.2p1, client_input_hostkeys and hostkeys_find in clientloop.c, check_host_key in
    // sshconnect.c). Each test sets up one case where ssh leaves known_hosts alone, or, for removals alone, where it updates
    // without a proof.

    private static string LineFor(string hosts, FakeHostKey key) => $"{hosts} {key.KeyType} {Convert.ToBase64String(key.Blob)}\n";

    private async Task<SshClient> ConnectAsync(FakeSessionServer server, StrictHostKeyChecking policy, string? globalFile = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts], globalFile is null ? null : [globalFile]) { Policy = policy, UpdateHostKeys = true },
        }, leaveOpen: true, Timeout());
    }

    /// <summary>Gives a skipped update the time an applied one would take, so a test that expects no change does not pass early.</summary>
    private static async Task SettleAsync(SshClient client)
    {
        await client.RunCommandAsync("sync", Timeout());
        await Task.Delay(200);
    }

    [Test]
    public async Task RemovalsAlone_AreAppliedWithoutAProof()
    {
        // ssh: "We can proceed to do this without requiring a fresh proof from the server" (nnew == 0).
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current) + Line(retired));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);

        var lines = await WaitForLinesAsync(l => l.Length == 1);
        await Assert.That(lines).IsEquivalentTo([Line(current).TrimEnd()]);
        await Assert.That(Proved(server)).IsFalse();
    }

    [Test]
    public async Task AKeyFirstRecordedByAcceptNew_DoesNotUpdateOnThatConnection()
    {
        // ssh turns UpdateHostKeys off for a connection whose key was neither known nor confirmed by the user: accept-new records the
        // key and nothing else, and the update starts with the next connection.
        var current = FakeHostKey.Ed25519();
        var other = FakeHostKey.Ecdsa(256);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, other] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.AcceptNew);
        await SettleAsync(client);

        await Assert.That(Proved(server)).IsFalse();
        await Assert.That(Recorded()).IsEquivalentTo([Line(current).TrimEnd()]);
    }

    [Test]
    public async Task AKeyTheUserConfirmed_UpdatesOnThatConnection()
    {
        // ssh's "user explicitly confirmed": unlike AcceptNew, a key accepted at the Ask prompt is trusted for the update.
        var current = FakeHostKey.Ed25519();
        var other = FakeHostKey.Ecdsa(256);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, other] };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts])
            {
                Policy = StrictHostKeyChecking.Ask,
                AskHostKey = (_, _) => ValueTask.FromResult(true),
                UpdateHostKeys = true,
            },
        }, leaveOpen: true, Timeout());

        var lines = await WaitForLinesAsync(l => l.Length == 2);
        await Assert.That(lines).IsEquivalentTo([Line(current).TrimEnd(), Line(other).TrimEnd()]);
    }

    [Test]
    public async Task ALineForMoreThanHostAndAddress_SkipsTheUpdate()
    {
        // ssh never writes a list longer than host,ip, and skips the update when one matches (hostspec_is_complex).
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var original = Line(current) + LineFor($"{Host},192.0.2.10,alias.example.com", retired);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);
        await SettleAsync(client);

        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
    }

    [Test]
    public async Task AWildcardLineForTheHost_SkipsTheUpdate()
    {
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var shared = FakeHostKey.Ecdsa(384);
        var original = Line(current) + Line(retired) + LineFor("*.example.com", shared);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);
        await SettleAsync(client);

        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
    }

    [Test]
    public async Task ACertAuthorityLineForTheHost_SkipsTheUpdate()
    {
        // ssh: "CA/revocation marker, manual host list or wildcard host pattern found, skipping UserKnownHostsFile update".
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var ca = FakeHostKey.Ed25519();
        var original = Line(current) + Line(retired) + LineFor("@cert-authority *.example.com", ca);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);
        await SettleAsync(client);

        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
    }

    [Test]
    public async Task AnAnnouncedKeyRecordedUnderAnotherName_SkipsTheUpdate()
    {
        // ssh: "host key found matching a different name/address, skipping UserKnownHostsFile update" (other_name_seen).
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var original = Line(current) + Line(retired) + LineFor("alias.example.com", current);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);
        await SettleAsync(client);

        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
    }

    [Test]
    public async Task ARetiredKeyAlsoRecordedUnderAnotherName_SkipsTheUpdate()
    {
        // ssh: "key(s) for <host> exist under other names; skipping UserKnownHostsFile update" (old_key_seen), so a host with several
        // names does not lose the key under one of them only.
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var original = Line(current) + Line(retired) + LineFor("alias.example.com", retired);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes);
        await SettleAsync(client);

        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
    }

    [Test]
    public async Task AKeyTrustedThroughTheGlobalFile_DoesNotUpdateTheUserFile()
    {
        // ssh: "host key found in GlobalKnownHostsFile; disabling UpdateHostkeys".
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var global = Path.Combine(_dir, "ssh_known_hosts");
        File.WriteAllText(global, Line(current));
        var original = Line(retired);
        File.WriteAllText(KnownHosts, original);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, FakeHostKey.Ecdsa(384)] };
        await using var client = await ConnectAsync(server, StrictHostKeyChecking.Yes, global);
        await SettleAsync(client);

        await Assert.That(Proved(server)).IsFalse();
        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(original);
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
