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
    public async Task ASecondAnnouncement_FailsTheConnection_AfterTheFirstUpdatedKnownHosts()
    {
        // sshd announces its keys once per connection; OpenSSH fails the connection on a second announcement ("server already sent
        // hostkeys"), so a server cannot have the client update known_hosts again and again.
        var current = FakeHostKey.Ed25519();
        var added = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] };
        await using var client = await ConnectAsync(server, update: true);

        // The first announcement updates known_hosts as before.
        var lines = await WaitForLinesAsync(l => l.Length == 2);
        await Assert.That(lines).IsEquivalentTo(new[] { Line(current).TrimEnd(), Line(added).TrimEnd() });

        // The second one arrives before the replies to the command's channel, so the connection has failed by the time they would.
        await server.AnnounceHostKeysAgainAsync();
        await AssertFailedWithProtocolErrorAsync(client);
        await Assert.That(Recorded()).IsEquivalentTo(new[] { Line(current).TrimEnd(), Line(added).TrimEnd() });
    }

    [Test]
    public async Task ASecondAnnouncement_WhileTheFirstUpdateRuns_StartsNoSecondUpdate()
    {
        // Two updates at once would race each other on known_hosts. The first one is held at its confirmation while the second
        // announcement arrives: the connection fails, and no second update reaches the confirmation.
        var current = FakeHostKey.Ed25519();
        var added = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, Line(current));
        var asked = 0;
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, added] };
        await using var client = await ConnectAsync(server, async (_, ct) =>
        {
            Interlocked.Increment(ref asked);
            waiting.TrySetResult();
            await Task.Delay(System.Threading.Timeout.Infinite, ct); // held until the connection ends
            return true;
        });

        await waiting.Task.WaitAsync(Timeout());
        await server.AnnounceHostKeysAgainAsync();
        await AssertFailedWithProtocolErrorAsync(client);
        await Assert.That(Volatile.Read(ref asked)).IsEqualTo(1);
        int proveRequests;
        lock (server.GlobalRequests)
        {
            proveRequests = server.GlobalRequests.Count(r => r == "hostkeys-prove-00@openssh.com");
        }

        await Assert.That(proveRequests).IsEqualTo(1);
    }

    [Test]
    public async Task WithUpdateHostKeysOff_RepeatedAnnouncementsAreIgnored()
    {
        // As in OpenSSH, only a client that acts on the announcements checks for repeats.
        var current = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, Line(current));
        await using var server = new FakeSessionServer(new FakeServerOptions { HostKey = current }) { AnnouncedHostKeys = [current, FakeHostKey.Ed25519()] };
        await using var client = await ConnectAsync(server, update: false);
        await server.AnnounceHostKeysAgainAsync();
        await server.AnnounceHostKeysAgainAsync();
        await client.RunCommandAsync("sync", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(Proved(server)).IsFalse();
        await Assert.That(Recorded().Length).IsEqualTo(1);
    }

    /// <summary>
    /// The next command fails, and the connection with a protocol error: the server sent what came before the command's replies, so the
    /// client handled it first.
    /// </summary>
    private static async Task AssertFailedWithProtocolErrorAsync(SshClient client)
    {
        SshException? failure = null;
        try
        {
            await client.RunCommandAsync("sync", Timeout());
        }
        catch (SshException ex)
        {
            failure = ex;
        }

        await Assert.That(failure).IsNotNull();
        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(client.ConnectionError).IsTypeOf<SshProtocolException>();
        await Assert.That(((SshException)client.ConnectionError!).Reason).IsEqualTo(SshFailureReason.ProtocolError);
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

    // ---- the verifier's checks, called directly: which lines are stale, and why an update is skipped (the reason is logged) ----

    private string SecondFile => Path.Combine(_dir, "known_hosts2");

    private KnownHostsVerifier TwoFiles() => new([KnownHosts, SecondFile]) { UpdateHostKeys = true };

    /// <summary>A key of a type this client does not use (DSA): it is never removed as stale, since the server could not announce it.</summary>
    private static string UnsupportedLine(string hosts)
    {
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        var writer = new SshSharp.Protocol.SshWriter(buffer);
        writer.WriteString("ssh-dss");
        writer.WriteString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        return $"{hosts} ssh-dss {Convert.ToBase64String(buffer.WrittenSpan)}\n";
    }

    [Test]
    public async Task TheCheck_FindsTheStaleKeys_OfTheFirstUserFileOnly()
    {
        var current = FakeHostKey.Ed25519();
        var retired = FakeHostKey.Ecdsa(256);
        var retiredHashed = FakeHostKey.Ecdsa(384);
        var inSecondFile = FakeHostKey.Ecdsa(521);
        File.WriteAllText(KnownHosts,
            Line(current)
            + LineFor($"{Host},192.0.2.10", retired) // host and address, as ssh writes them: not a list to leave alone
            + $"{KnownHostsEntry.HashHost(Host, 22)} {retiredHashed.KeyType} {Convert.ToBase64String(retiredHashed.Blob)}\n"
            + UnsupportedLine(Host)
            + LineFor("other.example.com", FakeHostKey.Ed25519())); // another host's key: neither stale nor a reason to skip
        File.WriteAllText(SecondFile, Line(inSecondFile));

        var (skip, stale) = await TwoFiles().CheckHostKeyUpdateAsync(Host, 22, current.Blob, [current.Blob], Timeout());

        await Assert.That(skip).IsNull();
        await Assert.That(stale.Count).IsEqualTo(2);
        await Assert.That(stale.Any(k => k.SequenceEqual(retired.Blob))).IsTrue();
        await Assert.That(stale.Any(k => k.SequenceEqual(retiredHashed.Blob))).IsTrue();
    }

    [Test]
    public async Task TheCheck_NeedsTheConnectionsKey_AsAPlainLineInAUserFile()
    {
        var current = FakeHostKey.Ed25519();
        var other = FakeHostKey.Ecdsa(256);

        // In the second user file only: that is still a user file.
        File.WriteAllText(KnownHosts, Line(other));
        File.WriteAllText(SecondFile, Line(current));
        await Assert.That((await TwoFiles().CheckHostKeyUpdateAsync(Host, 22, current.Blob, [current.Blob, other.Blob], Timeout())).Skip).IsNull();

        // Another key recorded for the host does not stand for the connection's key.
        File.WriteAllText(SecondFile, "");
        var (skip, stale) = await TwoFiles().CheckHostKeyUpdateAsync(Host, 22, current.Blob, [current.Blob, other.Blob], Timeout());
        await Assert.That(skip).IsEqualTo("the connection's host key is not in a user known_hosts file");
        await Assert.That(stale).IsEmpty();

        // Nor does a @revoked line for it.
        File.WriteAllText(KnownHosts, LineFor($"@revoked {Host}", current));
        await Assert.That((await TwoFiles().CheckHostKeyUpdateAsync(Host, 22, current.Blob, [current.Blob], Timeout())).Skip)
            .IsEqualTo("the connection's host key is not in a user known_hosts file");
    }

    [Test]
    public async Task TheCheck_SaysWhyItSkips()
    {
        var current = FakeHostKey.Ed25519();
        var announced = FakeHostKey.Ecdsa(256);
        var retired = FakeHostKey.Ecdsa(384);

        async Task<string?> SkipAsync(string first, string second = "")
        {
            File.WriteAllText(KnownHosts, first);
            File.WriteAllText(SecondFile, second);
            var (skip, stale) = await TwoFiles().CheckHostKeyUpdateAsync(Host, 22, current.Blob, [current.Blob, announced.Blob], Timeout());
            await Assert.That(stale).IsEmpty();
            return skip;
        }

        // One of the announced keys (not the one in use) under another name.
        await Assert.That(await SkipAsync(Line(current) + LineFor("alias.example.com", announced)))
            .IsEqualTo("an announced key is also recorded under another name");
        await Assert.That(await SkipAsync(Line(current) + LineFor($"@cert-authority {Host}", retired)))
            .IsEqualTo("a @cert-authority or @revoked line applies to the host");
        const string Complex = "a wildcard line, or a line naming more than a host and its address, applies to the host";
        await Assert.That(await SkipAsync(Line(current) + LineFor("*.example.com", retired))).IsEqualTo(Complex);
        await Assert.That(await SkipAsync(Line(current) + LineFor("rotating.example.co?", retired))).IsEqualTo(Complex);
        await Assert.That(await SkipAsync(Line(current) + LineFor($"{Host},192.0.2.10,alias.example.com", retired))).IsEqualTo(Complex);

        // The key to remove is also recorded under another name, in one user file of two.
        await Assert.That(await SkipAsync(Line(current) + Line(retired) + LineFor("alias.example.com", retired)))
            .IsEqualTo("a key to remove is also recorded under another name");
    }

    [Test]
    public async Task TheUpdate_AddsAndRemoves_InTheFirstUserFile_AndOnlyRewritesItWhenSomethingIsRemoved()
    {
        var current = FakeHostKey.Ed25519();
        var added = FakeHostKey.Ecdsa(256);
        var retired = FakeHostKey.Ecdsa(384);
        var retiredToo = FakeHostKey.Ecdsa(521);
        File.WriteAllText(KnownHosts, Line(current) + Line(retired) + Line(retiredToo));

        await TwoFiles().ApplyHostKeyUpdateAsync(Host, 22, [added.Blob], [retired.Blob, retiredToo.Blob], Timeout());
        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(Line(current) + Line(added));
        await Assert.That(File.Exists(SecondFile)).IsFalse();

        // A removal that finds nothing leaves the file as it was, byte for byte (a rewrite would end the last line).
        const string Unterminated = "# hand edited, no newline";
        File.WriteAllText(KnownHosts, Unterminated);
        await TwoFiles().ApplyHostKeyUpdateAsync(Host, 22, [], [retired.Blob], Timeout());
        await Assert.That(File.ReadAllText(KnownHosts)).IsEqualTo(Unterminated);

        // Without a user file there is nowhere to write.
        await new KnownHostsVerifier([]).ApplyHostKeyUpdateAsync(Host, 22, [added.Blob], [retired.Blob], Timeout());
    }

    [Test]
    public async Task KeysAlreadyKnown_InAnyFile_AreNotProvenAgain_NorAreKeysRevokedWithoutAPortInAnyFile()
    {
        var known = FakeHostKey.Ed25519();
        var revoked = FakeHostKey.Ecdsa(256);
        var unknown = FakeHostKey.Ecdsa(384);
        var global = Path.Combine(_dir, "ssh_known_hosts");
        File.WriteAllText(KnownHosts, LineFor($"[{Host}]:2222", known));
        File.WriteAllText(global, LineFor($"@revoked {Host}", revoked));
        var verifier = new KnownHostsVerifier([KnownHosts], [global]) { UpdateHostKeys = true };

        var result = await verifier.UnknownHostKeysAsync(Host, 2222, [known.Blob, revoked.Blob, unknown.Blob], Timeout());

        await Assert.That(result.Count).IsEqualTo(1);
        await Assert.That(result[0].SequenceEqual(unknown.Blob)).IsTrue();
    }

    [Test]
    public async Task ARevokedKeysFileThatCannotBeRead_LearnsNoKeys()
    {
        var verifier = new KnownHostsVerifier([KnownHosts]) { UpdateHostKeys = true, RevokedHostKeys = Path.Combine(_dir, "missing") };
        await Assert.That(await verifier.UnknownHostKeysAsync(Host, 22, [FakeHostKey.Ed25519().Blob], Timeout())).IsEmpty();
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
