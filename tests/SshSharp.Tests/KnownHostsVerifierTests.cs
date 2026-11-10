using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;

namespace SshSharp.Tests;

/// <summary>StrictHostKeyChecking semantics against real files: what is trusted, refused, asked about and recorded.</summary>
public sealed class KnownHostsVerifierTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-kh-" + Guid.NewGuid().ToString("N"));

    public KnownHostsVerifierTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string UserFile => Path.Combine(_dir, "known_hosts");

    private static SshHostKey Ed25519Key()
    {
        var blob = Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(RandomNumberGenerator.GetBytes(32));
        });
        return new SshHostKey("ssh-ed25519", "ssh-ed25519", "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), blob, 256);
    }

    private static SshHostKey EcdsaKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = ecdsa.ExportParameters(false).Q;
        var blob = Blob(w =>
        {
            w.WriteString("ecdsa-sha2-nistp256");
            w.WriteString("nistp256");
            w.WriteString([4, .. q.X!, .. q.Y!]);
        });
        return new SshHostKey("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), blob, 256);
    }

    private static SshHostKeyContext Context(SshHostKey key, string? host = "server.example", int port = 22, string? alias = null) =>
        new(host, port, alias, key);

    private static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static string Line(string host, SshHostKey key, string marker = "") =>
        $"{marker}{host} {key.KeyType} {Convert.ToBase64String(key.PublicKey.Span)}\n";

    private KnownHostsVerifier Verifier(StrictHostKeyChecking policy, Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? ask = null, string? global = null) =>
        new([UserFile], global is null ? [] : [global]) { Policy = policy, AskHostKey = ask };

    [Test]
    public async Task AMatchingKeyIsTrusted_UnderEveryPolicy()
    {
        var key = Ed25519Key();
        File.WriteAllText(UserFile, Line("server.example", key));
        foreach (var policy in Enum.GetValues<StrictHostKeyChecking>())
        {
            var verdict = await Verifier(policy).VerifyAsync(Context(key), default);
            await Assert.That(verdict.IsAccepted).IsTrue();
            await Assert.That(verdict.IsUntrusted).IsFalse();
        }
    }

    [Test]
    public async Task AnUnknownKey_IsRefusedByYes_AndRecordedByAcceptNewAndNo()
    {
        var key = Ed25519Key();
        var refused = await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key), default);
        await Assert.That(refused.IsAccepted).IsFalse();
        await Assert.That(refused.Reason).Contains("not in known_hosts");
        await Assert.That(File.Exists(UserFile)).IsFalse();

        await Assert.That((await Verifier(StrictHostKeyChecking.AcceptNew).VerifyAsync(Context(key), default)).IsAccepted).IsTrue();
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(Line("server.example", key));

        // Recorded once: the next connection matches and appends nothing.
        await Assert.That((await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key), default)).IsAccepted).IsTrue();
        await Assert.That(File.ReadAllLines(UserFile).Length).IsEqualTo(1);

        // No records an unknown key and trusts it, as ssh does: only a changed key leaves the connection untrusted.
        var other = Ed25519Key();
        var recorded = await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(other, host: "other.example"), default);
        await Assert.That(recorded.IsAccepted).IsTrue();
        await Assert.That(recorded.IsUntrusted).IsFalse();
        await Assert.That(File.ReadAllLines(UserFile).Length).IsEqualTo(2);
    }

    [Test]
    public async Task AChangedKey_IsRefused_ExceptWithNo_WhichDoesNotRecordIt()
    {
        var old = Ed25519Key();
        File.WriteAllText(UserFile, Line("server.example", old));
        var changed = Ed25519Key();
        foreach (var policy in new[] { StrictHostKeyChecking.Yes, StrictHostKeyChecking.AcceptNew, StrictHostKeyChecking.Ask })
        {
            var verdict = await Verifier(policy, ask: (_, _) => ValueTask.FromResult(true)).VerifyAsync(Context(changed), default);
            await Assert.That(verdict.IsAccepted).IsFalse();
            await Assert.That(verdict.Reason).Contains("changed");
        }

        // Accepted, but not trusted: the connection then sends no password and forwards nothing (see ChangedHostKeyTests).
        var accepted = await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(changed), default);
        await Assert.That(accepted.IsAccepted).IsTrue();
        await Assert.That(accepted.IsUntrusted).IsTrue();
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(Line("server.example", old));
    }

    [Test]
    [Arguments("*")]
    [Arguments("*.example.com")]
    [Arguments("server.example,other.example")]
    [Arguments("!server.example")]
    [Arguments("ser?er.example")]
    [Arguments("server.example\n* ssh-ed25519 AAAA")]
    [Arguments("server example")]
    [Arguments("@cert-authority")] // a marker in the host field: the line would be read as a marker line
    [Arguments("#server.example")] // the line would be a comment
    public async Task AHostNameThatWouldBeRecordedAsAPattern_IsRefused_NotRecorded(string host)
    {
        // Written as is, these would trust the key for other hosts, or add hosts, fields or lines.
        foreach (var policy in new[] { StrictHostKeyChecking.AcceptNew, StrictHostKeyChecking.No })
        {
            var verdict = await Verifier(policy).VerifyAsync(Context(Ed25519Key(), host: host), default);
            await Assert.That(verdict.IsAccepted).IsFalse();
            await Assert.That(verdict.Reason).Contains("cannot be recorded");
        }

        await Assert.That(File.Exists(UserFile)).IsFalse();
    }

    [Test]
    public async Task KnownHostsFile_RefusesHostFieldsWithWhiteSpaceOrControlCharacters()
    {
        var key = Ed25519Key();
        await Assert.That(async () => await KnownHostsFile.AppendAsync(UserFile, "a b", 22, key.KeyType, key.PublicKey)).Throws<ArgumentException>();
        await Assert.That(() => new KnownHostsFile().Add("a\nb", 22, key.KeyType, key.PublicKey.Span)).Throws<ArgumentException>();

        // A host field starting with '@' would make the line a marker line: written as "@cert-authority * <key> <comment>", the comment
        // (a key of the caller's choosing) would be read back as a certificate authority trusted for every host. '#' would make it a comment.
        var authority = Convert.ToBase64String(EcdsaKey().PublicKey.Span);
        foreach (var host in new[] { "@cert-authority", "@revoked", "#comment" })
        {
            await Assert.That(() => new KnownHostsEntry(host, "*", key.PublicKey, KnownHostsMarker.None, comment: authority)).Throws<ArgumentException>();
            await Assert.That(() => KnownHostsEntry.ForHost(host, 22, key.KeyType, key.PublicKey, hash: false, comment: null, KnownHostsMarker.None))
                .Throws<ArgumentException>();
            await Assert.That(() => new KnownHostsFile().Add(host, 22, key.KeyType, key.PublicKey.Span)).Throws<ArgumentException>();
        }

        // Elsewhere in the field, '@' is only a character (OpenSSH matches it literally); hashed hosts start with '|'.
        await Assert.That(new KnownHostsEntry("a@b.example", key.KeyType, key.PublicKey).HostPatterns).IsEqualTo("a@b.example");
        await Assert.That(new KnownHostsEntry(KnownHostsEntry.HashHost("server.example", 22), key.KeyType, key.PublicKey).Marker).IsEqualTo(KnownHostsMarker.None);

        // Patterns stay possible when written on purpose (for @cert-authority lines, for example).
        await Assert.That(new KnownHostsFile().Add("*.example.com", 22, key.KeyType, key.PublicKey.Span, marker: KnownHostsMarker.CertAuthority).HostPatterns)
            .IsEqualTo("*.example.com");
    }

    [Test]
    public async Task HostKeys_AreEqualWhenTheirKeysAre_NotTheirBuffers()
    {
        var key = Ed25519Key();
        var copy = key with { PublicKey = key.PublicKey.ToArray() }; // the same key from another connection: another buffer
        await Assert.That(copy).IsEqualTo(key);
        await Assert.That(copy.GetHashCode()).IsEqualTo(key.GetHashCode());
        await Assert.That(Ed25519Key()).IsNotEqualTo(key);
    }

    [Test]
    public async Task ARevokedKey_IsRefusedEvenWithNo()
    {
        var key = Ed25519Key();
        File.WriteAllText(UserFile, Line("server.example", key) + Line("*", key, "@revoked "));
        var verdict = await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(key), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("@revoked");
    }

    // ---- host certificates: one from a trusted authority that cannot be used falls back to the plain key, as ssh does ----

    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A host key with a certificate for it from <paramref name="authority"/>, unusable for the default host as <paramref name="problem"/> says.</summary>
    private static SshHostKey CertifiedKey(SshPrivateKey authority, SshPrivateKey host, string problem = "expired")
    {
        var (principals, after, before) = problem switch
        {
            "expired" => (new[] { "server.example" }, (DateTimeOffset?)null, (DateTimeOffset?)Now.AddHours(-1)),
            "not yet valid" => (["server.example"], Now.AddHours(1), null),
            "principal" => (["other.example"], null, null),
            _ => (["server.example"], null, null),
        };
        var blob = host.PublicKey.ToArray();
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, blob, SshCertificateType.Host, principals, after, before, keyId: "web-1"));
        return new SshHostKey(certificate.Algorithm, host.KeyType, host.Fingerprint, blob, 256) { Certificate = certificate };
    }

    private static string AuthorityLine(SshPrivateKey authority, string marker = "@cert-authority") =>
        $"{marker} * {authority.KeyType} {Convert.ToBase64String(authority.PublicKey.Span)}\n";

    private KnownHostsVerifier CertificateVerifier(StrictHostKeyChecking policy, Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? ask = null) =>
        new([UserFile]) { Policy = policy, AskHostKey = ask, Clock = new FakeTimeProvider(Now) };

    private static SshHostKeyContext LoggedContext(SshHostKey key, ListLogger log) => new("server.example", 22, null, key) { Logger = log };

    [Test]
    [Arguments("expired")]
    [Arguments("not yet valid")]
    [Arguments("principal")]
    public async Task AnUnusableCertificateFromATrustedAuthority_IsCheckedAsItsPlainKey_WhichAKnownLineAccepts(string problem)
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var key = CertifiedKey(authority, host, problem);
        var contents = AuthorityLine(authority) + Line("server.example", key);
        File.WriteAllText(UserFile, contents);

        var log = new ListLogger();
        var verdict = await CertificateVerifier(StrictHostKeyChecking.Yes).VerifyAsync(LoggedContext(key, log), default);
        await Assert.That(verdict.IsAccepted).IsTrue();
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(contents);

        // The problem is a warning that names the keys, never the host (nor the key id, which is often a host name).
        await Assert.That(log.Entries.Count).IsEqualTo(1);
        var (level, message) = log.Entries[0];
        await Assert.That(level).IsEqualTo(LogLevel.Warning);
        await Assert.That(message).Contains(host.Fingerprint).And.Contains(authority.Fingerprint).And.Contains("plain key");
        await Assert.That(message).DoesNotContain("server.example").And.DoesNotContain("other.example").And.DoesNotContain("web-1");
    }

    [Test]
    public async Task AnUnusableCertificate_WithoutAPlainLine_IsRefusedByYes_AndItsPlainKeyIsWhatAcceptNewAndAskRecord()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var key = CertifiedKey(authority, host);
        File.WriteAllText(UserFile, AuthorityLine(authority));

        var refused = await CertificateVerifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key), default);
        await Assert.That(refused.IsAccepted).IsFalse();
        await Assert.That(refused.Reason).Contains("not in known_hosts, and StrictHostKeyChecking is yes").And.Contains("could not be used either")
            .And.Contains("valid only");
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(AuthorityLine(authority));

        // As with ssh, Ask offers the key; the prompt's context still has the certificate.
        SshHostKeyPrompt? prompt = null;
        var declined = await CertificateVerifier(StrictHostKeyChecking.Ask, (p, _) =>
        {
            prompt = p;
            return ValueTask.FromResult(false);
        }).VerifyAsync(Context(key), default);
        await Assert.That(declined.IsAccepted).IsFalse();
        await Assert.That(declined.Reason).Contains("was not accepted").And.Contains("could not be used either");
        await Assert.That(prompt!.Context.HostKey.Certificate).IsNotNull();

        // AcceptNew records the certified key as a plain key (ssh drops the certificate before it retries), which is then known.
        var recorded = await CertificateVerifier(StrictHostKeyChecking.AcceptNew).VerifyAsync(Context(key), default);
        await Assert.That(recorded.IsAccepted).IsTrue();
        await Assert.That(File.ReadAllText(UserFile))
            .IsEqualTo(AuthorityLine(authority) + $"server.example ssh-ed25519 {Convert.ToBase64String(host.PublicKey.Span)}\n");
        await Assert.That((await CertificateVerifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key), default)).IsAccepted).IsTrue();
    }

    [Test]
    public async Task AnUnusableCertificate_ForAKeyThatChanged_IsRefusedAsAChangedKey()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        File.WriteAllText(UserFile, AuthorityLine(authority) + Line("server.example", Ed25519Key()));
        var verdict = await CertificateVerifier(StrictHostKeyChecking.AcceptNew).VerifyAsync(Context(CertifiedKey(authority, host, "principal")), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("has changed").And.Contains("not issued for the name connected to");
    }

    [Test]
    public async Task ARevokedAuthorityOrKey_RefusesAnUnusableCertificate_WithoutFallingBackToThePlainKey()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var key = CertifiedKey(authority, host);
        var trusted = AuthorityLine(authority) + Line("server.example", key);

        File.WriteAllText(UserFile, trusted + AuthorityLine(authority, "@revoked"));
        var verdict = await CertificateVerifier(StrictHostKeyChecking.No).VerifyAsync(Context(key), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("authority is marked @revoked");

        File.WriteAllText(UserFile, trusted + Line("*", key, "@revoked "));
        verdict = await CertificateVerifier(StrictHostKeyChecking.No).VerifyAsync(Context(key), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("key is marked @revoked");

        // RevokedHostKeys is checked before anything else, the certificate included.
        var revokedFile = Path.Combine(_dir, "revoked");
        File.WriteAllText(revokedFile, $"{key.KeyType} {Convert.ToBase64String(key.PublicKey.Span)}\n");
        File.WriteAllText(UserFile, trusted);
        var withList = new KnownHostsVerifier([UserFile]) { Policy = StrictHostKeyChecking.No, RevokedHostKeys = revokedFile, Clock = new FakeTimeProvider(Now) };
        verdict = await withList.VerifyAsync(Context(key), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("revoked by file");
    }

    [Test]
    public async Task AValidCertificateFromATrustedAuthority_IsAccepted_WithoutAWarningOrAKnownHostsChange()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var host = SshPrivateKey.Generate(SshKeyType.Ed25519);
        File.WriteAllText(UserFile, AuthorityLine(authority));
        var log = new ListLogger();
        var verdict = await CertificateVerifier(StrictHostKeyChecking.AcceptNew).VerifyAsync(LoggedContext(CertifiedKey(authority, host, "valid"), log), default);
        await Assert.That(verdict.IsAccepted).IsTrue();
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(AuthorityLine(authority));
        await Assert.That(log.Entries).IsEmpty();
    }

    /// <summary>Collects log entries.</summary>
    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    [Test]
    public async Task ARevokedLineWithoutAPort_RefusesTheKeyOnEveryPort_UnderEveryPolicy_AndRecordsNothing()
    {
        // As ssh: "@revoked host" applies to the host on every port, not only 22.
        var key = Ed25519Key();
        var contents = Line("server.example", key, "@revoked ");
        File.WriteAllText(UserFile, contents);
        foreach (var policy in Enum.GetValues<StrictHostKeyChecking>())
        {
            var verdict = await Verifier(policy, ask: (_, _) => ValueTask.FromResult(true)).VerifyAsync(Context(key, port: 2222), default);
            await Assert.That(verdict.IsAccepted).IsFalse().Because($"policy {policy}");
            await Assert.That(verdict.Reason).Contains("@revoked");
        }

        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(contents);
    }

    [Test]
    public async Task ARevokedLineWithoutAPort_WinsOverAMatchForThePort_EvenInAGlobalFile()
    {
        var key = Ed25519Key();
        var global = Path.Combine(_dir, "global_known_hosts");
        File.WriteAllText(UserFile, Line("[server.example]:2222", key));
        File.WriteAllText(global, Line("server.example", key, "@revoked "));

        var verdict = await Verifier(StrictHostKeyChecking.Yes, global: global).VerifyAsync(Context(key, port: 2222), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("@revoked");
    }

    [Test]
    public async Task ARevokedLineForAnotherPort_OrAnotherHost_DoesNotApply_NorDoesTheHostsLineUnderAnAlias()
    {
        var key = Ed25519Key();
        File.WriteAllText(UserFile, Line("[server.example]:2200", key, "@revoked ") + Line("other.example", key, "@revoked ") + Line("[server.example]:2222", key));
        await Assert.That((await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key, port: 2222), default)).IsAccepted).IsTrue();

        // An alias is looked up under its own name, so the host's port-less revocation is not consulted (as ssh with HostKeyAlias).
        File.WriteAllText(UserFile, Line("server.example", key, "@revoked ") + Line("box", key));
        await Assert.That((await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(key, port: 2222, alias: "box"), default)).IsAccepted).IsTrue();
    }

    [Test]
    public async Task ARevokedLineWithoutAPort_RefusesAHostCertificate_ByItsAuthorityOrItsKey()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certificate = SshCertificate.FromBlob(Keys.TestKeys.Certificate(authority, hostKey.PublicKey.ToArray(), SshCertificateType.Host, ["server.example"]));
        var presented = new SshHostKey(certificate.Algorithm, hostKey.KeyType, hostKey.Fingerprint, hostKey.PublicKey, 256) { Certificate = certificate };
        var trust = $"@cert-authority * {authority.ToAuthorizedKeysLine()}\n";

        File.WriteAllText(UserFile, trust);
        await Assert.That((await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(presented, port: 2222), default)).IsAccepted).IsTrue();

        File.WriteAllText(UserFile, trust + $"@revoked server.example {authority.ToAuthorizedKeysLine()}\n");
        var byAuthority = await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(presented, port: 2222), default);
        await Assert.That(byAuthority.IsAccepted).IsFalse();
        await Assert.That(byAuthority.Reason).Contains("authority is marked @revoked");

        File.WriteAllText(UserFile, trust + $"@revoked server.example {hostKey.ToAuthorizedKeysLine()}\n");
        var byKey = await Verifier(StrictHostKeyChecking.Yes).VerifyAsync(Context(presented, port: 2222), default);
        await Assert.That(byKey.IsAccepted).IsFalse();
        await Assert.That(byKey.Reason).Contains("key is marked @revoked");
    }

    [Test]
    public async Task UpdateHostKeys_NeverLearnsAKeyRevokedWithoutAPort()
    {
        var revoked = Ed25519Key();
        var fine = EcdsaKey();
        File.WriteAllText(UserFile, Line("server.example", revoked, "@revoked "));
        var verifier = new KnownHostsVerifier([UserFile]) { UpdateHostKeys = true };

        var unknown = await verifier.UnknownHostKeysAsync("server.example", 2222, [revoked.PublicKey.ToArray(), fine.PublicKey.ToArray()], default);

        await Assert.That(unknown.Count).IsEqualTo(1);
        await Assert.That(unknown[0].AsSpan().SequenceEqual(fine.PublicKey.Span)).IsTrue();
    }

    [Test]
    public async Task AcceptNew_RefusesANewKeyTypeForAKnownHost_AskSaysWhichTypesAreKnown()
    {
        // A man in the middle without the recorded Ed25519 key could offer an ECDSA key instead.
        File.WriteAllText(UserFile, Line("server.example", Ed25519Key()));
        var ecdsa = EcdsaKey();
        var verdict = await Verifier(StrictHostKeyChecking.AcceptNew).VerifyAsync(Context(ecdsa), default);
        await Assert.That(verdict.IsAccepted).IsFalse();
        await Assert.That(verdict.Reason).Contains("only ssh-ed25519 keys");

        SshHostKeyPrompt? prompt = null;
        var asked = await Verifier(StrictHostKeyChecking.Ask, ask: (p, _) => { prompt = p; return ValueTask.FromResult(false); }).VerifyAsync(Context(ecdsa), default);
        await Assert.That(asked.IsAccepted).IsFalse();
        await Assert.That(prompt!.KnownKeyTypes).IsEquivalentTo(new[] { "ssh-ed25519" });
        await Assert.That(prompt.Context.HostKey).IsEqualTo(ecdsa);
    }

    [Test]
    public async Task Ask_RecordsWhatTheUserAccepts_AndWithoutACallbackBehavesLikeYes()
    {
        var key = Ed25519Key();
        await Assert.That((await Verifier(StrictHostKeyChecking.Ask).VerifyAsync(Context(key), default)).IsAccepted).IsFalse();
        await Assert.That((await Verifier(StrictHostKeyChecking.Ask, ask: (_, _) => ValueTask.FromResult(false)).VerifyAsync(Context(key), default)).IsAccepted).IsFalse();
        await Assert.That(File.Exists(UserFile)).IsFalse();

        SshHostKeyPrompt? prompt = null;
        var accepted = await Verifier(StrictHostKeyChecking.Ask, ask: (p, _) => { prompt = p; return ValueTask.FromResult(true); }).VerifyAsync(Context(key), default);
        await Assert.That(accepted.IsAccepted).IsTrue();
        await Assert.That(prompt!.KnownKeyTypes).IsEmpty();
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo(Line("server.example", key));
    }

    [Test]
    public async Task NonDefaultPorts_AliasesAndHashing_AreRecordedLikeSsh()
    {
        var key = Ed25519Key();
        await new KnownHostsVerifier([UserFile]) { Policy = StrictHostKeyChecking.AcceptNew }.VerifyAsync(Context(key, port: 2222), default);
        await new KnownHostsVerifier([UserFile]) { Policy = StrictHostKeyChecking.AcceptNew }.VerifyAsync(Context(key, port: 2222, alias: "box"), default);
        await new KnownHostsVerifier([UserFile]) { Policy = StrictHostKeyChecking.AcceptNew, HashNewEntries = true }.VerifyAsync(Context(key, host: "hidden.example"), default);

        var lines = File.ReadAllLines(UserFile);
        await Assert.That(lines[0]).StartsWith("[server.example]:2222 ");
        await Assert.That(lines[1]).StartsWith("box "); // an alias is looked up without the port, as ssh does
        await Assert.That(lines[2]).StartsWith("|1|");
        await Assert.That(lines[2]).DoesNotContain("hidden");
        await Assert.That(KnownHostsFile.Load(UserFile).Check("hidden.example", 22, key.KeyType, key.PublicKey.Span)).IsEqualTo(KnownHostsCheckResult.Match);
    }

    [Test]
    public async Task GlobalFiles_AreTrustedButNeverWritten_AndWithoutAHostNameNothingCanBeChecked()
    {
        var key = Ed25519Key();
        var global = Path.Combine(_dir, "ssh_known_hosts");
        File.WriteAllText(global, Line("server.example", key));
        await Assert.That((await Verifier(StrictHostKeyChecking.Yes, global: global).VerifyAsync(Context(key), default)).IsAccepted).IsTrue();

        var noHost = await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(key, host: null), default);
        await Assert.That(noHost.IsAccepted).IsFalse();
        await Assert.That(noHost.Reason).Contains("HostKeyAlias");
        await Assert.That(File.Exists(UserFile)).IsFalse();
    }

    [Test]
    public async Task Append_StartsANewLineWhenTheFileDoesNotEndWithOne_AndCreatesDirectories()
    {
        var key = Ed25519Key();
        File.WriteAllText(UserFile, "# hand edited, no newline");
        await KnownHostsFile.AppendAsync(UserFile, "a.example", 22, key.KeyType, key.PublicKey);
        await Assert.That(File.ReadAllText(UserFile)).IsEqualTo("# hand edited, no newline\n" + Line("a.example", key));

        var nested = Path.Combine(_dir, "x", "y", "known_hosts");
        await KnownHostsFile.AppendAsync(nested, "a.example", 22, key.KeyType, key.PublicKey);
        await Assert.That(File.ReadAllText(nested)).IsEqualTo(Line("a.example", key));

        // An empty file has no last line to end, so the entry is its first line.
        var empty = Path.Combine(_dir, "empty_known_hosts");
        File.WriteAllText(empty, "");
        await KnownHostsFile.AppendAsync(empty, "a.example", 22, key.KeyType, key.PublicKey);
        await Assert.That(File.ReadAllText(empty)).IsEqualTo(Line("a.example", key));
    }

    [Test]
    public async Task FromConfig_TakesFilesPolicyAndHashing()
    {
        var config = SshConfig.Parse($"Host *\n UserKnownHostsFile \"{UserFile}\"\n StrictHostKeyChecking accept-new\n HashKnownHosts yes\n")
            .Resolve("server.example", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = _dir });
        var verifier = KnownHostsVerifier.FromConfig(config);
        await Assert.That(verifier.Policy).IsEqualTo(StrictHostKeyChecking.AcceptNew);
        await Assert.That(verifier.HashNewEntries).IsTrue();

        await verifier.VerifyAsync(Context(Ed25519Key()), default);
        await Assert.That(File.ReadAllText(UserFile)).StartsWith("|1|");
    }
}
