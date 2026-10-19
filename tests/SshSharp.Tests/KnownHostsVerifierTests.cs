using System.Buffers;
using System.Security.Cryptography;
using SshSharp.Config;
using SshSharp.Protocol;

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
            await Assert.That((await Verifier(policy).VerifyAsync(Context(key), default)).IsAccepted).IsTrue();
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

        var other = Ed25519Key();
        await Assert.That((await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(other, host: "other.example"), default)).IsAccepted).IsTrue();
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

        await Assert.That((await Verifier(StrictHostKeyChecking.No).VerifyAsync(Context(changed), default)).IsAccepted).IsTrue();
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
