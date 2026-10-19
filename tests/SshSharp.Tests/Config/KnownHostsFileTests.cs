using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class KnownHostsFileTests
{
    private static readonly byte[] KeyA = [1, 2, 3, 4];
    private static readonly byte[] KeyB = [9, 9, 9, 9];

    private const string KeyAText = "AQIDBA==";

    [Test]
    public async Task AppendAsync_WritesACommentAndAMarker_AsAddDoes()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("kh").FullName, "known_hosts");
        try
        {
            await KnownHostsFile.AppendAsync(path, "*.example.com", 22, "ssh-ed25519", KeyA, hash: false, "corp CA", KnownHostsMarker.CertAuthority);
            await KnownHostsFile.AppendAsync(path, "plain.example.com", 2222, "ssh-ed25519", KeyB); // the old overload: no comment, no marker
            await Assert.That(await File.ReadAllTextAsync(path)).IsEqualTo(
                $"@cert-authority *.example.com ssh-ed25519 {KeyAText} corp CA\n[plain.example.com]:2222 ssh-ed25519 CQkJCQ==\n");

            var entry = KnownHostsFile.Load(path).Entries[0];
            await Assert.That(entry.Marker).IsEqualTo(KnownHostsMarker.CertAuthority);
            await Assert.That(entry.Comment).IsEqualTo("corp CA");
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Test]
    public async Task AddAndAppendAsync_RefuseACommentOrKeyTypeThatWouldWriteAnotherLine()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var key = hostKey.GetPublicKey();
        const string Injected = "ok\n@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==";
        var file = new KnownHostsFile();
        await Assert.That(() => file.Add("srv.example.com", 22, key, comment: Injected)).Throws<ArgumentException>();
        await Assert.That(() => file.Add("srv.example.com", 22, "ssh-ed25519\n@revoked", KeyA)).Throws<ArgumentException>();
        await Assert.That(() => file.Add("srv.example.com", 22, "ssh-ed25519", KeyA, comment: "ok\r")).Throws<ArgumentException>();
        await Assert.That(() => KnownHostsEntry.ForHost("srv.example.com", 22, key, comment: Injected)).Throws<ArgumentException>();
        await Assert.That(file.ToString()).IsEqualTo("");

        var path = Path.Combine(Directory.CreateTempSubdirectory("kh").FullName, "known_hosts");
        try
        {
            await Assert.ThrowsAsync<ArgumentException>(() => KnownHostsFile.AppendAsync(path, "srv.example.com", 22, key, comment: Injected));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                KnownHostsFile.AppendAsync(path, "srv.example.com", 22, "ssh-ed25519", KeyA, hash: false, Injected, KnownHostsMarker.None));
            await Assert.ThrowsAsync<ArgumentException>(() => KnownHostsFile.AppendAsync(path, "srv.example.com", 22, "ssh-ed25519 x", KeyA));
            await Assert.That(File.Exists(path)).IsFalse();
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Test]
    public async Task Parse_StillReadsALineWithAControlCharacterInItsComment()
    {
        // Validation is for values an application writes; a file being read keeps working.
        var file = KnownHostsFile.Parse($"example.com ssh-ed25519 {KeyAText} odd\u0001comment\n");
        await Assert.That(file.Entries.Single().Comment).IsEqualTo("odd\u0001comment");
        await Assert.That(file.Remove("example.com")).IsEqualTo(1);
    }

    [Test]
    public async Task AppendAsync_WithAnSshPublicKey_RoundTripsThroughTheParser_PlainAndHashed()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519, "host-comment");
        var key = hostKey.GetPublicKey();
        var path = Path.Combine(Directory.CreateTempSubdirectory("kh").FullName, "known_hosts");
        try
        {
            var plain = await KnownHostsFile.AppendAsync(path, "srv.example.com", 2222, key);
            var hashed = await KnownHostsFile.AppendAsync(path, "hidden.example.com", 22, key, hash: true, comment: "added by test");

            // The key's own comment is not written; the line is what Add writes, and the library's own parser reads it back.
            await Assert.That(plain.ToLine()).IsEqualTo($"[srv.example.com]:2222 {key.KeyType} {Convert.ToBase64String(key.Blob.Span)}");
            await Assert.That(hashed.IsHashed).IsTrue();
            var file = KnownHostsFile.Load(path);
            await Assert.That(file.InvalidLineCount).IsEqualTo(0);
            await Assert.That(file.Entries.Select(e => e.ToLine())).IsEquivalentTo([plain.ToLine(), hashed.ToLine()]);
            await Assert.That(file.Check("srv.example.com", 2222, key)).IsEqualTo(KnownHostsCheckResult.Match);
            await Assert.That(file.Check("hidden.example.com", key)).IsEqualTo(KnownHostsCheckResult.Match);
            await Assert.That(file.Check("srv.example.com", key)).IsEqualTo(KnownHostsCheckResult.Unknown); // port 22 is another host
            await Assert.That(file.Entries[1].Comment).IsEqualTo("added by test");
            await Assert.That(file.Entries[1].GetPublicKey()).IsEqualTo(key);
            await Assert.That(file.Entries[1].HostPatterns).DoesNotContain("hidden");

            await Assert.ThrowsAsync<ArgumentNullException>(() => KnownHostsFile.AppendAsync(path, "srv.example.com", 22, (SshPublicKey)null!));
            await Assert.ThrowsAsync<ArgumentException>(() => KnownHostsFile.AppendAsync(path, "two hosts", 22, key));
            await Assert.That(KnownHostsFile.Load(path).Entries.Count).IsEqualTo(2); // nothing written for a refused call
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Test]
    public async Task AnEntry_CanBeMadeFromAnSshPublicKey()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256, "ignored");
        var key = hostKey.GetPublicKey();

        var entry = new KnownHostsEntry("a.example.com,192.0.2.10", key, KnownHostsMarker.Revoked, "old key");
        await Assert.That(entry.KeyType).IsEqualTo("ecdsa-sha2-nistp256");
        await Assert.That(entry.PublicKey.ToArray()).IsEquivalentTo(key.Blob.ToArray());
        await Assert.That(entry.ToLine()).IsEqualTo($"@revoked a.example.com,192.0.2.10 ecdsa-sha2-nistp256 {Convert.ToBase64String(key.Blob.Span)} old key");
        await Assert.That(entry.Matches("192.0.2.10")).IsTrue();
        await Assert.That(KnownHostsFile.Parse(entry.ToLine()).Check("a.example.com", key)).IsEqualTo(KnownHostsCheckResult.Revoked);

        // ForHost: the host as ssh stores it, or hashed with a fresh salt each time, as HashKnownHosts does.
        var plain = KnownHostsEntry.ForHost("Srv.Example.com", 22, key);
        await Assert.That(plain.HostPatterns).IsEqualTo("srv.example.com");
        await Assert.That(plain.Comment).IsNull();
        var hashed = KnownHostsEntry.ForHost("srv.example.com", 2200, key, hash: true, comment: "c", KnownHostsMarker.CertAuthority);
        await Assert.That(hashed.IsHashed).IsTrue();
        await Assert.That(hashed.Matches("srv.example.com", 2200)).IsTrue();
        await Assert.That(hashed.Matches("srv.example.com")).IsFalse();
        await Assert.That(hashed.Marker).IsEqualTo(KnownHostsMarker.CertAuthority);
        await Assert.That(KnownHostsEntry.ForHost("srv.example.com", 2200, key, hash: true).HostPatterns).IsNotEqualTo(
            KnownHostsEntry.ForHost("srv.example.com", 2200, key, hash: true).HostPatterns);
        var reparsed = KnownHostsFile.Parse(hashed.ToLine()).Entries.Single();
        await Assert.That((reparsed.HostPatterns, reparsed.Comment, reparsed.Marker)).IsEqualTo((hashed.HostPatterns, "c", KnownHostsMarker.CertAuthority));

        await Assert.That(() => new KnownHostsEntry("a.example.com", (SshPublicKey)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => KnownHostsEntry.ForHost("a.example.com", 22, null!)).Throws<ArgumentNullException>();
        await Assert.That(() => KnownHostsEntry.ForHost("a b", 22, key)).Throws<ArgumentException>();
        await Assert.That(() => KnownHostsEntry.ForHost("a.example.com\n", 22, key)).Throws<ArgumentException>();
        await Assert.That(() => KnownHostsEntry.ForHost(" ", 22, key)).Throws<ArgumentException>();
        await Assert.That(() => KnownHostsEntry.ForHost("a.example.com", 0, key)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task AProtocolException_CanCarryItsCause()
    {
        var cause = new FormatException("bad field");
        var ex = new SshProtocolException("The reply is malformed.", cause);
        await Assert.That(ex.InnerException).IsSameReferenceAs(cause);
        await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task Check_WithoutAPort_IsPort22()
    {
        var file = KnownHostsFile.Parse($"example.com ssh-ed25519 {KeyAText}\n[example.com]:2222 ssh-ed25519 CQkJCQ==\n");
        await Assert.That(file.Check("example.com", "ssh-ed25519", KeyA)).IsEqualTo(file.Check("example.com", 22, "ssh-ed25519", KeyA));
        await Assert.That(file.Check("example.com", "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("example.com", "ssh-ed25519", KeyB)).IsNotEqualTo(KnownHostsCheckResult.Match);
    }

    [Test]
    public async Task Parse_EmptyText()
    {
        var file = KnownHostsFile.Parse("");
        await Assert.That(file.Entries.Count).IsEqualTo(0);
        await Assert.That(file.ToString()).IsEqualTo("");
    }

    [Test]
    public async Task Parse_NullThrows()
    {
        await Assert.That(() => KnownHostsFile.Parse(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task Parse_EntriesCommentsAndInvalidLines_AreKeptVerbatim()
    {
        var text = $"# a comment\n\nexample.com ssh-ed25519 {KeyAText} trailing comment\nnot a valid line\n@bogus h ssh-ed25519 {KeyAText}\nh ssh-ed25519 !!!notbase64\nonly two\n";
        var file = KnownHostsFile.Parse(text);

        await Assert.That(file.Entries.Count).IsEqualTo(1);
        await Assert.That(file.InvalidLineCount).IsEqualTo(4);
        await Assert.That(file.Entries[0].Comment).IsEqualTo("trailing comment");
        await Assert.That(file.ToString()).IsEqualTo(text);
    }

    [Test]
    public async Task Parse_HandlesCrLfAndMissingFinalNewline()
    {
        var file = KnownHostsFile.Parse($"a ssh-ed25519 {KeyAText}\r\nb ssh-ed25519 {KeyAText}");
        await Assert.That(file.Entries.Count).IsEqualTo(2);
        await Assert.That(file.ToString()).IsEqualTo($"a ssh-ed25519 {KeyAText}\nb ssh-ed25519 {KeyAText}\n");
    }

    [Test]
    public async Task Parse_MarkersAndTabs()
    {
        var file = KnownHostsFile.Parse($"@cert-authority\t*.example.com\tssh-ed25519\t{KeyAText}\tca comment\n@revoked h ssh-ed25519 {KeyAText}\n@revoked h2 ssh-ed25519 {KeyAText} why\n");

        await Assert.That(file.Entries.Count).IsEqualTo(3);
        await Assert.That(file.Entries[0].Marker).IsEqualTo(KnownHostsMarker.CertAuthority);
        await Assert.That(file.Entries[0].Comment).IsEqualTo("ca comment");
        await Assert.That(file.Entries[1].Marker).IsEqualTo(KnownHostsMarker.Revoked);
        await Assert.That(file.Entries[1].Comment).IsNull();
        await Assert.That(file.Entries[2].Comment).IsEqualTo("why");
    }

    [Test]
    public async Task Parse_MarkerWithoutEnoughFields_IsInvalid()
    {
        var file = KnownHostsFile.Parse("@revoked h ssh-ed25519\n");
        await Assert.That(file.Entries.Count).IsEqualTo(0);
        await Assert.That(file.InvalidLineCount).IsEqualTo(1);
    }

    [Test]
    public async Task Check_Unknown_Match_Changed()
    {
        var file = KnownHostsFile.Parse($"example.com ssh-ed25519 {KeyAText}\n");

        await Assert.That(file.Check("example.com", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("example.com", 22, "ssh-ed25519", KeyB)).IsEqualTo(KnownHostsCheckResult.Changed);
        await Assert.That(file.Check("example.com", 22, "ssh-rsa", KeyB)).IsEqualTo(KnownHostsCheckResult.Unknown);
        await Assert.That(file.Check("other.com", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Unknown);
        await Assert.That(file.Check("example.com", 2222, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Unknown);
    }

    [Test]
    public async Task Check_MatchBeatsChanged_WhenHostHasSeveralKeys()
    {
        var file = KnownHostsFile.Parse($"h ssh-ed25519 AAAA\nh ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Check("h", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);
    }

    [Test]
    public async Task Check_RevokedWinsOverMatch_OtherRevokedKeysDoNot()
    {
        var file = KnownHostsFile.Parse($"h ssh-ed25519 {KeyAText}\n@revoked h ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Check("h", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Revoked);

        var other = KnownHostsFile.Parse($"h ssh-ed25519 {KeyAText}\n@revoked h ssh-ed25519 /////w==\n");
        await Assert.That(other.Check("h", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);
    }

    [Test]
    public async Task Check_IgnoresCertAuthorityLines_AndFindsThem()
    {
        var file = KnownHostsFile.Parse($"@cert-authority *.example.com ssh-ed25519 {KeyAText}\n");

        await Assert.That(file.Check("a.example.com", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Unknown);
        await Assert.That(file.FindCertificateAuthorities("a.example.com").Count()).IsEqualTo(1);
        await Assert.That(file.FindCertificateAuthorities("other.org").Count()).IsEqualTo(0);
    }

    [Test]
    public async Task Add_PlainAndHashed()
    {
        var file = new KnownHostsFile();
        file.Add("example.com", 22, "ssh-ed25519", KeyA, comment: "added");
        file.Add("example.com", 2222, "ssh-ed25519", KeyB, hash: true);

        await Assert.That(file.Entries.Count).IsEqualTo(2);
        await Assert.That(file.ToString().StartsWith($"example.com ssh-ed25519 {KeyAText} added\n|1|", StringComparison.Ordinal)).IsTrue();
        await Assert.That(file.Entries[1].IsHashed).IsTrue();
        await Assert.That(file.Check("example.com", 2222, "ssh-ed25519", KeyB)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("example.com", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);

        var reparsed = KnownHostsFile.Parse(file.ToString());
        await Assert.That(reparsed.Check("example.com", 2222, "ssh-ed25519", KeyB)).IsEqualTo(KnownHostsCheckResult.Match);
    }

    [Test]
    public async Task FieldsOfOtherWhitespace_AreAnInvalidLine_NotAnException()
    {
        // Found by the coverage-guided fuzzer: fields are split on space and tab, so a key type of "\v" reached the entry constructor.
        var file = KnownHostsFile.Parse($"host \v {KeyAText}\n  ssh-ed25519 {KeyAText}\ngood ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Entries.Count).IsEqualTo(1);
        await Assert.That(file.InvalidLineCount).IsEqualTo(2);
    }

    [Test]
    public async Task Remove_DropsLine_ButKeepsComments()
    {
        var file = KnownHostsFile.Parse($"# keep me\na ssh-ed25519 {KeyAText}\nb ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Remove("a")).IsEqualTo(1);
        await Assert.That(file.ToString()).IsEqualTo($"# keep me\nb ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Remove("missing")).IsEqualTo(0);
    }

    [Test]
    public async Task Remove_StripsOnlyThePatternOnSharedLines()
    {
        var file = KnownHostsFile.Parse($"a.example.com,192.0.2.1,[a.example.com]:2222 ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Remove("a.example.com")).IsEqualTo(1);
        await Assert.That(file.ToString()).IsEqualTo($"192.0.2.1,[a.example.com]:2222 ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Remove("192.0.2.1")).IsEqualTo(1);
        await Assert.That(file.Remove("a.example.com", 2222)).IsEqualTo(1);
        await Assert.That(file.Entries.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Remove_KeepsLinesMatchedOnlyByAWildcard_AndMarkerLines()
    {
        // Removing one host must not drop keys for other hosts, a CA trusted for a whole domain, or a revocation.
        var text = $"*.example.com,10.0.0.5 ssh-ed25519 {KeyAText}\n@cert-authority *.example.com ssh-ed25519 {KeyAText}\n@revoked a.example.com ssh-ed25519 {KeyAText}\n";
        var file = KnownHostsFile.Parse(text);
        await Assert.That(file.Remove("a.example.com")).IsEqualTo(0);
        await Assert.That(file.ToString()).IsEqualTo(text);

        // An exact pattern on the shared line is still removed.
        await Assert.That(file.Remove("10.0.0.5")).IsEqualTo(1);
        await Assert.That(file.ToString()).StartsWith($"*.example.com ssh-ed25519 {KeyAText}\n");
    }

    [Test]
    public async Task Remove_HashedLine()
    {
        var file = new KnownHostsFile();
        file.Add("example.com", 22, "ssh-ed25519", KeyA, hash: true);
        await Assert.That(file.Remove("example.com")).IsEqualTo(1);
        await Assert.That(file.Entries.Count).IsEqualTo(0);
    }

    [Test]
    public async Task SaveAndLoad_RoundTrip_CreatesDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sshsharp-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "sub", "known_hosts");
        try
        {
            var file = new KnownHostsFile();
            file.Add("example.com", 22, "ssh-ed25519", KeyA);
            file.Save(path);

            var loaded = KnownHostsFile.Load(path);
            await Assert.That(loaded.Check("example.com", 22, "ssh-ed25519", KeyA)).IsEqualTo(KnownHostsCheckResult.Match);

            file.Add("two.com", 22, "ssh-ed25519", KeyB);
            await file.SaveAsync(path);
            var loadedAsync = await KnownHostsFile.LoadAsync(path);
            await Assert.That(loadedAsync.Entries.Count).IsEqualTo(2);
            await Assert.That(Directory.GetFiles(Path.GetDirectoryName(path)!).Length).IsEqualTo(1);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Test]
    public async Task Load_MissingFileGivesEmptyFile()
    {
        var path = Path.Combine(Path.GetTempPath(), "sshsharp-missing-" + Guid.NewGuid().ToString("N"));
        await Assert.That(KnownHostsFile.Load(path).Entries.Count).IsEqualTo(0);
        await Assert.That((await KnownHostsFile.LoadAsync(path)).Entries.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PathArguments_AreValidated()
    {
        var file = new KnownHostsFile();
        await Assert.That(() => KnownHostsFile.Load("")).Throws<ArgumentException>();
        await Assert.That(() => file.Save("")).Throws<ArgumentException>();
        await Assert.That(async () => await KnownHostsFile.LoadAsync("")).Throws<ArgumentException>();
        await Assert.That(async () => await file.SaveAsync("")).Throws<ArgumentException>();
    }
}