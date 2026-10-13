using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class KnownHostsFileTests
{
    private static readonly byte[] KeyA = [1, 2, 3, 4];
    private static readonly byte[] KeyB = [9, 9, 9, 9];

    private const string KeyAText = "AQIDBA==";

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
    public async Task Remove_WildcardLineIsDropped()
    {
        var file = KnownHostsFile.Parse($"*.example.com ssh-ed25519 {KeyAText}\n");
        await Assert.That(file.Remove("a.example.com")).IsEqualTo(1);
        await Assert.That(file.Entries.Count).IsEqualTo(0);
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