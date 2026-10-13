using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class KnownHostsEntryTests
{
    private static readonly byte[] Key = [1, 2, 3, 4];

    [Test]
    [Arguments("example.com", 22, "example.com")]
    [Arguments("EXAMPLE.com", 22, "example.com")]
    [Arguments("example.com", 2222, "[example.com]:2222")]
    public async Task FormatHost(string host, int port, string expected)
    {
        await Assert.That(KnownHostsEntry.FormatHost(host, port)).IsEqualTo(expected);
    }

    [Test]
    public async Task FormatHost_RejectsBadInput()
    {
        await Assert.That(() => KnownHostsEntry.FormatHost("", 22)).Throws<ArgumentException>();
        await Assert.That(() => KnownHostsEntry.FormatHost("h", 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => KnownHostsEntry.FormatHost("h", 65536)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Constructor_RejectsEmptyFields()
    {
        await Assert.That(() => new KnownHostsEntry("", "ssh-ed25519", Key)).Throws<ArgumentException>();
        await Assert.That(() => new KnownHostsEntry("h", "", Key)).Throws<ArgumentException>();
    }

    [Test]
    public async Task Matches_PlainHost()
    {
        var entry = new KnownHostsEntry("example.com", "ssh-ed25519", Key);
        await Assert.That(entry.Matches("example.com")).IsTrue();
        await Assert.That(entry.Matches("EXAMPLE.COM")).IsTrue();
        await Assert.That(entry.Matches("other.com")).IsFalse();
        await Assert.That(entry.Matches("example.com", 2222)).IsFalse();
    }

    [Test]
    public async Task Matches_PortForm()
    {
        var entry = new KnownHostsEntry("[example.com]:2222", "ssh-ed25519", Key);
        await Assert.That(entry.Matches("example.com", 2222)).IsTrue();
        await Assert.That(entry.Matches("example.com")).IsFalse();
    }

    [Test]
    public async Task Matches_CommaListWildcardAndNegation()
    {
        var entry = new KnownHostsEntry("*.example.com,!bad.example.com,192.0.2.?,,", "ssh-ed25519", Key);
        await Assert.That(entry.Matches("good.example.com")).IsTrue();
        await Assert.That(entry.Matches("bad.example.com")).IsFalse();
        await Assert.That(entry.Matches("192.0.2.9")).IsTrue();
        await Assert.That(entry.Matches("unrelated.org")).IsFalse();
    }

    [Test]
    public async Task Matches_OnlyNegationNeverMatches()
    {
        var entry = new KnownHostsEntry("!example.com", "ssh-ed25519", Key);
        await Assert.That(entry.Matches("other.com")).IsFalse();
    }

    [Test]
    public async Task HashHost_RoundTripsThroughMatches()
    {
        var field = KnownHostsEntry.HashHost("example.com", 22);
        var entry = new KnownHostsEntry(field, "ssh-ed25519", Key);
        await Assert.That(entry.IsHashed).IsTrue();
        await Assert.That(entry.Matches("example.com")).IsTrue();
        await Assert.That(entry.Matches("Example.Com")).IsTrue();
        await Assert.That(entry.Matches("example.com", 2222)).IsFalse();
        await Assert.That(entry.Matches("other.com")).IsFalse();
    }

    [Test]
    public async Task HashHost_UsesGivenSalt()
    {
        var salt = new byte[20];
        var a = KnownHostsEntry.HashHost("example.com", 22, salt);
        var b = KnownHostsEntry.HashHost("example.com", 22, salt);
        var c = KnownHostsEntry.HashHost("example.com", 22);
        await Assert.That(a).IsEqualTo(b);
        await Assert.That(a).IsNotEqualTo(c);
        await Assert.That(() => KnownHostsEntry.HashHost("example.com", 22, new byte[5])).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("|1|notbase64!|alsonot")]
    [Arguments("|1|AAAA")]
    [Arguments("|2|AAAA|AAAA")]
    public async Task Matches_MalformedHashNeverMatches(string field)
    {
        var entry = new KnownHostsEntry(field, "ssh-ed25519", Key);
        await Assert.That(entry.Matches("example.com")).IsFalse();
    }

    [Test]
    public async Task ToLine_FormatsMarkerAndComment()
    {
        var plain = new KnownHostsEntry("h", "ssh-ed25519", Key);
        await Assert.That(plain.ToLine()).IsEqualTo("h ssh-ed25519 AQIDBA==");

        var ca = new KnownHostsEntry("*.h", "ssh-ed25519", Key, KnownHostsMarker.CertAuthority, "my ca");
        await Assert.That(ca.ToLine()).IsEqualTo("@cert-authority *.h ssh-ed25519 AQIDBA== my ca");

        var revoked = new KnownHostsEntry("h", "ssh-ed25519", Key, KnownHostsMarker.Revoked);
        await Assert.That(revoked.ToLine()).IsEqualTo("@revoked h ssh-ed25519 AQIDBA==");
    }
}