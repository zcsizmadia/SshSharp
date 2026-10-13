using SshSharp.Config;

namespace SshSharp.Tests.Config;

/// <summary>Cross-checks against a file produced by <c>ssh-keygen -H</c> (real OpenSSH hashing).</summary>
public class KnownHostsOpenSshFixtureTests
{
    private static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static (string Type, byte[] Blob) ReadKey(int index)
    {
        var parts = File.ReadAllLines(FixturePath("keys.txt"))[index].Split(' ');
        return (parts[0], Convert.FromBase64String(parts[1]));
    }

    [Test]
    public async Task HashedEntries_MatchTheirHosts()
    {
        var file = KnownHostsFile.Load(FixturePath("known_hosts_openssh_hashed"));
        var (edType, ed) = ReadKey(0);
        var (rsaType, rsa) = ReadKey(1);

        await Assert.That(file.Entries.Count).IsEqualTo(4);
        await Assert.That(file.Entries.All(e => e.IsHashed || e.HostPatterns.Contains("other"))).IsTrue();

        await Assert.That(file.Check("host.example.com", 22, edType, ed)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("192.0.2.1", 22, edType, ed)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("git.example.com", 2222, rsaType, rsa)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("other.example.com", 22, rsaType, rsa)).IsEqualTo(KnownHostsCheckResult.Match);

        await Assert.That(file.Check("git.example.com", 22, rsaType, rsa)).IsEqualTo(KnownHostsCheckResult.Unknown);
        await Assert.That(file.Check("host.example.com", 22, edType, rsa)).IsEqualTo(KnownHostsCheckResult.Changed);
        await Assert.That(file.Check("unknown.example.com", 22, edType, ed)).IsEqualTo(KnownHostsCheckResult.Unknown);
    }

    [Test]
    public async Task Fixture_SurvivesParseAndFormatUnchanged()
    {
        var text = File.ReadAllText(FixturePath("known_hosts_openssh_hashed"));
        await Assert.That(KnownHostsFile.Parse(text).ToString()).IsEqualTo(text);
    }
}