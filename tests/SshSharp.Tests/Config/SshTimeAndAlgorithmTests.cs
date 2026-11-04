using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class SshTimeAndAlgorithmTests
{
    [Test]
    [Arguments("30", 30)]
    [Arguments("30s", 30)]
    [Arguments("90S", 90)]
    [Arguments("10m", 600)]
    [Arguments("1h", 3600)]
    [Arguments("1h30m", 5400)]
    [Arguments("1d", 86400)]
    [Arguments("2w", 1209600)]
    [Arguments("1m30s", 90)]
    [Arguments("2147483647", int.MaxValue)] // the most OpenSSH's convtime takes
    public async Task Time_Parses(string text, int seconds)
    {
        await Assert.That(SshTime.TryParse(text, out var t)).IsTrue();
        await Assert.That(t).IsEqualTo(TimeSpan.FromSeconds(seconds));
    }

    [Test]
    [Arguments("")]
    [Arguments("abc")]
    [Arguments("5x")]
    [Arguments("99999999999999w")] // found by the fuzzer: overflowed TimeSpan
    [Arguments("2147483648")]
    [Arguments("m5")]
    [Arguments("-1")]
    [Arguments("99999999999999999999")]
    public async Task Time_RejectsGarbage(string text)
    {
        await Assert.That(SshTime.TryParse(text, out _)).IsFalse();
    }

    private static readonly string[] Defaults = ["aes256-ctr", "aes128-ctr", "chacha20-poly1305@openssh.com"];

    [Test]
    public async Task Algorithms_Replace()
    {
        await Assert.That(string.Join(",", SshAlgorithmList.Apply("a,b,a", Defaults))).IsEqualTo("a,b");
    }

    [Test]
    public async Task Algorithms_Append()
    {
        // As ssh: a name already among the defaults keeps its place.
        await Assert.That(string.Join(",", SshAlgorithmList.Apply("+x,aes256-ctr", Defaults))).IsEqualTo("aes256-ctr,aes128-ctr,chacha20-poly1305@openssh.com,x");
    }

    [Test]
    public async Task Algorithms_Prepend()
    {
        await Assert.That(string.Join(",", SshAlgorithmList.Apply("^chacha20-poly1305@openssh.com,y", Defaults))).IsEqualTo("chacha20-poly1305@openssh.com,y,aes256-ctr,aes128-ctr");
    }

    [Test]
    public async Task Algorithms_RemoveWithWildcards()
    {
        await Assert.That(string.Join(",", SshAlgorithmList.Apply("-aes*", Defaults))).IsEqualTo("chacha20-poly1305@openssh.com");
    }

    [Test]
    public async Task Algorithms_EmptyKeepsDefaults_AndArgumentsAreChecked()
    {
        await Assert.That(string.Join(",", SshAlgorithmList.Apply("  ", Defaults))).IsEqualTo(string.Join(",", Defaults));
        await Assert.That(() => SshAlgorithmList.Apply(null!, Defaults)).Throws<ArgumentNullException>();
        await Assert.That(() => SshAlgorithmList.Apply("a", null!)).Throws<ArgumentNullException>();
    }
}