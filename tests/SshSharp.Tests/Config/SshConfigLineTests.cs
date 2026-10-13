using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class SshConfigLineTests
{
    [Test]
    [Arguments("")]
    [Arguments("   ")]
    [Arguments("# comment")]
    [Arguments("   # indented comment")]
    public async Task BlankAndCommentLines_AreSkipped(string line)
    {
        await Assert.That(SshConfigLine.TryParse(line, out _, out _, out _)).IsFalse();
    }

    [Test]
    [Arguments("Port 22", "Port", "22")]
    [Arguments("Port=22", "Port", "22")]
    [Arguments("Port = 22", "Port", "22")]
    [Arguments("  \tPort\t22  ", "Port", "22")]
    [Arguments("port 22 # trailing comment", "port", "22")]
    public async Task KeywordAndSingleArgument(string line, string keyword, string argument)
    {
        await Assert.That(SshConfigLine.TryParse(line, out var k, out var args, out _)).IsTrue();
        await Assert.That(k).IsEqualTo(keyword);
        await Assert.That(args.Count).IsEqualTo(1);
        await Assert.That(args[0]).IsEqualTo(argument);
    }

    [Test]
    public async Task MultipleArguments_AndQuotes()
    {
        var ok = SshConfigLine.TryParse("Host a \"b c\" d\\e \"q\\\"uote\" \"back\\\\slash\"", out _, out var args, out var raw);
        await Assert.That(ok).IsTrue();
        await Assert.That(string.Join("|", args)).IsEqualTo("a|b c|d\\e|q\"uote|back\\slash");
        await Assert.That(raw).IsEqualTo("a \"b c\" d\\e \"q\\\"uote\" \"back\\\\slash\"");
    }

    [Test]
    public async Task RawValue_KeepsProxyCommandVerbatim()
    {
        var ok = SshConfigLine.TryParse("ProxyCommand ssh -W %h:%p \"gate way\"  ", out _, out _, out var raw);
        await Assert.That(ok).IsTrue();
        await Assert.That(raw).IsEqualTo("ssh -W %h:%p \"gate way\"");
    }

    [Test]
    public async Task MissingArgument_Throws()
    {
        await Assert.That(() => SshConfigLine.TryParse("Port", out _, out _, out _)).Throws<FormatException>();
        await Assert.That(() => SshConfigLine.TryParse("Port # only a comment", out _, out _, out _)).Throws<FormatException>();
    }

    [Test]
    public async Task UnterminatedQuote_Throws()
    {
        await Assert.That(() => SshConfigLine.TryParse("Host \"abc", out _, out _, out _)).Throws<FormatException>();
    }
}