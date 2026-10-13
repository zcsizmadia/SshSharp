using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class SshTokensTests
{
    private static SshTokenContext Context(Func<string, string?>? env = null) => new(
        OriginalHost: "alias", Host: "real.example.com", Port: 2222, RemoteUser: "bob", LocalUser: "alice",
        HomeDirectory: "/home/alice", LocalHostName: "laptop.corp.example", GetEnvironmentVariable: env ?? (_ => null));

    [Test]
    [Arguments("plain", "plain")]
    [Arguments("%%", "%")]
    [Arguments("%h", "real.example.com")]
    [Arguments("%n", "alias")]
    [Arguments("%p", "2222")]
    [Arguments("%r", "bob")]
    [Arguments("%u", "alice")]
    [Arguments("%d", "/home/alice")]
    [Arguments("%l", "laptop.corp.example")]
    [Arguments("%L", "laptop")]
    [Arguments("a-%r@%h:%p-b", "a-bob@real.example.com:2222-b")]
    public async Task ExpandTokens(string input, string expected)
    {
        await Assert.That(Context().ExpandTokens(input)).IsEqualTo(expected);
    }

    [Test]
    public async Task ExpandTokens_ConnectionHash_IsStableLowercaseSha1Hex()
    {
        var a = Context().ExpandTokens("%C");
        await Assert.That(a.Length).IsEqualTo(40);
        await Assert.That(a).IsEqualTo(a.ToLowerInvariant());
        await Assert.That(Context().ExpandTokens("%C")).IsEqualTo(a);
        await Assert.That(Context() with { Port = 22 }).IsNotEqualTo(Context());
        await Assert.That((Context() with { Port = 22 }).ExpandTokens("%C")).IsNotEqualTo(a);
    }

    [Test]
    public async Task ExpandTokens_UnknownOrTrailing_Throws()
    {
        await Assert.That(() => Context().ExpandTokens("%z")).Throws<FormatException>();
        await Assert.That(() => Context().ExpandTokens("abc%")).Throws<FormatException>();
    }

    [Test]
    public async Task ShortLocalHostName_WithoutDomain()
    {
        await Assert.That((Context() with { LocalHostName = "box" }).ExpandTokens("%L")).IsEqualTo("box");
    }

    [Test]
    [Arguments("~", "/home/alice")]
    [Arguments("~/.ssh/id", "/home/alice/.ssh/id")]
    [Arguments("~\\.ssh\\id", "/home/alice\\.ssh\\id")]
    [Arguments("/abs/path", "/abs/path")]
    [Arguments("rel~/x", "rel~/x")]
    [Arguments("${KEYDIR}/id", "/keys/id")]
    [Arguments("~/${KEYDIR}/id", "/home/alice//keys/id")]
    [Arguments("$notbraced", "$notbraced")]
    public async Task ExpandPath(string input, string expected)
    {
        var ctx = Context(name => name == "KEYDIR" ? "/keys" : null);
        await Assert.That(ctx.ExpandPath(input)).IsEqualTo(expected);
    }

    [Test]
    public async Task ExpandPath_UnsetVariableOrUnterminated_Throws()
    {
        await Assert.That(() => Context().ExpandPath("${MISSING}")).Throws<FormatException>();
        await Assert.That(() => Context().ExpandPath("${oops")).Throws<FormatException>();
    }
}