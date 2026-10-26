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
    [Arguments("%T", "NONE")]
    [Arguments("${HOME}{x}%%", "${HOME}{x}%")] // no variables here: ${...} and braces stay as they are
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
        await Assert.That((Context() with { LocalHostName = ".corp" }).ExpandTokens("%L")).IsEqualTo(""); // up to the first dot, as ssh does
    }

    [Test]
    public async Task ExpandTokensAndVariables_ExpandsBothInOnePass()
    {
        // Only ${ starts a variable: other braces and a '$' at the end are kept, and a variable's value is not expanded again.
        var ctx = Context(name => name == "KEYDIR" ? "/keys/%h" : null);
        await Assert.That(ctx.ExpandTokensAndVariables("%h ${KEYDIR} a{b} $")).IsEqualTo("real.example.com /keys/%h a{b} $");
        await Assert.That(ctx.ExpandTokensAndVariables("plain")).IsEqualTo("plain");

        // Every name is set here, so only the empty name and the missing brace can fail.
        var any = Context(_ => "v");
        await Assert.That(() => any.ExpandTokensAndVariables("${}")).Throws<FormatException>();
        await Assert.That(() => any.ExpandTokensAndVariables("${open")).Throws<FormatException>();
        await Assert.That(() => ctx.ExpandTokensAndVariables("${UNSET}")).Throws<FormatException>();
    }

    [Test]
    public async Task LocalUserId_IsTheUidOrRefusedOnWindows()
    {
        if (OperatingSystem.IsWindows())
        {
            await Assert.That(() => Context().ExpandTokens("%i")).Throws<FormatException>();
        }
        else
        {
            await Assert.That(uint.TryParse(Context().ExpandTokens("%i"), System.Globalization.NumberStyles.None, null, out _)).IsTrue();
        }
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
    [Arguments("/x{y}/${KEYDIR}$", "/x{y}//keys$")] // only ${ starts a variable, and a '$' at the end is kept
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