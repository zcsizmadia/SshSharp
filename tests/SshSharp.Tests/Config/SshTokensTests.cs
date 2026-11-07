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
    public async Task ConnectionHash_IsOpenSsh106p2s_WithEachFieldNulTerminated()
    {
        // SHA-1 of "laptop.corp.example\0real.example.com\0" "2222\0bob\0" + %j + "\0", as OpenSSH 10.6p2's ssh_connection_hash.
        await Assert.That(Context().ExpandTokens("%C")).IsEqualTo("8bf3d5e25763262ea4768b72db65e6bd159321a0");
        await Assert.That((Context() with { ProxyJump = "jump.example.com" }).ExpandTokens("%C")).IsEqualTo("4f1e25ea4131f3d7c0247bcf869d5a53d674dede");
    }

    [Test]
    public async Task ConnectionHash_KeepsTheFieldsApart()
    {
        // Run together, "192.0.2.1" + "2222" and "192.0.2.12" + "222" are the same text; older OpenSSH hashed them alike.
        var a = (Context() with { Host = "192.0.2.1", Port = 2222 }).ExpandTokens("%C");
        var b = (Context() with { Host = "192.0.2.12", Port = 222 }).ExpandTokens("%C");
        await Assert.That(a).IsNotEqualTo(b);
    }

    [Test]
    [Arguments(null, "")]
    [Arguments("none", "")]
    [Arguments("j1", "j1")]
    [Arguments("user@j1", "user@j1")]
    [Arguments("j1:2222", "j1:2222")]
    [Arguments("user@j1:2222", "user@j1:2222")]
    [Arguments("j2,j1", "j2,j1")]
    [Arguments("ssh://u2@j2:22,ssh://alice@jump.example.com:2222", "ssh://u2@j2:22,alice@jump.example.com:2222")]
    [Arguments("192.0.2.10", "[192.0.2.10]")]
    [Arguments("192.0.2.10:2222", "[192.0.2.10]:2222")]
    [Arguments("[2001:db8::1]:22", "[2001:db8::1]:22")]
    [Arguments("ssh://[2001:db8::1]", "[2001:db8::1]")]
    [Arguments("j1:notaport", "j1:notaport")] // does not parse: kept as written
    public async Task JumpSpec_IsTheWholeProxyJump_WithTheLastHopAsSshPrintsIt(string? proxyJump, string expected)
    {
        // As OpenSSH 10.6p2's ssh_jump_spec (and its regress test proxyjump.sh): earlier hops as written, the last one rebuilt.
        await Assert.That(SshTokenContext.JumpSpec(proxyJump)).IsEqualTo(expected);
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