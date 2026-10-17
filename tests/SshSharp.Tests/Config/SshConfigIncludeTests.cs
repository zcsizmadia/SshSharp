using SshSharp.Config;

namespace SshSharp.Tests.Config;

/// <summary>Expected values were checked against `ssh -G` (OpenSSH for Windows).</summary>
public sealed class SshConfigIncludeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-inc-" + Guid.NewGuid().ToString("N"));

    public SshConfigIncludeTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private SshConfigResolveOptions Options => new() { LocalUser = "local", HomeDirectory = _dir, LocalHostName = "box" };

    private string P(string name) => Path.Combine(_dir, name).Replace('\\', '/');

    private void File_(string name, string text)
    {
        var path = Path.Combine(_dir, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
    }

    private SshHostConfig Resolve(string main, string host) => SshConfig.Parse(main, _dir).Resolve(host, Options);

    [Test]
    public async Task IncludeInsideHostBlock_IsClosedScope_ForStateAfterTheInclude()
    {
        File_("i1.inc", "Host nomatch\n User x\n AddressFamily inet\n");
        var main = $"Host a\n Include {P("i1.inc")}\n Port 7\nHost b\n Port 8\n";

        var a = Resolve(main, "a");
        await Assert.That(a.Port).IsEqualTo(7);
        await Assert.That(a.User).IsEqualTo("local");
        await Assert.That(a.AddressFamily).IsEqualTo(SshAddressFamily.Any);
        await Assert.That(Resolve(main, "b").Port).IsEqualTo(8);
    }

    [Test]
    public async Task IncludedGlobalSection_AppliesUnderTheIncludingBlockOnly()
    {
        File_("i2.inc", "User fromInc\nPort 5\n");
        var main = $"Host a\n Include {P("i2.inc")}\nHost b\n Port 8\n";

        await Assert.That(Resolve(main, "a").User).IsEqualTo("fromInc");
        await Assert.That(Resolve(main, "a").Port).IsEqualTo(5);
        await Assert.That(Resolve(main, "b").User).IsEqualTo("local");
        await Assert.That(Resolve(main, "c").Port).IsEqualTo(22);
    }

    [Test]
    public async Task TopLevelInclude_WithHostBlocks_ThenMoreTopLevelDirectives()
    {
        File_("i3.inc", "Host a\n User aa\n");
        var main = $"Include {P("i3.inc")}\nPort 9\nHost b\n User bb\n";

        var a = Resolve(main, "a");
        await Assert.That(a.User).IsEqualTo("aa");
        await Assert.That(a.Port).IsEqualTo(9);
        await Assert.That(Resolve(main, "b").User).IsEqualTo("bb");
        await Assert.That(Resolve(main, "c").User).IsEqualTo("local");
        await Assert.That(Resolve(main, "c").Port).IsEqualTo(9);
    }

    [Test]
    public async Task NestedHostBlocks_UseTheirOwnCriteria()
    {
        File_("i4.inc", "Host a\n User inner\nHost *\n AddressFamily inet6\n");
        var main = $"Host a\n Include {P("i4.inc")}\n RequestTTY yes\n";

        var a = Resolve(main, "a");
        await Assert.That(a.User).IsEqualTo("inner");
        await Assert.That(a.AddressFamily).IsEqualTo(SshAddressFamily.Inet6);
        await Assert.That(a.RequestTty).IsEqualTo(RequestTty.Yes);

        var b = Resolve(main, "b");
        await Assert.That(b.AddressFamily).IsEqualTo(SshAddressFamily.Any);
        await Assert.That(b.RequestTty).IsEqualTo(RequestTty.Auto);
    }

    [Test]
    public async Task AnIncludeFanOut_IsCut_RatherThanParsedForEver()
    {
        // 15 levels of 4 files, each including the whole next level: within the depth limit, but 4^15 parses. Cut at 1024 files.
        for (var level = 0; level < 15; level++)
        {
            Directory.CreateDirectory(Path.Combine(_dir, $"l{level}"));
            for (var file = 0; file < 4; file++)
            {
                File_($"l{level}/{file}.conf", level < 14 ? $"Include {P($"l{level + 1}")}/*.conf\n" : "Port 2\n");
            }
        }

        var error = await Assert.That(() => Resolve($"Include {P("l0")}/*.conf\n", "a")).Throws<FormatException>();
        await Assert.That(error!.Message).Contains("1024 files");
    }

    [Test]
    public async Task Globs_AreInLexicalOrder_MissingFilesAreIgnored()
    {
        File_("conf.d/b.conf", "Port 31\n");
        File_("conf.d/a.conf", "Port 32\n");
        File_("conf.d/.hidden.conf", "Port 33\n");
        File_("conf.d/notes.txt", "Port 34\n");
        var main = $"Include {P("conf.d")}/*.conf\nInclude {P("nonexistent.inc")}\nInclude {P("nodir")}/*.conf\n";

        await Assert.That(Resolve(main, "a").Port).IsEqualTo(32);
    }

    [Test]
    public async Task Globs_WorkInDirectorySegments_AndDotPatternsMatchHiddenFiles()
    {
        File_("site1/x.conf", "User one\n");
        File_("site2/x.conf", "User two\n");
        File_(".dot/y.conf", "Port 41\n");
        var main = $"Include {P("site*")}/x.conf\nInclude {P(".d*")}/y.conf\nInclude {P("site1")}/*/z.conf\n";

        var c = Resolve(main, "a");
        await Assert.That(c.User).IsEqualTo("one");
        await Assert.That(c.Port).IsEqualTo(41);
    }

    [Test]
    public async Task Tokens_AreExpandedInIncludePaths()
    {
        File_("i7_a.inc", "Port 71\n");
        await Assert.That(Resolve($"Include {P("i7_%h.inc")}\n", "a").Port).IsEqualTo(71);
        await Assert.That(Resolve($"Include {P("i7_%h.inc")}\n", "other").Port).IsEqualTo(22);
    }

    [Test]
    public async Task RelativePaths_ResolveAgainstTheBaseDirectory_AndMultipleArguments()
    {
        File_("rel1.inc", "User r1\n");
        File_("rel2.inc", "Port 12\n");
        var c = Resolve("Include rel1.inc rel2.inc\n", "a");
        await Assert.That(c.User).IsEqualTo("r1");
        await Assert.That(c.Port).IsEqualTo(12);
    }

    [Test]
    public async Task RelativePaths_DefaultToDotSshInTheHomeDirectory()
    {
        File_(".ssh/def.inc", "Port 13\n");
        var c = SshConfig.Parse("Include def.inc\n").Resolve("a", Options);
        await Assert.That(c.Port).IsEqualTo(13);
    }

    [Test]
    public async Task MatchAfterInclude_StillEvaluates()
    {
        File_("i8.inc", "Host nomatch\n User x\n");
        await Assert.That(Resolve($"Host a\n Include {P("i8.inc")}\nMatch host a\n Port 81\n", "a").Port).IsEqualTo(81);
    }

    [Test]
    public async Task IncludeInsideFinalPass_DoesNotDuplicateAccumulatedValues()
    {
        File_("id.inc", "IdentityFile ~/k1\nLocalForward 1 h:1\n");
        var c = Resolve($"Include {P("id.inc")}\nMatch final\n Port 2\n", "a");
        await Assert.That(c.IdentityFiles.Count).IsEqualTo(1);
        await Assert.That(c.LocalForwards.Count).IsEqualTo(1);
        await Assert.That(c.Port).IsEqualTo(2);
    }

    [Test]
    public async Task RecursiveIncludes_AreLimited()
    {
        File_("loop.inc", $"Include {P("loop.inc")}\n");
        await Assert.That(() => Resolve($"Include {P("loop.inc")}\n", "a")).Throws<FormatException>();
    }

    [Test]
    public async Task SyntaxErrorsInIncludedFiles_NameTheFile()
    {
        File_("bad.inc", "Port 1\nUser \"oops\n");
        var ex = Assert.Throws<FormatException>(() => Resolve($"Include {P("bad.inc")}\n", "a"));
        await Assert.That(ex.Message).Contains("bad.inc");
        await Assert.That(ex.Message).Contains("line 2");
    }

    [Test]
    public async Task LoadDefault_CombinesUserThenSystem_FirstWins()
    {
        File_(".ssh/config", "Host a\n User fromUser\n");
        var config = SshConfig.LoadDefault(_dir);
        var c = config.Resolve("a", Options);
        await Assert.That(c.User).IsEqualTo("fromUser");
        await Assert.That(config.Blocks.Count).IsGreaterThanOrEqualTo(3);
    }

    [Test]
    public async Task Combine_EarlierConfigsTakePrecedence()
    {
        var first = SshConfig.Parse("User first\n", _dir);
        var second = SshConfig.Parse("User second\nPort 99\n", _dir);
        var c = SshConfig.Combine(first, second).Resolve("a", Options);
        await Assert.That(c.User).IsEqualTo("first");
        await Assert.That(c.Port).IsEqualTo(99);
    }

    [Test]
    public async Task ExpandFiles_EmptyAndMissing()
    {
        await Assert.That(Glob.ExpandFiles(Path.GetPathRoot(_dir)!).Count).IsEqualTo(0);
        await Assert.That(Glob.ExpandFiles(Path.Combine(_dir, "nope", "*.x")).Count).IsEqualTo(0);
    }
}