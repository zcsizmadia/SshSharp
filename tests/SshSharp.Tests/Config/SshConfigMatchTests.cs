using SshSharp.Config;

namespace SshSharp.Tests.Config;

/// <summary>Expected values were checked against `ssh -G` (OpenSSH for Windows).</summary>
public class SshConfigMatchTests
{
    private static readonly SshConfigResolveOptions Options = new()
    {
        LocalUser = "local",
        HomeDirectory = "/home/local",
        LocalHostName = "box",
    };

    private static SshHostConfig Resolve(string config, string host, SshConfigResolveOptions? options = null) =>
        SshConfig.Parse(config).Resolve(host, options ?? Options);

    [Test]
    public async Task HostCriterion_UsesHostNameSetEarlier_NotOriginalName()
    {
        const string config = "Host a\n HostName real.example.com\nMatch host real.example.com\n Port 11\nMatch originalhost a\n User orig\nMatch host a\n AddressFamily inet\n";
        var c = Resolve(config, "a");
        await Assert.That(c.Port).IsEqualTo(11);
        await Assert.That(c.User).IsEqualTo("orig");
        await Assert.That(c.AddressFamily).IsEqualTo(SshAddressFamily.Any);
    }

    [Test]
    public async Task HostCriterion_BeforeHostNameIsSet_DoesNotMatch()
    {
        var c = Resolve("Match host real.example.com\n Port 11\nHost a\n HostName real.example.com\n", "a");
        await Assert.That(c.Port).IsEqualTo(22);
        await Assert.That(c.HostName).IsEqualTo("real.example.com");
    }

    [Test]
    public async Task UserCriterion_SeesTheUserSetSoFar()
    {
        await Assert.That(Resolve("Host a\n User bob\nMatch user bob\n Port 33\nMatch user alice\n Port 44\n", "a").Port).IsEqualTo(33);
        await Assert.That(Resolve("Match user bob\n Port 33\nHost a\n User bob\n", "a").Port).IsEqualTo(22);
        await Assert.That(Resolve("Match user bob\n Port 33\n", "a", new SshConfigResolveOptions { User = "bob", LocalUser = "local", HomeDirectory = "/h" }).Port).IsEqualTo(33);
        await Assert.That(Resolve("Match user local\n Port 34\n", "a").Port).IsEqualTo(34);
    }

    [Test]
    public async Task LocalUserCriterion()
    {
        await Assert.That(Resolve("Match localuser loc*\n Port 35\n", "a").Port).IsEqualTo(35);
        await Assert.That(Resolve("Match localuser other\n Port 35\n", "a").Port).IsEqualTo(22);
    }

    [Test]
    public async Task PatternListsNegationAndMultipleCriteria()
    {
        const string config = "Match host !a,*\n Port 1\nMatch host a user nobody\n Port 2\nMatch all\n User allu\nMatch host a !user zed\n AddressFamily inet\n";
        var a = Resolve(config, "a");
        await Assert.That(a.Port).IsEqualTo(22);
        await Assert.That(a.User).IsEqualTo("allu");
        await Assert.That(a.AddressFamily).IsEqualTo(SshAddressFamily.Inet);

        var b = Resolve(config, "b");
        await Assert.That(b.Port).IsEqualTo(1);
        await Assert.That(b.AddressFamily).IsEqualTo(SshAddressFamily.Any);
    }

    [Test]
    public async Task NegatedAllNeverMatches()
    {
        await Assert.That(Resolve("Match !all\n Port 5\n", "a").Port).IsEqualTo(22);
    }

    [Test]
    public async Task Tagged_UsesTagFromFileOrCaller()
    {
        await Assert.That(Resolve("Tag blue\nMatch tagged blue\n Port 71\n", "a").Port).IsEqualTo(71);
        await Assert.That(Resolve("Match tagged red\n Port 72\n", "a", new SshConfigResolveOptions { Tag = "red", LocalUser = "l", HomeDirectory = "/h" }).Port).IsEqualTo(72);
        await Assert.That(Resolve("Match tagged red\n Port 72\n", "a").Port).IsEqualTo(22);
    }

    [Test]
    public async Task LocalNetwork_MatchesTheLocalAddresses()
    {
        var inside = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = "/home/local", LocalAddresses = () => [System.Net.IPAddress.Parse("10.9.8.7")] };
        var outside = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = "/home/local", LocalAddresses = () => [System.Net.IPAddress.Parse("192.0.2.1")] };
        await Assert.That(Resolve("Match localnetwork 10.0.0.0/8\n Port 5\n", "a", inside).Port).IsEqualTo(5);
        await Assert.That(Resolve("Match localnetwork 10.0.0.0/8\n Port 5\n", "a", outside).Port).IsEqualTo(22);
    }

    [Test]
    public async Task LocalNetwork_ReadsTheInterfacesOncePerResolution()
    {
        var reads = 0;
        var options = new SshConfigResolveOptions
        {
            LocalUser = "local",
            HomeDirectory = "/home/local",
            LocalAddresses = () =>
            {
                reads++;
                return [System.Net.IPAddress.Parse("10.9.8.7")];
            },
        };

        const string config = "Match localnetwork 192.168.0.0/16\n Port 1\nMatch localnetwork 172.16.0.0/12\n Port 2\nMatch localnetwork 10.0.0.0/8\n Port 3\n";
        await Assert.That(Resolve(config, "a", options).Port).IsEqualTo(3);
        await Assert.That(reads).IsEqualTo(1);
    }

    [Test]
    public async Task Exec_IsOffByDefault_AndRunsThroughTheMatcherWithExpandedTokens()
    {
        const string config = "Match exec \"check %h %r\"\n Port 51\n";
        await Assert.That(Resolve(config, "a").Port).IsEqualTo(22);

        var commands = new List<string>();
        var options = new SshConfigResolveOptions
        {
            LocalUser = "local",
            HomeDirectory = "/h",
            ExecMatcher = command => { commands.Add(command); return command.StartsWith("check", StringComparison.Ordinal); },
        };
        await Assert.That(Resolve(config, "a", options).Port).IsEqualTo(51);
        await Assert.That(commands.Single()).IsEqualTo("check a local");
    }

    [Test]
    public async Task Exec_IsNotRunWhenAnEarlierCriterionAlreadyFailed()
    {
        var ran = false;
        var options = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", ExecMatcher = _ => ran = true };
        Resolve("Match host other exec \"x\"\n Port 5\n", "a", options);
        await Assert.That(ran).IsFalse();
    }

    [Test]
    public async Task RunShell_ReportsExitStatus()
    {
        await Assert.That(SshExecMatcher.RunShell("exit 0")).IsTrue();
        await Assert.That(SshExecMatcher.RunShell("exit 1")).IsFalse();
        await Assert.That(() => SshExecMatcher.RunShell("")).Throws<ArgumentException>();
    }

    [Test]
    public async Task Final_RunsASecondPass()
    {
        var c = Resolve("Match final\n Port 61\nMatch !final\n User early\n", "a");
        await Assert.That(c.Port).IsEqualTo(61);
        await Assert.That(c.User).IsEqualTo("early");

        var d = Resolve("Host a\n HostName x.y\nMatch final host x.y\n Port 62\n", "a");
        await Assert.That(d.Port).IsEqualTo(62);
    }

    [Test]
    public async Task Canonical_IsFalseWithoutCanonicalization()
    {
        await Assert.That(Resolve("Match canonical\n Port 5\nMatch !canonical\n User nc\n", "a").Port).IsEqualTo(22);
        await Assert.That(Resolve("Match canonical\n Port 5\nMatch !canonical\n User nc\n", "a").User).IsEqualTo("nc");
    }

    private static SshConfigResolveOptions Canonicalizing(Func<string, IReadOnlyList<string>, string?> canonicalizer) =>
        new() { LocalUser = "l", HomeDirectory = "/h", HostCanonicalizer = canonicalizer };

    [Test]
    public async Task Canonicalization_ReplacesTheHostName_AndEnablesMatchCanonical()
    {
        const string config = "CanonicalizeHostname yes\nCanonicalDomains corp.example.com other.example\nMatch canonical host web.corp.example.com\n Port 81\nHost *\n HostName %h\n";
        IReadOnlyList<string>? seenDomains = null;
        string? seenHost = null;
        var c = Resolve(config, "web", Canonicalizing((host, domains) => { seenHost = host; seenDomains = domains; return "web.corp.example.com"; }));

        await Assert.That(seenHost).IsEqualTo("web");
        await Assert.That(string.Join(",", seenDomains!)).IsEqualTo("corp.example.com,other.example");
        await Assert.That(c.HostName).IsEqualTo("web.corp.example.com");
        await Assert.That(c.Port).IsEqualTo(81);
    }

    [Test]
    public async Task Canonicalization_SkippedWhenDisabledProxiedTooManyDotsOrNoCanonicalizer()
    {
        var calls = 0;
        var canonicalizer = Canonicalizing((_, _) => { calls++; return "x.example"; });

        Resolve("CanonicalizeHostname no\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname yes\nProxyJump jump\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname yes\nProxyCommand nc %h %p\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname yes\n", "a.b.c", canonicalizer);
        Resolve("CanonicalizeHostname maybe\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname yes\n", "web");
        Resolve("Port 1\n", "web", canonicalizer);
        await Assert.That(calls).IsEqualTo(0);

        Resolve("CanonicalizeHostname yes\nProxyJump none\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname always\nProxyJump jump\n", "web", canonicalizer);
        Resolve("CanonicalizeHostname yes\nCanonicalizeMaxDots 2\n", "a.b.c", canonicalizer);
        await Assert.That(calls).IsEqualTo(3);
    }

    [Test]
    public async Task Canonicalization_FallbackLocalControlsFailure()
    {
        var notFound = Canonicalizing((_, _) => null);
        await Assert.That(Resolve("CanonicalizeHostname yes\n", "web", notFound).HostName).IsEqualTo("web");
        await Assert.That(Resolve("CanonicalizeHostname yes\nCanonicalizeFallbackLocal yes\n", "web", notFound).HostName).IsEqualTo("web");
        await Assert.That(() => Resolve("CanonicalizeHostname yes\nCanonicalizeFallbackLocal no\n", "web", notFound)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Match_SyntaxErrors()
    {
        await Assert.That(() => Resolve("Match host\n Port 1\n", "a")).Throws<FormatException>();
        await Assert.That(() => Resolve("Match bogus\n Port 1\n", "a")).Throws<FormatException>();
    }
}