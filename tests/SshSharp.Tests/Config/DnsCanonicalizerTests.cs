using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Config;

/// <summary>
/// <see cref="SshConfigResolveOptions.UseDnsCanonicalizer"/>: OpenSSH's canonicalization algorithm against a fake resolver that knows a
/// few names and their CNAME targets, and the real resolver for <c>localhost</c>.
/// </summary>
public sealed class DnsCanonicalizerTests
{
    /// <summary>A resolver that knows <paramref name="names"/> (name to canonical name) and records every lookup, with its family.</summary>
    private sealed class FakeDns(params (string Name, string Canonical)[] names)
    {
        public List<(string Name, SshAddressFamily Family)> Lookups { get; } = [];

        public ValueTask<string?> LookUpAsync(string name, SshAddressFamily family, CancellationToken cancellationToken)
        {
            lock (Lookups)
            {
                Lookups.Add((name, family));
            }

            return ValueTask.FromResult<string?>(names.FirstOrDefault(n => string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)).Canonical);
        }

        public IEnumerable<string> Names => Lookups.Select(l => l.Name);
    }

    private static SshConfigResolveOptions Options(FakeDns dns, bool useDns = true) => new()
    {
        LocalUser = "local",
        HomeDirectory = "/home/local",
        UseDnsCanonicalizer = useDns,
        NameLookup = dns.LookUpAsync,
    };

    private static Task<SshHostConfig> ResolveAsync(string config, string host, FakeDns dns) =>
        SshConfig.Parse(config).ResolveAsync(host, Options(dns));

    private const string Canonicalize = "CanonicalizeHostname yes\nCanonicalDomains corp.example.com example.com\n";

    [Test]
    public async Task TheDomains_AreTriedInOrder_AsAbsoluteNames_AndTheFirstFoundIsTheHostName()
    {
        var dns = new FakeDns(("web.example.com.", "web.example.com"));
        var host = await ResolveAsync(Canonicalize + "Match canonical host web.example.com\n Port 2222\n", "web", dns);

        await Assert.That(string.Join(",", dns.Names)).IsEqualTo("web.corp.example.com.,web.example.com.");
        await Assert.That(host.HostName).IsEqualTo("web.example.com");
        await Assert.That(host.Port).IsEqualTo(2222); // the configuration was read again for the canonical name
    }

    [Test]
    public async Task EachNameIsLookedUpOnce_ThoughTheConfigurationIsReadAgain()
    {
        var dns = new FakeDns(("web.example.com.", "web.example.com"));
        await ResolveAsync(Canonicalize + "Match canonical\n User canon\nMatch final\n Port 2\n", "web", dns);
        await Assert.That(dns.Lookups.Count).IsEqualTo(2);
    }

    [Test]
    public async Task NoneEndsTheDomains()
    {
        var dns = new FakeDns(("web.example.com.", "web.example.com"));
        var host = await ResolveAsync("CanonicalizeHostname yes\nCanonicalDomains corp.example.com none example.com\n", "web", dns);
        await Assert.That(dns.Names).IsEquivalentTo(new[] { "web.corp.example.com." });
        await Assert.That(host.HostName).IsEqualTo("web");
    }

    [Test]
    public async Task ANameEndingInADot_IsLookedUpAsItIs()
    {
        var dns = new FakeDns(("db.example.org.", "db.example.org"));
        var host = await ResolveAsync(Canonicalize + "CanonicalizeMaxDots 0\n", "db.example.org.", dns);
        await Assert.That(dns.Names).IsEquivalentTo(new[] { "db.example.org." });
        await Assert.That(host.HostName).IsEqualTo("db.example.org");
    }

    [Test]
    [Arguments("192.0.2.10")]
    [Arguments("2001:db8::1")]
    public async Task AnAddress_IsNotCanonicalized(string address)
    {
        var dns = new FakeDns();
        var host = await ResolveAsync(Canonicalize + "CanonicalizeMaxDots 9\nCanonicalizePermittedCNAMEs *:*\n", address, dns);
        await Assert.That(dns.Lookups).IsEmpty();
        await Assert.That(host.HostName).IsEqualTo(address);
    }

    [Test]
    public async Task ANameWithMoreThanMaxDots_IsNotTriedUnderTheDomains()
    {
        var dns = new FakeDns(("a.b.c.corp.example.com.", "a.b.c.corp.example.com"), ("a.b.corp.example.com.", "a.b.corp.example.com"));
        var host = await ResolveAsync(Canonicalize, "a.b.c", dns); // CanonicalizeMaxDots is 1 by default
        await Assert.That(dns.Lookups).IsEmpty();
        await Assert.That(host.HostName).IsEqualTo("a.b.c");

        await Assert.That((await ResolveAsync(Canonicalize, "a.b", dns)).HostName).IsEqualTo("a.b.corp.example.com"); // one dot is not too many
        var allowed = await ResolveAsync(Canonicalize + "CanonicalizeMaxDots 2\n", "a.b.c", dns);
        await Assert.That(allowed.HostName).IsEqualTo("a.b.c.corp.example.com");
    }

    [Test]
    public async Task ThroughAProxy_OnlyAlwaysCanonicalizes()
    {
        var dns = new FakeDns(("web.corp.example.com.", "web.corp.example.com"));
        await ResolveAsync(Canonicalize + "ProxyJump jump.example.com\n", "web", dns);
        await ResolveAsync(Canonicalize + "ProxyCommand nc %h %p\n", "web", dns);
        await Assert.That(dns.Lookups).IsEmpty();

        var always = await ResolveAsync("CanonicalizeHostname always\nCanonicalDomains corp.example.com\nProxyJump jump.example.com\n", "web", dns);
        await Assert.That(always.HostName).IsEqualTo("web.corp.example.com");
    }

    [Test]
    public async Task NotFound_KeepsTheName_UnlessFallbackLocalIsOff()
    {
        var dns = new FakeDns();
        await Assert.That((await ResolveAsync(Canonicalize, "web", dns)).HostName).IsEqualTo("web");
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizeFallbackLocal yes\n", "web", dns)).HostName).IsEqualTo("web");
        await Assert.That(async () => await ResolveAsync(Canonicalize + "CanonicalizeFallbackLocal no\n", "web", dns)).Throws<InvalidOperationException>();
        await Assert.That(async () => await ResolveAsync("CanonicalizeHostname yes\nCanonicalizeFallbackLocal no\n", "web.example.org.", dns))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ACnameIsFollowed_OnlyWhenARuleAllowsThePair()
    {
        // web.corp.example.com is a CNAME for lb-7.cdn.example.net.
        var dns = new FakeDns(("web.corp.example.com.", "lb-7.cdn.example.net"));

        await Assert.That((await ResolveAsync(Canonicalize, "web", dns)).HostName).IsEqualTo("web.corp.example.com"); // no rules
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs *.corp.example.com:*.cdn.example.net\n", "web", dns)).HostName)
            .IsEqualTo("lb-7.cdn.example.net");
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs *.corp.example.com:*.cdn.example.org\n", "web", dns)).HostName)
            .IsEqualTo("web.corp.example.com"); // the target is not allowed
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs *.other.example.com:*\n", "web", dns)).HostName)
            .IsEqualTo("web.corp.example.com"); // the source is not
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs a.example.com:b.example.com *.CORP.example.com:*.example.net,*.example.org\n", "web", dns)).HostName)
            .IsEqualTo("lb-7.cdn.example.net"); // any rule, pattern lists, any case
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs none\n", "web", dns)).HostName).IsEqualTo("web.corp.example.com");
        await Assert.That((await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs *.corp.example.com *:\n", "web", dns)).HostName)
            .IsEqualTo("web.corp.example.com"); // malformed rules are left out
    }

    [Test]
    public async Task WithoutACanonicalName_TheNameIsKeptAsFound()
    {
        // A resolver that reports the name itself (no CNAME, or a platform that does not say).
        var dns = new FakeDns(("web.corp.example.com.", "web.corp.example.com."));
        var host = await ResolveAsync(Canonicalize + "CanonicalizePermittedCNAMEs *:*\n", "web", dns);
        await Assert.That(host.HostName).IsEqualTo("web.corp.example.com");
    }

    [Test]
    public async Task WhenNothingIsFound_TheBareNamesCname_IsStillFollowedUnderARule()
    {
        // As ssh: canonicalization found nothing (or the name had too many dots), but the system resolver (search list included) knows
        // the name, and a rule allows its CNAME.
        var dns = new FakeDns(("build", "build-7.ci.example.net"), ("a.b.c", "x.ci.example.net"));
        const string rules = "CanonicalizePermittedCNAMEs *:*.ci.example.net\n";

        var bare = await ResolveAsync(Canonicalize + rules + "Match canonical\n User canonical\n", "build", dns);
        await Assert.That(string.Join(",", dns.Names)).IsEqualTo("build.corp.example.com.,build.example.com.,build");
        await Assert.That(bare.HostName).IsEqualTo("build-7.ci.example.net");
        await Assert.That(bare.User).IsEqualTo("canonical");

        await Assert.That((await ResolveAsync(Canonicalize + rules, "a.b.c", dns)).HostName).IsEqualTo("x.ci.example.net");
        await Assert.That((await ResolveAsync(Canonicalize, "a.b.c", dns)).HostName).IsEqualTo("a.b.c"); // no rules, no lookup
    }

    [Test]
    [Arguments("", SshAddressFamily.Any)]
    [Arguments("AddressFamily inet\n", SshAddressFamily.Inet)]
    [Arguments("AddressFamily inet6\n", SshAddressFamily.Inet6)]
    public async Task TheLookups_AreForTheConfiguredAddressFamily(string family, SshAddressFamily expected)
    {
        var dns = new FakeDns();
        await ResolveAsync(Canonicalize + family, "web", dns);
        await Assert.That(dns.Lookups.Select(l => l.Family).Distinct()).IsEquivalentTo(new[] { expected });
    }

    [Test]
    public async Task ItIsOffByDefault_AndHostCanonicalizerWins()
    {
        var dns = new FakeDns(("web.corp.example.com.", "web.corp.example.com"));
        var off = SshConfig.Parse(Canonicalize).Resolve("web", Options(dns, useDns: false)); // nothing to await: no lookups
        await Assert.That(off.HostName).IsEqualTo("web");
        await Assert.That(dns.Lookups).IsEmpty();

        var options = Options(dns);
        var mine = await SshConfig.Parse(Canonicalize).ResolveAsync("web", new SshConfigResolveOptions
        {
            LocalUser = options.LocalUser,
            HomeDirectory = options.HomeDirectory,
            UseDnsCanonicalizer = true,
            NameLookup = dns.LookUpAsync,
            HostCanonicalizer = (_, _, _) => ValueTask.FromResult<string?>("mine.example.com"),
        });
        await Assert.That(mine.HostName).IsEqualTo("mine.example.com");
        await Assert.That(dns.Lookups).IsEmpty();
    }

    [Test]
    public async Task Resolve_SaysToUseResolveAsync_WhenLookupsAreNeeded()
    {
        var dns = new FakeDns();
        await Assert.That(() => SshConfig.Parse(Canonicalize).Resolve("web", Options(dns))).Throws<NotSupportedException>();
        await Assert.That(SshConfig.Parse("Port 2\n").Resolve("web", Options(dns)).Port).IsEqualTo(2); // nothing to canonicalize
    }

    [Test]
    public async Task ConnectingByAlias_GoesToTheCanonicalName()
    {
        var password = Guid.NewGuid().ToString("N");
        await using var server = new FakeSessionServer { Password = password };
        var dns = new FakeDns(("build.corp.example.com.", "build.corp.example.com"));
        string? connectedTo = null;
        await using var client = await SshClient.ConnectAsync("build", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(Canonicalize + "Host build.corp.example.com\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"),
            ResolveOptions = Options(dns),
            UseAgent = false,
            Password = password,
            TcpConnector = (host, _, _, _) =>
            {
                connectedTo = host;
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);

        await Assert.That(connectedTo).IsEqualTo("build.corp.example.com");
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task TheSystemResolver_FindsLocalhost()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await Assert.That(await SshDnsLookup.CanonicalNameAsync("localhost", SshAddressFamily.Any, timeout.Token)).IsNotNull();
        await Assert.That(await SshDnsLookup.CanonicalNameAsync("localhost", SshAddressFamily.Inet, timeout.Token)).IsNotNull();
        await Assert.That(await SshDnsLookup.CanonicalNameAsync(new string('a', 300), SshAddressFamily.Any, timeout.Token)).IsNull(); // too long to ask
    }
}
