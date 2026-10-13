using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class SshConfigTests
{
    private static readonly SshConfigResolveOptions Options = new()
    {
        LocalUser = "alice",
        HomeDirectory = "/home/alice",
        LocalHostName = "laptop.corp",
        GetEnvironmentVariable = name => name == "SOCK" ? "/run/agent.sock" : null,
    };

    private static SshConfig Sample() =>
        SshConfig.Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ssh_config_sample"));

    // Expected values below were checked against `ssh -G -F ssh_config_sample <host>` (OpenSSH for Windows).

    [Test]
    public async Task Resolve_AliasWithManyDirectives()
    {
        var c = Sample().Resolve("web", Options);

        await Assert.That(c.Alias).IsEqualTo("web");
        await Assert.That(c.HostName).IsEqualTo("web.example.com");
        await Assert.That(c.User).IsEqualTo("deploy");
        await Assert.That(c.Port).IsEqualTo(2222);
        await Assert.That(c.IdentitiesOnly).IsTrue();
        await Assert.That(c.ForwardAgent).IsTrue();
        await Assert.That(string.Join("|", c.IdentityFiles))
            .IsEqualTo("/home/alice/.ssh/web_key|/home/alice/.ssh/web_key2|/home/alice/.ssh/web.example.com_key");
        await Assert.That(c.LocalForwards.Single()).IsEqualTo("8080 localhost:80");
        await Assert.That(string.Join("|", c.ProxyJump)).IsEqualTo("jump1|jump2:2200");
        await Assert.That(string.Join("|", c.SendEnv)).IsEqualTo("LANG|LC_*");
        await Assert.That(c.SetEnv.Count).IsEqualTo(2);
        await Assert.That(c.SetEnv["A"]).IsEqualTo("1");
        await Assert.That(c.SetEnv["B"]).IsEqualTo("two");
        await Assert.That(c.ServerAliveInterval).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(c.AddressFamily).IsEqualTo(SshAddressFamily.Inet);
        await Assert.That(c.RequestTty).IsEqualTo(RequestTty.Force);
        await Assert.That(c.StrictHostKeyChecking).IsEqualTo(StrictHostKeyChecking.Ask);
        await Assert.That(c.ConnectTimeout).IsNull();
        await Assert.That(c.Ciphers).IsEqualTo("+aes128-ctr");
        await Assert.That(string.Join("|", c.UserKnownHostsFiles)).IsEqualTo("/home/alice/.ssh/kh1|/home/alice/.ssh/kh2");
        // ProxyJump came first, so the later ProxyCommand is ignored (ssh -G prints only proxyjump).
        await Assert.That(c.ProxyCommand).IsNull();
    }

    [Test]
    public async Task Resolve_WildcardBlock_WithNegation()
    {
        var internalHost = Sample().Resolve("db.internal", Options);
        await Assert.That(internalHost.User).IsEqualTo("internal");
        await Assert.That(internalHost.StrictHostKeyChecking).IsEqualTo(StrictHostKeyChecking.AcceptNew);
        await Assert.That(internalHost.ConnectTimeout).IsEqualTo(TimeSpan.FromSeconds(90));
        await Assert.That(internalHost.HostName).IsEqualTo("db.internal");
        await Assert.That(internalHost.Port).IsEqualTo(22);
        await Assert.That(internalHost.IdentitiesOnly).IsFalse();
        await Assert.That(internalHost.ForwardAgent).IsFalse();

        var excluded = Sample().Resolve("secret.internal", Options);
        await Assert.That(excluded.User).IsEqualTo("fallback");
        await Assert.That(excluded.StrictHostKeyChecking).IsEqualTo(StrictHostKeyChecking.Ask);
        await Assert.That(excluded.ConnectTimeout).IsNull();
    }

    [Test]
    public async Task Resolve_UnknownHost_GetsDefaultsAndStarBlock()
    {
        var c = Sample().Resolve("plain", Options);

        await Assert.That(c.HostName).IsEqualTo("plain");
        await Assert.That(c.User).IsEqualTo("fallback");
        await Assert.That(c.ServerAliveInterval).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(c.ServerAliveCountMax).IsEqualTo(3);
        await Assert.That(c.IdentityFiles.Count).IsEqualTo(5);
        await Assert.That(c.IdentityFiles[0]).IsEqualTo("/home/alice/.ssh/id_rsa");
        await Assert.That(c.GlobalKnownHostsFiles.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Resolve_ExplicitUserAndPortOverrideTheFile()
    {
        var c = Sample().Resolve("web", new SshConfigResolveOptions { User = "root", Port = 22022, LocalUser = "alice", HomeDirectory = "/h" });
        await Assert.That(c.User).IsEqualTo("root");
        await Assert.That(c.Port).IsEqualTo(22022);
    }

    [Test]
    public async Task Resolve_DefaultUserIsLocalUser()
    {
        var c = SshConfig.Parse("").Resolve("h", Options);
        await Assert.That(c.User).IsEqualTo("alice");
        await Assert.That(c.Port).IsEqualTo(22);
    }

    [Test]
    public async Task Resolve_FirstValueWins_AcrossBlocks()
    {
        var c = SshConfig.Parse("Host a\n User first\nHost a\n User second\nHost *\n User third\n").Resolve("a", Options);
        await Assert.That(c.User).IsEqualTo("first");
    }

    [Test]
    public async Task Resolve_GlobalSectionAppliesToEveryHost()
    {
        var c = SshConfig.Parse("User everyone\nHost x\n Port 1\n").Resolve("other", Options);
        await Assert.That(c.User).IsEqualTo("everyone");
    }

    [Test]
    public async Task Resolve_HostLineWithSeveralPatterns_IsCaseInsensitive()
    {
        var config = SshConfig.Parse("Host a b* C?\n Port 99\n");
        foreach (var host in new[] { "a", "bee", "c1", "C1" })
        {
            await Assert.That(config.Resolve(host, Options).Port).IsEqualTo(99);
        }

        await Assert.That(config.Resolve("zzz", Options).Port).IsEqualTo(22);
    }

    [Test]
    public async Task Resolve_HostNameTokenUsesTheAlias()
    {
        var c = SshConfig.Parse("Host web-*\n HostName %h.internal.example\n").Resolve("web-1", Options);
        await Assert.That(c.HostName).IsEqualTo("web-1.internal.example");
    }

    [Test]
    public async Task Resolve_IdentityAgentVariants()
    {
        await Assert.That(SshConfig.Parse("IdentityAgent none\n").Resolve("h", Options).IdentityAgent).IsEqualTo("none");
        await Assert.That(SshConfig.Parse("IdentityAgent SSH_AUTH_SOCK\n").Resolve("h", Options).IdentityAgent).IsEqualTo("SSH_AUTH_SOCK");
        await Assert.That(SshConfig.Parse("IdentityAgent $SOCK\n").Resolve("h", Options).IdentityAgent).IsEqualTo("/run/agent.sock");
        await Assert.That(SshConfig.Parse("IdentityAgent ~/agent-%r\n").Resolve("h", Options).IdentityAgent).IsEqualTo("/home/alice/agent-alice");
        await Assert.That(() => SshConfig.Parse("IdentityAgent $NOPE\n").Resolve("h", Options)).Throws<FormatException>();
        await Assert.That(SshConfig.Parse("User x\n").Resolve("h", Options).IdentityAgent).IsNull();
    }

    [Test]
    public async Task Resolve_ProxyJumpNoneAndProxyCommandNone()
    {
        var c = SshConfig.Parse("ProxyJump none\nProxyCommand none\n").Resolve("h", Options);
        await Assert.That(c.ProxyJump.Count).IsEqualTo(0);
        await Assert.That(c.ProxyCommand).IsNull();
    }

    [Test]
    public async Task Resolve_TypedValues()
    {
        var text = """
            StrictHostKeyChecking yes
            ServerAliveInterval 0
            ServerAliveCountMax 5
            ConnectTimeout 10
            AddressFamily inet6
            RequestTTY no
            ForwardAgent no
            BatchMode yes
            PubkeyAuthentication no
            PasswordAuthentication false
            ChallengeResponseAuthentication off
            PreferredAuthentications publickey,password
            HostKeyAlgorithms ssh-ed25519
            KexAlgorithms curve25519-sha256
            MACs hmac-sha2-256-etm@openssh.com
            PubkeyAcceptedKeyTypes ssh-ed25519
            HostKeyAlias alias-%h
            CertificateFile ~/cert-%r.pub
            DynamicForward 1080
            RemoteForward 9000 localhost:9000
            SomethingUnknown a b
            """;
        var c = SshConfig.Parse(text).Resolve("h", Options);

        await Assert.That(c.StrictHostKeyChecking).IsEqualTo(StrictHostKeyChecking.Yes);
        await Assert.That(c.ServerAliveInterval).IsNull();
        await Assert.That(c.ServerAliveCountMax).IsEqualTo(5);
        await Assert.That(c.ConnectTimeout).IsEqualTo(TimeSpan.FromSeconds(10));
        await Assert.That(c.AddressFamily).IsEqualTo(SshAddressFamily.Inet6);
        await Assert.That(c.RequestTty).IsEqualTo(RequestTty.No);
        await Assert.That(c.ForwardAgent).IsFalse();
        await Assert.That(c.BatchMode).IsTrue();
        await Assert.That(c.PubkeyAuthentication).IsFalse();
        await Assert.That(c.PasswordAuthentication).IsFalse();
        await Assert.That(c.KbdInteractiveAuthentication).IsFalse();
        await Assert.That(string.Join("|", c.PreferredAuthentications)).IsEqualTo("publickey|password");
        await Assert.That(c.HostKeyAlgorithms).IsEqualTo("ssh-ed25519");
        await Assert.That(c.KexAlgorithms).IsEqualTo("curve25519-sha256");
        await Assert.That(c.Macs).IsEqualTo("hmac-sha2-256-etm@openssh.com");
        await Assert.That(c.PubkeyAcceptedAlgorithms).IsEqualTo("ssh-ed25519");
        await Assert.That(c.HostKeyAlias).IsEqualTo("alias-%h"); // not token-expanded (ssh -G agrees)
        await Assert.That(c.CertificateFiles.Single()).IsEqualTo("/home/alice/cert-alice.pub");
        await Assert.That(c.DynamicForwards.Single()).IsEqualTo("1080");
        await Assert.That(c.RemoteForwards.Single()).IsEqualTo("9000 localhost:9000");
        await Assert.That(string.Join(" ", c.Options["somethingunknown"])).IsEqualTo("a b");
    }

    [Test]
    public async Task Resolve_BadValuesFallBackToDefaults()
    {
        var c = SshConfig.Parse("Port 99999\nConnectTimeout soon\nServerAliveCountMax many\nStrictHostKeyChecking maybe\nAddressFamily any\nRequestTTY auto\n").Resolve("h", Options);
        await Assert.That(c.Port).IsEqualTo(22);
        await Assert.That(c.ConnectTimeout).IsNull();
        await Assert.That(c.ServerAliveCountMax).IsEqualTo(3);
        await Assert.That(c.StrictHostKeyChecking).IsEqualTo(StrictHostKeyChecking.Ask);
        await Assert.That(c.AddressFamily).IsEqualTo(SshAddressFamily.Any);
        await Assert.That(c.RequestTty).IsEqualTo(RequestTty.Auto);
    }

    [Test]
    public async Task Resolve_StrictHostKeyCheckingSpellings()
    {
        foreach (var (text, expected) in new[]
        {
            ("true", StrictHostKeyChecking.Yes), ("no", StrictHostKeyChecking.No), ("off", StrictHostKeyChecking.No),
            ("false", StrictHostKeyChecking.No), ("accept-new", StrictHostKeyChecking.AcceptNew), ("ask", StrictHostKeyChecking.Ask),
        })
        {
            await Assert.That(SshConfig.Parse($"StrictHostKeyChecking {text}\n").Resolve("h", Options).StrictHostKeyChecking).IsEqualTo(expected);
        }

        await Assert.That(SshConfig.Parse("RequestTTY yes\n").Resolve("h", Options).RequestTty).IsEqualTo(RequestTty.Yes);
    }

    [Test]
    public async Task Resolve_SendEnvRemoval()
    {
        var c = SshConfig.Parse("SendEnv LANG LC_* FOO\nSendEnv -LC_*\n").Resolve("h", Options);
        await Assert.That(string.Join("|", c.SendEnv)).IsEqualTo("LANG|FOO");
    }

    [Test]
    public async Task Resolve_SetEnvFirstDirectiveOnly_AndMalformedIgnored()
    {
        var c = SshConfig.Parse("SetEnv A=1 B=2 A=3 novalue\nSetEnv C=9\n").Resolve("h", Options);
        await Assert.That(c.SetEnv.Count).IsEqualTo(2);
        await Assert.That(c.SetEnv["A"]).IsEqualTo("1");
    }

    [Test]
    public async Task Parse_BuildsBlocks()
    {
        var config = SshConfig.Parse("Port 1\nHost a b\n User x\nMatch all\n User y\n");

        await Assert.That(config.Blocks.Count).IsEqualTo(3);
        await Assert.That(config.Blocks[0].HostPatterns).IsNull();
        await Assert.That(config.Blocks[0].Directives.Single().Keyword).IsEqualTo("Port");
        await Assert.That(config.Blocks[0].Directives.Single().Line).IsEqualTo(1);
        await Assert.That(string.Join(",", config.Blocks[1].HostPatterns!)).IsEqualTo("a,b");
        await Assert.That(config.Blocks[2].IsMatch).IsTrue();
        await Assert.That(string.Join(",", config.Blocks[2].MatchCriteria)).IsEqualTo("all");
    }

    [Test]
    public async Task Parse_ErrorsCarryTheLineNumber()
    {
        await Assert.That(() => SshConfig.Parse("Port 1\nHost\n")).Throws<FormatException>();
        var ex = Assert.Throws<FormatException>(() => SshConfig.Parse("Port 1\n\nUser \"oops\n"));
        await Assert.That(ex.Message).Contains("line 3");
        await Assert.That(() => SshConfig.Parse(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task Parse_HandlesCrLf()
    {
        var c = SshConfig.Parse("Host a\r\n User crlf\r\n").Resolve("a", Options);
        await Assert.That(c.User).IsEqualTo("crlf");
    }

    [Test]
    public async Task Load_MissingFileIsEmpty_AndArgumentsAreChecked()
    {
        var missing = Path.Combine(Path.GetTempPath(), "sshsharp-nocfg-" + Guid.NewGuid().ToString("N"));
        await Assert.That(SshConfig.Load(missing).Blocks.Count).IsEqualTo(1);
        await Assert.That((await SshConfig.LoadAsync(missing)).Blocks.Count).IsEqualTo(1);
        await Assert.That(() => SshConfig.Combine(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => SshConfig.Load("")).Throws<ArgumentException>();
        await Assert.That(async () => await SshConfig.LoadAsync("")).Throws<ArgumentException>();
        await Assert.That(() => SshConfig.Parse("").Resolve("")).Throws<ArgumentException>();
    }

    [Test]
    public async Task LoadAsync_ReadsTheFile()
    {
        var c = (await SshConfig.LoadAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ssh_config_sample"))).Resolve("web", Options);
        await Assert.That(c.User).IsEqualTo("deploy");
    }

    [Test]
    public async Task Resolve_UsesProcessDefaultsWhenNoOptionsGiven()
    {
        var c = SshConfig.Parse("").Resolve("h");
        await Assert.That(c.User).IsEqualTo(Environment.UserName);
    }
}