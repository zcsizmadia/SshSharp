using System.Runtime.InteropServices;
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

    // Resolve when no callback is set, ResolveAsync otherwise (the tests' callbacks complete at once).
    private static SshHostConfig Resolve(string config, string host, SshConfigResolveOptions? options = null) =>
        options is { ExecMatcher: not null } or { HostCanonicalizer: not null }
            ? SshConfig.Parse(config).ResolveAsync(host, options).GetAwaiter().GetResult()
            : SshConfig.Parse(config).Resolve(host, options ?? Options);

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

        // The caller's tag wins over the file's.
        var red = new SshConfigResolveOptions { Tag = "red", LocalUser = "l", HomeDirectory = "/h" };
        await Assert.That(Resolve("Tag blue\nMatch tagged red\n Port 73\n", "a", red).Port).IsEqualTo(73);
        await Assert.That(Resolve("Tag blue\nMatch tagged blue\n Port 74\n", "a", red).Port).IsEqualTo(22);
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
            ExecMatcher = (command, _) => { commands.Add(command); return ValueTask.FromResult(command.StartsWith("check", StringComparison.Ordinal)); },
        };
        await Assert.That(Resolve(config, "a", options).Port).IsEqualTo(51);
        await Assert.That(commands.Single()).IsEqualTo("check a local");
    }

    [Test]
    public async Task Exec_ExpandsTheHostKeyAliasAndProxyJumpSetSoFar()
    {
        var commands = new List<string>();
        var options = new SshConfigResolveOptions
        {
            LocalUser = "l",
            HomeDirectory = "/h",
            ExecMatcher = (command, _) => { commands.Add(command); return ValueTask.FromResult(false); },
        };

        Resolve("HostKeyAlias alias1\nProxyJump jump.example.com\nMatch exec \"c %k %j\"\n Port 5\n", "a", options);
        Resolve("Match exec \"d %k %j\"\n Port 5\n", "a", options); // %k is the host without an alias, %j empty without a jump
        Resolve("ProxyJump none\nMatch exec \"e %j\"\n Port 5\n", "a", options);
        await Assert.That(string.Join("|", commands)).IsEqualTo("c alias1 jump.example.com|d a |e ");
    }

    [Test]
    [Arguments("Port 2200\n", null, "2200")]
    [Arguments("Port 1\n", null, "1")]
    [Arguments("Port 65535\n", null, "65535")]
    [Arguments("Port 0\n", null, "22")]
    [Arguments("Port 65536\n", null, "22")]
    [Arguments("Port 2200\n", 2222, "2222")]
    public async Task Exec_ExpandsThePortSoFar_TheCallersFirst_AndOnlyAValidOne(string config, int? port, string expected)
    {
        var commands = new List<string>();
        var options = new SshConfigResolveOptions
        {
            LocalUser = "l",
            HomeDirectory = "/h",
            Port = port,
            ExecMatcher = (command, _) => { commands.Add(command); return ValueTask.FromResult(false); },
        };

        Resolve(config + "Match exec \"p %p\"\n User u\n", "a", options);
        await Assert.That(commands.Single()).IsEqualTo("p " + expected);
    }

    [Test]
    public async Task Exec_IsNotRunWhenAnEarlierCriterionAlreadyFailed()
    {
        var ran = false;
        var options = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", ExecMatcher = (_, _) => ValueTask.FromResult(ran = true) };
        Resolve("Match host other exec \"x\"\n Port 5\n", "a", options);
        await Assert.That(ran).IsFalse();
    }

    [Test]
    public async Task Exec_NeedsResolveAsync_AndEachCommandRunsOnce()
    {
        const string config = "Match exec \"one\"\n Port 51\nMatch exec \"two\"\n User u2\nMatch final exec \"one\"\n AddressFamily inet\n";
        var commands = new List<string>();
        var options = new SshConfigResolveOptions
        {
            LocalUser = "l",
            HomeDirectory = "/h",
            ExecMatcher = async (command, ct) => { await Task.Yield(); commands.Add(command); return command == "one"; },
        };

        // Resolve cannot wait for the callback; a config whose Match exec is never reached still resolves.
        await Assert.That(() => SshConfig.Parse(config).Resolve("a", options)).Throws<NotSupportedException>();
        await Assert.That(SshConfig.Parse("Match host other exec \"x\"\n Port 5\n").Resolve("a", options).Port).IsEqualTo(22);

        commands.Clear();
        var c = await SshConfig.Parse(config).ResolveAsync("a", options);
        await Assert.That(c.Port).IsEqualTo(51);
        await Assert.That(c.User).IsEqualTo("l");
        await Assert.That(c.AddressFamily).IsEqualTo(SshAddressFamily.Inet);
        await Assert.That(string.Join(",", commands)).IsEqualTo("one,two");
    }

    [Test]
    public async Task RunShellAsync_IsCancelled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var command = OperatingSystem.IsWindows() ? "ping -n 30 127.0.0.1 >nul" : "sleep 30";
        await Assert.That(() => SshExecMatcher.RunShellAsync(command, cts.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task RunShellAsync_ThatRunsOutOfTime_DoesNotMatch()
    {
        var command = OperatingSystem.IsWindows() ? "ping -n 30 127.0.0.1 >nul" : "sleep 30";
        await Assert.That(await SshExecMatcher.RunShellWithinAsync(command, TimeSpan.FromMilliseconds(200), CancellationToken.None)).IsFalse();
    }

    [Test]
    public async Task RunShellAsync_Cancelled_KillsTheCommand_AndWhatItStarted_WithoutAHangup()
    {
        // The command would write the marker a second later: from the shell itself on Windows, and from a background child elsewhere,
        // which only killing the whole process tree stops. Killing it must not hang up this process's own group, as .NET's tree kill
        // did on macOS by stopping the child first (#432).
        var marker = Path.Combine(Path.GetTempPath(), "sshsharp-exec-" + Guid.NewGuid().ToString("N"));
        var command = OperatingSystem.IsWindows()
            ? $"ping -n 2 127.0.0.1 >nul & echo x > \"{marker}\""
            : $"(sleep 1; echo x > '{marker}') & wait";
        var hangups = 0;
        using var hangup = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGHUP, context =>
        {
            Interlocked.Increment(ref hangups);
            context.Cancel = true;
        });
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            var before = ProcessTree.RecentKills;
            await Assert.That(() => SshExecMatcher.RunShellAsync(command, cts.Token)).Throws<OperationCanceledException>();

            // For a failure: what of the command still ran right after the kill, and (in the stress workflow's instrumented build) how
            // the kill went. A subshell outlived the kill of its own child on macOS once in 70 stress iterations, after #438.
            var survivors = OperatingSystem.IsWindows() ? "" : await RunningAsync(marker);
            var kills = ProcessTree.RecentKills;
            kills = kills.StartsWith(before, StringComparison.Ordinal) ? kills[before.Length..] : kills;

            await Task.Delay(TimeSpan.FromSeconds(2));
            await Assert.That(File.Exists(marker)).IsFalse().Because($"running after the kill:\n{survivors}\nthe kill:\n{kills}");
            await Assert.That(hangups).IsEqualTo(0);
        }
        finally
        {
            File.Delete(marker);
        }
    }

    // The processes whose command line names the marker (the shell and its subshell), and every sleep, from ps.
    private static async Task<string> RunningAsync(string marker)
    {
        var info = new System.Diagnostics.ProcessStartInfo("/bin/ps", "-A -o pid,ppid,pgid,stat,command") { RedirectStandardOutput = true };
        string table;
        try
        {
            using var ps = System.Diagnostics.Process.Start(info)!;
            table = await ps.StandardOutput.ReadToEndAsync();
            await ps.WaitForExitAsync();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return "(no ps: " + ex.Message + ")"; // only a failure's report needs it
        }

        return string.Join("\n", table.Split('\n').Where(line => line.Contains(marker, StringComparison.Ordinal) ||
            line.Contains(" sleep ", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Runs <see cref="SshExecMatcher.RunShellAsync"/> on the thread pool and gives up after 30 seconds, so that a run that never ends
    /// (even one blocked before its first await) fails the test with the step it was on, rather than hanging the test run.
    /// </summary>
    private static async Task<bool> RunShellWithinAsync(string step, string command, CancellationToken cancellationToken)
    {
        try
        {
            // The token goes to the command alone: it is what must answer the cancellation.
            return await Task.Run(() => SshExecMatcher.RunShellAsync(command, cancellationToken))
                .WaitAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
        }
        catch (TimeoutException ex)
        {
            throw new TimeoutException($"{step} did not finish within 30 s.", ex);
        }
    }

    [Test]
    public async Task RunShell_ReportsExitStatus()
    {
        await Assert.That(await SshExecMatcher.RunShellAsync("exit 0")).IsTrue();
        await Assert.That(await SshExecMatcher.RunShellAsync("exit 1")).IsFalse();
        await Assert.That(() => SshExecMatcher.RunShellAsync("")).Throws<ArgumentException>();
    }

    [Test]
    public async Task RunShell_GivesTheCommandNoInput_AndReadsAwayItsOutput()
    {
        // sort reads its input to the end, and 1 MiB is far more than a pipe holds: either would wait out the deadline below if the
        // input were left open or the output unread.
        var path = Path.Combine(Path.GetTempPath(), "sshsharp-exec-" + Guid.NewGuid().ToString("N"));
        await File.WriteAllTextAsync(path, new string('x', 1024 * 1024));
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await Assert.That(await RunShellWithinAsync("sort", "sort", deadline.Token)).IsTrue();
            var print = OperatingSystem.IsWindows() ? $"type \"{path}\"" : $"cat '{path}'";
            await Assert.That(await RunShellWithinAsync("Printing 1 MiB", print, deadline.Token)).IsTrue();
        }
        finally
        {
            File.Delete(path);
        }
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

    // The second-pass cases below follow OpenSSH 10.1 and later, where "Match !final" no longer asks for a second pass
    // (openssh-portable 688fa02728); earlier releases read the configuration again for it.
    [Test]
    public async Task NegatedFinal_Alone_DoesNotReadAgain()
    {
        var c = Resolve("Host a\n HostName B.Example\nMatch !final\n User x\nHost b.example\n Port 7\n", "a");
        await Assert.That(c.User).IsEqualTo("x");
        await Assert.That(c.Port).IsEqualTo(22);
    }

    [Test]
    public async Task Canonical_Alone_DoesNotReadAgain()
    {
        var c = Resolve("Host a\n HostName B.Example\nMatch canonical\n User x\nHost b.example\n Port 7\n", "a");
        await Assert.That(c.User).IsEqualTo("local");
        await Assert.That(c.Port).IsEqualTo(22);
    }

    [Test]
    public async Task Final_WithoutCanonicalization_MakesCanonicalTrue()
    {
        // ssh has one flag for both: the second pass, however it came about.
        var c = Resolve("Match final\n User f\nMatch canonical\n Port 6\nMatch !canonical\n Compression yes\n", "a");
        await Assert.That(c.User).IsEqualTo("f");
        await Assert.That(c.Port).IsEqualTo(6);
        await Assert.That(c.Compression).IsTrue();
    }

    [Test]
    public async Task Final_SecondPass_SeesTheLowercasedHostName()
    {
        var c = Resolve("Host a\n HostName B.Example\nMatch final\n User x\nHost b.example\n Port 7\nMatch final host b.example\n Compression yes\n", "a");
        await Assert.That(c.HostName).IsEqualTo("b.example");
        await Assert.That(c.Port).IsEqualTo(7);
        await Assert.That(c.Compression).IsTrue();
    }

    [Test]
    public async Task SecondPass_KeepsAPercentSignInTheName_AsItIs()
    {
        // The name is expanded once, in the first pass; the second does not expand it again.
        await Assert.That(Resolve("Match final\n Port 2\n", "a%h").HostName).IsEqualTo("a%h");
    }

    [Test]
    public async Task SecondPass_KeepsTheHostNameOfTheFirst()
    {
        // ssh sets HostName to the name it settled on before reading again, so a HostName met only in the second pass is ignored.
        await Assert.That(Resolve("Match final\n HostName h1\n", "a").HostName).IsEqualTo("a");
        await Assert.That(Resolve("CanonicalizeHostname yes\nMatch canonical\n HostName h1\n", "a").HostName).IsEqualTo("a");
        await Assert.That(Resolve("Match !final\n HostName h1\n", "a").HostName).IsEqualTo("h1");
    }

    [Test]
    public async Task CanonicalizationOn_ReadsAgain_WithoutACanonicalizer()
    {
        // ssh reads the configuration again whenever CanonicalizeHostname is not no, whether or not a name is looked up or found.
        const string config = "Host a\n HostName B.Example\nMatch canonical\n User c\nHost b.example\n Port 7\n";
        foreach (var mode in new[] { "yes", "always", "true" })
        {
            var c = Resolve($"CanonicalizeHostname {mode}\n" + config, "a");
            await Assert.That(c.User).IsEqualTo("c");
            await Assert.That(c.Port).IsEqualTo(7);
        }

        var off = Resolve("CanonicalizeHostname no\n" + config, "a");
        await Assert.That(off.User).IsEqualTo("local");
        await Assert.That(off.Port).IsEqualTo(22);

        // Proxied with yes, no name is looked up, but the configuration is still read again.
        await Assert.That(Resolve("CanonicalizeHostname yes\nProxyJump j\n" + config, "a").User).IsEqualTo("c");
    }

    [Test]
    public async Task CanonicalizationOn_NoNameFound_ReadsAgain_AndCanonicalIsTrue()
    {
        const string config = "CanonicalizeHostname yes\nCanonicalDomains example.com\nHost web\n HostName Web.Internal\nMatch canonical\n Port 5\n"
            + "Host web.internal\n User found\nMatch canonical host web.internal\n Compression yes\n";
        var c = Resolve(config, "web", Canonicalizing((_, _) => null));
        await Assert.That(c.HostName).IsEqualTo("web.internal");
        await Assert.That(c.Port).IsEqualTo(5);
        await Assert.That(c.User).IsEqualTo("found");
        await Assert.That(c.Compression).IsTrue();
    }

    private static SshConfigResolveOptions Canonicalizing(Func<string, IReadOnlyList<string>, string?> canonicalizer) =>
        new() { LocalUser = "l", HomeDirectory = "/h", HostCanonicalizer = (host, domains, _) => ValueTask.FromResult(canonicalizer(host, domains)) };

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
        var off = await Assert.That(() => Resolve("CanonicalizeHostname yes\nCanonicalizeFallbackLocal false\n", "web", notFound)).Throws<InvalidOperationException>();
        await Assert.That(off!.Message).Contains("CanonicalizeFallbackLocal is off");
        await Assert.That(() => Resolve("CanonicalizeHostname yes\nCanonicalizeFallbackLocal no\n", "web", notFound)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Match_SyntaxErrors()
    {
        var noHost = await Assert.That(() => Resolve("Match host\n Port 1\n", "a")).ThrowsExactly<FormatException>();
        await Assert.That(noHost!.Message).Contains("Match criterion 'host' needs an argument");
        var bogus = await Assert.That(() => Resolve("Match bogus\n Port 1\n", "a")).ThrowsExactly<FormatException>();
        await Assert.That(bogus!.Message).Contains("Unsupported Match criterion 'bogus'");

        // A session criterion needs its argument whether or not the caller described the session.
        var shell = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h", SessionType = "shell" };
        var described = await Assert.That(() => Resolve("Match sessiontype\n Port 1\n", "a", shell)).ThrowsExactly<FormatException>();
        await Assert.That(described!.Message).Contains("Match criterion 'sessiontype' needs an argument");
        var undescribed = await Assert.That(() => Resolve("Match command\n Port 1\n", "a")).ThrowsExactly<FormatException>();
        await Assert.That(undescribed!.Message).Contains("Match criterion 'command' needs an argument");
    }
}