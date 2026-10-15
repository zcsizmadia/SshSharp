using System.Net;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Config;

/// <summary>RefuseConnection, Match localnetwork, Match sessiontype and command, and KnownHostsCommand.</summary>
public sealed class ConfigGapsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-configgaps-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private SshConfigResolveOptions Options(Func<IReadOnlyList<IPAddress>>? addresses = null, string? sessionType = null, string? command = null) => new()
    {
        LocalUser = "local",
        HomeDirectory = _dir,
        LocalAddresses = addresses,
        SessionType = sessionType,
        Command = command,
    };

    private static int ResolvedPort(string config, SshConfigResolveOptions options) => SshConfig.Parse(config).Resolve("h", options).Port;

    [Test]
    public async Task RefuseConnection_FailsBeforeAnyNetworkActivity()
    {
        var config = SshConfig.Parse("Host blocked\n RefuseConnection yes\nHost *\n RefuseConnection no\n");
        await Assert.That(config.Resolve("blocked", Options()).RefuseConnection).IsTrue();
        await Assert.That(config.Resolve("other", Options()).RefuseConnection).IsFalse();

        var connected = false;
        var error = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("blocked", new SshConfigConnectOptions
        {
            Config = config,
            ResolveOptions = Options(),
            TcpConnector = (_, _, _, _) =>
            {
                connected = true;
                throw new InvalidOperationException("must not connect");
            },
        }, Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(error.Message).Contains("RefuseConnection");
        await Assert.That(error.Message).DoesNotContain("blocked");
        await Assert.That(connected).IsFalse();
    }

    [Test]
    public async Task MatchLocalNetwork_ComparesTheInterfaceAddressesWithTheNetworks()
    {
        IReadOnlyList<IPAddress> Addresses() => [IPAddress.Parse("10.1.2.3"), IPAddress.Parse("fe80::1"), IPAddress.Loopback];

        string Block(string criteria) => $"Match {criteria}\n Port 2222\n";
        await Assert.That(ResolvedPort(Block("localnetwork 10.0.0.0/8"), Options(Addresses))).IsEqualTo(2222);
        await Assert.That(ResolvedPort(Block("localnetwork 192.168.0.0/16,10.1.2.0/24"), Options(Addresses))).IsEqualTo(2222);
        await Assert.That(ResolvedPort(Block("localnetwork 10.1.2.3"), Options(Addresses))).IsEqualTo(2222);
        await Assert.That(ResolvedPort(Block("localnetwork fe80::/10"), Options(Addresses))).IsEqualTo(2222);
        await Assert.That(ResolvedPort(Block("localnetwork 10.1.2.128/25"), Options(Addresses))).IsEqualTo(22);
        await Assert.That(ResolvedPort(Block("localnetwork 192.168.0.0/16"), Options(Addresses))).IsEqualTo(22);
        await Assert.That(ResolvedPort(Block("!localnetwork 192.168.0.0/16"), Options(Addresses))).IsEqualTo(2222);
        await Assert.That(ResolvedPort(Block("!localnetwork 10.0.0.0/8"), Options(Addresses))).IsEqualTo(22);

        await Assert.That(() => ResolvedPort(Block("localnetwork 10.0.0.0/33"), Options(Addresses))).Throws<FormatException>();
        await Assert.That(() => ResolvedPort(Block("localnetwork 300.1.1.1/8"), Options(Addresses))).Throws<FormatException>();
        await Assert.That(() => ResolvedPort(Block("localnetwork nonsense"), Options(Addresses))).Throws<FormatException>();

        // Without an injected list, the machine's own interfaces are read; loopback is always among them where interfaces are up.
        await Assert.That(ResolvedPort(Block("localnetwork 127.0.0.0/8,::1/128,0.0.0.0/0,::/0"), Options())).IsEqualTo(2222);
    }

    [Test]
    public async Task MatchSessionTypeAndCommand_UseWhatTheCallerSays_AndNeverApplyWhenItSaysNothing()
    {
        const string Config = "Match sessiontype subsystem command sftp\n Port 1001\nMatch sessiontype exec command \"git-*\"\n Port 1002\n"
            + "Match command \"\"\n Port 1003\n";

        await Assert.That(ResolvedPort(Config, Options(sessionType: "subsystem", command: "sftp"))).IsEqualTo(1001);
        await Assert.That(ResolvedPort(Config, Options(sessionType: "exec", command: "git-upload-pack 'repo.git'"))).IsEqualTo(1002);
        await Assert.That(ResolvedPort(Config, Options(sessionType: "exec", command: "Git-upload-pack"))).IsEqualTo(22); // case-sensitive
        await Assert.That(ResolvedPort(Config, Options(sessionType: "shell"))).IsEqualTo(1003);
        await Assert.That(ResolvedPort(Config, Options(sessionType: "none"))).IsEqualTo(1003);

        // Unknown: no block with these criteria applies, negated or not.
        await Assert.That(ResolvedPort(Config, Options())).IsEqualTo(22);
        await Assert.That(ResolvedPort("Match !sessiontype shell\n Port 1004\n", Options())).IsEqualTo(22);
        await Assert.That(ResolvedPort("Match !sessiontype shell\n Port 1004\n", Options(sessionType: "exec", command: "ls"))).IsEqualTo(1004);

        await Assert.That(() => new SshConfigResolveOptions { SessionType = "interactive" }).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("/usr/bin/lookup %H", new[] { "/usr/bin/lookup", "%H" })]
    [Arguments("  /bin/a   b  c ", new[] { "/bin/a", "b", "c" })]
    [Arguments("/bin/a \"two words\" 'single quoted' x\\ y", new[] { "/bin/a", "two words", "single quoted", "x y" })]
    [Arguments("/bin/a \"say \\\"hi\\\"\"", new[] { "/bin/a", "say \"hi\"" })]
    [Arguments("/bin/a ''", new[] { "/bin/a", "" })]
    public async Task KnownHostsCommand_IsSplitAsOpenSshSplitsIt(string command, string[] expected)
    {
        await Assert.That(KnownHostsCommandRunner.Split(command)).IsEquivalentTo(expected);
    }

    [Test]
    public async Task KnownHostsCommand_IsKeptAsWritten_AndNoneMeansNone()
    {
        await Assert.That(SshConfig.Parse("Host *\n KnownHostsCommand /usr/bin/lookup \"%H\" %K\n").Resolve("h", Options()).KnownHostsCommand)
            .IsEqualTo("/usr/bin/lookup \"%H\" %K");
        await Assert.That(SshConfig.Parse("Host *\n KnownHostsCommand none\n").Resolve("h", Options()).KnownHostsCommand).IsNull();
        await Assert.That(() => KnownHostsCommandRunner.Split("/bin/a \"open")).Throws<FormatException>();
    }

    /// <summary>A command that writes its arguments as one line: with %H %t %K that is a known_hosts line for the presented key.</summary>
    private static string Echo(string arguments) => OperatingSystem.IsWindows()
        ? $"\"{Path.Combine(Environment.SystemDirectory, "cmd.exe")}\" /c echo {arguments}"
        : $"/bin/sh -c \"echo {arguments}\"";

    private static string Exit(int status) => OperatingSystem.IsWindows()
        ? $"\"{Path.Combine(Environment.SystemDirectory, "cmd.exe")}\" /c exit {status}"
        : $"/bin/sh -c \"exit {status}\"";

    private async Task<SshClient> ConnectWithCommandAsync(FakeSessionServer server, string command, bool allow, SshHostKeyVerifier? verifier = null)
    {
        var config = $"Host *\n User tester\n StrictHostKeyChecking yes\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n KnownHostsCommand {command}\n";
        return await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse(config),
            ResolveOptions = Options(),
            Password = "secret",
            UseAgent = false,
            AllowKnownHostsCommand = allow,
            HostKeyVerifier = verifier,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
    }

    [Test]
    public async Task KnownHostsCommand_SuppliesTheHostKey_WithItsTokensExpanded()
    {
        await using var server = new FakeSessionServer();

        // StrictHostKeyChecking yes and no files: only the command's line (built from %H %t %K) can vouch for the key.
        await using var client = await ConnectWithCommandAsync(server, Echo("%H %t %K"), allow: true);

        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task KnownHostsCommand_ThatFails_OrIsNotAllowed_FailsTheConnection()
    {
        await using (var server = new FakeSessionServer())
        {
            var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectWithCommandAsync(server, Exit(3), allow: true));
            await Assert.That(error!.Message).Contains("KnownHostsCommand");
        }

        await using (var server = new FakeSessionServer())
        {
            var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectWithCommandAsync(server, Echo("%H %t %K"), allow: false));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
            await Assert.That(error.Message).Contains("AllowKnownHostsCommand");
        }

        // A relative program is refused, as OpenSSH refuses it.
        await using (var server = new FakeSessionServer())
        {
            var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectWithCommandAsync(server, "lookup %H", allow: true));
            await Assert.That(error!.Message).Contains("absolute path");
        }

        // With the application's own verifier, the command does not matter, and nothing runs.
        await using (var server = new FakeSessionServer())
        {
            await using var client = await ConnectWithCommandAsync(server, Exit(3), allow: false,
                SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)));
            await Assert.That(client.IsConnected).IsTrue();
        }
    }

    [Test]
    public async Task KnownHostsCommand_ThatIsABatchFile_IsRefusedOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // elsewhere a .cmd file is just a program
        }

        foreach (var program in new[] { "lookup.cmd", "lookup.BAT", "lookup.bat." })
        {
            await using var server = new FakeSessionServer();
            var error = await Assert.ThrowsAsync<SshException>(async () =>
                await ConnectWithCommandAsync(server, $"\"{Path.Combine(_dir, program)}\" %H", allow: true));
            await Assert.That(error!.Message).Contains("batch file");
        }
    }

    [Test]
    public async Task AJumpHost_IsResolvedWithoutTheCallersSession()
    {
        // ssh runs each ProxyJump hop as ssh -W: session type none, no command.
        var options = Options(sessionType: "subsystem", command: "sftp");
        var hop = options.With(user: null, port: null, jumpHost: true);
        var destination = options.With(user: null, port: null);

        await Assert.That(hop.SessionType).IsEqualTo("none");
        await Assert.That(hop.Command).IsNull();
        await Assert.That(destination.SessionType).IsEqualTo("subsystem");
        await Assert.That(destination.Command).IsEqualTo("sftp");
        await Assert.That(ResolvedPort("Match sessiontype subsystem\n Port 1001\n", hop)).IsEqualTo(22);
        await Assert.That(ResolvedPort("Match sessiontype none\n Port 1002\n", hop)).IsEqualTo(1002);
    }
}
