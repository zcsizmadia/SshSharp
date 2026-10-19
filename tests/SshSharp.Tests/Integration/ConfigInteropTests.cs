using SshSharp.Config;

namespace SshSharp.Tests.Integration;

/// <summary>
/// M3's goal against a real OpenSSH server: connect using only an ssh_config alias, through a two-hop ProxyJump chain, with an
/// IdentityFile and known_hosts accept-new. The one sshd plays every hop (it forwards to itself). Needs SSHSHARP_TEST_SSHD,
/// SSHSHARP_TEST_USER and SSHSHARP_TEST_KEYDIR (with an unencrypted "ed25519" key authorized for the user); skipped otherwise.
/// </summary>
public sealed class ConfigInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-cfgi-" + Guid.NewGuid().ToString("N"));

    public ConfigInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    private static string? Key => Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;

    private string? WriteConfig(string extra = "")
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || Key is not { } key || !File.Exists(key))
        {
            return null;
        }

        var path = Path.Combine(_dir, "config");
        File.WriteAllText(path, $"""
            Host target
              HostName localhost
              ProxyJump jump-a,jump-b
            Host jump-a jump-b
              HostName {host}
            {extra}
            Host *
              Port {port}
              User {user}
              IdentityFile "{key}"
              IdentitiesOnly yes
              StrictHostKeyChecking accept-new
              UserKnownHostsFile "{Path.Combine(_dir, "known_hosts")}"
              ServerAliveInterval 5
            """);
        return path;
    }

    [Test]
    public async Task TwoHopProxyJump_ByAliasOnly()
    {
        if (WriteConfig() is not { } path)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_KEYDIR are needed.");
            return;
        }

        var config = await SshConfig.LoadAsync(path);
        await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions { Config = config }, Timeout());
        var result = await client.RunCommandAsync("echo through-two-hops", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("through-two-hops\n");

        // accept-new recorded the server's key under each name it was reached by.
        var known = KnownHostsFile.Load(Path.Combine(_dir, "known_hosts"));
        await Assert.That(known.Entries.Count).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task TwoJumpHosts_ConfiguredInCode()
    {
        // The same chain as above, from SshClientOptions.JumpHosts: each hop with its own options and known_hosts check.
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || Key is not { } path || !File.Exists(path))
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_KEYDIR are needed.");
            return;
        }

        using var key = await SshPrivateKey.LoadAsync(path, cancellationToken: Timeout());
        var knownHosts = Path.Combine(_dir, "known_hosts");
        SshClientOptions Hop() => new()
        {
            UserName = user,
            PrivateKeys = [key],
            HostKeyVerifier = new KnownHostsVerifier([knownHosts]) { Policy = StrictHostKeyChecking.AcceptNew },
            KeepAliveInterval = TimeSpan.FromSeconds(5),
        };

        var hop = Hop();
        await using var client = await SshClient.ConnectAsync("localhost", port, new SshClientOptions
        {
            UserName = user,
            PrivateKeys = [key],
            HostKeyVerifier = hop.HostKeyVerifier,
            ConnectTimeout = TimeSpan.FromSeconds(60),
            JumpHosts = [new SshJumpHost(host, port, hop), new SshJumpHost(host, port, Hop())],
        }, Timeout());
        var result = await client.RunCommandAsync("echo through-two-jump-hosts", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("through-two-jump-hosts\n");

        // accept-new recorded the server's key under each name it was reached by.
        var known = KnownHostsFile.Load(knownHosts);
        await Assert.That(known.Entries.Count).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task ProxyCommand_WithNetcat()
    {
        var netcat = new[] { "/usr/bin/nc", "/bin/nc" }.FirstOrDefault(File.Exists);
        if (netcat is null || WriteConfig($"Host via-command\n  HostName {RealServer.Endpoint?.Host}\n  ProxyCommand {netcat} %h %p") is not { } path)
        {
            Skip.Test("Needs nc and SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER, SSHSHARP_TEST_KEYDIR.");
            return;
        }

        await using var client = await SshClient.ConnectAsync("via-command", new SshConfigConnectOptions { Config = await SshConfig.LoadAsync(path) }, Timeout());
        var result = await client.RunCommandAsync("echo through-proxycommand", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("through-proxycommand\n");
    }
}
