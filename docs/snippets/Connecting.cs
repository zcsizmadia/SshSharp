using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/jump-hosts.md, docs/how-to/ssh-config-and-known-hosts.md and docs/connecting.md.</summary>
internal static class Connecting
{
    public static async Task AliasAsync(CancellationToken cancellationToken)
    {
        // <alias>
        // Everything comes from ~/.ssh/config: HostName, User, IdentityFile, ProxyJump, known_hosts, ...
        await using var client = await SshClient.ConnectAsync("prod-db", cancellationToken: cancellationToken);

        // The other destination forms ssh accepts.
        await using var other = await SshClient.ConnectAsync("deploy@build.example.com", cancellationToken: cancellationToken);
        await using var third = await SshClient.ConnectAsync("ssh://deploy@build.example.com:2222", cancellationToken: cancellationToken);
        // </alias>
    }

    public static async Task AliasOptionsAsync(CancellationToken cancellationToken)
    {
        // <alias-options>
        await using var client = await SshClient.ConnectAsync("prod-db", new SshConfigConnectOptions
        {
            // Encrypted IdentityFile keys: the passphrase from a secret store or the environment, never from source code.
            PassphraseProvider = (path, ct) =>
                ValueTask.FromResult(Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE")),
            // StrictHostKeyChecking ask: decide about an unknown host key.
            AskHostKey = (prompt, ct) =>
                ValueTask.FromResult(Confirm($"Trust {prompt.Context.HostKey.KeyType} {prompt.Context.HostKey.Fingerprint}?")),
            // A configuration that names a ProxyCommand runs a local program: refuse it unless the file is trusted.
            AllowProxyCommand = false,
        }, cancellationToken);
        // </alias-options>
    }

    public static async Task AliasOverridesAsync(CancellationToken cancellationToken)
    {
        // <alias-overrides>
        // ssh_config decides the rest; these win over what it says, as ssh -p and ssh -o do.
        await using var client = await SshClient.ConnectAsync("prod-db", new SshConfigConnectOptions
        {
            Port = 2222,                                  // the destination's port (ssh -p); not a ProxyJump hop's
            ConnectTimeout = TimeSpan.FromSeconds(15),    // per host, from loading keys through authentication
            ConnectionAttempts = 3,                       // try an unreachable server again, one second apart
            AddressFamily = SshAddressFamily.Inet,        // IPv4 only, for the connection this machine makes
            KeepAliveInterval = TimeSpan.FromSeconds(30), // TimeSpan.Zero turns keep-alives off
            KeepAliveCountMax = 4,
        }, cancellationToken);
        // </alias-overrides>
    }

    public static async Task CustomConfigAsync(CancellationToken cancellationToken)
    {
        // <custom-config>
        // A configuration that ships with the application, instead of the user's ~/.ssh/config.
        var config = SshConfig.Parse("""
            Host bastion
              HostName bastion.example.com
              User jump
              IdentityFile ~/.ssh/fleet_ed25519

            Host app-*
              ProxyJump bastion
              User deploy
              IdentityFile ~/.ssh/fleet_ed25519
              UserKnownHostsFile /etc/myapp/known_hosts
              StrictHostKeyChecking yes
              ServerAliveInterval 30
            """);

        await using var client = await SshClient.ConnectAsync("app-3", new SshConfigConnectOptions { Config = config }, cancellationToken);
        // </custom-config>
    }

    public static async Task ManualJumpAsync(SshPrivateKey key, SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <manual-jump>
        // The bastion: an ordinary connection.
        await using var bastion = await SshClient.ConnectAsync("bastion.example.com", 22, new SshClientOptions
        {
            UserName = "jump",
            PrivateKeys = [key],
            HostKeyVerifier = verifier,
        }, cancellationToken);

        // A tunnel from the bastion to the target's SSH port, and a second SSH connection over it. The target's host key is
        // verified as always; HostKeyAlias names it in known_hosts, since this connection has no host name of its own.
        var tunnel = await bastion.OpenTcpTunnelAsync("app1.internal", 22, cancellationToken);
        await using var target = await SshClient.ConnectAsync(tunnel, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyAlias = "app1.internal",
            HostKeyVerifier = verifier,
        }, leaveOpen: false, cancellationToken);

        var result = await target.RunCommandAsync("hostname", cancellationToken);
        // </manual-jump>
        _ = result;
    }

    public static async Task JumpHostsAsync(SshPrivateKey bastionKey, SshPrivateKey deployKey, string bastionFingerprint, CancellationToken cancellationToken)
    {
        // <jump-hosts>
        // The destination: its own user, key and host key check, which the bastion is never offered.
        await using var client = await SshClient.ConnectAsync("app1.internal", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [deployKey],
            HostKeyVerifier = new KnownHostsVerifier([Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "known_hosts")]),
            ConnectTimeout = TimeSpan.FromSeconds(30), // the whole chain: every hop and the destination

            // First to last: each hop logs in and is verified with its own options.
            JumpHosts =
            [
                new SshJumpHost("bastion.example.com", 22, new SshClientOptions
                {
                    UserName = "jump",
                    PrivateKeys = [bastionKey],
                    HostKeyVerifier = SshHostKeyVerifier.Pinned(bastionFingerprint),
                    HostKeyAlgorithms = SshAlgorithmList.Only("ssh-ed25519"), // any client option, for this hop alone
                }),
            ],
        }, cancellationToken);

        var result = await client.RunCommandAsync("hostname", cancellationToken);
        // </jump-hosts>
        _ = result;
    }

    /// <summary>A tunnel service the application already has, such as a cloud provider's (#237).</summary>
    public interface ITunnelService
    {
        Task<Stream> OpenAsync(string host, int port, CancellationToken cancellationToken);
    }

    public static async Task CustomProxyAsync(ITunnelService tunnels, SshPrivateKey key, SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <custom-proxy>
        // Any transport that returns a connected stream: it is asked for the first network hop (here, the server itself).
        var proxy = SshProxy.FromConnector(async (host, port, ct) => await tunnels.OpenAsync(host, port, ct));

        await using var client = await SshClient.ConnectAsync("app1.internal", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = verifier, // the tunnel is not trusted: the server's key is checked as always
            Proxy = proxy,
        }, cancellationToken);
        // </custom-proxy>
        _ = client;
    }

    public static async Task ScanThroughJumpAsync(SshClient bastion, CancellationToken cancellationToken)
    {
        // <scan-jump>
        var keys = await SshClient.ScanHostKeysAsync(
            ct => new ValueTask<Stream>(bastion.OpenTcpTunnelAsync("app1.internal", 22, ct)), cancellationToken: cancellationToken);
        // </scan-jump>
        _ = keys;
    }

    public static void Resolve()
    {
        // <resolve>
        var config = SshConfig.LoadDefault();                 // ~/.ssh/config, then the system-wide file
        SshHostConfig host = config.Resolve("prod-db");        // what ssh -G prod-db prints
        Console.WriteLine($"{host.User}@{host.HostName}:{host.Port}");
        Console.WriteLine($"via {string.Join(" -> ", host.ProxyJump)}");
        Console.WriteLine($"keys {string.Join(", ", host.IdentityFiles)}");
        Console.WriteLine($"StrictHostKeyChecking {host.StrictHostKeyChecking}");
        // </resolve>
    }

    public static async Task KnownHostsAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <known-hosts>
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "known_hosts");
        var knownHosts = await KnownHostsFile.LoadAsync(path, cancellationToken);

        switch (knownHosts.Check("example.com", 22, client.HostKey.KeyType, client.HostKey.PublicKey.Span))
        {
            case KnownHostsCheckResult.Match:
                Console.WriteLine("known");
                break;
            case KnownHostsCheckResult.Unknown:
                await KnownHostsFile.AppendAsync(path, "example.com", 22, client.HostKey.KeyType, client.HostKey.PublicKey, hash: true,
                    cancellationToken: cancellationToken);
                break;
            case KnownHostsCheckResult.Changed or KnownHostsCheckResult.Revoked:
                throw new InvalidOperationException("The host key does not match known_hosts.");
        }
        // </known-hosts>
    }

    public static async Task AddressFamilyAsync(IReadOnlyList<SshPrivateKey> keys, SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <address-family>
        // Only the server's IPv4 addresses are tried (ssh -4, AddressFamily inet): for a network whose IPv6 route is broken.
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = keys,
            HostKeyVerifier = verifier,
            AddressFamily = SshAddressFamily.Inet,       // or Inet6; Any (the default) tries every address
            ConnectTimeout = TimeSpan.FromSeconds(15),
        }, cancellationToken);
        // </address-family>
    }

    public static SshHostKeyVerifier VerifierFromConfig()
    {
        // <verifier-from-config>
        // The verifier ssh would use for this host: its known_hosts files, StrictHostKeyChecking, HashKnownHosts, RevokedHostKeys ...
        var host = SshConfig.LoadDefault().Resolve("prod-db");
        var verifier = KnownHostsVerifier.FromConfig(host);
        // </verifier-from-config>
        return verifier;
    }

    private static bool Confirm(string question)
    {
        Console.Write($"{question} (yes/no) ");
        return string.Equals(Console.ReadLine(), "yes", StringComparison.OrdinalIgnoreCase);
    }
}
