using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/unit-testing.md.</summary>
internal static class Testing
{
    // <seam>
    /// <summary>The few remote operations the application needs: the seam tests replace.</summary>
    public interface IRemoteShell
    {
        Task<RemoteResult> RunAsync(string command, CancellationToken cancellationToken);
    }

    public sealed record RemoteResult(int? ExitStatus, string Output, string Error);

    /// <summary>The production implementation: a thin wrapper over SshSharp, too small to need tests of its own.</summary>
    public sealed class SshRemoteShell(SshClient client) : IRemoteShell
    {
        public async Task<RemoteResult> RunAsync(string command, CancellationToken cancellationToken)
        {
            var result = await client.RunCommandAsync(command, cancellationToken);
            return new RemoteResult(result.ExitStatus, result.StandardOutputText, result.StandardErrorText);
        }
    }
    // </seam>

    // <logic>
    /// <summary>The logic worth testing: it depends on the seam, not on SSH.</summary>
    public sealed class DiskMonitor(IRemoteShell shell)
    {
        public async Task<bool> IsAlmostFullAsync(string mount, CancellationToken cancellationToken)
        {
            var result = await shell.RunAsync($"df -P {Commands.Quote(mount)} | tail -1", cancellationToken);
            if (result.ExitStatus != 0)
            {
                throw new InvalidOperationException($"df failed: {result.Error.Trim()}");
            }

            var usedPercent = int.Parse(result.Output.Split(' ', StringSplitOptions.RemoveEmptyEntries)[4].TrimEnd('%'),
                System.Globalization.CultureInfo.InvariantCulture);
            return usedPercent >= 90;
        }
    }
    // </logic>

    // <fake>
    /// <summary>A scripted fake: answers by command, and records what was run.</summary>
    public sealed class FakeRemoteShell(Dictionary<string, RemoteResult> answers) : IRemoteShell
    {
        public List<string> Commands { get; } = [];

        public Task<RemoteResult> RunAsync(string command, CancellationToken cancellationToken)
        {
            Commands.Add(command);
            return Task.FromResult(answers.TryGetValue(command, out var answer) ? answer : new RemoteResult(127, "", "command not found"));
        }
    }
    // </fake>

    public static async Task TestAsync()
    {
        // <test>
        // In a test (any framework): no server, no network.
        var shell = new FakeRemoteShell(new()
        {
            ["df -P '/var' | tail -1"] = new(0, "/dev/sda1 1000 950 50 95% /var\n", ""),
        });

        var almostFull = await new DiskMonitor(shell).IsAlmostFullAsync("/var", CancellationToken.None);

        if (!almostFull || shell.Commands.Count != 1)
        {
            throw new InvalidOperationException("Expected a full disk after one command.");   // Assert.That(...) in your framework
        }
        // </test>
    }

    public static void ConfigTest()
    {
        // <config-test>
        // ssh_config logic is testable without files or a network: parse a string, resolve with a fixed home and user.
        var config = SshConfig.Parse("""
            Host app-*
              User deploy
              ProxyJump bastion.example.com
            """);
        var resolved = config.Resolve("app-7", new SshConfigResolveOptions { HomeDirectory = "/home/test", LocalUser = "test" });

        if (resolved.User != "deploy" || resolved.ProxyJump is not ["bastion.example.com"])
        {
            throw new InvalidOperationException("The configuration does not route app hosts through the bastion.");
        }
        // </config-test>
    }

    public static async Task VerifierTestAsync()
    {
        // <known-hosts-test>
        // known_hosts content, checked in memory.
        byte[] key = [0, 0, 0, 11, .. "ssh-ed25519"u8, 0, 0, 0, 32, .. new byte[32]];
        var file = KnownHostsFile.Parse($"app1.example.com ssh-ed25519 {Convert.ToBase64String(key)}\n");

        var result = file.Check("app1.example.com", 22, "ssh-ed25519", key);   // KnownHostsCheckResult.Match
        // </known-hosts-test>
        await Task.CompletedTask;
        _ = result;
    }
}
