using System.Text.RegularExpressions;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/interactive-shell.md.</summary>
internal static class Shells
{
    public static async Task TerminalAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <shell-terminal>
        await using var shell = await client.StartShellAsync(new SshSessionOptions
        {
            Terminal = new SshTerminalOptions { TerminalType = "xterm-256color", Columns = 120, Rows = 40 },
            Environment = new Dictionary<string, string> { ["LANG"] = "C.UTF-8" }, // only if sshd's AcceptEnv allows it
        }, cancellationToken);

        // Relay the shell to the console until it exits.
        var output = shell.StandardOutput.CopyToAsync(Console.OpenStandardOutput(), cancellationToken);
        await shell.StandardInput.WriteAsync("uname -a; exit\n"u8.ToArray(), cancellationToken);
        await output;
        // </shell-terminal>
    }

    public static async Task ResizeAsync(SshSession shell, CancellationToken cancellationToken)
    {
        // <shell-resize>
        await shell.ResizeTerminalAsync(columns: Console.WindowWidth, rows: Console.WindowHeight, cancellationToken: cancellationToken);
        await shell.StandardInput.WriteAsync(new byte[] { 0x03 }, cancellationToken); // Ctrl-C: interrupt the foreground program
        // </shell-resize>
    }

    public static async Task ExpectSudoAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <expect-sudo>
        // The password comes from the environment (or a secret store), never from source code.
        var sudoPassword = Environment.GetEnvironmentVariable("SUDO_PASSWORD")
            ?? throw new InvalidOperationException("Set SUDO_PASSWORD.");
        var prompt = new Regex(@"[$#] $", RegexOptions.None, TimeSpan.FromSeconds(1));

        await using var shell = await client.StartShellAsync(
            new SshSessionOptions { Terminal = new SshTerminalOptions { TerminalType = "dumb" } }, cancellationToken);
        var expect = new SshExpect(shell);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));                 // the whole conversation, not each step

        await expect.ExpectAsync(prompt, timeout.Token);                // the first prompt
        await expect.SendLineAsync("sudo systemctl restart myapp", timeout.Token);
        await expect.ExpectAsync("password", timeout.Token);           // "[sudo] password for user:"
        await expect.SendLineAsync(sudoPassword, timeout.Token);
        var done = await expect.ExpectAsync(prompt, timeout.Token);
        Console.WriteLine(done.Before);                                 // what the command printed
        await expect.SendLineAsync("exit", timeout.Token);
        // </expect-sudo>
    }

    public static async Task ExpectLinesAsync(SshExpect expect, CancellationToken cancellationToken)
    {
        // <expect-lines>
        // A marker line ends the output, since the prompt that follows has no line feed.
        await expect.SendLineAsync("ls -1 /etc/ssh; echo '--end--'", cancellationToken);
        await expect.ReadLineAsync(cancellationToken);                 // the terminal's echo of the command
        while (await expect.ReadLineAsync(cancellationToken) is { } line && line != "--end--")
        {
            Console.WriteLine(line);
        }
        // </expect-lines>
    }

    public static async Task ExpectGroupsAsync(SshExpect expect, CancellationToken cancellationToken)
    {
        // <expect-groups>
        await expect.SendLineAsync("df -P / | tail -1", cancellationToken);
        var match = await expect.ExpectAsync(new Regex(@"(\d+)%\s+/\r?\n", RegexOptions.None, TimeSpan.FromSeconds(1)), cancellationToken);
        var usedPercent = int.Parse(match.Match!.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        // </expect-groups>
        _ = usedPercent;
    }

    public static async Task NetworkDeviceAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <expect-device>
        // A router or switch CLI: no POSIX shell, so commands go through the interactive session.
        await using var cli = await client.StartShellAsync(
            new SshSessionOptions { Terminal = new SshTerminalOptions { TerminalType = "vt100", Columns = 200, Rows = 50 } }, cancellationToken);
        var expect = new SshExpect(cli);
        var prompt = new Regex(@"[>#]\s*$", RegexOptions.None, TimeSpan.FromSeconds(1));

        await expect.ExpectAsync(prompt, cancellationToken);
        await expect.SendLineAsync("terminal length 0", cancellationToken); // no --More-- paging
        await expect.ExpectAsync(prompt, cancellationToken);
        await expect.SendLineAsync("show version", cancellationToken);
        var version = await expect.ExpectAsync(prompt, cancellationToken);
        Console.WriteLine(version.Before);
        // </expect-device>
    }

    public static async Task SubsystemAsync(SshClient client, ReadOnlyMemory<byte> helloMessage, CancellationToken cancellationToken)
    {
        // <subsystem>
        await using var netconf = await client.StartSubsystemAsync("netconf", cancellationToken: cancellationToken);
        await netconf.StandardInput.WriteAsync(helloMessage, cancellationToken);
        // ... then read the server's hello from netconf.StandardOutput, framed as NETCONF frames it.
        // </subsystem>
    }
}
