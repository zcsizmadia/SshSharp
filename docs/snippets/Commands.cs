using System.Text;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/run-a-command.md and docs/how-to/stream-output.md.</summary>
internal static class Commands
{
    public static async Task RunBasicAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <run-basic>
        var result = await client.RunCommandAsync("df -h /", cancellationToken);

        Console.WriteLine($"exit status: {result.ExitStatus}");    // null when the command was killed by a signal
        Console.WriteLine(result.StandardOutputText);              // stdout, decoded as UTF-8
        Console.Error.WriteLine(result.StandardErrorText);         // stderr, kept apart from stdout
        // </run-basic>
    }

    public static async Task RunCheckedAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <run-checked>
        var result = await client.RunCommandAsync("systemctl is-active nginx", cancellationToken);
        switch (result)
        {
            case { ExitStatus: 0 }:
                Console.WriteLine("nginx is running");
                break;
            case { ExitSignal: { } signal }:
                Console.WriteLine($"killed by SIG{signal.Name}{(signal.CoreDumped ? " (core dumped)" : "")}");
                break;
            default:
                Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText.Trim()}");
                break;
        }
        // </run-checked>
    }

    // <quote>
    /// <summary>Quotes one argument for a POSIX shell (sh, bash): single quotes, with each ' written as '\''.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    // </quote>

    public static async Task RunQuotedAsync(SshClient client, string userSuppliedPath, CancellationToken cancellationToken)
    {
        // <run-quoted>
        // The command line is parsed by the server's shell: quote anything you did not write yourself.
        var result = await client.RunCommandAsync($"ls -l -- {Quote(userSuppliedPath)}", cancellationToken);
        // </run-quoted>
        _ = result;
    }

    public static async Task RunBinaryAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <run-bytes>
        var result = await client.RunCommandAsync("cat /etc/machine-id | sha256sum", cancellationToken);
        ReadOnlyMemory<byte> raw = result.StandardOutput;           // the bytes, for output that is not UTF-8 text
        var text = Encoding.Latin1.GetString(raw.Span);
        // </run-bytes>
        _ = text;
    }

    public static async Task RunConcurrentAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <run-parallel>
        // One connection, three channels at once: each command gets its own session.
        var commands = new[] { "uptime", "free -m", "df -h /" };
        var results = await Task.WhenAll(commands.Select(c => client.RunCommandAsync(c, cancellationToken)));
        foreach (var (command, result) in commands.Zip(results))
        {
            Console.WriteLine($"$ {command}\n{result.StandardOutputText}");
        }
        // </run-parallel>
    }

    public static async Task StreamLinesAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stream-lines>
        await using var session = await client.StartCommandAsync("journalctl -f -u myapp", cancellationToken: cancellationToken);
        using var reader = new StreamReader(session.StandardOutput);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            Console.WriteLine(line);
        }
        // </stream-lines>
    }

    public static async Task StreamBothAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stream-both>
        await using var session = await client.StartCommandAsync("make test", cancellationToken: cancellationToken);

        // Read both streams at the same time: a stream nobody reads fills its window, and then the server stops sending on both.
        var stdout = PumpAsync(session.StandardOutput, Console.Out, cancellationToken);
        var stderr = PumpAsync(session.StandardError, Console.Error, cancellationToken);
        await Task.WhenAll(stdout, stderr);

        await session.WaitForExitAsync(cancellationToken);
        Console.WriteLine($"make exited with {session.ExitStatus}");

        static async Task PumpAsync(Stream source, TextWriter target, CancellationToken cancellationToken)
        {
            using var reader = new StreamReader(source);
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                await target.WriteLineAsync(line);
            }
        }
        // </stream-both>
    }

    public static async Task StreamToFileAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stream-to-file>
        // A database dump of any size, straight to disk: nothing is held in memory.
        await using var session = await client.StartCommandAsync("pg_dump --format=custom appdb", cancellationToken: cancellationToken);
        await using (var file = File.Create("appdb.dump"))
        {
            var errors = new StreamReader(session.StandardError).ReadToEndAsync(cancellationToken);
            await session.StandardOutput.CopyToAsync(file, cancellationToken);
            Console.Error.Write(await errors);
        }

        await session.WaitForExitAsync(cancellationToken);
        if (session.ExitStatus != 0)
        {
            throw new InvalidOperationException($"pg_dump failed with exit status {session.ExitStatus}.");
        }
        // </stream-to-file>
    }

    public static async Task StreamInputAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stream-input>
        await using var session = await client.StartCommandAsync("gzip -c > /tmp/backup.tar.gz", cancellationToken: cancellationToken);
        await using (var source = File.OpenRead("backup.tar"))
        {
            await source.CopyToAsync(session.StandardInput, cancellationToken);
        }

        await session.CloseInputAsync(cancellationToken);   // end of input: gzip finishes and exits
        await session.WaitForExitAsync(cancellationToken);
        // </stream-input>
    }

    public static async Task StopEarlyAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <stream-stop>
        await using var session = await client.StartCommandAsync("find / -name '*.log'", cancellationToken: cancellationToken);
        using var reader = new StreamReader(session.StandardOutput);
        var first = new List<string>();
        while (first.Count < 10 && await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            first.Add(line);
        }

        // Enough: ask the program to stop. Disposing the session (at the end of the block) closes the channel either way.
        await session.SendSignalAsync("TERM", cancellationToken);
        // </stream-stop>
    }
}
