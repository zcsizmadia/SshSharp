using System.Net;
using SshSharp;
using SshSharp.Scp;

// A small ssh-like tool built on SshSharp. The destination is resolved with ~/.ssh/config and known_hosts, as ssh does: an alias,
// user@host, or ssh://user@host:port. Keys come from the config and the agent; a password, if the server wants one, from
// SSHSHARP_PASSWORD.
//
//   run <destination> <command>                  run a command, print its output, exit with its status
//   tail <destination> <file>                    stream a growing file (Ctrl+C stops)
//   shell <destination>                          a line-based shell with a pseudo-terminal
//   forward <destination> <port> <host> <port>   ssh -L: forward a local port until Ctrl+C
//   socks <destination> <port>                   ssh -D: a SOCKS proxy on a local port until Ctrl+C
//   upload <destination> <local> <remote>        SCP a file or directory to the server
//   download <destination> <remote> <local>      SCP a file from the server
if (args.Length < 2)
{
    Console.Error.WriteLine("usage: <run|tail|shell|forward|socks|upload|download> <destination> [arguments]");
    return 2;
}

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};

await using var client = await SshClient.ConnectAsync(args[1], new SshConfigConnectOptions
{
    Password = Environment.GetEnvironmentVariable("SSHSHARP_PASSWORD"),
    PassphraseProvider = (path, _) => ValueTask.FromResult(ReadSecret($"Passphrase for {Path.GetFileName(path)}: ")),
    AskHostKey = (prompt, _) => ValueTask.FromResult(Confirm(
        $"The authenticity of host '{prompt.Context.Host}' can't be established.\n{prompt.Context.HostKey.KeyType} key fingerprint is {prompt.Context.HostKey.Fingerprint}.\nContinue connecting?")),
}, stop.Token);

switch (args[0])
{
    case "run" when args.Length == 3:
        var result = await client.RunCommandAsync(args[2], stop.Token);
        Console.Write(result.StandardOutputText);
        Console.Error.Write(result.StandardErrorText);
        return result.ExitStatus ?? 255;

    case "tail" when args.Length == 3:
        await using (var session = await client.StartCommandAsync($"tail -f '{args[2].Replace("'", "'\\''", StringComparison.Ordinal)}'", cancellationToken: stop.Token))
        {
            using var reader = new StreamReader(session.StandardOutput);
            try
            {
                while (await reader.ReadLineAsync(stop.Token) is { } line)
                {
                    Console.WriteLine(line);
                }
            }
            catch (OperationCanceledException)
            {
                // Ctrl+C: disposing the session closes the channel, and the server stops tail.
            }
        }

        return 0;

    case "shell" when args.Length == 2:
        await using (var shell = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions { TerminalType = "dumb" } }, stop.Token))
        {
            // Output and input in parallel: the shell writes prompts and output whenever it likes.
            var output = shell.StandardOutput.CopyToAsync(Console.OpenStandardOutput(), stop.Token);
            using var input = new StreamWriter(shell.StandardInput) { AutoFlush = true };
            while (!output.IsCompleted && Console.ReadLine() is { } line)
            {
                await input.WriteLineAsync(line);
            }

            await shell.CloseInputAsync(stop.Token);
            await output;
            await shell.WaitForExitAsync(stop.Token);
            return shell.ExitStatus ?? 255;
        }

    case "forward" when args.Length == 5:
        await using (var forward = await client.ForwardLocalPortAsync(
            new IPEndPoint(IPAddress.Loopback, int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture)),
            args[3], int.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture), stop.Token))
        {
            Console.WriteLine($"Forwarding {forward.LocalEndPoint} to {forward.RemoteHost}:{forward.RemotePort}; Ctrl+C stops.");
            await WaitAsync(stop.Token);
        }

        return 0;

    case "socks" when args.Length == 3:
        await using (var proxy = await client.ForwardDynamicPortAsync(
            new IPEndPoint(IPAddress.Loopback, int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture)), stop.Token))
        {
            Console.WriteLine($"SOCKS proxy on {proxy.LocalEndPoint}; Ctrl+C stops.");
            await WaitAsync(stop.Token);
        }

        return 0;

    case "upload" when args.Length == 4:
        var progress = new SshScpOptions
        {
            PreserveTimes = true,
            Progress = new Progress<SshScpProgress>(p => Console.Write($"\r{p.Path}: {p.BytesTransferred:N0} of {p.TotalBytes:N0} bytes")),
        };
        if (Directory.Exists(args[2]))
        {
            await client.UploadDirectoryAsync(args[2], args[3], progress, stop.Token);
        }
        else
        {
            await client.UploadFileAsync(args[2], args[3], progress, stop.Token);
        }

        Console.WriteLine();
        return 0;

    case "download" when args.Length == 4:
        await client.DownloadFileAsync(args[2], args[3], new SshScpOptions { PreserveTimes = true }, stop.Token);
        return 0;

    default:
        Console.Error.WriteLine($"Unknown command or wrong number of arguments: {args[0]}");
        return 2;
}

static async Task WaitAsync(CancellationToken cancellationToken)
{
    try
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
    }
    catch (OperationCanceledException)
    {
    }
}

static bool Confirm(string question)
{
    Console.Error.Write($"{question} (yes/no) ");
    return string.Equals(Console.ReadLine()?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
}

static string? ReadSecret(string prompt)
{
    Console.Error.Write(prompt);
    var secret = new System.Text.StringBuilder();
    while (Console.ReadKey(intercept: true) is { Key: not ConsoleKey.Enter } key)
    {
        if (key.Key == ConsoleKey.Backspace && secret.Length > 0)
        {
            secret.Length--;
        }
        else if (!char.IsControl(key.KeyChar))
        {
            secret.Append(key.KeyChar);
        }
    }

    Console.Error.WriteLine();
    return secret.Length > 0 ? secret.ToString() : null;
}
