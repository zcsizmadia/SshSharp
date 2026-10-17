using System.IO.Abstractions;
using System.Net;
using System.Security.Cryptography;
using SshSharp;
using SshSharp.IO.Abstractions;
using SshSharp.Scp;
using SshSharp.Sftp;

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
//   get <destination> <remote> <local>           SFTP download: times and permissions kept, progress, 4 parallel ranges, resumable
//   put <destination> <local> <remote>           SFTP upload of a file or directory: times and permissions kept, progress, resumable
//   tree <destination> <directory>               list a remote tree with code written against System.IO.Abstractions' IFileSystem
//   run-cng <destination> <key> <command>        run a command, logging in with a Windows CNG (TPM, smart card) key that never
//                                                leaves its store, through a signer that signs for logging in only
if (args.Length < 2)
{
    Console.Error.WriteLine("usage: <run|tail|shell|forward|socks|upload|download|get|put|tree|run-cng> <destination> [arguments]");
    return 2;
}

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};

// run-cng logs in with a key held in a Windows key store, in addition to the config's keys and the agent's.
using var cngKey = args is ["run-cng", _, var keyName, _] ? SshPrivateKey.FromSigner(new LoginOnlySigner(OpenCngKey(keyName)), keyName) : null;

await using var client = await SshClient.ConnectAsync(args[1], new SshConfigConnectOptions
{
    PrivateKeys = cngKey is null ? [] : [cngKey],
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
            Preserve = true,
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
        await client.DownloadFileAsync(args[2], args[3], new SshScpOptions { Preserve = true }, stop.Token);
        return 0;

    case "get" when args.Length == 4:
        await using (var sftp = await client.OpenSftpAsync(stop.Token))
        {
            // A partial file from an interrupted download is continued (Resume, as sftp's reget); a new one is fetched in parallel ranges
            // over several SFTP sessions (Segments), which helps on links with latency.
            var resume = File.Exists(args[3]);
            var options = new SftpTransferOptions { Preserve = true, Progress = ShowProgress(), Resume = resume, Segments = resume ? 1 : 4 };
            await sftp.DownloadFileAsync(args[2], args[3], options, stop.Token);
        }

        Console.WriteLine();
        return 0;

    case "put" when args.Length == 4:
        await using (var sftp = await client.OpenSftpAsync(stop.Token))
        {
            var options = new SftpTransferOptions { Preserve = true, Progress = ShowProgress() };
            if (Directory.Exists(args[2]))
            {
                var summary = await sftp.UploadDirectoryAsync(args[2], args[3], options, stop.Token);
                Console.WriteLine($"\n{summary.Files} files, {summary.Directories} directories, {summary.Bytes:N0} bytes ({summary.Skipped} skipped)");
            }
            else
            {
                // Resume: what the remote file already holds is taken as the start of this one, as sftp's reput does, so an interrupted
                // upload continues where it stopped (and a new one starts from the beginning).
                await sftp.UploadFileAsync(args[2], args[3], new SftpTransferOptions { Preserve = true, Progress = ShowProgress(), Resume = true }, stop.Token);
                Console.WriteLine();
            }
        }

        return 0;

    case "tree" when args.Length == 3:
        await using (var sftp = await client.OpenSftpAsync(stop.Token))
        {
            // Any code written against IFileSystem works on the server unchanged; on this machine it would take new FileSystem().
            PrintTree(new SftpFileSystem(sftp), args[2]);
        }

        return 0;

    case "run-cng" when args.Length == 4:
        var cngResult = await client.RunCommandAsync(args[3], stop.Token);
        Console.Write(cngResult.StandardOutputText);
        Console.Error.Write(cngResult.StandardErrorText);
        return cngResult.ExitStatus ?? 255;

    default:
        Console.Error.WriteLine($"Unknown command or wrong number of arguments: {args[0]}");
        return 2;
}

static IProgress<SftpTransferProgress> ShowProgress() => new Progress<SftpTransferProgress>(p =>
    Console.Write(p.TotalBytes is { } total ? $"\r{p.Path}: {p.BytesTransferred:N0} of {total:N0} bytes" : $"\r{p.Path}: {p.BytesTransferred:N0} bytes"));

static void PrintTree(IFileSystem fileSystem, string directory)
{
    long total = 0;
    foreach (var path in fileSystem.Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
    {
        var file = fileSystem.FileInfo.New(path);
        total += file.Length;
        Console.WriteLine($"{file.LastWriteTimeUtc:yyyy-MM-dd HH:mm}  {file.Length,12:N0}  {fileSystem.Path.GetRelativePath(directory, path)}");
    }

    Console.WriteLine($"{total:N0} bytes");
}

static RSA OpenCngKey(string name)
{
    if (!OperatingSystem.IsWindows())
    {
        throw new PlatformNotSupportedException("run-cng uses a Windows CNG key.");
    }

    // A persisted key in the user's store: the Microsoft Software Key Storage Provider by default, or the TPM (Microsoft Platform
    // Crypto Provider) or a smart card, when the key was created there. The private key stays in the store.
    return new RSACng(CngKey.Open(name));
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

/// <summary>
/// A key service's policy in miniature: this key signs for logging in, and nothing else (no SSH signatures over files, for example).
/// SshSharp says what each signature is for (<see cref="SshSignRequest.Purpose"/>); a signer for a cloud key service or an HSM would
/// call the service here instead.
/// </summary>
internal sealed class LoginOnlySigner(RSA rsa) : SshKeySigner(PublicKeyOf(rsa))
{
    public override ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken)
    {
        if (request.Purpose != SshSignaturePurpose.Authentication)
        {
            throw new UnauthorizedAccessException("This key signs for logging in only.");
        }

        var hash = request.Algorithm == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
        return ValueTask.FromResult(rsa.SignData(request.Data.Span, hash, RSASignaturePadding.Pkcs1));
    }

    private static ReadOnlyMemory<byte> PublicKeyOf(RSA rsa)
    {
        using var key = SshPrivateKey.FromRsa(rsa);
        return key.PublicKey.ToArray();
    }
}
