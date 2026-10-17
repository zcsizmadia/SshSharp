using SshSharp;
using SshSharp.Config;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/getting-started.md and docs/tutorial.md: a small tool, built up step by step.</summary>
internal static class Tutorial
{
    public static async Task QuickStartAsync()
    {
        // <quick-start>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "user",
            Password = Environment.GetEnvironmentVariable("SSH_PASSWORD"),      // from the environment, not the source code
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.AcceptNew),
        });

        var result = await client.RunCommandAsync("uname -a");
        Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
        // </quick-start>
    }

    public static async Task<int> Step1Async(string[] args)
    {
        // <step1>
        // Program.cs: dotnet run -- <host> <user>
        var (host, user) = (args[0], args[1]);
        var agent = SshAgent.FromEnvironment();
        var keys = agent is null ? [] : await agent.GetKeysAsync();

        await using var client = await SshClient.ConnectAsync(host, 22, new SshClientOptions
        {
            UserName = user,
            PrivateKeys = keys,
            Password = Environment.GetEnvironmentVariable("SSH_PASSWORD"),      // tried after the keys, if set
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
        });

        Console.WriteLine($"Connected to {client.ServerIdentification}, host key {client.HostKey.Fingerprint}");
        return 0;
        // </step1>
    }

    public static SshHostKeyVerifier Step2()
    {
        // <step2>
        var verifier = new KnownHostsVerifier([Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "known_hosts")])
        {
            Policy = StrictHostKeyChecking.Ask,
            AskHostKey = (prompt, ct) =>
            {
                Console.WriteLine($"The authenticity of host '{prompt.Context.Host}' can't be established.");
                Console.WriteLine($"{prompt.Context.HostKey.KeyType} key fingerprint is {prompt.Context.HostKey.Fingerprint}.");
                Console.Write("Are you sure you want to continue connecting (yes/no)? ");
                return ValueTask.FromResult(Console.ReadLine()?.Trim() == "yes");   // accepted keys are added to known_hosts
            },
        };
        // </step2>
        return verifier;
    }

    public static async Task Step3Async(SshClient client)
    {
        // <step3>
        var checks = new Dictionary<string, string>
        {
            ["uptime"] = "uptime",
            ["disk"] = "df -h / | tail -1",
            ["memory"] = "free -m | sed -n 2p",
        };

        foreach (var (name, command) in checks)
        {
            var result = await client.RunCommandAsync(command);
            var text = result.ExitStatus == 0 ? result.StandardOutputText.Trim() : $"failed ({result.ExitStatus}): {result.StandardErrorText.Trim()}";
            Console.WriteLine($"{name,-8} {text}");
        }
        // </step3>
    }

    public static async Task Step4Async(SshClient client)
    {
        // <step4>
        await using var sftp = await client.OpenSftpAsync();
        var report = $"report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.txt";
        await File.WriteAllTextAsync(report, "collected by the tutorial tool\n");
        await sftp.UploadFileAsync(report, $"reports/{report}", new SftpTransferOptions { Overwrite = false });
        Console.WriteLine($"Uploaded {report}");
        // </step4>
    }

    public static async Task<int> Step5Async(string host, SshClientOptions options)
    {
        // <step5>
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };   // Ctrl-C cancels cleanly

        try
        {
            await using var client = await SshClient.ConnectAsync(host, 22, options, cts.Token);
            var result = await client.RunCommandAsync("uptime", cts.Token);
            Console.WriteLine(result.StandardOutputText);
            return result.ExitStatus ?? 1;
        }
        catch (SshHostKeyException ex)
        {
            Console.Error.WriteLine($"Refusing to connect: {ex.Message}");
        }
        catch (SshAuthenticationException ex)
        {
            Console.Error.WriteLine($"Login failed. The server accepts: {string.Join(", ", ex.AllowedMethods)}");
        }
        catch (SshException ex)
        {
            Console.Error.WriteLine($"{ex.Reason}: {ex.Message}");
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Timed out or cancelled.");
        }

        return 2;
        // </step5>
    }
}
