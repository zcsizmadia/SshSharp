using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/fips-mode.md and docs/how-to/native-aot.md.</summary>
internal static class Platform
{
    public static async Task FipsAsync(CancellationToken cancellationToken)
    {
        // <fips>
        using var key = await SshPrivateKey.LoadAsync("id_ecdsa", cancellationToken: cancellationToken);   // ECDSA or RSA: Ed25519 is not FIPS-approved
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            FipsMode = true,
        }, cancellationToken);

        // For an audit log: what was negotiated.
        var a = client.Algorithms;
        Console.WriteLine($"{a.KeyExchange}, {a.HostKeyAlgorithm}, {a.EncryptionClientToServer}, {a.MacClientToServer}");
        // </fips>
    }

    public static async Task FipsScanAsync(CancellationToken cancellationToken)
    {
        // <fips-scan>
        // Which FIPS-approved host keys does a server have? (none means FipsMode cannot connect to it)
        var keys = await SshClient.ScanHostKeysAsync("example.com", options: new SshHostKeyScanOptions { FipsMode = true },
            cancellationToken: cancellationToken);
        // </fips-scan>
        _ = keys;
    }

    public static async Task<int> AotMainAsync(string[] args)
    {
        // <aot>
        // Program.cs of an app published with <PublishAot>true</PublishAot>: nothing AOT-specific in the code.
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        await using var client = await SshClient.ConnectAsync(args[0], cancellationToken: stop.Token);
        var result = await client.RunCommandAsync(args[1], stop.Token);
        Console.Write(result.StandardOutputText);
        return result.ExitStatus ?? 255;
        // </aot>
    }
}
