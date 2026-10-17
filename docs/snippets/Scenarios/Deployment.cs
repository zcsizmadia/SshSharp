using SshSharp;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/deployment-script.md.</summary>
internal static class Deployment
{
    // <deploy>
    /// <summary>
    /// Uploads a release, unpacks it next to the previous ones, switches the "current" link atomically, restarts the service and
    /// checks its health; on a failed health check, switches back.
    /// </summary>
    public static async Task<bool> DeployAsync(string host, string archive, string version, CancellationToken cancellationToken)
    {
        const string root = "/srv/myapp";
        var release = $"{root}/releases/{version}";
        var upload = $"{root}/incoming/{version}.tar.gz";

        // By ssh_config alias: the bastion (ProxyJump), the deploy key and known_hosts all come from the configuration.
        await using var client = await SshClient.ConnectAsync(host, cancellationToken: cancellationToken);
        await using var sftp = await client.OpenSftpAsync(cancellationToken);

        // 1. Upload. Resume makes a retry after a dropped connection send only the rest.
        await sftp.UploadFileAsync(archive, upload, new SftpTransferOptions
        {
            Resume = true,
            Progress = new Progress<SftpTransferProgress>(p => Console.Write($"\rupload {p.BytesTransferred * 100 / Math.Max(1, p.TotalBytes ?? 1)}%")),
        }, cancellationToken);
        Console.WriteLine();

        // 2. Unpack beside the other releases.
        await RunAsync(client, $"mkdir -p {Quote(release)} && tar -xzf {Quote(upload)} -C {Quote(release)} && rm -f {Quote(upload)}", cancellationToken);

        // 3. Switch: a new link, renamed over the old one, so "current" always points at a complete release.
        var previous = await sftp.ReadSymbolicLinkAsync($"{root}/current", cancellationToken);
        await SwitchAsync(sftp, root, release, cancellationToken);

        // 4. Restart and check, through the same connection: "localhost" is the server's own loopback.
        await RunAsync(client, "sudo systemctl restart myapp", cancellationToken);
        if (await IsHealthyAsync(client, cancellationToken))
        {
            Console.WriteLine($"{host}: {version} is live");
            return true;
        }

        // 5. Roll back.
        Console.Error.WriteLine($"{host}: {version} failed its health check; rolling back to {previous}");
        await SwitchAsync(sftp, root, previous, cancellationToken);
        await RunAsync(client, "sudo systemctl restart myapp", cancellationToken);
        return false;
    }

    private static async Task SwitchAsync(SftpClient sftp, string root, string target, CancellationToken cancellationToken)
    {
        var next = $"{root}/current.next";
        if (await sftp.ExistsAsync(next, cancellationToken))
        {
            await sftp.DeleteFileAsync(next, cancellationToken);
        }

        await sftp.CreateSymbolicLinkAsync(next, target, cancellationToken);
        await sftp.RenameAsync(next, $"{root}/current", overwrite: true, cancellationToken);   // rename(2): atomic
    }

    private static async Task<bool> IsHealthyAsync(SshClient client, CancellationToken cancellationToken)
    {
        using var http = new HttpClient(new SocketsHttpHandler { ConnectCallback = client.CreateHttpConnectCallback(), UseProxy = false })
        {
            Timeout = TimeSpan.FromSeconds(5),
        };

        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                using var response = await http.GetAsync(new Uri("http://localhost:8080/health"), cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch (HttpRequestException)
            {
                // Not listening yet.
            }

            await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
        }

        return false;
    }

    /// <summary>Runs a command and throws, with its stderr, when it fails.</summary>
    private static async Task RunAsync(SshClient client, string command, CancellationToken cancellationToken)
    {
        var result = await client.RunCommandAsync(command, cancellationToken);
        if (result.ExitStatus != 0)
        {
            throw new InvalidOperationException($"'{command}' failed with exit status {result.ExitStatus}: {result.StandardErrorText.Trim()}");
        }
    }

    private static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    // </deploy>

    public static async Task<int> MainAsync(string[] args)
    {
        // <deploy-main>
        // deploy <version> <archive> <host>...: one host after another, stopping at the first failure.
        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

        var (version, archive, hosts) = (args[0], args[1], args[2..]);
        foreach (var host in hosts)
        {
            if (!await DeployAsync(host, archive, version, cancel.Token))
            {
                return 1;   // the rest of the fleet keeps the old version
            }
        }

        return 0;
        // </deploy-main>
    }
}
