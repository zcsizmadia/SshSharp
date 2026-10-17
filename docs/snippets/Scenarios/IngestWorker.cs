using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshSharp;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/background-worker.md.</summary>
internal static class IngestWorkerProgram
{
    public static async Task MainAsync(string[] args)
    {
        // <program>
        // Program.cs
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSshClient("partner")
            .BindConfiguration("Ssh:Partner")
            .ValidateOnStart();
        builder.Services.AddHostedService<IngestWorker>();
        await builder.Build().RunAsync();
        // </program>
    }
}

// <worker>
/// <summary>Every few minutes, downloads new files from a partner's outbox and moves them to "done" on the server.</summary>
internal sealed class IngestWorker(ISshConnectionProvider connections, IConfiguration configuration, ILogger<IngestWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var inbox = configuration["Ingest:LocalDirectory"] ?? "inbox";
        Directory.CreateDirectory(inbox);
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5));
        do
        {
            try
            {
                var count = await RunOnceAsync(inbox, stoppingToken);
                logger.LogInformation("Fetched {Count} files", count);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is SshException or IOException or TimeoutException)
            {
                // The connection dropped or could not be opened; the provider opens a new one on the next run, backing off
                // after failures. Files not yet moved to "done" are fetched again then.
                logger.LogWarning(ex, "Fetching failed; trying again at the next run");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task<int> RunOnceAsync(string inbox, CancellationToken cancellationToken)
    {
        var client = await connections.GetClientAsync("partner", cancellationToken);   // shared, reconnecting: do not dispose
        await using var sftp = await client.OpenSftpAsync(cancellationToken);          // a session per run

        var count = 0;
        await foreach (var entry in sftp.ListDirectoryAsync("outbox", cancellationToken))
        {
            if (!entry.Attributes.IsRegularFile || entry.Name.EndsWith(".partial", StringComparison.Ordinal))
            {
                continue;   // still being written by the partner
            }

            var local = Path.Combine(inbox, Path.GetFileName(entry.Name));
            await sftp.DownloadFileAsync(entry.FullPath, local, new SftpTransferOptions { Preserve = true }, cancellationToken);
            await sftp.RenameAsync(entry.FullPath, $"done/{entry.Name}", overwrite: true, cancellationToken);
            count++;
        }

        return count;
    }
}
// </worker>
