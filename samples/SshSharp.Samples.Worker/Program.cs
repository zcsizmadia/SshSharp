using SshSharp;
using SshSharp.Extensions.DependencyInjection;

// A worker service that follows a log file on an SSH server (tail -F) and logs each line, for as long as it runs. The connection is
// the shared one from SshSharp.Extensions.DependencyInjection: when it drops, the worker waits a moment and starts again on a new one.
// The server is the "Ssh:Server" section of appsettings.json; the file is "Tail:File".
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSshClient("server").BindConfiguration("Ssh:Server").ValidateOnStart();
builder.Services.AddHostedService<RemoteLogFollower>();
await builder.Build().RunAsync();

/// <summary>Follows a remote file, line by line, across dropped connections.</summary>
internal sealed partial class RemoteLogFollower(ISshConnectionProvider connections, IConfiguration configuration, ILogger<RemoteLogFollower> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var file = configuration["Tail:File"] ?? "/var/log/syslog";
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var client = await connections.GetClientAsync("server", stoppingToken);

                // tail -F follows the file by name, so it carries on after the log is rotated; -n 0 starts at its end.
                await using var session = await client.StartCommandAsync($"tail -n 0 -F {Quote(file)}", cancellationToken: stoppingToken);
                using var reader = new StreamReader(session.StandardOutput);
                while (await reader.ReadLineAsync(stoppingToken) is { } line)
                {
                    LogLine(file, line);
                }

                LogEnded(file); // tail exited (the file's directory went away, say): start it again
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is SshException or IOException or TimeoutException)
            {
                // The connection dropped, or could not be opened. The provider opens a new one on the next call, waiting longer after
                // each failure, so this loop does not hammer a server that is down.
                LogInterrupted(ex, file);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }
    }

    /// <summary>Quotes a value for the remote POSIX shell.</summary>
    private static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    [LoggerMessage(Level = LogLevel.Information, Message = "{File}: {Line}")]
    private partial void LogLine(string file, string line);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Following {File} ended; starting again")]
    private partial void LogEnded(string file);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Following {File} was interrupted; starting again")]
    private partial void LogInterrupted(Exception exception, string file);
}
