using System.Diagnostics;

namespace SshSharp.Config;

/// <summary>
/// Runs <c>Match exec</c> commands. Running commands named in a config file is how OpenSSH works, but it executes local
/// programs, so <see cref="SshConfigResolveOptions.ExecMatcher"/> is null by default (exec criteria never match) and you opt in with
/// <see cref="RunShellAsync"/> only for config files you trust.
/// </summary>
public static class SshExecMatcher
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Runs <paramref name="command"/> with the system shell and completes with whether it exited with status 0. Gives up (and
    /// kills the command) after 30 seconds or when <paramref name="cancellationToken"/> is cancelled.
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public static async Task<bool> RunShellAsync(string command, CancellationToken cancellationToken = default)
    {
        using var process = Start(command);

        // Stryker disable once Block,Boolean : without shell execute, Process.Start returns a process or throws
        if (process is null)
        {
            return false;
        }

        using var timeout = new CancellationTokenSource(Limit);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            return process.ExitCode == 0;
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            cancellationToken.ThrowIfCancellationRequested();
            return false; // the 30 seconds ran out
        }
    }

    private static Process? Start(string command)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        var windows = OperatingSystem.IsWindows();
        var info = new ProcessStartInfo(windows ? "cmd.exe" : "/bin/sh")
        {
            UseShellExecute = false,

            // Stryker disable once Boolean : a console window is not something a test can see
            CreateNoWindow = true,
            RedirectStandardInput = true,

            // Like OpenSSH (stdout to /dev/null): the command must not write into the host application's own output.
            RedirectStandardOutput = true,
        };

        if (windows)
        {
            // cmd.exe does not follow the C runtime's quoting rules that ArgumentList applies; "/s /c "..."" passes the command
            // through verbatim (cmd strips the outer quotes).
            info.Arguments = "/d /s /c \"" + command + "\"";
        }
        else
        {
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add(command);
        }

        var process = Process.Start(info);

        // Stryker disable once Block : as above, Process.Start does not return null here
        if (process is null)
        {
            return null;
        }

        process.StandardInput.Close();

        // Stryker disable once Assignment : the output is read and dropped with or without a handler
        process.OutputDataReceived += static (_, _) => { };
        process.BeginOutputReadLine();
        return process;
    }
}
