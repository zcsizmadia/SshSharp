using System.Diagnostics;

namespace SshSharp.Config;

/// <summary>
/// Runs <c>Match exec</c> commands. Running commands named in a config file is how OpenSSH works, but it executes local
/// programs, so <see cref="SshConfigResolveOptions.ExecMatcher"/> is null by default (exec criteria never match) and you opt in with
/// <see cref="RunShell"/> only for config files you trust.
/// </summary>
public static class SshExecMatcher
{
    /// <summary>Runs <paramref name="command"/> with the system shell and returns whether it exited with status 0. Gives up after 30 seconds.</summary>
    public static bool RunShell(string command)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        var windows = OperatingSystem.IsWindows();
        var info = new ProcessStartInfo(windows ? "cmd.exe" : "/bin/sh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
        };
        info.ArgumentList.Add(windows ? "/c" : "-c");
        info.ArgumentList.Add(command);

        using var process = Process.Start(info);
        if (process is null)
        {
            return false;
        }

        process.StandardInput.Close();
        if (process.WaitForExit(TimeSpan.FromSeconds(30)))
        {
            return process.ExitCode == 0;
        }

        process.Kill(entireProcessTree: true);
        return false;
    }
}