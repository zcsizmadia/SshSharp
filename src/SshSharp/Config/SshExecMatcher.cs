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

        using var process = Process.Start(info);
        if (process is null)
        {
            return false;
        }

        process.StandardInput.Close();
        process.OutputDataReceived += static (_, _) => { };
        process.BeginOutputReadLine();
        if (process.WaitForExit(TimeSpan.FromSeconds(30)))
        {
            return process.ExitCode == 0;
        }

        process.Kill(entireProcessTree: true);
        return false;
    }
}