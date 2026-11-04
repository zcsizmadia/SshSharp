using System.Diagnostics;
using System.Globalization;
using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class ChildProcessTests
{
    [Test]
    public async Task Stop_EndsTheCommand_AndWhatItStarted()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Needs /bin/sh; ProcessTreeTests cover the kill itself.");
            return;
        }

        // The command (a sleep, exec'd by the shell) has a background child of its own. On .NET 11 it gets SIGTERM and exits from it,
        // which leaves the child reparented and outside any tree walk: only its mark finds it. Before .NET 11 the tree is killed at once.
        var pidFile = Path.Combine(Path.GetTempPath(), "sshsharp-stop-" + Guid.NewGuid().ToString("N"));
        var info = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardInput = true };
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("sleep 30 & echo $! > \"$0.tmp\" && mv \"$0.tmp\" \"$0\" && exec sleep 30");
        info.ArgumentList.Add(pidFile);
        ChildProcess.InheritStandardStreamsOnly(info);
        using var process = ProcessTree.Start(info)!;
        var child = 0;
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!File.Exists(pidFile) && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            child = int.Parse(File.ReadAllText(pidFile).Trim(), CultureInfo.InvariantCulture);

            ChildProcess.Stop(process);

            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
#if NET11_0_OR_GREATER
            await Assert.That(process.ExitCode).IsEqualTo(128 + 15); // SIGTERM: it was asked, not killed
#else
            await Assert.That(process.ExitCode).IsEqualTo(128 + 9); // SIGKILL
#endif
            await Assert.That(await GoneWithinAsync(child)).IsTrue();
        }
        finally
        {
            File.Delete(pidFile);
            if (child > 0 && IsRunning(child))
            {
                using var leftover = Process.GetProcessById(child);
                leftover.Kill();
            }
        }
    }

    private static async Task<bool> GoneWithinAsync(int pid)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (IsRunning(pid) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        return !IsRunning(pid);
    }

    // A killed process may stay a zombie until init reaps it; that is not running.
    private static bool IsRunning(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            if (OperatingSystem.IsLinux())
            {
                var stat = File.ReadAllText($"/proc/{pid}/stat");
                return stat[(stat.LastIndexOf(')') + 2)..][0] != 'Z';
            }

            return !process.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}
