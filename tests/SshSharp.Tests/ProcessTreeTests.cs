using System.Diagnostics;

namespace SshSharp.Tests;

public class ProcessTreeTests
{
    [Test]
    public async Task Kill_EndsTheCommandAndEveryProcessItStarted()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Windows uses .NET's own tree kill, which stops nothing.");
            return;
        }

        // sh, a subshell (kept from exec'ing its sleep by the "; true"), its sleep, and a second sleep of sh's own: three descendants,
        // two levels deep.
        var info = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardInput = true };
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("(sleep 30; true) & sleep 30 & wait");
        using var process = Process.Start(info)!;
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            var tree = ProcessTree.Descendants(process.Id);
            while (tree.Count < 3 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
                tree = ProcessTree.Descendants(process.Id);
            }

            await Assert.That(tree.Count).IsEqualTo(3);

            ProcessTree.Kill(process);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            foreach (var pid in tree)
            {
                await Assert.That(IsRunning(pid)).IsFalse();
            }
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
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
