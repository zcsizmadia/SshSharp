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

            // SIGKILL is delivered at once, but each process finishes exiting a moment later, and the shell (killed last) can be gone
            // first: a loaded runner showed one still running (1 in 60 stress iterations). A process the kill missed is a sleep of 30 s,
            // still running at the deadline.
            var gone = DateTime.UtcNow.AddSeconds(10);
            var running = tree.Where(IsRunning).ToList();
            while (running.Count > 0 && DateTime.UtcNow < gone)
            {
                await Task.Delay(20);
                running = running.Where(IsRunning).ToList();
            }

            await Assert.That(string.Join("; ", running.Select(Describe))).IsEqualTo(string.Empty);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private static string Describe(int pid)
    {
        try
        {
            return OperatingSystem.IsLinux() ? File.ReadAllText($"/proc/{pid}/stat").Trim() : $"{pid} still running";
        }
        catch (IOException)
        {
            return $"{pid} (exited)";
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
