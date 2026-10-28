using System.Diagnostics;
using System.Globalization;
using System.Text;

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

    [Test]
    public async Task Kill_EndsWhatTheCommandStartedOutsideItsTree()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Windows uses .NET's own tree kill, which stops nothing.");
            return;
        }

        // The command's background child is reparented when the command exits: no tree walk finds it any more, as when a fork meets the
        // kill. Only the variable it inherited does.
        var (process, orphan) = await StartWithOrphanAsync();
        using (process)
        {
            try
            {
                await Assert.That(ProcessTree.Descendants(process.Id)).IsEmpty();

                ProcessTree.Kill(process);

                await Assert.That(await GoneWithinAsync(orphan)).IsTrue();
            }
            finally
            {
                KillIfRunning(orphan);
            }
        }
    }

    [Test]
    public async Task Kill_LeavesAnotherCommandsProcessesAlone()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Windows uses .NET's own tree kill, which stops nothing.");
            return;
        }

        var (first, firstOrphan) = await StartWithOrphanAsync();
        var (second, secondOrphan) = await StartWithOrphanAsync();
        using (first)
        using (second)
        {
            try
            {
                ProcessTree.Kill(first);
                await Assert.That(await GoneWithinAsync(firstOrphan)).IsTrue();
                await Assert.That(IsRunning(secondOrphan)).IsTrue();

                ProcessTree.Kill(second);
                await Assert.That(await GoneWithinAsync(secondOrphan)).IsTrue();
            }
            finally
            {
                KillIfRunning(firstOrphan);
                KillIfRunning(secondOrphan);
            }
        }
    }

    [Test]
    public async Task Start_MarksEachCommandWithAValueOfItsOwn()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Windows uses .NET's own tree kill, which needs no mark.");
            return;
        }

        var values = new List<string>();
        for (var i = 0; i < 2; i++)
        {
            var info = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardOutput = true };
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add($"printf %s \"${ProcessTree.TagVariable}\"");
            using var process = ProcessTree.Start(info)!;
            values.Add(await process.StandardOutput.ReadToEndAsync());
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }

        await Assert.That(values[0]).Matches("^[0-9A-F]{32}$");
        await Assert.That(values[1]).Matches("^[0-9A-F]{32}$");
        await Assert.That(values[1]).IsNotEqualTo(values[0]);
    }

    [Test]
    [Arguments("SSHSHARP_PROCESS_TREE=AB\0", true)]
    [Arguments("PATH=/bin\0SSHSHARP_PROCESS_TREE=AB\0HOME=/h\0", true)]
    [Arguments("XSSHSHARP_PROCESS_TREE=AB\0", false)]
    [Arguments("SSHSHARP_PROCESS_TREE=ABC\0", false)]
    [Arguments("SSHSHARP_PROCESS_TREE=XAB\0", false)]
    [Arguments("SSHSHARP_PROCESS_TREE=AB", false)]
    [Arguments("XSSHSHARP_PROCESS_TREE=AB\0SSHSHARP_PROCESS_TREE=AB\0", true)]
    [Arguments("", false)]
    public async Task Carries_FindsTheMarkOnlyAsAWholeString(string block, bool expected)
    {
        await Assert.That(ProcessTree.Carries(Encoding.ASCII.GetBytes(block), ProcessTree.Tag("AB"))).IsEqualTo(expected);
    }

    // A command whose background child (a sleep of 30 s) outlives it: the command has exited once this returns, and the child is no
    // longer its descendant.
    private static async Task<(Process Process, int Orphan)> StartWithOrphanAsync()
    {
        var pidFile = Path.Combine(Path.GetTempPath(), "sshsharp-tree-" + Guid.NewGuid().ToString("N"));
        var info = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardInput = true };
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("sh -c 'echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\" && exec sleep 30' sh \"$0\" & exit 0");
        info.ArgumentList.Add(pidFile);
        var process = ProcessTree.Start(info)!;
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!File.Exists(pidFile) && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            return (process, int.Parse(File.ReadAllText(pidFile).Trim(), CultureInfo.InvariantCulture));
        }
        catch
        {
            process.Dispose();
            throw;
        }
        finally
        {
            File.Delete(pidFile);
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

    private static void KillIfRunning(int pid)
    {
        if (IsRunning(pid))
        {
            using var process = Process.GetProcessById(pid);
            process.Kill();
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
