using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace SshSharp;

/// <summary>
/// Kills a command the library started (<c>ProxyCommand</c>, <c>KnownHostsCommand</c>, <c>Match exec</c>) and everything it started,
/// without stopping any of them first.
/// </summary>
/// <remarks>
/// On Unix, <see cref="Process.Kill(bool)"/> with the whole tree sends each process SIGSTOP before SIGKILL. A shell runs in the
/// application's own process group, and so do its background children. When the shell dies while such a child is stopped, the kernel
/// can send SIGHUP and SIGCONT to that group (macOS does), and SIGHUP terminates the application (#432). Here each process gets SIGKILL
/// alone, so none is ever stopped. The command itself is killed last: until then, each round also finds what it started meanwhile. A
/// process started meanwhile by one of its descendants can escape; .NET's SIGSTOP was there to prevent that.
/// </remarks>
internal static class ProcessTree
{
    // The rounds stop when one finds nothing new; the limit is for a tree that keeps starting processes as fast as they are killed.
    private const int MaxRounds = 16;

    /// <summary>Kills <paramref name="process"/> and its descendants, sending each SIGKILL alone on Unix.</summary>
    /// <exception cref="InvalidOperationException">No process is associated with <paramref name="process"/>.</exception>
    public static void Kill(Process process)
    {
        // Stryker disable once all : on Linux, where the mutation workflow runs, .NET's tree kill ends the same processes; the macOS test
        // job is where the difference shows (#432)
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
        {
            // Windows stops nothing; it ends each process in the tree.
            process.Kill(entireProcessTree: true);
            return;
        }

        var killed = new HashSet<int>();
        for (var round = 0; round < MaxRounds; round++)
        {
            // Breadth first lists parents before their children, so a process is killed before it can start more.
            var fresh = Descendants(process.Id).Where(pid => !killed.Contains(pid)).ToList();
            if (fresh.Count == 0)
            {
                break;
            }

            foreach (var pid in fresh)
            {
                killed.Add(pid);
                KillOne(pid);
            }
        }

        process.Kill();
    }

    // Process.Kill sends SIGKILL alone on Unix; only the whole-tree overload stops processes first.
    private static void KillOne(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // It exited meanwhile.
        }
    }

    /// <summary>The descendants of <paramref name="root"/>, breadth first.</summary>
    internal static List<int> Descendants(int root)
    {
        var children = OperatingSystem.IsLinux() ? LinuxChildren() : null;
        var found = new List<int>();
        var queue = new Queue<int>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            IReadOnlyList<int> direct = children is null ? MacChildren(parent) : children.GetValueOrDefault(parent) ?? [];
            foreach (var child in direct.Where(child => child != root && !found.Contains(child)))
            {
                found.Add(child);
                queue.Enqueue(child);
            }
        }

        return found;
    }

    /// <summary>Every process's children, from the parent ids in <c>/proc/[pid]/stat</c>.</summary>
    private static Dictionary<int, List<int>> LinuxChildren()
    {
        var children = new Dictionary<int, List<int>>();
        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            string stat;
            try
            {
                stat = File.ReadAllText(directory + "/stat");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue; // it exited, or is not ours to read
            }

            // "pid (comm) state ppid ...": the command name can hold spaces and parentheses, so the fields count from the last ')'.
            var fields = stat[(stat.LastIndexOf(')') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length > 1 && int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid))
            {
                if (!children.TryGetValue(ppid, out var list))
                {
                    children[ppid] = list = [];
                }

                list.Add(pid);
            }
        }

        return children;
    }

    // Stryker disable once all : macOS only, where the mutation workflow does not run (the macOS test job runs it)
    private static int[] MacChildren(int parent)
    {
        var buffer = new int[64];
        while (true)
        {
            var count = NativeMethods.ListChildPids(parent, buffer, buffer.Length * sizeof(int));
            if (count <= 0)
            {
                return [];
            }

            // A full buffer may have cut the list short.
            if (count < buffer.Length)
            {
                return buffer[..count];
            }

            buffer = new int[buffer.Length * 2];
        }
    }

    private static class NativeMethods
    {
        // Returns the number of pids written (libproc divides proc_listpids's byte count by sizeof(int)).
        [DllImport("libproc", EntryPoint = "proc_listchildpids")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int ListChildPids(int ppid, [Out] int[] buffer, int bufferSize);
    }
}
