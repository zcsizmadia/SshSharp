using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp;

/// <summary>
/// Kills a command the library started (<c>ProxyCommand</c>, <c>KnownHostsCommand</c>, <c>Match exec</c>) and everything it started,
/// without stopping any of them first.
/// </summary>
/// <remarks>
/// <para>
/// On Unix, <see cref="Process.Kill(bool)"/> with the whole tree sends each process SIGSTOP before SIGKILL. A shell runs in the
/// application's own process group, and so do its background children. When the shell dies while such a child is stopped, the kernel
/// can send SIGHUP and SIGCONT to that group (macOS does), and SIGHUP terminates the application (#432). Here each process gets SIGKILL
/// alone, so none is ever stopped. The command itself is killed last: until then, each round also finds what it started meanwhile.
/// </para>
/// <para>
/// What a process forks as it is killed is not in the tree: the fork completes (macOS does not abort it for the pending SIGKILL), and
/// the child is reparented to init, still in the application's group. A shell's background subshell escaped that way when its fork
/// met the cancellation (1 in 70 stress iterations on macOS, 72 in 400 with the cancellation timed to meet it). So each command started
/// by <see cref="Start"/> carries an environment variable with a random value of its own, which everything it starts inherits, and the
/// kill ends with a sweep: while any process carrying that value is alive, it gets SIGKILL too. A process that is gone has finished
/// any fork it was in, so once none is left, nothing that inherited the value is. A process that drops the variable from its
/// environment and leaves the tree is not found.
/// </para>
/// </remarks>
internal static class ProcessTree
{
    /// <summary>The environment variable that marks the processes of one command started by <see cref="Start"/>.</summary>
    internal const string TagVariable = "SSHSHARP_PROCESS_TREE";

    // The rounds stop when one finds nothing new; the limit is for a tree that keeps starting processes as fast as they are killed.
    private const int MaxRounds = 16;

    // The same on Linux and macOS.
    private const int SigKill = 9;
    private const int Eperm = 1;
    private const int Esrch = 3;

    private const int CtlKern = 1;
    private const int KernArgMax = 8;
    private const int KernProcArgs2 = 49;

    // A killed process is gone within milliseconds; the limit is for one that cannot be killed (stuck in the kernel).
    private static readonly TimeSpan SweepLimit = TimeSpan.FromSeconds(2);

    private static readonly ConditionalWeakTable<Process, byte[]> Tags = new();

    // The instrumented build's own record of each kill, apart from Instrumentation's shared trace: the forwarding relays fill that one
    // during a test run, which would push these out before the test that needs them reads them.
    private static readonly ConcurrentQueue<string> KillTrace = new();
    private const int MaxKillTrace = 400;

    /// <summary>The newest steps of the kills in this process (the instrumented build only; empty otherwise), for a test.</summary>
    internal static string RecentKills => string.Join(Environment.NewLine, KillTrace);

    /// <summary>
    /// Starts a command with <see cref="Process.Start(ProcessStartInfo)"/>, marking it and what it starts for <see cref="Kill"/>.
    /// </summary>
    public static Process? Start(ProcessStartInfo info)
    {
        // Stryker disable once all : Windows only, where the mutation workflow does not run
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
        {
            return Process.Start(info);
        }

        var value = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        info.Environment[TagVariable] = value;
        var process = Process.Start(info);
        if (process is not null)
        {
            Tags.Add(process, Tag(value));
        }

        return process;
    }

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

        var root = process.Id;
        var killed = new HashSet<int>();
        for (var round = 0; round < MaxRounds; round++)
        {
            // Breadth first lists parents before their children, so a process is killed before it can start more.
            var tree = Descendants(root);
            Trace(root, $"round {round}: [{string.Join(",", tree)}]");
            var fresh = tree.Where(pid => !killed.Contains(pid)).ToList();
            if (fresh.Count == 0)
            {
                break;
            }

            foreach (var pid in fresh)
            {
                killed.Add(pid);
                var result = KillOne(pid);
                Trace(root, $"{pid}: {result}"); // not inside the call: it compiles away outside the stress build, arguments and all
            }
        }

        process.Kill();
        Trace(root, "root killed");
        if (Tags.TryGetValue(process, out var tag))
        {
            Sweep(tag, root);
        }
    }

    /// <summary>The bytes <see cref="Tagged"/> looks for: the variable, its value and the NUL that ends them.</summary>
    internal static byte[] Tag(string value) => Encoding.ASCII.GetBytes(TagVariable + "=" + value + "\0");

    /// <summary>Kills every live process whose environment holds <paramref name="tag"/>, until none is left.</summary>
    internal static void Sweep(byte[] tag, int root = 0)
    {
        var limit = Stopwatch.StartNew();
        while (true)
        {
            var tagged = Tagged(tag);
            Trace(root, $"sweep: [{string.Join(",", tagged)}]");
            if (tagged.Count == 0 || limit.Elapsed > SweepLimit)
            {
                return;
            }

            foreach (var pid in tagged)
            {
                var result = KillOne(pid);
                Trace(root, $"{pid}: {result}"); // not inside the call: it compiles away outside the stress build, arguments and all
            }

            // SIGKILL is sent at once, but each process finishes exiting a moment later; until then it still reads as alive.
            Thread.Sleep(1);
        }
    }

    /// <summary>The live processes, other than this one, whose environment holds <paramref name="tag"/>.</summary>
    internal static List<int> Tagged(byte[] tag)
    {
        if (OperatingSystem.IsLinux())
        {
            return Directory.EnumerateDirectories("/proc")
                .Select(directory => (Directory: directory, Pid: ParsePid(directory)))
                .Where(process => process.Pid > 0 && process.Pid != Environment.ProcessId &&
                    Carries(LinuxEnvironment(process.Directory), tag))
                .Select(process => process.Pid)
                .ToList();
        }

        // Stryker disable all : macOS only, where the mutation workflow does not run (the macOS test job runs it)
        var buffer = new byte[MacArgumentsLimit()];
        return MacPids().Where(pid => pid != Environment.ProcessId && Carries(MacArguments(pid, buffer), tag)).ToList();

        // Stryker restore all
    }

    /// <summary>
    /// Whether <paramref name="block"/>, NUL-separated strings, holds <paramref name="tag"/> (<c>NAME=value</c> and its NUL) as one of
    /// them, not as the end of a longer one.
    /// </summary>
    internal static bool Carries(ReadOnlySpan<byte> block, ReadOnlySpan<byte> tag)
    {
        var offset = 0;
        while (true)
        {
            var at = block[offset..].IndexOf(tag);
            if (at < 0)
            {
                return false;
            }

            at += offset;
            if (at == 0 || block[at - 1] == 0)
            {
                return true;
            }

            offset = at + 1;
        }
    }

    // SIGKILL alone, with kill(2) itself: Process.Kill returns without a word when the process is not found (ESRCH), and sends nothing
    // when its cached state says that pid has exited, so it cannot tell which happened. Returns what did, for the trace. ESRCH: it
    // exited meanwhile; EPERM: another user's process.
    // Stryker disable once all : what it returns only feeds the stress build's trace; the kill itself is what the tests check
    private static string KillOne(int pid) =>
        NativeMethods.Kill(pid, SigKill) == 0 ? "killed" : Marshal.GetLastPInvokeError() switch
        {
            Esrch => "not killed: ESRCH",
            Eperm => "not killed: EPERM",
            var errno => $"not killed: errno {errno}",
        };

    [Conditional("SSHSHARP_INSTRUMENT")]
    private static void Trace(int root, string step)
    {
        KillTrace.Enqueue($"{DateTime.UtcNow:HH:mm:ss.ffffff} kill {root}: {step}");
        while (KillTrace.Count > MaxKillTrace && KillTrace.TryDequeue(out _))
        {
            // The oldest go once the trace is full.
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

    // A /proc entry's pid, or 0 for an entry that is not a process.
    private static int ParsePid(string directory) =>
        int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : 0;

    /// <summary>A process's environment from <c>/proc/[pid]/environ</c>: empty for a zombie, and for another user's process.</summary>
    private static byte[] LinuxEnvironment(string directory)
    {
        try
        {
            return File.ReadAllBytes(directory + "/environ");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return []; // it exited, or is not ours to read
        }
    }

    // Stryker disable all : macOS only, where the mutation workflow does not run (the macOS test job runs it)
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

    private static int[] MacPids()
    {
        var buffer = new int[1024];
        while (true)
        {
            var count = NativeMethods.ListAllPids(buffer, buffer.Length * sizeof(int));
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

    // The most a process's arguments and environment take (sysctl kern.argmax).
    private static int MacArgumentsLimit()
    {
        var value = new byte[sizeof(int)];
        var length = (nuint)value.Length;
        return NativeMethods.Sysctl([CtlKern, KernArgMax], 2, value, ref length, IntPtr.Zero, 0) == 0
            ? BitConverter.ToInt32(value)
            : 1 << 20;
    }

    // A process's argument count, executable path, arguments and environment, as NUL-separated strings (sysctl kern.procargs2). It
    // fails for a zombie, and for another user's process, so neither is found.
    private static ReadOnlySpan<byte> MacArguments(int pid, byte[] buffer)
    {
        var length = (nuint)buffer.Length;
        return NativeMethods.Sysctl([CtlKern, KernProcArgs2, pid], 3, buffer, ref length, IntPtr.Zero, 0) == 0
            ? buffer.AsSpan(0, (int)length)
            : [];
    }

    // Stryker restore all
    private static class NativeMethods
    {
        // Returns the number of pids written (libproc divides proc_listpids's byte count by sizeof(int)).
        [DllImport("libproc", EntryPoint = "proc_listchildpids")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int ListChildPids(int ppid, [Out] int[] buffer, int bufferSize);

        // Returns the number of pids written, as proc_listchildpids does.
        [DllImport("libproc", EntryPoint = "proc_listallpids")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int ListAllPids([Out] int[] buffer, int bufferSize);

        [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int Kill(int pid, int signal);

        [DllImport("libc", EntryPoint = "sysctl")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int Sysctl(
            [In] int[] name, uint nameLength, [Out] byte[] value, ref nuint valueLength, IntPtr newValue, nuint newValueLength);
    }
}
