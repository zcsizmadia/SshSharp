using System.Diagnostics;
#if NET11_0_OR_GREATER
using System.Runtime.InteropServices;
#endif

namespace SshSharp.Config;

/// <summary>What the programs SshSharp starts (ProxyCommand, KnownHostsCommand, <c>Match exec</c>) share: how they start and stop.</summary>
internal static class ChildProcess
{
    /// <summary>How long a program asked to stop (SIGTERM) gets before it is killed.</summary>
    private static readonly TimeSpan StopGrace = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Makes the program inherit its standard streams only, not whatever other handles this process has open (sockets, files, the
    /// agent's pipe). On .NET 11; earlier runtimes inherit what the OS passes by default.
    /// </summary>
    public static void InheritStandardStreamsOnly(ProcessStartInfo info)
    {
#if NET11_0_OR_GREATER
        info.InheritedHandles = [];
#endif
    }

    /// <summary>
    /// Stops the program and everything it started: on .NET 11 outside Windows, SIGTERM first, so it can close its connections
    /// cleanly, then a kill if it has not exited within half a second; otherwise a kill at once.
    /// </summary>
    public static void Stop(Process process)
    {
#if NET11_0_OR_GREATER
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                if (process.Signal(PosixSignal.SIGTERM) && process.WaitForExit(StopGrace))
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
            {
                // Exited already, or no signals here: the kill below decides.
            }
        }
#endif
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // It exited meanwhile.
        }
    }
}
