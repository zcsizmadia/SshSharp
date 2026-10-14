using System.Runtime.InteropServices;

namespace SshSharp.Sftp;

/// <summary>
/// Whether a local path is a regular file. .NET has no public API for the file type on Unix, and opening a FIFO blocks until a writer
/// comes (with no way to cancel), so a directory upload asks the runtime's own native shim (<c>SystemNative_LStat</c> in
/// libSystem.Native, part of every .NET runtime on Unix), whose file-status layout and type bits are the same on every platform.
/// </summary>
internal static class LocalFileType
{
    private const int TypeMask = 0xF000; // S_IFMT
    private const int RegularFile = 0x8000; // S_IFREG

    private static int s_unavailable;

    /// <summary>True for a regular file, and whenever the type cannot be told (Windows has no FIFOs or device files in a directory tree).</summary>
    public static bool IsRegularFile(string path)
    {
        if (OperatingSystem.IsWindows() || Volatile.Read(ref s_unavailable) != 0)
        {
            return true;
        }

        try
        {
            // struct FileStatus { int32 Flags; int32 Mode; ... }: a generous buffer, since only Mode is read.
            var status = new byte[256];
            if (LStat(path, status) != 0)
            {
                return true; // gone or unreadable: the upload reports the real error when it opens the file
            }

            return (MemoryMarshal.Read<int>(status.AsSpan(4)) & TypeMask) == RegularFile;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            Volatile.Write(ref s_unavailable, 1);
            return true;
        }
    }

    [DllImport("libSystem.Native", EntryPoint = "SystemNative_LStat")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int LStat(byte[] utf8PathWithNul, [Out] byte[] status);

    private static int LStat(string path, byte[] status) => LStat([.. System.Text.Encoding.UTF8.GetBytes(path), 0], status);
}
