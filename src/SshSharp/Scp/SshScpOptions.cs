namespace SshSharp.Scp;

/// <summary>Options for the SCP transfers in <see cref="SshScpExtensions"/>.</summary>
public sealed class SshScpOptions
{
    /// <summary>
    /// Keep the source's modification and access times and its permission bits, as <c>scp -p</c> does: on uploads the server gets
    /// them, and on downloads the local file gets them (the permission bits on Unix only). Default false.
    /// </summary>
    public bool Preserve { get; init; }

    /// <summary>Receives progress per file: its path, the bytes done so far, and its size.</summary>
    public IProgress<SshScpProgress>? Progress { get; init; }

    /// <summary>The permission bits for uploaded files when they are not preserved from the source. Default 0644.</summary>
    public UnixFileMode FileMode { get; init; } =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    /// <summary>The permission bits for directories created by recursive uploads. Default 0755.</summary>
    public UnixFileMode DirectoryMode { get; init; } =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    /// <summary>The server's scp program. Default <c>scp</c>.</summary>
    public string ScpCommand { get; init; } = "scp";

    /// <summary>
    /// How the remote path is written on the command line run on the server. Default <see cref="SshScpPathQuoting.Posix"/>, one
    /// single-quoted word, which is safe for any path with a POSIX shell. <see cref="SshScpPathQuoting.None"/> is for network devices
    /// that read the line without a shell, and <see cref="SshScpPathQuoting.DoubleQuote"/> for Windows OpenSSH with <c>cmd.exe</c>; both
    /// refuse, before anything is sent, a path they cannot pass on safely (an <see cref="ArgumentException"/>), and are meant only for
    /// paths the application controls.
    /// </summary>
    public SshScpPathQuoting PathQuoting { get; init; }
}

/// <summary>Progress of one file in an SCP transfer.</summary>
/// <param name="Path">The file: the remote path for uploads of a single file, otherwise the path relative to the transfer's root.</param>
/// <param name="BytesTransferred">Bytes of this file transferred so far.</param>
/// <param name="TotalBytes">The file's size.</param>
public sealed record SshScpProgress(string Path, long BytesTransferred, long TotalBytes);
