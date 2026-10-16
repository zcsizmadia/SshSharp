namespace SshSharp.Scp;

/// <summary>Options for the SCP transfers in <see cref="SshScpExtensions"/>.</summary>
public sealed class SshScpOptions
{
    /// <summary>
    /// Keep the source's modification and access times and its permission bits, as <c>scp -p</c> does: on uploads the server gets
    /// them, and on downloads the local file gets them (the permission bits on Unix only). Default false.
    /// </summary>
    public bool Preserve { get; init; }

    /// <summary>Keep times and permission bits: <see cref="Preserve"/>, which is what this always did.</summary>
    [Obsolete("Use Preserve: it keeps the permission bits too, as scp -p does (#88).")]
    public bool PreserveTimes { get => Preserve; init => Preserve = value; }

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
}

/// <summary>Progress of one file in an SCP transfer.</summary>
/// <param name="Path">The file: the remote path for uploads of a single file, otherwise the path relative to the transfer's root.</param>
/// <param name="BytesTransferred">Bytes of this file transferred so far.</param>
/// <param name="TotalBytes">The file's size.</param>
public readonly record struct SshScpProgress(string Path, long BytesTransferred, long TotalBytes);
