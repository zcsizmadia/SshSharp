namespace SshSharp.Scp;

/// <summary>Options for the SCP transfers in <see cref="SshScpExtensions"/>.</summary>
public sealed class SshScpOptions
{
    /// <summary>Keep modification and access times (<c>scp -p</c>), and for downloads the permission bits on Unix. Default false.</summary>
    public bool PreserveTimes { get; init; }

    /// <summary>Receives progress per file: its path, the bytes done so far, and its size.</summary>
    public IProgress<SshScpProgress>? Progress { get; init; }

    /// <summary>The permission bits for uploaded files when they are not preserved from the source. Default 0644.</summary>
    public int FileMode { get; init; } = Convert.ToInt32("644", 8);

    /// <summary>The permission bits for directories created by recursive uploads. Default 0755.</summary>
    public int DirectoryMode { get; init; } = Convert.ToInt32("755", 8);

    /// <summary>The server's scp program. Default <c>scp</c>.</summary>
    public string ScpCommand { get; init; } = "scp";
}

/// <summary>Progress of one file in an SCP transfer.</summary>
/// <param name="Path">The file: the remote path for uploads of a single file, otherwise the path relative to the transfer's root.</param>
/// <param name="BytesTransferred">Bytes of this file transferred so far.</param>
/// <param name="TotalBytes">The file's size.</param>
public readonly record struct SshScpProgress(string Path, long BytesTransferred, long TotalBytes);
