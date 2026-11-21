namespace SshSharp.Scp;

/// <summary>
/// How SCP writes the remote path on the command line it runs on the server (<c>scp -t</c> to upload, <c>scp -f</c> to download).
/// Set it as <see cref="SshScpOptions.PathQuoting"/>.
/// </summary>
/// <remarks>
/// Only <see cref="Posix"/> is safe for any path. The other modes are for servers that do not read the line as a POSIX shell does.
/// They refuse, before anything is sent, the paths they cannot pass on safely, and should be given only paths the application
/// controls.
/// </remarks>
public enum SshScpPathQuoting
{
    /// <summary>
    /// The default: <c>scp -t -- '/path'</c>, one single-quoted shell word, with each <c>'</c>, <c>\</c> and <c>!</c> in it written
    /// outside the quotes, escaped (<c>'\''</c>, <c>'\\'</c>, <c>'\!'</c>). Safe for any path with the login shells sshd runs the
    /// line with: <c>sh</c>, <c>bash</c>, <c>zsh</c>, <c>fish</c> and <c>tcsh</c>. Refuses an empty path, NUL and line breaks.
    /// </summary>
    Posix,

    /// <summary>
    /// <c>scp -t /path</c>: the path as given, with no quotes and no <c>--</c>, for the SCP servers built into network devices (Cisco
    /// IOS, MikroTik RouterOS and others), which read the line themselves, without a shell. Only letters, digits and
    /// <c>/ . _ - : + @ =</c> are allowed, and not <c>-</c>, <c>=</c> or <c>@</c> first, so the path cannot be split, taken for an
    /// option, expanded or run anything even where a shell does read the line. Any other path is refused.
    /// </summary>
    None,

    /// <summary>
    /// <c>scp -t -- "C:\path"</c>: one double-quoted word, for Windows OpenSSH servers whose default shell is <c>cmd.exe</c> (the
    /// default there). Refuses what double quotes cannot carry safely through <c>cmd.exe</c>, PowerShell and the program's own
    /// argument parsing: control characters, <c>"</c>, the expansions <c>%</c>, <c>!</c>, <c>$</c> and <c>`</c>, PowerShell's
    /// typographic double quotes, the characters Windows forbids in names (<c>&lt; &gt; | * ?</c>), a <c>-</c> first, and a <c>\</c>
    /// at the end (write <c>C:\dir</c> or <c>C:/dir/</c> instead).
    /// </summary>
    DoubleQuote,
}
