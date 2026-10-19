namespace SshSharp;

/// <summary>
/// A request for a password, passed to <see cref="SshClientOptions.PasswordProvider"/> when authentication reaches a password (the
/// <c>password</c> method, or a keyboard-interactive round that asks for exactly one hidden input). It carries what an interactive
/// tool shows, as ssh's <c>user@host's password:</c> prompt does.
/// </summary>
public sealed class SshPasswordPrompt
{
    internal SshPasswordPrompt(string userName, string? host, int port, string method, int attempt, bool isRetry)
    {
        UserName = userName;
        Host = host;
        Port = port;
        Method = method;
        Attempt = attempt;
        IsRetry = isRetry;
    }

    /// <summary>The user the password is for (<see cref="SshClientOptions.UserName"/>).</summary>
    public string UserName { get; }

    /// <summary>
    /// The host as the caller gave it to <c>ConnectAsync</c> (the <c>HostName</c> when connecting by <c>ssh_config</c> alias), or null when
    /// connecting over a <see cref="Stream"/>.
    /// </summary>
    public string? Host { get; }

    /// <summary>The server's port (22 when connecting over a <see cref="Stream"/>, where it is not known).</summary>
    public int Port { get; }

    /// <summary>The method the password is for: <c>password</c>, or <c>keyboard-interactive</c> on a server that asks for it that way (PAM).</summary>
    public string Method { get; }

    /// <summary>
    /// Which prompt this is on this connection, from 1 to <see cref="SshClientOptions.NumberOfPasswordPrompts"/>. The given
    /// <see cref="SshClientOptions.Password"/> is not a prompt and is not counted.
    /// </summary>
    public int Attempt { get; }

    /// <summary>
    /// Whether a password was already rejected on this connection (a prompted one, or the given <see cref="SshClientOptions.Password"/>):
    /// show something like ssh's "Permission denied, please try again."
    /// </summary>
    public bool IsRetry { get; }
}

/// <summary>
/// The server's request for a new password (<c>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</c>, RFC 4252 section 8), passed to
/// <see cref="SshClientOptions.ChangePassword"/>: the password was right, but has expired. The server can ask again when it refuses
/// the new password (too short, reused), with a new <see cref="Prompt"/> that usually says why.
/// </summary>
public sealed class SshPasswordChangeRequest
{
    internal SshPasswordChangeRequest(string prompt, string language, string userName, string? host, int port, int attempt)
    {
        Prompt = prompt;
        Language = language;
        UserName = userName;
        Host = host;
        Port = port;
        Attempt = attempt;
    }

    /// <summary>
    /// The server's message, for example <c>Your password has expired.</c>, often empty. Server-supplied text: strip control characters
    /// before showing it in a terminal.
    /// </summary>
    public string Prompt { get; }

    /// <summary>The language tag of <see cref="Prompt"/> (RFC 3066), usually empty.</summary>
    public string Language { get; }

    /// <summary>The user whose password has expired.</summary>
    public string UserName { get; }

    /// <summary>The host as the caller gave it (see <see cref="SshPasswordPrompt.Host"/>), or null when connecting over a <see cref="Stream"/>.</summary>
    public string? Host { get; }

    /// <summary>The server's port (22 when connecting over a <see cref="Stream"/>, where it is not known).</summary>
    public int Port { get; }

    /// <summary>
    /// 1 for the server's first request; more when it refused the new password and asks again. The client stops after
    /// <c>3</c> requests for one password.
    /// </summary>
    public int Attempt { get; }
}
