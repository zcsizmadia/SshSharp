namespace SshSharp.Config;

/// <summary>Inputs to <see cref="SshConfig.Resolve(string, SshConfigResolveOptions?)"/> that come from outside the config file.</summary>
public sealed class SshConfigResolveOptions
{
    /// <summary>A user given explicitly by the caller; overrides <c>User</c> in the file.</summary>
    public string? User { get; init; }

    /// <summary>A port given explicitly by the caller; overrides <c>Port</c> in the file.</summary>
    public int? Port { get; init; }

    /// <summary>The local user name (<c>%u</c>, and the default remote user). Defaults to the current user.</summary>
    public string LocalUser { get; init; } = Environment.UserName;

    /// <summary>The home directory (<c>~</c>, <c>%d</c>). Defaults to the current user's profile folder.</summary>
    public string HomeDirectory { get; init; } = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>The local host name (<c>%l</c>, <c>%L</c>). Defaults to the machine name.</summary>
    public string LocalHostName { get; init; } = Environment.MachineName;

    /// <summary>Looks up environment variables for <c>${VAR}</c> expansion. Defaults to the process environment.</summary>
    public Func<string, string?> GetEnvironmentVariable { get; init; } = Environment.GetEnvironmentVariable;

    /// <summary>
    /// Evaluates <c>Match exec</c> commands (after token expansion): returns true when the command succeeds. Null (the default)
    /// means exec criteria never match, because running commands from a config file is opt-in; use <see cref="SshExecMatcher.RunShell"/>
    /// for trusted files.
    /// </summary>
    public Func<string, bool>? ExecMatcher { get; init; }

    /// <summary>
    /// Looks up the canonical name for <c>CanonicalizeHostname</c>: receives the host and the <c>CanonicalDomains</c> and returns
    /// the canonical name, or null when none is found. Null (the default) disables canonicalization, since resolving names is
    /// the caller's business (DNS, <c>CanonicalizePermittedCNAMEs</c> policy).
    /// </summary>
    public Func<string, IReadOnlyList<string>, string?>? HostCanonicalizer { get; init; }

    /// <summary>A tag given by the caller (<c>ssh -P</c>), matched by <c>Match tagged</c>; overrides <c>Tag</c> in the file.</summary>
    public string? Tag { get; init; }

    /// <summary>
    /// The kind of session the caller will start, for <c>Match sessiontype</c>: <c>shell</c> (an interactive shell), <c>exec</c> (a
    /// command), <c>subsystem</c> (for example SFTP) or <c>none</c> (forwarding only, <c>ssh -N</c>). Null (the default) when unknown: a
    /// <c>Match</c> block with <c>sessiontype</c> or <c>command</c> then never applies, negated or not, since either answer could be
    /// wrong. ssh itself always knows, because the command line says.
    /// </summary>
    /// <exception cref="ArgumentException">Not one of the four.</exception>
    public string? SessionType
    {
        get;
        init
        {
            if (value is not (null or "shell" or "exec" or "subsystem" or "none"))
            {
                throw new ArgumentException("The session type is shell, exec, subsystem or none.", nameof(value));
            }

            field = value;
        }
    }

    /// <summary>
    /// The command (with <see cref="SessionType"/> <c>exec</c>) or subsystem name (with <c>subsystem</c>, for example <c>sftp</c>) the
    /// caller will start, for <c>Match command</c>; null or empty for none, which <c>Match command ""</c> matches. Used only when
    /// <see cref="SessionType"/> is set.
    /// </summary>
    public string? Command { get; init; }

    /// <summary>
    /// The local addresses for <c>Match localnetwork</c>. Null (the default) reads the addresses of the network interfaces that are up,
    /// as ssh does; set it to decide yourself (or in tests). Note that a network address is not a trustworthy criterion in many
    /// situations, as ssh_config(5) warns.
    /// </summary>
    public Func<IReadOnlyList<System.Net.IPAddress>>? LocalAddresses { get; init; }

    /// <summary>A copy with the user and port overridden where given (from a destination like <c>user@host:port</c>).</summary>
    internal SshConfigResolveOptions With(string? user, int? port) => new()
    {
        User = user ?? User,
        Port = port ?? Port,
        LocalUser = LocalUser,
        HomeDirectory = HomeDirectory,
        LocalHostName = LocalHostName,
        GetEnvironmentVariable = GetEnvironmentVariable,
        ExecMatcher = ExecMatcher,
        HostCanonicalizer = HostCanonicalizer,
        Tag = Tag,
        SessionType = SessionType,
        Command = Command,
        LocalAddresses = LocalAddresses,
    };
}