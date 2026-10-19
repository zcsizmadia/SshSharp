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
    /// Evaluates <c>Match exec</c> commands (after token expansion): completes with true when the command succeeds. Null (the
    /// default) means exec criteria never match, because running commands from a config file is opt-in; for trusted files, run them with
    /// <see cref="SshExecMatcher.RunShellAsync"/>: <c>(command, ct) =&gt; new(SshExecMatcher.RunShellAsync(command, ct))</c>. Asynchronous,
    /// so a config that needs it resolves with <see cref="SshConfig.ResolveAsync"/>.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<bool>>? ExecMatcher { get; init; }

    /// <summary>
    /// Looks up the canonical name for <c>CanonicalizeHostname</c>: receives the host and the <c>CanonicalDomains</c> and completes
    /// with the canonical name, or null when none is found. Null (the default) disables canonicalization, since resolving names is
    /// the caller's business (DNS, <c>CanonicalizePermittedCNAMEs</c> policy), unless <see cref="UseDnsCanonicalizer"/> turns on the
    /// built-in one; when set, it is used instead of that. Asynchronous, so a config that needs it resolves with
    /// <see cref="SshConfig.ResolveAsync"/>.
    /// </summary>
    public Func<string, IReadOnlyList<string>, CancellationToken, ValueTask<string?>>? HostCanonicalizer { get; init; }

    /// <summary>
    /// Canonicalizes host names with DNS, as ssh does, when the configuration asks for it (<c>CanonicalizeHostname yes</c> or
    /// <c>always</c>) and <see cref="HostCanonicalizer"/> is not set. The host is looked up with each of <c>CanonicalDomains</c> appended,
    /// in order, as a fully qualified name (no search list); the first that resolves is the new <c>HostName</c>, and the configuration
    /// is read again for it. <c>CanonicalizeMaxDots</c>, <c>CanonicalizeFallbackLocal</c> and <c>CanonicalizePermittedCNAMEs</c> apply
    /// as in ssh: the name becomes its CNAME target only when a rule allows that pair. A name ending in a dot is looked up as it is, and
    /// an IP address is never canonicalized. The lookups use the system's resolver (<see cref="System.Net.Dns"/>), which reports the end
    /// of a CNAME chain as ssh's <c>getaddrinfo</c> does, but not the chain's middle; when it reports no canonical name, CNAME rules have
    /// nothing to act on and the name stays as found. Off by default: resolving a configuration then makes DNS queries, and needs
    /// <see cref="SshConfig.ResolveAsync"/>.
    /// </summary>
    public bool UseDnsCanonicalizer { get; init; }

    /// <summary>
    /// Looks up a fully qualified name for <see cref="UseDnsCanonicalizer"/>: its canonical name (the end of its CNAME chain), or null
    /// when it does not resolve. The system's resolver by default; replaceable in tests.
    /// </summary>
    internal Func<string, SshAddressFamily, CancellationToken, ValueTask<string?>>? NameLookup { get; init; }

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

    /// <summary>
    /// A copy with the user and port overridden where given (from a destination like <c>user@host:port</c>). A jump host gets session
    /// type <c>none</c> and no command, as the <c>ssh -W</c> that ssh runs for each ProxyJump hop has: the caller's session is the
    /// destination's, not the hop's.
    /// </summary>
    internal SshConfigResolveOptions With(string? user, int? port, bool jumpHost = false) => new()
    {
        User = user ?? User,
        Port = port ?? Port,
        LocalUser = LocalUser,
        HomeDirectory = HomeDirectory,
        LocalHostName = LocalHostName,
        GetEnvironmentVariable = GetEnvironmentVariable,
        ExecMatcher = ExecMatcher,
        HostCanonicalizer = HostCanonicalizer,
        UseDnsCanonicalizer = UseDnsCanonicalizer,
        NameLookup = NameLookup,
        Tag = Tag,
        SessionType = jumpHost ? "none" : SessionType,
        Command = jumpHost ? null : Command,
        LocalAddresses = LocalAddresses,
    };
}