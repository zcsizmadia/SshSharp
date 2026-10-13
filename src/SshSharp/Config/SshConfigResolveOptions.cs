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
}