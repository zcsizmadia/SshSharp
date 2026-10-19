namespace SshSharp.Config;

/// <summary>The <c>StrictHostKeyChecking</c> policy.</summary>
public enum StrictHostKeyChecking
{
    /// <summary>Ask the user about unknown keys (the OpenSSH default); refuse changed keys.</summary>
    Ask,

    /// <summary>Refuse unknown and changed keys.</summary>
    Yes,

    /// <summary>Accept and record unknown keys; refuse changed keys.</summary>
    AcceptNew,

    /// <summary>Accept unknown keys, and allow changed keys with a warning (<c>no</c> or <c>off</c>).</summary>
    No,
}

/// <summary>The <c>UpdateHostKeys</c> setting: whether known_hosts follows the host keys a server announces after login.</summary>
public enum UpdateHostKeys
{
    /// <summary>Leave known_hosts as it is (also when the setting is absent).</summary>
    No,

    /// <summary>Add the server's new keys and remove the ones it no longer has.</summary>
    Yes,

    /// <summary>Ask before changing known_hosts; without a way to ask, leave it.</summary>
    Ask,
}

/// <summary>The <c>AddressFamily</c> setting.</summary>
public enum SshAddressFamily
{
    /// <summary>Any address family.</summary>
    Any,

    /// <summary>IPv4 only.</summary>
    Inet,

    /// <summary>IPv6 only.</summary>
    Inet6,
}

/// <summary>The <c>RequestTTY</c> setting.</summary>
public enum RequestTty
{
    /// <summary>Request a TTY only for interactive sessions (the default).</summary>
    Auto,

    /// <summary>Never request a TTY.</summary>
    No,

    /// <summary>Always request a TTY.</summary>
    Yes,

    /// <summary>Force a TTY even without a local one.</summary>
    Force,
}

/// <summary>The effective settings for one host, resolved from an <see cref="SshConfig"/>.</summary>
public sealed class SshHostConfig
{
    /// <summary>The host name as given by the caller (the alias, <c>%n</c>).</summary>
    public required string Alias { get; init; }

    /// <summary>The real host name to connect to (<c>HostName</c>, or the alias).</summary>
    public required string HostName { get; init; }

    /// <summary>The port (default 22).</summary>
    public int Port { get; init; } = 22;

    /// <summary>The remote user.</summary>
    public required string User { get; init; }

    /// <summary>Identity files, in order, with tokens and <c>~</c> expanded. Defaults to the standard <c>id_*</c> names when none are configured.</summary>
    public IReadOnlyList<string> IdentityFiles { get; init; } = [];

    /// <summary>Certificate files (<c>CertificateFile</c>).</summary>
    public IReadOnlyList<string> CertificateFiles { get; init; } = [];

    /// <summary>Whether only the configured identities are offered (<c>IdentitiesOnly</c>).</summary>
    public bool IdentitiesOnly { get; init; }

    /// <summary>The agent socket or pipe (<c>IdentityAgent</c>), or <c>none</c>/<c>SSH_AUTH_SOCK</c> as written.</summary>
    public string? IdentityAgent { get; init; }

    /// <summary>The <c>ProxyJump</c> hops, in order. Empty for none.</summary>
    public IReadOnlyList<string> ProxyJump { get; init; } = [];

    /// <summary>The <c>ProxyCommand</c>, with tokens expanded, or null.</summary>
    public string? ProxyCommand { get; init; }

    /// <summary>
    /// <c>RefuseConnection yes</c>: connecting to this host is refused outright, before any network activity (OpenSSH 10.0+; meant for
    /// <c>Match</c> blocks that rule out a situation).
    /// </summary>
    public bool RefuseConnection { get; init; }

    /// <summary>
    /// The <c>KnownHostsCommand</c>, as written (its tokens, including <c>%H %I %K %f %t</c>, are expanded each time it runs), or null.
    /// Connecting by alias runs it only with <see cref="SshConfigConnectOptions.AllowKnownHostsCommand"/>; its output is read as
    /// known_hosts lines, in addition to the files.
    /// </summary>
    public string? KnownHostsCommand { get; init; }

    /// <summary>The token values of this resolution, for commands expanded later (<c>KnownHostsCommand</c>).</summary>
    internal SshTokenContext? Tokens { get; init; }

    /// <summary>User known_hosts files, with <c>~</c> expanded.</summary>
    public IReadOnlyList<string> UserKnownHostsFiles { get; init; } = [];

    /// <summary>System-wide known_hosts files.</summary>
    public IReadOnlyList<string> GlobalKnownHostsFiles { get; init; } = [];

    /// <summary>
    /// <c>RevokedHostKeys</c>: a file of host keys never to accept (an OpenSSH KRL, as <c>ssh-keygen -k</c> writes, or a list of public
    /// keys), with <c>~</c> and tokens expanded; null when not set (or <c>none</c>).
    /// </summary>
    public string? RevokedHostKeys { get; init; }

    /// <summary>The host key checking policy.</summary>
    public StrictHostKeyChecking StrictHostKeyChecking { get; init; } = StrictHostKeyChecking.Ask;

    /// <summary>Whether new known_hosts entries are written hashed (<c>HashKnownHosts</c>).</summary>
    public bool HashKnownHosts { get; init; }

    /// <summary>Whether known_hosts follows the host keys the server announces after login (<c>UpdateHostKeys</c>).</summary>
    public UpdateHostKeys UpdateHostKeys { get; init; } = UpdateHostKeys.No;

    /// <summary>The name to look up in known_hosts instead of the host (<c>HostKeyAlias</c>).</summary>
    public string? HostKeyAlias { get; init; }

    /// <summary>Raw <c>HostKeyAlgorithms</c> specification (a list, or <c>+</c>, <c>-</c> or <c>^</c> applied to the defaults, as in OpenSSH), or null.</summary>
    public string? HostKeyAlgorithms { get; init; }

    /// <summary>Raw <c>KexAlgorithms</c> specification, or null.</summary>
    public string? KexAlgorithms { get; init; }

    /// <summary>Raw <c>Ciphers</c> specification, or null.</summary>
    public string? Ciphers { get; init; }

    /// <summary>Raw <c>MACs</c> specification, or null.</summary>
    public string? Macs { get; init; }

    /// <summary>Raw <c>PubkeyAcceptedAlgorithms</c> specification, or null.</summary>
    public string? PubkeyAcceptedAlgorithms { get; init; }

    /// <summary>The interval for server keep-alive messages, or null for none.</summary>
    public TimeSpan? ServerAliveInterval { get; init; }

    /// <summary>The number of unanswered keep-alives before disconnecting (default 3).</summary>
    public int ServerAliveCountMax { get; init; } = 3;

    /// <summary>The connection timeout, or null.</summary>
    public TimeSpan? ConnectTimeout { get; init; }

    /// <summary>The address family restriction.</summary>
    public SshAddressFamily AddressFamily { get; init; }

    /// <summary>The local address to connect from (<c>BindAddress</c>, <c>ssh -b</c>), or null.</summary>
    public string? BindAddress { get; init; }

    /// <summary>The network interface to connect from (<c>BindInterface</c>, <c>ssh -B</c>), or null; <see cref="BindAddress"/> wins.</summary>
    public string? BindInterface { get; init; }

    /// <summary>Whether agent forwarding is requested.</summary>
    public bool ForwardAgent { get; init; }

    /// <summary>Whether Kerberos authentication (<c>gssapi-with-mic</c>) is tried (<c>GSSAPIAuthentication</c>, off by default as in ssh).</summary>
    public bool GssapiAuthentication { get; init; }

    /// <summary>Whether the Kerberos ticket is forwarded to the server (<c>GSSAPIDelegateCredentials</c>, off by default).</summary>
    public bool GssapiDelegateCredentials { get; init; }

    /// <summary>
    /// <c>AddKeysToAgent</c>: when not null, a key loaded from an identity file that the server accepts is added to the agent with these
    /// constraints (<c>yes</c>; <c>confirm</c> asks for each use; a time interval sets the lifetime). Null for <c>no</c> (the default) and
    /// for <c>ask</c>, which needs a prompt this library does not show.
    /// </summary>
    public SshAgentKeyConstraints? AddKeysToAgent { get; init; }

    /// <summary>
    /// <c>ChannelTimeout type=interval ...</c>: idle timeouts by channel type, in the order given (the first matching type applies). Empty
    /// for <c>none</c> or when unset. Entries that do not parse are left out.
    /// </summary>
    public IReadOnlyList<SshChannelTimeout> ChannelTimeouts { get; init; } = [];

    /// <summary>
    /// <c>ObscureKeystrokeTiming yes|no|interval:milliseconds</c>: the interval keystrokes are sent on in terminal sessions, or null for
    /// <c>no</c>. 20 ms for <c>yes</c> and when unset, as in ssh; a value that does not parse, or an interval outside 1 to 1000 ms, also
    /// gives 20 ms. See <see cref="SshClientOptions.ObscureKeystrokeTiming"/>.
    /// </summary>
    public TimeSpan? ObscureKeystrokeTiming { get; init; } = SshConfig.DefaultKeystrokeInterval;

    /// <summary>
    /// <c>RequiredRSASize</c>: the smallest RSA host key accepted, in bits, or null when unset (SshSharp's own minimum, 2048, applies;
    /// ssh's default is 1024). Values below 1024, which ssh refuses, are left out.
    /// </summary>
    public int? RequiredRsaSize { get; init; }

    /// <summary>The TTY request mode.</summary>
    public RequestTty RequestTty { get; init; }

    /// <summary>Authentication methods in preference order (<c>PreferredAuthentications</c>), or empty for the default.</summary>
    public IReadOnlyList<string> PreferredAuthentications { get; init; } = [];

    /// <summary>Whether public key authentication is allowed.</summary>
    public bool PubkeyAuthentication { get; init; } = true;

    /// <summary>Whether password authentication is allowed.</summary>
    public bool PasswordAuthentication { get; init; } = true;

    /// <summary>Whether keyboard-interactive authentication is allowed.</summary>
    public bool KbdInteractiveAuthentication { get; init; } = true;

    /// <summary>
    /// <c>NumberOfPasswordPrompts</c>: how many times to ask for a password before giving up (see
    /// <see cref="SshClientOptions.NumberOfPasswordPrompts"/>). Default 3, as in ssh; a value that is not a number from 0 up also gives 3.
    /// </summary>
    public int NumberOfPasswordPrompts { get; init; } = SshClientOptions.DefaultNumberOfPasswordPrompts;

    /// <summary>Whether non-interactive mode is requested (<c>BatchMode</c>).</summary>
    public bool BatchMode { get; init; }

    /// <summary>Environment variable name patterns to send (<c>SendEnv</c>).</summary>
    public IReadOnlyList<string> SendEnv { get; init; } = [];

    /// <summary>Environment variables to set on the server (<c>SetEnv</c>); the first definition of a name wins.</summary>
    public IReadOnlyDictionary<string, string> SetEnv { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// <c>LocalForward</c> specifications, as written: <c>[bind:]port host:hostport</c>, or with a Unix socket path on either side
    /// (<c>/local/socket host:hostport</c>, <c>[bind:]port /remote/socket</c>, <c>/local/socket /remote/socket</c>).
    /// </summary>
    public IReadOnlyList<string> LocalForwards { get; init; } = [];

    /// <summary><c>RemoteForward</c> specifications, as written.</summary>
    public IReadOnlyList<string> RemoteForwards { get; init; } = [];

    /// <summary><c>DynamicForward</c> specifications, as written (<c>[bind:]port</c>).</summary>
    public IReadOnlyList<string> DynamicForwards { get; init; } = [];

    /// <summary>Whether local forwardings may listen on every address, not only loopback, when the bind address says so (<c>GatewayPorts</c>).</summary>
    public bool GatewayPorts { get; init; }

    /// <summary>
    /// <c>StreamLocalBindUnlink</c>: whether an existing file where a <c>LocalForward</c> creates its Unix socket is removed first
    /// (typically a stale socket of an earlier run). Off by default, as in ssh: the forwarding then fails.
    /// </summary>
    public bool StreamLocalBindUnlink { get; init; }

    /// <summary>Whether a forwarding that cannot be set up fails the connection (<c>ExitOnForwardFailure</c>).</summary>
    public bool ExitOnForwardFailure { get; init; }

    /// <summary>All directives that applied, by lower-case keyword, with the arguments of the first (or all, for accumulating ones) occurrence. Includes keywords this library has no typed property for.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Options { get; init; } = new Dictionary<string, IReadOnlyList<string>>();
}