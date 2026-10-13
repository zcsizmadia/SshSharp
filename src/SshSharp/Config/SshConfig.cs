using System.Globalization;

namespace SshSharp.Config;

/// <summary>One directive in an <c>ssh_config</c> file.</summary>
/// <param name="Keyword">The keyword as written.</param>
/// <param name="Arguments">The arguments, with quotes removed.</param>
/// <param name="RawValue">Everything after the keyword, verbatim (used for <c>ProxyCommand</c>).</param>
/// <param name="Line">The 1-based line number.</param>
public sealed record SshConfigDirective(string Keyword, IReadOnlyList<string> Arguments, string RawValue, int Line);

/// <summary>The sections of one parsed config file and the directory its relative <c>Include</c> paths resolve against.</summary>
internal sealed record SshConfigDocument(IReadOnlyList<SshConfigBlock> Blocks, string? BaseDirectory);

/// <summary>A <c>Host</c> or <c>Match</c> section, or the global section before the first one.</summary>
public sealed class SshConfigBlock
{
    internal SshConfigBlock(IReadOnlyList<string>? hostPatterns, bool isMatch, IReadOnlyList<string> matchCriteria)
    {
        HostPatterns = hostPatterns;
        IsMatch = isMatch;
        MatchCriteria = matchCriteria;
    }

    /// <summary>The patterns of a <c>Host</c> line, or null for the global section and <c>Match</c> sections.</summary>
    public IReadOnlyList<string>? HostPatterns { get; }

    /// <summary>Whether this is a <c>Match</c> section.</summary>
    public bool IsMatch { get; }

    /// <summary>The criteria of a <c>Match</c> line, as written.</summary>
    public IReadOnlyList<string> MatchCriteria { get; }

    /// <summary>The directives in this section, in order.</summary>
    public IReadOnlyList<SshConfigDirective> Directives => _directives;

    private readonly List<SshConfigDirective> _directives = [];

    internal void Add(SshConfigDirective directive) => _directives.Add(directive);

    /// <summary>
    /// Whether a <c>Host</c> (or the global) section applies to <paramref name="host"/>: a positive pattern matches and no negated
    /// one does. <c>Match</c> sections depend on resolution state and are evaluated by the resolver.
    /// </summary>
    internal bool AppliesToHost(string host) =>
        HostPatterns is null || Glob.IsMatchList(string.Join(',', HostPatterns), host);
}

/// <summary>
/// An OpenSSH client configuration (<c>ssh_config</c>): parsed into <c>Host</c> sections and resolved per host with
/// OpenSSH's first-obtained-value-wins rules.
/// </summary>
public sealed class SshConfig
{

    private static readonly string[] DefaultIdentityFiles = ["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk"];

    private readonly List<SshConfigDocument> _documents = [];

    private SshConfig(string? baseDirectory) =>
        _documents.Add(new SshConfigDocument([new SshConfigBlock(null, false, [])], baseDirectory));

    private SshConfig(IEnumerable<SshConfigDocument> documents) => _documents.AddRange(documents);

    /// <summary>
    /// The sections of every loaded file in order; the first section of each file is its global part before any <c>Host</c> line.
    /// </summary>
    public IReadOnlyList<SshConfigBlock> Blocks => [.. _documents.SelectMany(d => d.Blocks)];

    internal IReadOnlyList<SshConfigDocument> Documents => _documents;

    /// <summary>Parses <c>ssh_config</c> text. Throws <see cref="FormatException"/> (with the line number) on syntax errors.</summary>
    /// <param name="text">The file contents.</param>
    /// <param name="baseDirectory">
    /// The directory relative <c>Include</c> paths resolve against. OpenSSH uses <c>~/.ssh</c> for user files and the system
    /// directory for the system file; the default (null) is <c>.ssh</c> in the home directory given when resolving.
    /// </param>
    public static SshConfig Parse(string text, string? baseDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        var config = new SshConfig(baseDirectory);
        var blocks = new List<SshConfigBlock>(config._documents[0].Blocks);
        config._documents[0] = config._documents[0] with { Blocks = blocks };
        var lineNumber = 0;
        foreach (var raw in text.Split('\n'))
        {
            lineNumber++;
            try
            {
                if (!SshConfigLine.TryParse(raw.TrimEnd('\r'), out var keyword, out var args, out var rawValue))
                {
                    continue;
                }

                if (keyword.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    blocks.Add(new SshConfigBlock(args, false, []));
                }
                else if (keyword.Equals("Match", StringComparison.OrdinalIgnoreCase))
                {
                    blocks.Add(new SshConfigBlock(null, true, args));
                }
                else
                {
                    blocks[^1].Add(new SshConfigDirective(keyword, args, rawValue, lineNumber));
                }
            }
            catch (FormatException ex)
            {
                throw new FormatException($"ssh_config line {lineNumber}: {ex.Message}", ex);
            }
        }

        return config;
    }

    /// <summary>Loads a config file. A missing file gives an empty config. See <see cref="Parse"/> for <paramref name="baseDirectory"/>.</summary>
    public static SshConfig Load(string path, string? baseDirectory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path) ? Parse(File.ReadAllText(path), baseDirectory) : new SshConfig(baseDirectory);
    }

    /// <summary>Loads a config file asynchronously. A missing file gives an empty config.</summary>
    public static async Task<SshConfig> LoadAsync(string path, string? baseDirectory = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path)
            ? Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false), baseDirectory)
            : new SshConfig(baseDirectory);
    }

    /// <summary>
    /// Loads the standard files like <c>ssh</c> does: the user's <c>~/.ssh/config</c> first, then the system-wide file
    /// (<c>/etc/ssh/ssh_config</c>, or <c>%ProgramData%\ssh\ssh_config</c> on Windows). Earlier files win.
    /// </summary>
    /// <param name="homeDirectory">The home directory; defaults to the current user's profile folder.</param>
    public static SshConfig LoadDefault(string? homeDirectory = null)
    {
        var home = homeDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var userDirectory = Path.Combine(home, ".ssh");
        var systemDirectory = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh")
            : "/etc/ssh";
        return Combine(Load(Path.Combine(userDirectory, "config"), userDirectory), Load(Path.Combine(systemDirectory, "ssh_config"), systemDirectory));
    }

    /// <summary>Combines several configs; earlier ones take precedence (first obtained value wins).</summary>
    public static SshConfig Combine(params SshConfig[] configs)
    {
        ArgumentNullException.ThrowIfNull(configs);
        return new SshConfig(configs.SelectMany(c => c._documents));
    }

    /// <summary>Resolves the effective settings for <paramref name="host"/>.</summary>
    /// <param name="host">The host name or alias, as the user typed it.</param>
    /// <param name="options">External inputs (explicit user and port, home directory, ...); defaults are taken from the process.</param>
    public SshHostConfig Resolve(string host, SshConfigResolveOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        options ??= new SshConfigResolveOptions();

        // The host and user come from the caller, and may come from untrusted input. They are substituted into Match exec and
        // ProxyCommand (%h, %n, %r), which run in a shell, so shell metacharacters are refused, as OpenSSH does since 9.6 (CVE-2023-51385).
        // A host name never contains white space, and a space would split %h into extra arguments of ProxyCommand. User names keep
        // theirs (Windows account names can have spaces), as OpenSSH allows.
        RequireSafe(host, nameof(host), "host name");
        if (host.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("The host name contains white space.", nameof(host));
        }

        if (options.User is { } explicitUser)
        {
            RequireSafe(explicitUser, nameof(options), "user name");
        }

        var values = new SshConfigResolver(_documents, host, options).Run();

        string? First(string key) => values.TryGetValue(key, out var v) && v.Count > 0 ? v[0] : null;
        IReadOnlyList<string> All(string key) => values.TryGetValue(key, out var v) ? v : [];

        var hostContext = new SshTokenContext(host, host, 22, string.Empty, options.LocalUser, options.HomeDirectory,
            options.LocalHostName, options.GetEnvironmentVariable);
        // ssh lowercases the target name (it is a DNS name); %h and HostName then use the lowercase form.
        var hostName = hostContext.ExpandTokens(First("hostname") ?? host).ToLowerInvariant();
        var port = options.Port ?? ParsePort(First("port")) ?? 22;
        var user = options.User ?? First("user") ?? options.LocalUser;
        var proxyJump = First("proxyjump");
        var hostKeyAlias = First("hostkeyalias");
        var ctx = hostContext with
        {
            Host = hostName,
            Port = port,
            RemoteUser = user,
            HostKeyAlias = hostKeyAlias,
            ProxyJump = proxyJump is null || proxyJump.Equals("none", StringComparison.OrdinalIgnoreCase) ? string.Empty : proxyJump,
        };

        var identityFiles = All("identityfile").Select(v => ctx.ExpandPath(ctx.ExpandTokens(v))).ToList();
        if (identityFiles.Count == 0)
        {
            identityFiles = [.. DefaultIdentityFiles.Select(ctx.ExpandPath)];
        }

        // "none" means no file at all, not a file named "none".
        var userKnownHosts = KnownHostsFiles(values, "userknownhostsfile", ["~/.ssh/known_hosts", "~/.ssh/known_hosts2"]);
        var globalKnownHosts = KnownHostsFiles(values, "globalknownhostsfile", DefaultGlobalKnownHosts());

        // The resolver keeps only whichever of ProxyJump and ProxyCommand came first, as OpenSSH does.
        var proxyCommand = values.TryGetValue("proxycommand", out var pc) && pc.Count > 0 && !pc[0].Equals("none", StringComparison.OrdinalIgnoreCase)
            ? ctx.ExpandTokens(pc[0]) : null;

        return new SshHostConfig
        {
            Alias = host,
            HostName = hostName,
            Port = port,
            User = user,
            IdentityFiles = identityFiles,
            CertificateFiles = [.. All("certificatefile").Select(v => ctx.ExpandPath(ctx.ExpandTokens(v)))],
            IdentitiesOnly = Bool(First("identitiesonly"), false),
            IdentityAgent = First("identityagent") is { } agent ? ExpandAgent(agent, ctx) : null,
            ProxyJump = proxyJump is null || proxyJump.Equals("none", StringComparison.OrdinalIgnoreCase)
                ? [] : [.. proxyJump.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
            ProxyCommand = proxyCommand,
            UserKnownHostsFiles = [.. userKnownHosts.Select(v => ctx.ExpandPath(ctx.ExpandTokens(v)))],
            GlobalKnownHostsFiles = [.. globalKnownHosts.Select(v => ctx.ExpandPath(ctx.ExpandTokens(v)))],
            StrictHostKeyChecking = ParseStrict(First("stricthostkeychecking")),
            HostKeyAlias = hostKeyAlias, // not token-expanded (ssh_config(5) does not list it)
            HostKeyAlgorithms = First("hostkeyalgorithms"),
            KexAlgorithms = First("kexalgorithms"),
            Ciphers = First("ciphers"),
            Macs = First("macs"),
            PubkeyAcceptedAlgorithms = First("pubkeyacceptedalgorithms") ?? First("pubkeyacceptedkeytypes"),
            ServerAliveInterval = Time(First("serveraliveinterval")) is { } sai && sai > TimeSpan.Zero ? sai : null,
            ServerAliveCountMax = int.TryParse(First("serveralivecountmax"), NumberStyles.None, CultureInfo.InvariantCulture, out var count) ? count : 3,
            ConnectTimeout = Time(First("connecttimeout")),
            AddressFamily = ParseFamily(First("addressfamily")),
            ForwardAgent = First("forwardagent") is { } fa && !IsNo(fa),
            RequestTty = ParseTty(First("requesttty")),
            PreferredAuthentications = [.. All("preferredauthentications").SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))],
            PubkeyAuthentication = Bool(First("pubkeyauthentication"), true),
            PasswordAuthentication = Bool(First("passwordauthentication"), true),
            KbdInteractiveAuthentication = Bool(First("kbdinteractiveauthentication") ?? First("challengeresponseauthentication"), true),
            BatchMode = Bool(First("batchmode"), false),
            SendEnv = ResolveSendEnv(All("sendenv")),
            SetEnv = ResolveSetEnv(All("setenv")),
            // ClearAllForwardings yes empties the forwarding lists, as in ssh.
            LocalForwards = Bool(First("clearallforwardings"), false) ? [] : All("localforward"),
            RemoteForwards = Bool(First("clearallforwardings"), false) ? [] : All("remoteforward"),
            DynamicForwards = Bool(First("clearallforwardings"), false) ? [] : All("dynamicforward"),
            GatewayPorts = Bool(First("gatewayports"), false),
            ExitOnForwardFailure = Bool(First("exitonforwardfailure"), false),
            Options = values.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value, StringComparer.OrdinalIgnoreCase),
        };
    }

    private static void RequireSafe(string value, string parameterName, string what)
    {
        if (value.StartsWith('-') || value.AsSpan().IndexOfAny(UnsafeCharacters) >= 0 || value.Any(char.IsControl))
        {
            throw new ArgumentException($"The {what} contains characters that are not allowed (shell metacharacters, control characters, or a leading '-').", parameterName);
        }
    }

    private static readonly System.Buffers.SearchValues<char> UnsafeCharacters = System.Buffers.SearchValues.Create("'`\"$\\;&<>|(){}");

    private static IReadOnlyList<string> KnownHostsFiles(Dictionary<string, List<string>> values, string key, IReadOnlyList<string> defaults) =>
        !values.TryGetValue(key, out var files) || files.Count == 0 ? defaults
        : files.Count == 1 && files[0].Equals("none", StringComparison.OrdinalIgnoreCase) ? []
        : files;

    private static string[] DefaultGlobalKnownHosts()
    {
        var dir = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh")
            : "/etc/ssh";
        return [Path.Combine(dir, "ssh_known_hosts"), Path.Combine(dir, "ssh_known_hosts2")];
    }

    private static string ExpandAgent(string value, SshTokenContext ctx)
    {
        if (value.Equals("none", StringComparison.OrdinalIgnoreCase) || value.Equals("SSH_AUTH_SOCK", StringComparison.Ordinal))
        {
            return value;
        }

        // "$NAME" names an environment variable that holds the socket path.
        if (value.Length > 1 && value[0] == '$' && value[1] != '{')
        {
            return ctx.GetEnvironmentVariable(value[1..]) ?? throw new FormatException($"Environment variable '{value[1..]}' is not set.");
        }

        return ctx.ExpandPath(ctx.ExpandTokens(value));
    }

    private static int? ParsePort(string? value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p is >= 1 and <= 65535 ? p : null;

    private static bool IsNo(string value) => value.ToLowerInvariant() is "no" or "false" or "off";

    private static bool Bool(string? value, bool fallback) => value is null ? fallback : !IsNo(value);

    private static TimeSpan? Time(string? value) => value is not null && SshTime.TryParse(value, out var t) ? t : null;

    private static StrictHostKeyChecking ParseStrict(string? value) => value?.ToLowerInvariant() switch
    {
        "yes" or "true" => StrictHostKeyChecking.Yes,
        "no" or "false" or "off" => StrictHostKeyChecking.No,
        "accept-new" => StrictHostKeyChecking.AcceptNew,
        _ => StrictHostKeyChecking.Ask,
    };

    private static SshAddressFamily ParseFamily(string? value) => value?.ToLowerInvariant() switch
    {
        "inet" => SshAddressFamily.Inet,
        "inet6" => SshAddressFamily.Inet6,
        _ => SshAddressFamily.Any,
    };

    private static RequestTty ParseTty(string? value) => value?.ToLowerInvariant() switch
    {
        "no" or "false" => RequestTty.No,
        "yes" or "true" => RequestTty.Yes,
        "force" => RequestTty.Force,
        _ => RequestTty.Auto,
    };

    private static List<string> ResolveSendEnv(IReadOnlyList<string> values)
    {
        var result = new List<string>();
        foreach (var value in values)
        {
            if (value.StartsWith('-'))
            {
                result.RemoveAll(p => Glob.IsMatch(value.AsSpan(1), p));
            }
            else
            {
                result.Add(value);
            }
        }

        return result;
    }

    private static Dictionary<string, string> ResolveSetEnv(IReadOnlyList<string> values)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            var eq = value.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0)
            {
                result.TryAdd(value[..eq], value[(eq + 1)..]);
            }
        }

        return result;
    }
}