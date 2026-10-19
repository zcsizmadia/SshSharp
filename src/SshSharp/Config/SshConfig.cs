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
        var userDirectory = Path.Join(home, ".ssh");
        var systemDirectory = OperatingSystem.IsWindows()
            ? Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh")
            : "/etc/ssh";
        return Combine(Load(Path.Join(userDirectory, "config"), userDirectory), Load(Path.Join(systemDirectory, "ssh_config"), systemDirectory));
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
    /// <exception cref="NotSupportedException">
    /// The config needs <see cref="SshConfigResolveOptions.ExecMatcher"/> or <see cref="SshConfigResolveOptions.HostCanonicalizer"/>,
    /// which are asynchronous: use <see cref="ResolveAsync"/>.
    /// </exception>
    public SshHostConfig Resolve(string host, SshConfigResolveOptions? options = null)
    {
        try
        {
            return ResolveCore(host, options ?? new SshConfigResolveOptions(), new SshConfigCallbackAnswers());
        }
        catch (SshConfigCallbackNeeded)
        {
            throw new NotSupportedException(
                "This ssh_config needs Match exec or host canonicalization, whose callbacks are asynchronous: use ResolveAsync.");
        }
    }

    /// <summary>
    /// Resolves the effective settings for <paramref name="host"/>, as <see cref="Resolve"/> does, awaiting
    /// <see cref="SshConfigResolveOptions.ExecMatcher"/> and <see cref="SshConfigResolveOptions.HostCanonicalizer"/> when the config
    /// needs them (<c>Match exec</c>, <c>CanonicalizeHostname</c>).
    /// </summary>
    /// <param name="host">The host name or alias, as the user typed it.</param>
    /// <param name="options">External inputs (explicit user and port, home directory, ...); defaults are taken from the process.</param>
    /// <param name="cancellationToken">Cancels the callbacks.</param>
    public async Task<SshHostConfig> ResolveAsync(string host, SshConfigResolveOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new SshConfigResolveOptions();
        var answers = new SshConfigCallbackAnswers();

        // Each pass resolves until it needs an answer it does not have; the answer is awaited and recorded, and the next pass gets
        // further. The bound only guards against a callback that would never settle the same way twice.
        for (var pass = 0; pass < 256; pass++)
        {
            try
            {
                return ResolveCore(host, options, answers);
            }
            catch (SshConfigCallbackNeeded needed) when (needed.Domains is null)
            {
                answers.RecordExec(needed.Argument, await options.ExecMatcher!(needed.Argument, cancellationToken).ConfigureAwait(false));
            }
            catch (SshConfigCallbackNeeded needed)
            {
                var domains = needed.Domains!; // a host to canonicalize always comes with its domains
                answers.RecordCanonical(needed.Argument, domains,
                    await options.HostCanonicalizer!(needed.Argument, domains, cancellationToken).ConfigureAwait(false));
            }
        }

        throw new InvalidOperationException("Resolving the ssh_config needed too many Match exec or canonicalization answers.");
    }

    private SshHostConfig ResolveCore(string host, SshConfigResolveOptions options, SshConfigCallbackAnswers answers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

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

        var values = new SshConfigResolver(_documents, host, options, answers).Run();

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
            RefuseConnection = Bool(First("refuseconnection"), false),
            KnownHostsCommand = First("knownhostscommand") is { Length: > 0 } knownHostsCommand && !knownHostsCommand.Trim().Equals("none", StringComparison.OrdinalIgnoreCase)
                ? knownHostsCommand : null,
            Tokens = ctx,
            UserKnownHostsFiles = [.. userKnownHosts.Select(v => ctx.ExpandPath(ctx.ExpandTokens(v)))],
            GlobalKnownHostsFiles = [.. globalKnownHosts.Select(v => ctx.ExpandPath(ctx.ExpandTokens(v)))],
            RevokedHostKeys = First("revokedhostkeys") is { Length: > 0 } revoked && !revoked.Equals("none", StringComparison.OrdinalIgnoreCase)
                ? ctx.ExpandPath(ctx.ExpandTokens(revoked))
                : null,
            StrictHostKeyChecking = ParseStrict(First("stricthostkeychecking")),
            HashKnownHosts = First("hashknownhosts")?.ToLowerInvariant() is "yes" or "true",
            UpdateHostKeys = ParseUpdateHostKeys(First("updatehostkeys")),
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
            BindAddress = First("bindaddress") is { Length: > 0 } bindAddress ? bindAddress : null,
            BindInterface = First("bindinterface") is { Length: > 0 } bindInterface ? bindInterface : null,
            ForwardAgent = First("forwardagent") is { } fa && !IsNo(fa),
            GssapiAuthentication = Bool(First("gssapiauthentication"), false),
            GssapiDelegateCredentials = Bool(First("gssapidelegatecredentials"), false),
            AddKeysToAgent = ParseAddKeysToAgent(All("addkeystoagent") is { Count: > 0 } addKeys ? string.Join(' ', addKeys) : null),
            ChannelTimeouts = ParseChannelTimeouts(All("channeltimeout")),
            ObscureKeystrokeTiming = ParseObscureKeystrokeTiming(First("obscurekeystroketiming")),
            RequiredRsaSize = int.TryParse(First("requiredrsasize"), NumberStyles.None, CultureInfo.InvariantCulture, out var rsaBits) && rsaBits >= SshClientOptions.LowestRequiredRsaSize
                ? rsaBits
                : null,
            RequestTty = ParseTty(First("requesttty")),
            PreferredAuthentications = [.. All("preferredauthentications").SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))],
            PubkeyAuthentication = Bool(First("pubkeyauthentication"), true),
            PasswordAuthentication = Bool(First("passwordauthentication"), true),
            KbdInteractiveAuthentication = Bool(First("kbdinteractiveauthentication") ?? First("challengeresponseauthentication"), true),
            NumberOfPasswordPrompts = int.TryParse(First("numberofpasswordprompts"), NumberStyles.None, CultureInfo.InvariantCulture, out var passwordPrompts)
                ? passwordPrompts
                : SshClientOptions.DefaultNumberOfPasswordPrompts,
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
            ? Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh")
            : "/etc/ssh";
        return [Path.Join(dir, "ssh_known_hosts"), Path.Join(dir, "ssh_known_hosts2")];
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

    /// <summary>
    /// <c>ChannelTimeout type=interval [type=interval ...]</c> (OpenSSH 9.2+), or <c>none</c>: each type a pattern of channel type names,
    /// each interval an ssh time (<c>30s</c>, <c>10m</c>, <c>0</c> for none). Entries that do not parse are left out.
    /// </summary>
    internal static IReadOnlyList<SshChannelTimeout> ParseChannelTimeouts(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0 || (arguments.Count == 1 && arguments[0].Equals("none", StringComparison.OrdinalIgnoreCase)))
        {
            return [];
        }

        var timeouts = new List<SshChannelTimeout>();
        foreach (var argument in arguments)
        {
            var equals = argument.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0 || !SshTime.TryParse(argument[(equals + 1)..], out var interval) || interval < TimeSpan.Zero)
            {
                continue;
            }

            timeouts.Add(new SshChannelTimeout(argument[..equals], interval));
        }

        return timeouts;
    }

    /// <summary>ssh's keystroke interval for <c>ObscureKeystrokeTiming yes</c>, its default.</summary>
    internal static readonly TimeSpan DefaultKeystrokeInterval = TimeSpan.FromMilliseconds(20);

    /// <summary>
    /// <c>ObscureKeystrokeTiming yes|no|interval:milliseconds</c> (OpenSSH 9.5+): the interval, or null for <c>no</c>. Unset, <c>yes</c>,
    /// and anything ssh would reject (an unknown word, an interval outside 1 to 1000 ms) give ssh's default of 20 ms.
    /// </summary>
    internal static TimeSpan? ParseObscureKeystrokeTiming(string? value)
    {
        if (value is null)
        {
            return DefaultKeystrokeInterval;
        }

        if (value.Equals("no", StringComparison.OrdinalIgnoreCase) || value.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return value.StartsWith("interval:", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(value.AsSpan(9), NumberStyles.None, CultureInfo.InvariantCulture, out var milliseconds) && milliseconds is >= 1 and <= 1000
            ? TimeSpan.FromMilliseconds(milliseconds)
            : DefaultKeystrokeInterval;
    }

    /// <summary>
    /// <c>AddKeysToAgent yes|confirm|ask|no [time]</c>, or just a time (meaning yes), as ssh_config(5) has it. <c>ask</c>, and anything
    /// malformed, mean no.
    /// </summary>
    internal static SshAgentKeyConstraints? ParseAddKeysToAgent(string? value)
    {
        if (value is null)
        {
            return null;
        }

        var parts = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length is 0 or > 2)
        {
            return null;
        }

        var mode = parts[0].ToLowerInvariant();
        TimeSpan? lifetime = null;
        if (parts.Length == 2 || mode is not ("yes" or "no" or "ask" or "confirm"))
        {
            if (!SshTime.TryParse(parts[^1], out var time) || time <= TimeSpan.Zero)
            {
                return null;
            }

            lifetime = time;
            mode = parts.Length == 2 ? mode : "yes";
        }

        return mode switch
        {
            "yes" => new SshAgentKeyConstraints { Lifetime = lifetime },
            "confirm" => new SshAgentKeyConstraints { Lifetime = lifetime, Confirm = true },
            _ => null,
        };
    }

    private static TimeSpan? Time(string? value) => value is not null && SshTime.TryParse(value, out var t) ? t : null;

    private static StrictHostKeyChecking ParseStrict(string? value) => value?.ToLowerInvariant() switch
    {
        "yes" or "true" => StrictHostKeyChecking.Yes,
        "no" or "false" or "off" => StrictHostKeyChecking.No,
        "accept-new" => StrictHostKeyChecking.AcceptNew,
        _ => StrictHostKeyChecking.Ask,
    };

    private static UpdateHostKeys ParseUpdateHostKeys(string? value) => value?.ToLowerInvariant() switch
    {
        "yes" or "true" => UpdateHostKeys.Yes,
        "ask" => UpdateHostKeys.Ask,
        _ => UpdateHostKeys.No,
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