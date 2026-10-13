using System.Globalization;

namespace SshSharp.Config;

/// <summary>One directive in an <c>ssh_config</c> file.</summary>
/// <param name="Keyword">The keyword as written.</param>
/// <param name="Arguments">The arguments, with quotes removed.</param>
/// <param name="RawValue">Everything after the keyword, verbatim (used for <c>ProxyCommand</c>).</param>
/// <param name="Line">The 1-based line number.</param>
public sealed record SshConfigDirective(string Keyword, IReadOnlyList<string> Arguments, string RawValue, int Line);

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
    public IList<SshConfigDirective> Directives { get; } = [];

    /// <summary>Whether a <c>Host</c> section applies to <paramref name="host"/> (a positive pattern matches and no negated one does).</summary>
    internal bool AppliesToHost(string host)
    {
        if (IsMatch)
        {
            return MatchCriteria.Count == 1 && MatchCriteria[0].Equals("all", StringComparison.OrdinalIgnoreCase);
        }

        if (HostPatterns is null)
        {
            return true;
        }

        var matched = false;
        foreach (var pattern in HostPatterns)
        {
            if (pattern.StartsWith('!'))
            {
                if (Glob.IsMatch(pattern.AsSpan(1), host))
                {
                    return false;
                }
            }
            else if (Glob.IsMatch(pattern, host))
            {
                matched = true;
            }
        }

        return matched;
    }
}

/// <summary>
/// An OpenSSH client configuration (<c>ssh_config</c>): parsed into <c>Host</c> sections and resolved per host with
/// OpenSSH's first-obtained-value-wins rules.
/// </summary>
public sealed class SshConfig
{
    private static readonly HashSet<string> Accumulating = new(StringComparer.OrdinalIgnoreCase)
    {
        "identityfile", "certificatefile", "localforward", "remoteforward", "dynamicforward", "sendenv",
    };

    private static readonly string[] DefaultIdentityFiles = ["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk"];

    private readonly List<SshConfigBlock> _blocks = [new SshConfigBlock(null, false, [])];

    /// <summary>The sections in file order; the first is the global section before any <c>Host</c> line.</summary>
    public IReadOnlyList<SshConfigBlock> Blocks => _blocks;

    /// <summary>Parses <c>ssh_config</c> text. Throws <see cref="FormatException"/> (with the line number) on syntax errors.</summary>
    public static SshConfig Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var config = new SshConfig();
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
                    config._blocks.Add(new SshConfigBlock(args, false, []));
                }
                else if (keyword.Equals("Match", StringComparison.OrdinalIgnoreCase))
                {
                    config._blocks.Add(new SshConfigBlock(null, true, args));
                }
                else
                {
                    config._blocks[^1].Directives.Add(new SshConfigDirective(keyword, args, rawValue, lineNumber));
                }
            }
            catch (FormatException ex)
            {
                throw new FormatException($"ssh_config line {lineNumber}: {ex.Message}", ex);
            }
        }

        return config;
    }

    /// <summary>Loads a config file. A missing file gives an empty config.</summary>
    public static SshConfig Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path) ? Parse(File.ReadAllText(path)) : new SshConfig();
    }

    /// <summary>Loads a config file asynchronously. A missing file gives an empty config.</summary>
    public static async Task<SshConfig> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path) ? Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false)) : new SshConfig();
    }

    /// <summary>Resolves the effective settings for <paramref name="host"/>.</summary>
    /// <param name="host">The host name or alias, as the user typed it.</param>
    /// <param name="options">External inputs (explicit user and port, home directory, ...); defaults are taken from the process.</param>
    public SshHostConfig Resolve(string host, SshConfigResolveOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        options ??= new SshConfigResolveOptions();
        var values = Collect(host);

        string? First(string key) => values.TryGetValue(key, out var v) && v.Count > 0 ? v[0] : null;
        IReadOnlyList<string> All(string key) => values.TryGetValue(key, out var v) ? v : [];

        var hostContext = new SshTokenContext(host, host, 22, string.Empty, options.LocalUser, options.HomeDirectory,
            options.LocalHostName, options.GetEnvironmentVariable);
        var hostName = hostContext.ExpandTokens(First("hostname") ?? host);
        var port = options.Port ?? ParsePort(First("port")) ?? 22;
        var user = options.User ?? First("user") ?? options.LocalUser;
        var ctx = hostContext with { Host = hostName, Port = port, RemoteUser = user };

        var identityFiles = All("identityfile").Select(v => ctx.ExpandPath(ctx.ExpandTokens(v))).ToList();
        if (identityFiles.Count == 0)
        {
            identityFiles = [.. DefaultIdentityFiles.Select(ctx.ExpandPath)];
        }

        IReadOnlyList<string> userKnownHosts = values.TryGetValue("userknownhostsfile", out var ukh) && ukh.Count > 0
            ? ukh : ["~/.ssh/known_hosts", "~/.ssh/known_hosts2"];
        IReadOnlyList<string> globalKnownHosts = values.TryGetValue("globalknownhostsfile", out var gkh) && gkh.Count > 0
            ? gkh : DefaultGlobalKnownHosts();

        var proxyJump = First("proxyjump");
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
            HostKeyAlias = First("hostkeyalias") is { } alias ? ctx.ExpandTokens(alias) : null,
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
            LocalForwards = All("localforward"),
            RemoteForwards = All("remoteforward"),
            DynamicForwards = All("dynamicforward"),
            Options = values.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value, StringComparer.OrdinalIgnoreCase),
        };
    }

    private Dictionary<string, List<string>> Collect(string host)
    {
        var values = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var block in _blocks.Where(b => b.AppliesToHost(host)))
        {
            foreach (var directive in block.Directives)
            {
                var key = directive.Keyword;
                var isForward = key.EndsWith("forward", StringComparison.OrdinalIgnoreCase) && !key.Equals("forwardagent", StringComparison.OrdinalIgnoreCase);
                if (Accumulating.Contains(key))
                {
                    if (!values.TryGetValue(key, out var list))
                    {
                        values[key] = list = [];
                    }

                    if (isForward)
                    {
                        list.Add(string.Join(' ', directive.Arguments));
                    }
                    else
                    {
                        list.AddRange(directive.Arguments);
                    }
                }
                else if (!values.ContainsKey(key))
                {
                    values[key] = key.Equals("proxycommand", StringComparison.OrdinalIgnoreCase)
                        ? [directive.RawValue]
                        : [.. directive.Arguments];
                }
            }
        }

        return values;
    }

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