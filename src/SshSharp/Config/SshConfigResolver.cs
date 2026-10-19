using System.Globalization;

namespace SshSharp.Config;

/// <summary>
/// Walks the config documents for one host and collects the first-obtained value of each keyword. It follows OpenSSH:
/// blocks are evaluated in order against the state collected so far, <c>Include</c> is a closed scope, and a second
/// ("final") pass runs after canonicalization or when a <c>Match final</c> was seen.
/// </summary>
internal sealed class SshConfigResolver(IReadOnlyList<SshConfigDocument> documents, string originalHost, SshConfigResolveOptions options,
    SshConfigCallbackAnswers answers)
{
    private const int MaxIncludeDepth = 16;

    // Depth alone does not bound the work: a few globbed files at each of 16 levels would be millions of parses.
    private const int MaxIncludedFiles = 1024;

    private int _includedFiles;

    private static readonly HashSet<string> Accumulating = new(StringComparer.OrdinalIgnoreCase)
    {
        "identityfile", "certificatefile", "localforward", "remoteforward", "dynamicforward", "sendenv",
    };

    private readonly Dictionary<string, List<string>> _values = new(StringComparer.OrdinalIgnoreCase);
    private bool _finalPass;
    private bool _canonical;
    private bool _sawFinalOrCanonical;
    private string? _finalHost;

    public Dictionary<string, List<string>> Run()
    {
        Pass();

        var canonicalName = TryCanonicalize();
        if (canonicalName is not null)
        {
            _values["hostname"] = [canonicalName];
            _canonical = true;
        }

        if (_canonical || _sawFinalOrCanonical)
        {
            // OpenSSH re-reads the files with the new target name: Host sections now match the (HostName-substituted, canonicalized)
            // name, lowercased, rather than what the user typed.
            _finalHost = CurrentHost().ToLowerInvariant();
            _finalPass = true;
            Pass();
        }

        return _values;
    }

    private void Pass()
    {
        foreach (var document in documents)
        {
            ProcessBlocks(document.Blocks, document.BaseDirectory, 0);
        }
    }

    private void ProcessBlocks(IReadOnlyList<SshConfigBlock> blocks, string? baseDirectory, int depth)
    {
        foreach (var block in blocks)
        {
            if (!BlockApplies(block))
            {
                continue;
            }

            foreach (var directive in block.Directives)
            {
                if (directive.Keyword.Equals("Include", StringComparison.OrdinalIgnoreCase))
                {
                    Include(directive, baseDirectory, depth);
                }
                else
                {
                    Apply(directive);
                }
            }
        }
    }

    private void Include(SshConfigDirective directive, string? baseDirectory, int depth)
    {
        if (depth >= MaxIncludeDepth)
        {
            throw new FormatException($"ssh_config line {directive.Line}: too many recursive Include directives.");
        }

        var context = Context();
        var directory = baseDirectory ?? Path.Join(options.HomeDirectory, ".ssh");
        foreach (var argument in directive.Arguments)
        {
            var path = context.ExpandPath(context.ExpandTokens(argument));
            if (!Path.IsPathRooted(path))
            {
                path = Path.Join(directory, path);
            }

            IEnumerable<string> files = Glob.HasWildcards(path) ? Glob.ExpandFiles(path) : File.Exists(path) ? [path] : [];
            foreach (var file in files)
            {
                if (++_includedFiles > MaxIncludedFiles)
                {
                    throw new FormatException($"ssh_config line {directive.Line}: more than {MaxIncludedFiles} files included in all.");
                }

                SshConfig included;
                try
                {
                    included = SshConfig.Parse(File.ReadAllText(file), baseDirectory);
                }
                catch (FormatException ex)
                {
                    throw new FormatException($"{file}: {ex.Message}", ex);
                }

                ProcessBlocks(included.Blocks, baseDirectory, depth + 1);
            }
        }
    }

    private void Apply(SshConfigDirective directive)
    {
        var key = directive.Keyword;
        if (Accumulating.Contains(key))
        {
            if (!_values.TryGetValue(key, out var list))
            {
                _values[key] = list = [];
            }

            var isForward = key.EndsWith("forward", StringComparison.OrdinalIgnoreCase);
            var additions = isForward ? [string.Join(' ', directive.Arguments)] : directive.Arguments;
            foreach (var value in additions.Where(v => !list.Contains(v, StringComparer.Ordinal)))
            {
                list.Add(value);
            }
        }
        else if (IsProxyKeyword(key) && (_values.ContainsKey("proxyjump") || _values.ContainsKey("proxycommand")))
        {
            // ProxyJump and ProxyCommand compete: whichever comes first (even "none") wins and the other is ignored.
        }
        else if (!_values.ContainsKey(key))
        {
            _values[key] = key.Equals("proxycommand", StringComparison.OrdinalIgnoreCase) || key.Equals("knownhostscommand", StringComparison.OrdinalIgnoreCase)
                ? [directive.RawValue]
                : [.. directive.Arguments];
        }
    }

    private bool IsSet(string key) =>
        _values.TryGetValue(key, out var v) && v.Count > 0 && !v[0].Trim().Equals("none", StringComparison.OrdinalIgnoreCase);

    private static bool IsProxyKeyword(string key) =>
        key.Equals("proxyjump", StringComparison.OrdinalIgnoreCase) || key.Equals("proxycommand", StringComparison.OrdinalIgnoreCase);

    private bool BlockApplies(SshConfigBlock block) =>
        block.IsMatch ? EvaluateMatch(block.MatchCriteria) : block.AppliesToHost(_finalHost ?? originalHost);

    private SshTokenContext Context() => new(
        originalHost, CurrentHost(), CurrentPort(), CurrentUser(), options.LocalUser, options.HomeDirectory,
        options.LocalHostName, options.GetEnvironmentVariable)
    {
        HostKeyAlias = _values.TryGetValue("hostkeyalias", out var alias) && alias.Count > 0 ? alias[0] : null,
        ProxyJump = IsSet("proxyjump") ? _values["proxyjump"][0] : string.Empty,
    };

    private string CurrentHost() => _values.TryGetValue("hostname", out var v) && v.Count > 0
        ? new SshTokenContext(originalHost, originalHost, 22, string.Empty, options.LocalUser, options.HomeDirectory, options.LocalHostName, options.GetEnvironmentVariable).ExpandTokens(v[0])
        : originalHost;

    private int CurrentPort() => options.Port
        ?? (_values.TryGetValue("port", out var v) && v.Count > 0 && int.TryParse(v[0], NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p is >= 1 and <= 65535 ? p : 22);

    private string CurrentUser() => options.User ?? (_values.TryGetValue("user", out var v) && v.Count > 0 ? v[0] : options.LocalUser);

    private string? CurrentTag() => options.Tag ?? (_values.TryGetValue("tag", out var v) && v.Count > 0 ? v[0] : null);

    private bool EvaluateMatch(IReadOnlyList<string> criteria)
    {
        var result = true;
        var unsupported = false;
        for (var i = 0; i < criteria.Count; i++)
        {
            var token = criteria[i];
            var negate = token.StartsWith('!');
            var name = (negate ? token[1..] : token).ToLowerInvariant();

            bool value;
            switch (name)
            {
                case "all":
                    value = true;
                    break;
                case "final":
                    _sawFinalOrCanonical = true;
                    value = _finalPass;
                    break;
                case "canonical":
                    _sawFinalOrCanonical = true;
                    value = _canonical;
                    break;
                case "host" or "originalhost" or "user" or "localuser" or "tagged" or "exec" or "localnetwork":
                    if (++i >= criteria.Count)
                    {
                        throw new FormatException($"Match criterion '{name}' needs an argument.");
                    }

                    if (name == "localnetwork")
                    {
                        LocalNetwork.Validate(criteria[i]); // whatever the earlier criteria say, as ssh checks the list first
                    }

                    value = result && EvaluateWithArgument(name, criteria[i]);
                    break;
                case "sessiontype" or "command" when options.SessionType is not null:
                    if (++i >= criteria.Count)
                    {
                        throw new FormatException($"Match criterion '{name}' needs an argument.");
                    }

                    // The session the caller will start (SshConfigResolveOptions.SessionType and Command), as ssh matches its own.
                    var subject = name == "sessiontype" ? options.SessionType : options.Command ?? string.Empty;

                    // An empty pattern (Match command "") matches exactly when there is no command, as in OpenSSH.
                    value = criteria[i].Length == 0 ? subject.Length == 0 : Glob.IsMatchList(criteria[i], subject, ignoreCase: false);
                    break;
                case "version" or "sessiontype" or "command":
                    // Criteria this library cannot evaluate (a newer OpenSSH's version, or a session the caller has not described). The
                    // block never applies, negated or not: guessing either way could apply settings meant for another situation.
                    if (++i >= criteria.Count)
                    {
                        throw new FormatException($"Match criterion '{name}' needs an argument.");
                    }

                    unsupported = true;
                    continue;
                default:
                    throw new FormatException($"Unsupported Match criterion '{token}'.");
            }

            // Criteria with arguments are skipped once the result is false (no needless exec); final/canonical flags are always noticed.
            result &= value != negate;
        }

        return result && !unsupported;
    }

    private bool EvaluateWithArgument(string name, string argument) => name switch
    {
        "host" => Glob.IsMatchList(argument, CurrentHost()),
        "originalhost" => Glob.IsMatchList(argument, originalHost),
        "user" => Glob.IsMatchList(argument, CurrentUser()),
        "localuser" => Glob.IsMatchList(argument, options.LocalUser),
        "tagged" => CurrentTag() is { } tag && Glob.IsMatchList(argument, tag),
        "exec" => options.ExecMatcher is not null && answers.Exec(Context().ExpandTokens(argument)),
        "localnetwork" => LocalNetwork.AnyInside(LocalAddresses(), argument),
        _ => false,
    };

    // The interfaces are read once per resolution, not for every Match localnetwork line (each read enumerates every adapter).
    private IReadOnlyList<System.Net.IPAddress>? _localAddresses;

    private IReadOnlyList<System.Net.IPAddress> LocalAddresses() => _localAddresses ??= (options.LocalAddresses ?? LocalNetwork.InterfaceAddresses)();

    private string? TryCanonicalize()
    {
        if ((options.HostCanonicalizer is null && !options.UseDnsCanonicalizer)
            || !_values.TryGetValue("canonicalizehostname", out var setting) || setting.Count == 0)
        {
            return null;
        }

        var mode = setting[0].ToLowerInvariant();
        var always = mode == "always";
        if (!always && mode is not ("yes" or "true"))
        {
            return null;
        }

        var viaProxy = IsSet("proxycommand") || IsSet("proxyjump");
        var host = CurrentHost();
        var maxDots = _values.TryGetValue("canonicalizemaxdots", out var dots) && dots.Count > 0
            && int.TryParse(dots[0], NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : 1;
        var domains = _values.TryGetValue("canonicaldomains", out var list) ? list : [];
        if (!always && viaProxy)
        {
            return null;
        }

        if (options.HostCanonicalizer is null)
        {
            return CanonicalizeWithDns(host, maxDots, domains);
        }

        if (host.Count(c => c == '.') > maxDots)
        {
            return null;
        }

        var canonical = answers.Canonical(host, domains);
        if (canonical is null)
        {
            RequireFallbackLocal();
        }

        return canonical;
    }

    /// <summary>
    /// <c>CanonicalizeFallbackLocal</c>, after no canonical name was found: on (the default), the name is used as it is; <c>no</c> fails.
    /// </summary>
    /// <exception cref="InvalidOperationException"><c>CanonicalizeFallbackLocal no</c>.</exception>
    private void RequireFallbackLocal()
    {
        if (_values.TryGetValue("canonicalizefallbacklocal", out var fallback) && fallback.Count > 0 && fallback[0].ToLowerInvariant() is "no" or "false")
        {
            // The message leaves the host name out: exception messages end up in logs (docs/diagnostics.md).
            throw new InvalidOperationException("Could not canonicalize the host name, and CanonicalizeFallbackLocal is off.");
        }
    }

    /// <summary>
    /// The built-in canonicalizer (<see cref="SshConfigResolveOptions.UseDnsCanonicalizer"/>), as OpenSSH's <c>resolve_canonicalize</c>
    /// and <c>check_follow_cname</c> do it: a name ending in a dot is looked up as it is; otherwise, unless it has more than
    /// <paramref name="maxDots"/> dots, it is looked up with each domain appended (as an absolute name, so no search list applies) until
    /// one resolves, stopping at <c>none</c>. A found name becomes its CNAME target when <c>CanonicalizePermittedCNAMEs</c> allows the
    /// pair. When nothing is found (and the fallback allows going on), or the name has too many dots to try, the name is still
    /// looked up as the system resolves it and its CNAME target taken if a rule allows it, as ssh's main does after canonicalizing.
    /// Each lookup goes through the answers, so it runs once per resolution.
    /// </summary>
    private string? CanonicalizeWithDns(string host, int maxDots, IReadOnlyList<string> domains)
    {
        // An address is never a name to canonicalize; nor is anything with a colon (an address with a scope, which ssh skips too).
        if (host.Length == 0 || host.Contains(':', StringComparison.Ordinal) || System.Net.IPAddress.TryParse(host, out _))
        {
            return null;
        }

        var family = _values.TryGetValue("addressfamily", out var af) && af.Count > 0
            ? af[0].ToLowerInvariant() switch { "inet" => SshAddressFamily.Inet, "inet6" => SshAddressFamily.Inet6, _ => SshAddressFamily.Any }
            : SshAddressFamily.Any;
        if (host.EndsWith('.'))
        {
            if (answers.Lookup(host, family) is { } anchored)
            {
                return FollowCname(host[..^1], anchored);
            }

            RequireFallbackLocal();
            return null;
        }

        if (host.Count(c => c == '.') > maxDots)
        {
            return FollowBareName(host, family);
        }

        foreach (var domain in domains)
        {
            if (domain.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            var candidate = $"{host}.{domain}.";
            if (answers.Lookup(candidate, family) is { } canonicalName)
            {
                return FollowCname(candidate[..^1], canonicalName);
            }
        }

        RequireFallbackLocal();
        return FollowBareName(host, family);
    }

    /// <summary>
    /// No canonical name under the domains: with CNAME rules configured, the name as the system resolves it (search list included)
    /// becomes its CNAME target if a rule allows that pair; otherwise nothing changes (null).
    /// </summary>
    private string? FollowBareName(string host, SshAddressFamily family)
    {
        if (PermittedCnames().Count == 0 || answers.Lookup(host, family) is not { } canonicalName)
        {
            return null;
        }

        var followed = FollowCname(host, canonicalName);
        return string.Equals(followed, host, StringComparison.Ordinal) ? null : followed;
    }

    /// <summary>
    /// ssh's <c>check_follow_cname</c>: <paramref name="name"/>, or the canonical name the resolver reported for it when a
    /// <c>CanonicalizePermittedCNAMEs</c> rule matches both (the name against its source domains, the target against its targets).
    /// </summary>
    private string FollowCname(string name, string canonicalName)
    {
        var target = canonicalName.TrimEnd('.');
        if (target.Length == 0 || string.Equals(name, target, StringComparison.Ordinal))
        {
            return name;
        }

        foreach (var (sources, targets) in PermittedCnames())
        {
            if (Glob.IsMatchList(sources, name) && Glob.IsMatchList(targets, target))
            {
                return target;
            }
        }

        return name;
    }

    /// <summary>
    /// <c>CanonicalizePermittedCNAMEs source_domains:target_domains ...</c>: each rule a pair of comma-separated pattern lists; <c>none</c>
    /// or unset for no rules. A rule without a colon or with an empty side, which ssh rejects, is left out.
    /// </summary>
    private List<(string Sources, string Targets)> PermittedCnames()
    {
        var rules = new List<(string, string)>();
        if (!_values.TryGetValue("canonicalizepermittedcnames", out var arguments)
            || (arguments.Count == 1 && arguments[0].Equals("none", StringComparison.OrdinalIgnoreCase)))
        {
            return rules;
        }

        foreach (var argument in arguments)
        {
            var colon = argument.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0 && colon < argument.Length - 1)
            {
                rules.Add((argument[..colon], argument[(colon + 1)..]));
            }
        }

        return rules;
    }
}
/// <summary>
/// The answers of the asynchronous callbacks (<see cref="SshConfigResolveOptions.ExecMatcher"/>, <see cref="SshConfigResolveOptions.HostCanonicalizer"/>)
/// for one resolution. The resolver is synchronous: an answer it does not have yet raises <see cref="SshConfigCallbackNeeded"/>, and
/// <see cref="SshConfig.ResolveAsync"/> awaits the callback, records the answer and resolves again. Resolution is deterministic, so
/// each pass gets further, once per distinct callback.
/// </summary>
internal sealed class SshConfigCallbackAnswers
{
    private readonly Dictionary<string, bool> _exec = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _canonical = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _lookups = new(StringComparer.OrdinalIgnoreCase);

    public bool Exec(string command) =>
        _exec.TryGetValue(command, out var matched) ? matched : throw new SshConfigCallbackNeeded(command, null);

    public string? Canonical(string host, IReadOnlyList<string> domains) =>
        _canonical.TryGetValue(Key(host, domains), out var name) ? name : throw new SshConfigCallbackNeeded(host, domains);

    /// <summary>The canonical name <paramref name="name"/> resolves to, or null when it does not resolve (<see cref="SshConfigResolveOptions.UseDnsCanonicalizer"/>).</summary>
    public string? Lookup(string name, SshAddressFamily family) =>
        _lookups.TryGetValue(LookupKey(name, family), out var canonical) ? canonical : throw new SshConfigCallbackNeeded(name, family);

    public void RecordExec(string command, bool matched) => _exec[command] = matched;

    public void RecordCanonical(string host, IReadOnlyList<string> domains, string? name) => _canonical[Key(host, domains)] = name;

    public void RecordLookup(string name, SshAddressFamily family, string? canonical) => _lookups[LookupKey(name, family)] = canonical;

    private static string Key(string host, IReadOnlyList<string> domains) => host + "\0" + string.Join("\0", domains);

    private static string LookupKey(string name, SshAddressFamily family) => name + "\0" + ((int)family).ToString(CultureInfo.InvariantCulture);
}

/// <summary>
/// A callback answer the resolver needs and does not have yet: an exec command, a host and its canonical domains, or a name to look
/// up in DNS.
/// </summary>
internal sealed class SshConfigCallbackNeeded : Exception
{
    /// <summary>An exec command (<paramref name="domains"/> null), or a host to canonicalize and its domains.</summary>
    public SshConfigCallbackNeeded(string argument, IReadOnlyList<string>? domains)
    {
        Argument = argument;
        Domains = domains;
    }

    /// <summary>A name to look up, restricted to <paramref name="family"/>.</summary>
    public SshConfigCallbackNeeded(string name, SshAddressFamily family)
    {
        Argument = name;
        LookupFamily = family;
    }

    public string Argument { get; }

    /// <summary>The canonical domains, for a host to canonicalize; null for an exec command or a lookup.</summary>
    public IReadOnlyList<string>? Domains { get; }

    /// <summary>The address family, for a name to look up; null for an exec command or a host to canonicalize.</summary>
    public SshAddressFamily? LookupFamily { get; }
}
