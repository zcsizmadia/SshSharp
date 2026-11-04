using System.Globalization;

namespace SshSharp.Config;

/// <summary>
/// Walks the config documents for one host and collects the first-obtained value of each keyword. It follows OpenSSH:
/// blocks are evaluated in order against the state collected so far, <c>Include</c> is a closed scope, and a second
/// ("final") pass runs when <c>CanonicalizeHostname</c> is on or a <c>Match final</c> (not negated) was seen.
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
    private bool _wantFinalPass;
    private string? _finalHost;

    public Dictionary<string, List<string>> Run()
    {
        Pass();

        // As ssh's main: canonicalization that is on asks for the second pass whether or not it finds a name, since the name is
        // lowercased and HostName substituted either way, and blocks written for that name may now match.
        var canonicalize = CanonicalizationEnabled();
        var canonicalName = TryCanonicalize();
        if (canonicalName is not null)
        {
            _values["hostname"] = [canonicalName];
        }

        if (canonicalize || _wantFinalPass)
        {
            // OpenSSH re-reads the files with the new target name: Host sections, Match host and %h now see the (HostName-substituted,
            // canonicalized) name, lowercased, rather than what the user typed.
            _finalHost = CurrentHost().ToLowerInvariant();

            // ssh sets its HostName to that name before reading again, so a HostName met in the second pass does not change it. The
            // name is already expanded: % is escaped so that expanding it again (SshConfig.Resolve does) leaves it as it is.
            _values["hostname"] = [_finalHost.Replace("%", "%%", StringComparison.Ordinal)];
            _finalPass = true;
            Pass();
        }

        return _values;
    }

    /// <summary><c>CanonicalizeHostname yes</c> or <c>always</c>, as the first pass left it.</summary>
    private bool CanonicalizationEnabled() => First("canonicalizehostname")?.ToLowerInvariant() is "yes" or "true" or "always";

    // The parser turns down a directive without arguments (SshConfigLine), so a list that is set is never empty.
    private string? First(string key) => _values.TryGetValue(key, out var v) ? v[0] : null;

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
                    // The file name only: the directory is the user's home, or wherever the configuration keeps it.
                    throw new FormatException($"{Path.GetFileName(file)}: {ex.Message}", ex);
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

    private bool IsSet(string key) => First(key) is { } value && !value.Trim().Equals("none", StringComparison.OrdinalIgnoreCase);

    private static bool IsProxyKeyword(string key) =>
        key.Equals("proxyjump", StringComparison.OrdinalIgnoreCase) || key.Equals("proxycommand", StringComparison.OrdinalIgnoreCase);

    private bool BlockApplies(SshConfigBlock block) =>
        block.IsMatch ? EvaluateMatch(block.MatchCriteria) : block.AppliesToHost(_finalHost ?? originalHost);

    private SshTokenContext Context() => new(
        originalHost, CurrentHost(), CurrentPort(), CurrentUser(), options.LocalUser, options.HomeDirectory,
        options.LocalHostName, options.GetEnvironmentVariable)
    {
        HostKeyAlias = First("hostkeyalias"),
        ProxyJump = IsSet("proxyjump") ? First("proxyjump")! : string.Empty,
    };

    // In the second pass, ssh has replaced its HostName with the name the first pass settled on, so that is the name everywhere.
    // HostName expands as SshConfig.Resolve expands it at the end, so Match host sees the name the result reports.
    // Stryker disable once NullCoalescing : in the second pass the HostName is _finalHost with % escaped, which expands back to it
    private string CurrentHost() => _finalHost ?? (First("hostname") is { } hostName
        ? new SshTokenContext(originalHost, originalHost, 22, string.Empty, options.LocalUser, options.HomeDirectory, options.LocalHostName, options.GetEnvironmentVariable).ExpandTokens(hostName)
        : originalHost);

    private int CurrentPort() => options.Port ?? SshConfig.ParsePort(First("port")) ?? 22;

    private string CurrentUser() => options.User ?? First("user") ?? options.LocalUser;

    private string? CurrentTag() => options.Tag ?? First("tag");

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
                case "final" or "canonical":
                    // Both are true exactly in the second pass, found name or not, as in ssh's match_cfg_line. Only a Match final
                    // that is not negated asks for that pass: a block that wants the first pass only (!final) or the second
                    // (canonical) does not by itself make one happen.
                    _wantFinalPass |= name == "final" && !negate;
                    value = _finalPass;
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

    // Stryker disable once Boolean : EvaluateMatch sends only the names listed here, so the last arm is never taken
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
        if ((options.HostCanonicalizer is null && !options.UseDnsCanonicalizer) || !CanonicalizationEnabled())
        {
            return null;
        }

        var always = First("canonicalizehostname")!.Equals("always", StringComparison.OrdinalIgnoreCase);

        var viaProxy = IsSet("proxycommand") || IsSet("proxyjump") || options.ViaProxy;
        var host = CurrentHost();
        var maxDots = int.TryParse(First("canonicalizemaxdots"), NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : 1;
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
        if (First("canonicalizefallbacklocal")?.ToLowerInvariant() is "no" or "false")
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

        // The family the connection will use: the caller's override (SshConfigConnectOptions.AddressFamily), else the configuration's.
        var family = options.AddressFamily ?? First("addressfamily")?.ToLowerInvariant() switch
        {
            "inet" => SshAddressFamily.Inet,
            "inet6" => SshAddressFamily.Inet6,
            _ => SshAddressFamily.Any,
        };
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

        // Stryker disable once Conditional : the same name back is what the HostName already gives, so taking it changes nothing
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
    /// or unset for no rules. A rule without a colon or with an empty side, which ssh rejects, is left out (<c>none</c> has no colon).
    /// </summary>
    private List<(string Sources, string Targets)> PermittedCnames()
    {
        var rules = new List<(string, string)>();
        if (!_values.TryGetValue("canonicalizepermittedcnames", out var arguments))
        {
            return rules;
        }

        foreach (var argument in arguments)
        {
            var colon = argument.IndexOf(':', StringComparison.Ordinal);

            // Stryker disable once Equality,Arithmetic : an empty side matches no name, and the names and targets compared are never empty
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

    // Stryker disable once String : a resolution asks the canonicalizer about one host and one list of domains, so keys cannot collide
    private static string Key(string host, IReadOnlyList<string> domains) => host + "\0" + string.Join("\0", domains);

    // Stryker disable once String : every lookup of a resolution is for the same family, so the names alone tell keys apart
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
