using System.Globalization;

namespace SshSharp.Config;

/// <summary>
/// Walks the config documents for one host and collects the first-obtained value of each keyword. It follows OpenSSH:
/// blocks are evaluated in order against the state collected so far, <c>Include</c> is a closed scope, and a second
/// ("final") pass runs after canonicalization or when a <c>Match final</c> was seen.
/// </summary>
internal sealed class SshConfigResolver(IReadOnlyList<SshConfigDocument> documents, string originalHost, SshConfigResolveOptions options)
{
    private const int MaxIncludeDepth = 16;

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
        var directory = baseDirectory ?? Path.Combine(options.HomeDirectory, ".ssh");
        foreach (var argument in directive.Arguments)
        {
            var path = context.ExpandPath(context.ExpandTokens(argument));
            if (!Path.IsPathRooted(path))
            {
                path = Path.Combine(directory, path);
            }

            IEnumerable<string> files = Glob.HasWildcards(path) ? Glob.ExpandFiles(path) : File.Exists(path) ? [path] : [];
            foreach (var file in files)
            {
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
            _values[key] = key.Equals("proxycommand", StringComparison.OrdinalIgnoreCase)
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
                case "host" or "originalhost" or "user" or "localuser" or "tagged" or "exec":
                    if (++i >= criteria.Count)
                    {
                        throw new FormatException($"Match criterion '{name}' needs an argument.");
                    }

                    value = result && EvaluateWithArgument(name, criteria[i]);
                    break;
                case "localnetwork" or "version" or "sessiontype" or "command":
                    // Criteria this library cannot evaluate (newer OpenSSH, or about the local network or session). The block never
                    // applies, negated or not: guessing either way could apply settings meant for another situation.
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
        "exec" => options.ExecMatcher is { } run && run(Context().ExpandTokens(argument)),
        _ => false,
    };

    private string? TryCanonicalize()
    {
        if (options.HostCanonicalizer is not { } canonicalizer || !_values.TryGetValue("canonicalizehostname", out var setting) || setting.Count == 0)
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
        if ((!always && viaProxy) || host.Count(c => c == '.') > maxDots)
        {
            return null;
        }

        var domains = _values.TryGetValue("canonicaldomains", out var list) ? list : [];
        var canonical = canonicalizer(host, domains);
        if (canonical is null && _values.TryGetValue("canonicalizefallbacklocal", out var fallback) && fallback.Count > 0
            && fallback[0].ToLowerInvariant() is "no" or "false")
        {
            throw new InvalidOperationException($"Could not canonicalize host name '{host}' and CanonicalizeFallbackLocal is off.");
        }

        return canonical;
    }
}