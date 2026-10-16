namespace SshSharp.Config;

/// <summary>
/// Applies an OpenSSH algorithm list specification (<c>Ciphers</c>, <c>KexAlgorithms</c>, ...) to a default list:
/// a plain list replaces it, <c>+</c> appends, <c>-</c> removes (wildcards allowed), <c>^</c> puts the algorithms first.
/// </summary>
internal static class SshAlgorithmList
{
    /// <summary>Applies <paramref name="specification"/> to <paramref name="defaults"/>.</summary>
    /// <param name="specification">The comma-separated value from the config, possibly starting with <c>+</c>, <c>-</c> or <c>^</c>.</param>
    /// <param name="defaults">The default algorithms, in preference order.</param>
    /// <returns>The resulting list, without duplicates.</returns>
    public static IReadOnlyList<string> Apply(string specification, IReadOnlyList<string> defaults)
    {
        ArgumentNullException.ThrowIfNull(specification);
        ArgumentNullException.ThrowIfNull(defaults);

        var spec = specification.Trim();
        if (spec.Length == 0)
        {
            return [.. defaults];
        }

        var op = spec[0];
        var items = Split(op is '+' or '-' or '^' ? spec[1..] : spec);
        switch (op)
        {
            case '+':
                return Distinct([.. defaults.Where(d => !items.Contains(d, StringComparer.Ordinal)), .. items]);
            case '^':
                return Distinct([.. items, .. defaults]);
            case '-':
                return [.. defaults.Where(d => !items.Any(p => Glob.IsMatch(p, d)))];
            default:
                return Distinct(items);
        }
    }

    private static List<string> Split(string text) =>
        [.. text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    private static List<string> Distinct(IEnumerable<string> items)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return [.. items.Where(seen.Add)];
    }
}