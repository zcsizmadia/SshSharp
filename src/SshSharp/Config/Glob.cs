namespace SshSharp.Config;

/// <summary>OpenSSH-style glob matching (<c>*</c> and <c>?</c>), case-insensitive unless asked otherwise (as for user names and principals).</summary>
internal static class Glob
{
    public static bool IsMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text, bool ignoreCase = true)
    {
        int p = 0, t = 0, starP = -1, starT = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                starP = p++;
                starT = t;
            }
            else if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t] || (ignoreCase && CharsEqual(pattern[p], text[t]))))
            {
                p++;
                t++;
            }
            else if (starP >= 0)
            {
                p = starP + 1;
                t = ++starT;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    /// <summary>
    /// Matches <paramref name="text"/> against a comma-separated pattern list with <c>!</c> negation: a matching negated pattern
    /// rejects the text, otherwise any matching positive pattern accepts it.
    /// </summary>
    public static bool IsMatchList(ReadOnlySpan<char> patterns, ReadOnlySpan<char> text, bool ignoreCase = true)
    {
        var matched = false;
        var remaining = patterns;
        while (!remaining.IsEmpty)
        {
            var comma = remaining.IndexOf(',');
            var pattern = comma < 0 ? remaining : remaining[..comma];
            remaining = comma < 0 ? default : remaining[(comma + 1)..];
            if (pattern.IsEmpty)
            {
                continue;
            }

            if (pattern[0] == '!')
            {
                if (IsMatch(pattern[1..], text, ignoreCase))
                {
                    return false;
                }
            }
            else if (IsMatch(pattern, text, ignoreCase))
            {
                matched = true;
            }
        }

        return matched;
    }

    /// <summary>Whether the pattern contains wildcard characters.</summary>
    public static bool HasWildcards(string pattern) => pattern.AsSpan().IndexOfAny('*', '?') >= 0;

    /// <summary>
    /// Expands a rooted path pattern to existing files, in ordinal order. Wildcards may appear in any path segment and do not
    /// match names starting with a dot unless the pattern segment does.
    /// </summary>
    public static IReadOnlyList<string> ExpandFiles(string pattern)
    {
        // Stryker disable once String : GetPathRoot returns null only for a null path
        var root = Path.GetPathRoot(pattern) ?? string.Empty;
        var segments = pattern[root.Length..].Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        List<string> current = [root];
        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            var isLast = i == segments.Length - 1;
            List<string> next = [];
            foreach (var dir in current)
            {
                if (!HasWildcards(segment))
                {
                    var candidate = Path.Join(dir, segment);
                    if (isLast ? File.Exists(candidate) : Directory.Exists(candidate))
                    {
                        next.Add(candidate);
                    }

                    continue;
                }

                // Stryker disable once Block,Statement : every directory listed was just seen to exist, except the root, which exists unless it
                // names a missing drive
                if (!Directory.Exists(dir))
                {
                    continue;
                }

                var names = Directory.EnumerateFileSystemEntries(dir)
                    .Select(e => Path.GetFileName(e))
                    .Where(n => (segment[0] == '.' || n[0] != '.') && IsMatch(segment, n))
                    .Order(StringComparer.Ordinal);
                foreach (var name in names)
                {
                    var candidate = Path.Join(dir, name);
                    if (isLast ? File.Exists(candidate) : Directory.Exists(candidate))
                    {
                        next.Add(candidate);
                    }
                }
            }

            current = next;
        }

        return segments.Length == 0 ? [] : current;
    }

    private static bool CharsEqual(char a, char b) => a == b || char.ToLowerInvariant(a) == char.ToLowerInvariant(b);
}