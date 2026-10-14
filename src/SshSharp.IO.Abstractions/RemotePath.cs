namespace SshSharp.IO.Abstractions;

/// <summary>POSIX path operations for server paths: <c>/</c> is the only separator and the only root.</summary>
internal static class RemotePath
{
    public const char Separator = '/';

    public static bool IsRooted(ReadOnlySpan<char> path) => path.Length > 0 && path[0] == Separator;

    /// <summary>The two parts joined with exactly one separator (none added when either is empty).</summary>
    public static string Join(ReadOnlySpan<char> first, ReadOnlySpan<char> second)
    {
        if (first.IsEmpty)
        {
            return second.ToString();
        }

        if (second.IsEmpty)
        {
            return first.ToString();
        }

        return first[^1] == Separator || second[0] == Separator ? string.Concat(first, second) : string.Concat(first, "/", second);
    }

    /// <summary>Like <c>Path.Combine</c>: a rooted part replaces everything before it.</summary>
    public static string Combine(IEnumerable<string> parts)
    {
        var result = string.Empty;
        foreach (var part in parts)
        {
            ArgumentNullException.ThrowIfNull(part, nameof(parts));
            result = IsRooted(part) ? part : Join(result, part);
        }

        return result;
    }

    /// <summary>An absolute path with <c>.</c>, <c>..</c> and repeated separators resolved (<c>..</c> at the root stays at the root).</summary>
    public static string Normalize(string absolute)
    {
        var parts = new List<string>();
        foreach (var part in absolute.Split(Separator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                if (parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            parts.Add(part);
        }

        return "/" + string.Join(Separator, parts);
    }

    /// <summary>The part after the last separator.</summary>
    public static ReadOnlySpan<char> FileName(ReadOnlySpan<char> path) => path[(path.LastIndexOf(Separator) + 1)..];

    /// <summary>
    /// The part before the last separator, as <c>Path.GetDirectoryName</c> does on Unix: empty when there is no separator, and nothing
    /// (signalled by <paramref name="isRoot"/>) for the root itself.
    /// </summary>
    public static ReadOnlySpan<char> DirectoryName(ReadOnlySpan<char> path, out bool isRoot)
    {
        isRoot = false;
        var trimmed = path;
        while (trimmed.Length > 1 && trimmed[^1] == Separator)
        {
            trimmed = trimmed[..^1]; // a trailing separator belongs to the last component
        }

        if (trimmed.Length == 1 && trimmed[0] == Separator)
        {
            isRoot = true;
            return ReadOnlySpan<char>.Empty;
        }

        if (path.Length > 0 && path[^1] == Separator)
        {
            // "a/b/" names the directory a/b: its directory name is a/b, as .NET does.
            return path.TrimEnd(Separator).IsEmpty ? "/" : path.TrimEnd(Separator);
        }

        var last = path.LastIndexOf(Separator);
        if (last < 0)
        {
            return ReadOnlySpan<char>.Empty;
        }

        var directory = path[..last].TrimEnd(Separator);
        return directory.IsEmpty ? "/" : directory;
    }

    /// <summary>The extension of the file name, with its dot; empty when there is none (a trailing dot counts as none).</summary>
    public static ReadOnlySpan<char> Extension(ReadOnlySpan<char> path)
    {
        var name = FileName(path);
        var dot = name.LastIndexOf('.');
        return dot <= 0 || dot == name.Length - 1 ? ReadOnlySpan<char>.Empty : name[dot..];
    }

    public static ReadOnlySpan<char> FileNameWithoutExtension(ReadOnlySpan<char> path)
    {
        var name = FileName(path);
        var dot = name.LastIndexOf('.');
        return dot <= 0 ? name : name[..dot];
    }

    /// <summary>The path of <paramref name="path"/> relative to <paramref name="relativeTo"/>, both absolute and normalized.</summary>
    public static string Relative(string relativeTo, string path)
    {
        var from = relativeTo.Split(Separator, StringSplitOptions.RemoveEmptyEntries);
        var to = path.Split(Separator, StringSplitOptions.RemoveEmptyEntries);
        var common = 0;
        while (common < from.Length && common < to.Length && from[common] == to[common])
        {
            common++;
        }

        var parts = Enumerable.Repeat("..", from.Length - common).Concat(to.Skip(common)).ToArray();
        return parts.Length == 0 ? "." : string.Join(Separator, parts);
    }
}
