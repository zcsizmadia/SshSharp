using SshSharp.Sftp;

namespace SshSharp.IO.Abstractions;

/// <summary>Directory enumeration as <c>Directory.Enumerate*</c> does it: wildcards, recursion and <see cref="EnumerationOptions"/>.</summary>
internal static class Search
{
    public enum Kind
    {
        Files,
        Directories,
        Both,
    }

    /// <summary>
    /// An entry found: the path to return (the given path joined with names), the server path, its own attributes (a link's are the
    /// link's), what a link points to (null for other entries, and for a link that leads nowhere), and whether it is a directory.
    /// </summary>
    public readonly record struct Entry(string Path, string FullPath, string Name, SftpFileAttributes Attributes, SftpFileAttributes? Target, bool IsDirectory);

    /// <summary>
    /// The options the <see cref="SearchOption"/> overloads use: recursion as asked, nothing skipped, and inaccessible directories an
    /// error. (The <see cref="EnumerationOptions"/> overloads default to skipping hidden and system entries and ignoring inaccessible
    /// directories, as .NET's do.)
    /// </summary>
    public static EnumerationOptions Legacy(SearchOption searchOption) => new()
    {
        RecurseSubdirectories = searchOption == SearchOption.AllDirectories,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        MatchType = MatchType.Win32,
    };

    /// <summary>The matching entries; a missing directory fails here, before the first entry.</summary>
    public static IEnumerable<Entry> Entries(SftpFileSystem fileSystem, string path, string searchPattern, EnumerationOptions options, Kind kind)
    {
        ArgumentNullException.ThrowIfNull(searchPattern);
        ArgumentNullException.ThrowIfNull(options);
        var full = fileSystem.Full(path);
        if (fileSystem.Stat(full) is not { IsDirectory: true })
        {
            throw new DirectoryNotFoundException($"Could not find a part of the path '{path}'.");
        }

        return Walk(fileSystem, path, full, searchPattern, options, kind, 0);
    }

    private static IEnumerable<Entry> Walk(SftpFileSystem fileSystem, string display, string full, string pattern, EnumerationOptions options, Kind kind, int depth)
    {
        List<SftpFileInfo> listing;
        try
        {
            listing = fileSystem.Run(full, true, async (sftp, ct) =>
            {
                var entries = new List<SftpFileInfo>();
                await foreach (var entry in sftp.ListDirectoryAsync(full, ct).ConfigureAwait(false))
                {
                    entries.Add(entry);
                }

                return entries;
            }, retry: true);
        }
        catch (UnauthorizedAccessException) when (options.IgnoreInaccessible && depth > 0)
        {
            yield break;
        }

        if (options.ReturnSpecialDirectories && kind != Kind.Files)
        {
            foreach (var special in new[] { ".", ".." })
            {
                if (Matches(special, pattern, options))
                {
                    yield return new Entry(RemotePath.Join(display, special), RemotePath.Join(full, special), special, new SftpFileAttributes { FileType = SftpFileType.Directory }, null, true);
                }
            }
        }

        foreach (var item in listing.OrderBy(e => e.Name, StringComparer.Ordinal))
        {
            var attributes = item.Attributes;
            var childFull = RemotePath.Join(full, item.Name);
            var target = attributes.IsSymbolicLink ? fileSystem.Stat(childFull) : null;
            var isDirectory = attributes.IsDirectory || target is { IsDirectory: true };
            if ((Attributes.From(attributes, item.Name, target) & options.AttributesToSkip) != 0)
            {
                continue; // skipped entirely, as .NET does: a hidden directory is not searched either
            }

            var childDisplay = RemotePath.Join(display, item.Name);
            var wanted = kind == Kind.Both || (kind == Kind.Directories) == isDirectory;
            if (wanted && Matches(item.Name, pattern, options))
            {
                yield return new Entry(childDisplay, childFull, item.Name, attributes, target, isDirectory);
            }

            // Links to directories are listed but not followed, so a link cannot loop the search.
            if (options.RecurseSubdirectories && attributes.IsDirectory && depth < options.MaxRecursionDepth)
            {
                foreach (var nested in Walk(fileSystem, childDisplay, childFull, pattern, options, kind, depth + 1))
                {
                    yield return nested;
                }
            }
        }
    }

    /// <summary>
    /// Whether a name matches a search pattern: <c>*</c> any run of characters, <c>?</c> one character, and <c>*.*</c> everything, as
    /// .NET's Win32 matching treats it. Case-sensitive (the server's file names are) unless <see cref="MatchCasing.CaseInsensitive"/>.
    /// </summary>
    public static bool Matches(string name, string pattern, EnumerationOptions options)
    {
        if (pattern is "*" or "" || (pattern == "*.*" && options.MatchType == MatchType.Win32))
        {
            return true;
        }

        var ignoreCase = options.MatchCasing == MatchCasing.CaseInsensitive;
        return Wildcard(name.AsSpan(), pattern.AsSpan(), ignoreCase);
    }

    private static bool Wildcard(ReadOnlySpan<char> name, ReadOnlySpan<char> pattern, bool ignoreCase)
    {
        // Iterative matching with backtracking to the last '*': linear in practice, no recursion on hostile patterns.
        int n = 0, p = 0, star = -1, mark = 0;
        while (n < name.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || Same(pattern[p], name[n], ignoreCase)))
            {
                n++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = n;
            }
            else if (star >= 0)
            {
                p = star + 1;
                n = ++mark;
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

    private static bool Same(char a, char b, bool ignoreCase) => a == b || (ignoreCase && char.ToUpperInvariant(a) == char.ToUpperInvariant(b));
}
