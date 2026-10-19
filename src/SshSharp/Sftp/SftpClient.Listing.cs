using System.Runtime.CompilerServices;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>
    /// Lists a directory with <paramref name="options"/>: only the names that match <see cref="SftpListOptions.Pattern"/>, and with
    /// <see cref="SftpListOptions.Recursive"/> everything below it as well, depth first: a subdirectory's whole subtree follows the
    /// subdirectory's own entry, before the entries the server listed after it. Each directory is listed as
    /// <see cref="ListDirectoryAsync(string, CancellationToken)"/> lists it (pipelined, without <c>.</c> and <c>..</c>) and nothing is
    /// sorted: within a directory the entries come in the server's order, which is often the file system's and need not be
    /// alphabetical, so a file may come before or after a sibling directory's subtree. The order is the same every time the server
    /// returns the same listings; sort the results when you need a fixed one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A recursive listing reads up to <see cref="SftpListOptions.MaxConcurrentDirectories"/> subdirectories ahead while the caller
    /// works through the entries already listed, each subdirectory read whole (its handle closed) before its entries are returned. It
    /// goes no deeper than <see cref="SftpListOptions.MaxDepth"/>. Symbolic links are listed but not entered unless
    /// <see cref="SftpListOptions.FollowSymbolicLinks"/> is set. A subdirectory that cannot be listed (permission denied, or deleted
    /// meanwhile) ends the listing with its <see cref="SftpException"/> when the listing reaches it.
    /// </para>
    /// <para>
    /// Stopping early (leaving an <c>await foreach</c>) or cancelling stops the listings read ahead and waits for them to close their
    /// handles.
    /// </para>
    /// </remarks>
    /// <param name="path">The directory to list.</param>
    /// <param name="options">The pattern, and whether and how to descend into subdirectories.</param>
    /// <param name="cancellationToken">Cancels the listing.</param>
    /// <exception cref="SftpException">The directory, or a subdirectory of a recursive listing, cannot be listed.</exception>
    public IAsyncEnumerable<SftpFileInfo> ListDirectoryAsync(string path, SftpListOptions options, CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        ArgumentNullException.ThrowIfNull(options);
        var pattern = options.Pattern is { } text ? SftpGlob.Parse(text) : null;
        return options.Recursive ? ListTreeAsync(path, options, pattern, cancellationToken) : ListMatchingAsync(path, pattern, cancellationToken);
    }

    private async IAsyncEnumerable<SftpFileInfo> ListMatchingAsync(string path, SftpGlob? pattern, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var entry in ListDirectoryAsync(path, cancellationToken).ConfigureAwait(false))
        {
            if (pattern?.IsMatch(entry.Name) != false)
            {
                yield return entry;
            }
        }
    }

    /// <summary>
    /// The recursive listing: a stack of listed directories, the top one's entries returned in order, and each subdirectory's listing
    /// pushed when its entry has been returned. The listings of the top directory's subdirectories are started ahead, in entry order,
    /// while one of the slots is free; one not started by the time it is reached is started then, waiting for a slot. A slot is held only
    /// while a listing is read, so a listing waiting for one always gets it, and at most that many handles are open at once.
    /// </summary>
    private async IAsyncEnumerable<SftpFileInfo> ListTreeAsync(string path, SftpListOptions options, SftpGlob? pattern,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // A server that limits open handles keeps one free for the caller's other work.
        var concurrency = Limits.MaxOpenHandles is { } handles
            ? Math.Clamp(handles - 1, 1, options.MaxConcurrentDirectories)
            : options.MaxConcurrentDirectories;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var slots = new SemaphoreSlim(concurrency, concurrency);
        var started = new List<Task>();
        try
        {
            // With links followed, every directory's real path is known (the top one's from the server, the others' from their parent's,
            // or for a link from the server again), so a link to a directory the listing is already inside can be told apart.
            var realPath = options.FollowSymbolicLinks ? await GetFullPathAsync(path, stop.Token).ConfigureAwait(false) : null;
            var stack = new Stack<ListedDirectory>();
            stack.Push(await ReadListingAsync(path, realPath, parent: null, options, stop.Token).ConfigureAwait(false));
            while (stack.TryPeek(out var directory))
            {
                cancellationToken.ThrowIfCancellationRequested(); // entries already listed are not returned once cancelled
                StartAhead(directory);
                if (directory.Next == directory.Entries.Count)
                {
                    stack.Pop();
                    continue;
                }

                var index = directory.Next++;
                var entry = directory.Entries[index];
                if (pattern?.IsMatch(entry.Name) != false)
                {
                    yield return entry;
                }

                if (directory.Descents[index] is { } descent)
                {
                    directory.Descents[index] = null;
                    descent.Listing ??= Start(descent, directory, slotTaken: false);
                    if (await descent.Listing.ConfigureAwait(false) is { } child)
                    {
                        stack.Push(child);
                    }
                }
            }
        }
        finally
        {
            // Listings read ahead that nobody will reach: stopped, and waited for, so their handles are closed when this returns.
            await stop.CancelAsync().ConfigureAwait(false);
            foreach (var task in started)
            {
                await task.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }
        }

        void StartAhead(ListedDirectory directory)
        {
            for (; directory.NextToStart < directory.Entries.Count; directory.NextToStart++)
            {
                if (directory.Descents[directory.NextToStart] is not { Listing: null } descent)
                {
                    continue;
                }

                if (!slots.Wait(0, stop.Token))
                {
                    return;
                }

                descent.Listing = Start(descent, directory, slotTaken: true);
            }
        }

        Task<ListedDirectory?> Start(Descent descent, ListedDirectory parent, bool slotTaken)
        {
            var task = DescendAsync(descent.Entry, parent, slotTaken, stop.Token);
            if (started.Count >= 64)
            {
                // Those done need no waiting for at the end; dropping them lets their listings go once returned. A failure among them
                // is the descent's to report, if the listing reaches it: marked observed here in case it does not.
                started.RemoveAll(t => t.IsCompleted && (!t.IsFaulted || t.Exception is not null));
            }

            started.Add(task);
            return task;
        }

        async Task<ListedDirectory?> DescendAsync(SftpFileInfo entry, ListedDirectory parent, bool slotTaken, CancellationToken token)
        {
            if (!slotTaken)
            {
                await slots.WaitAsync(token).ConfigureAwait(false); // outside the try: a wait that is cancelled holds no slot to release
            }

            try
            {
                string? real = null;
                if (entry.Attributes.IsSymbolicLink)
                {
                    SftpFileAttributes target;
                    try
                    {
                        target = await GetAttributesAsync(entry.FullPath, followSymbolicLinks: true, token).ConfigureAwait(false);
                    }
                    catch (SftpException)
                    {
                        return null; // a dangling link, or a target this user may not look at: listed, not entered
                    }

                    if (!target.IsDirectory)
                    {
                        return null;
                    }

                    real = await GetFullPathAsync(entry.FullPath, token).ConfigureAwait(false);
                    for (var ancestor = parent; ancestor is not null; ancestor = ancestor.Parent)
                    {
                        if (string.Equals(ancestor.RealPath, real, StringComparison.Ordinal))
                        {
                            return null; // a loop: the link leads back to a directory this one is inside
                        }
                    }
                }
                else if (parent.RealPath is { } parentReal)
                {
                    real = parentReal.EndsWith('/') ? parentReal + entry.Name : parentReal + "/" + entry.Name;
                }

                return await ReadListingAsync(entry.FullPath, real, parent, options, token).ConfigureAwait(false);
            }
            finally
            {
                slots.Release();
            }
        }
    }

    /// <summary>Reads a directory of a recursive listing whole, and finds the subdirectories (and links, if followed) to descend into.</summary>
    private async Task<ListedDirectory> ReadListingAsync(string path, string? realPath, ListedDirectory? parent, SftpListOptions options,
        CancellationToken cancellationToken)
    {
        var entries = new List<SftpFileInfo>();
        await foreach (var entry in ListDirectoryAsync(path, cancellationToken).ConfigureAwait(false))
        {
            entries.Add(entry);
        }

        var directory = new ListedDirectory(entries, (parent?.Depth ?? 0) + 1, realPath, parent);
        if (directory.Depth < options.MaxDepth)
        {
            // A name listed twice (a broken or hostile server) is entered once: otherwise every level could double the work.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < entries.Count; i++)
            {
                var attributes = entries[i].Attributes;
                if ((attributes.IsDirectory || (options.FollowSymbolicLinks && attributes.IsSymbolicLink)) && seen.Add(entries[i].Name))
                {
                    directory.Descents[i] = new Descent(entries[i]);
                }
            }
        }

        return directory;
    }

    /// <summary>A directory of a recursive listing: its entries, at <paramref name="depth"/> (1 for the top one's), and where the listing is in them.</summary>
    private sealed class ListedDirectory(List<SftpFileInfo> entries, int depth, string? realPath, ListedDirectory? parent)
    {
        public List<SftpFileInfo> Entries { get; } = entries;

        public int Depth { get; } = depth;

        /// <summary>The directory's path as the server resolves it, when links are followed; null otherwise.</summary>
        public string? RealPath { get; } = realPath;

        public ListedDirectory? Parent { get; } = parent;

        /// <summary>For each entry, the subdirectory to descend into after it, if any; cleared once descended.</summary>
        public Descent?[] Descents { get; } = new Descent?[entries.Count];

        /// <summary>The next entry to return.</summary>
        public int Next { get; set; }

        /// <summary>The next entry whose subdirectory listing may be started ahead.</summary>
        public int NextToStart { get; set; }
    }

    /// <summary>A subdirectory (or a link that may lead to one) to descend into, and its listing once started; null when not entered.</summary>
    private sealed class Descent(SftpFileInfo entry)
    {
        public SftpFileInfo Entry { get; } = entry;

        public Task<ListedDirectory?>? Listing { get; set; }
    }
}

/// <summary>Options for <see cref="SftpClient.ListDirectoryAsync(string, SftpListOptions, CancellationToken)"/>.</summary>
public sealed class SftpListOptions
{
    /// <summary>
    /// List only the entries whose name matches this shell-style pattern; null (the default) lists every entry. <c>*</c> matches any run
    /// of characters, <c>?</c> any one character, and <c>[...]</c> one character of a set: <c>[abc]</c>, a range <c>[0-9]</c>, or a
    /// negated set <c>[!a-z]</c> (or <c>[^a-z]</c>); <c>\</c> takes the next character literally. The match is on the whole name (not
    /// the path) and case-sensitive, as on the POSIX file systems most servers have. Unlike a shell, <c>*</c> and <c>?</c> also match a
    /// leading dot, so <c>*</c> includes hidden files. In a recursive listing the pattern selects the entries returned, not the
    /// directories descended into: <c>*.log</c> finds the log files at every level, as <c>find -name</c> does.
    /// </summary>
    /// <remarks>
    /// Matching is by Unicode code point, so <c>?</c> matches one character outside the Basic Multilingual Plane (an emoji, say). A
    /// <c>[</c> without a closing <c>]</c> matches itself, as in fnmatch(3); POSIX named classes (<c>[[:digit:]]</c>) are not supported.
    /// </remarks>
    public string? Pattern { get; init; }

    /// <summary>
    /// List the subdirectories too, and theirs, depth first: a directory's subtree follows its own entry, before its later siblings,
    /// with each directory's entries in the server's order, unsorted (default false: the directory's entries only).
    /// </summary>
    public bool Recursive { get; init; }

    /// <summary>
    /// How many levels a recursive listing goes down (default 64, as directory transfers): 1 lists the directory's own entries, 2 also
    /// those of its subdirectories, and so on. Directories at the last level are listed but not entered. Unlike a directory transfer,
    /// which fails on a deeper tree, a listing just stops descending.
    /// </summary>
    public int MaxDepth
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 1024);
            field = value;
        }
    } = 64;

    /// <summary>
    /// In a recursive listing, enter symbolic links that lead to directories (default false: links are listed, described by their own
    /// attributes, and not entered). Each link costs two extra round trips (its target's attributes, and its real path); a dangling link,
    /// or one whose target cannot be looked at, is listed and not entered. A link back to a directory the listing is already inside (a
    /// loop) is not entered.
    /// </summary>
    /// <remarks>
    /// Loops are recognized by the real path the server resolves the link to (SSH_FXP_REALPATH). OpenSSH resolves links there; a server
    /// that does not leaves a loop to be stopped by <see cref="MaxDepth"/>. Links may lead anywhere the server lets this user see,
    /// outside the directory listed.
    /// </remarks>
    public bool FollowSymbolicLinks { get; init; }

    /// <summary>
    /// How many subdirectories a recursive listing reads at once, ahead of the entries being returned (default 4, at most 64). Each holds
    /// a directory handle while it is read; when the server announces <see cref="SftpLimits.MaxOpenHandles"/>, fewer are read at once if
    /// needed, keeping a handle free.
    /// </summary>
    public int MaxConcurrentDirectories
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 64);
            field = value;
        }
    } = 4;
}
