using System.Collections.Concurrent;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using SshSharp.Adapters;
using SshSharp.Sftp;

namespace SshSharp.FileProviders;

/// <summary>
/// An <see cref="IFileProvider"/> over SFTP: the files under a directory on an SSH server, for ASP.NET Core static files, Razor views,
/// configuration and anything else that reads through <c>Microsoft.Extensions.FileProviders</c>. Read-only; nothing is mounted, so only
/// this application sees the files.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IFileProvider"/> is synchronous, so each lookup waits for an SFTP round trip; attributes and listings are cached for
/// <see cref="SftpFileProviderOptions.CacheDuration"/> to keep that cheap. Streams from <see cref="IFileInfo.CreateReadStream"/> read ahead,
/// and are fastest read asynchronously (as ASP.NET Core's static files middleware does).
/// </para>
/// <para>
/// Paths cannot leave <see cref="Root"/>: any <c>..</c> segment gives a file that does not exist. Symbolic links are followed (on the
/// server, which decides where they lead). <see cref="Watch"/> never signals: SFTP has no change notifications.
/// </para>
/// <para>
/// Built from a session factory (<see cref="SftpFileProvider(Func{CancellationToken, Task{SftpClient}}, string, SftpFileProviderOptions?)"/>),
/// the provider follows a connection that drops and comes back: it keeps one session while it works, and opens a new one after the
/// session or its connection fails, trying the failed lookup once more on it. Built from one <see cref="SftpClient"/>, it uses that
/// session for its lifetime, and fails once it fails.
/// </para>
/// </remarks>
public sealed class SftpFileProvider : IFileProvider, IDisposable, IAsyncDisposable
{
    private readonly SftpSessions _sessions;
    private readonly SftpFileProviderOptions _options;
    private readonly ConcurrentDictionary<string, (long Expires, SftpFileAttributes? Attributes)> _attributes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (long Expires, List<IFileInfo>? Entries)> _listings = new(StringComparer.Ordinal);

    /// <summary>Serves the files under <paramref name="root"/> on the server.</summary>
    /// <param name="sftp">The SFTP session to use; it stays the caller's to dispose, after the provider is no longer used.</param>
    /// <param name="root">The directory on the server, absolute or relative to the login directory (<c>.</c> for the login directory itself).</param>
    /// <param name="options">Caching and timeouts.</param>
    public SftpFileProvider(SftpClient sftp, string root, SftpFileProviderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sftp);
        ArgumentException.ThrowIfNullOrEmpty(root);
        _options = options ?? new SftpFileProviderOptions();
        _sessions = new SftpSessions(sftp);
        Root = root.Length > 1 ? root.TrimEnd('/') : root;
    }

    /// <summary>
    /// Serves the files under <paramref name="root"/> on the server, through sessions from <paramref name="sessionFactory"/>: one is
    /// opened on the first lookup and shared by every lookup after it, and a new one is opened when the session or its connection
    /// fails. The provider owns the sessions it opens and disposes them (dispose the provider when it is no longer used).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only a session that has ended is replaced (<see cref="SftpClient.IsConnected"/> false: the connection dropped, a keep-alive
    /// declared it dead, and so on), and one found ended before a lookup is replaced before that lookup uses it; a missing or
    /// unreadable file, or one request's timeout, is not a failure of the session. Lookups that find no session
    /// share one call to the factory, so a dropped connection is followed by one reconnect, not one per request; a lookup that fails
    /// because the connection dropped is tried once more on a new session. If the factory fails, the lookup fails with an
    /// <see cref="SshException"/> and the next one calls the factory again. Opening a session counts against
    /// <see cref="SftpFileProviderOptions.OperationTimeout"/>.
    /// </para>
    /// <para>
    /// The factory opens a session on a connection it manages: the provider disposes the <see cref="SftpClient"/>, never the connection
    /// under it. With the dependency injection package, <c>ct =&gt; connections.OpenSftpAsync("name", ct)</c> opens it on the shared
    /// connection, which is itself opened again when it drops. Streams already open on a failed session fail; open them again.
    /// </para>
    /// </remarks>
    /// <param name="sessionFactory">Opens a new SFTP session; called on the first lookup and after a failure, never concurrently.</param>
    /// <param name="root">The directory on the server, absolute or relative to the login directory (<c>.</c> for the login directory itself).</param>
    /// <param name="options">Caching and timeouts.</param>
    public SftpFileProvider(Func<CancellationToken, Task<SftpClient>> sessionFactory, string root, SftpFileProviderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sessionFactory);
        ArgumentException.ThrowIfNullOrEmpty(root);
        _options = options ?? new SftpFileProviderOptions();
        _sessions = new SftpSessions(sessionFactory, _options.OperationTimeout);
        Root = root.Length > 1 ? root.TrimEnd('/') : root;
    }

    /// <summary>The directory on the server that the provider serves.</summary>
    public string Root { get; }

    /// <summary>The file at <paramref name="subpath"/>, or one with <see cref="IFileInfo.Exists"/> false.</summary>
    /// <exception cref="SshException">The SFTP session or the connection failed (not for a file that is missing or not allowed).</exception>
    public IFileInfo GetFileInfo(string subpath)
    {
        if (RemotePath(subpath) is not { } path)
        {
            return new NotFoundFileInfo(subpath ?? string.Empty);
        }

        var name = path == Root ? Path.GetFileName(Root) : path[(path.LastIndexOf('/') + 1)..];
        return GetAttributes(path) is { } attributes ? new SftpProviderFileInfo(this, path, name, attributes) : new NotFoundFileInfo(name);
    }

    /// <summary>The entries of the directory at <paramref name="subpath"/>, or contents with <see cref="IDirectoryContents.Exists"/> false.</summary>
    /// <exception cref="SshException">The SFTP session or the connection failed.</exception>
    public IDirectoryContents GetDirectoryContents(string subpath)
    {
        if (RemotePath(subpath) is not { } path)
        {
            return NotFoundDirectoryContents.Singleton;
        }

        var now = Environment.TickCount64;
        if (!_listings.TryGetValue(path, out var cached) || cached.Expires < now)
        {
            cached = (Expiry(now), List(path));
            Remember(_listings, path, cached, now);
        }

        return cached.Entries is { } entries ? new Contents(entries) : NotFoundDirectoryContents.Singleton;
    }

    /// <summary>When an entry cached at <paramref name="now"/> expires; a huge <see cref="SftpFileProviderOptions.CacheDuration"/> saturates.</summary>
    private long Expiry(long now)
    {
        var duration = _options.CacheDuration.TotalMilliseconds;
        return duration >= long.MaxValue - now ? long.MaxValue : now + (long)duration;
    }

    /// <summary>
    /// Caches an entry, keeping the cache within <see cref="SftpFileProviderOptions.MaxCacheEntries"/>: when it is full, expired entries go
    /// first, and if that is not enough the cache starts over. Lookups of paths that do not exist are cached too, so without the bound
    /// requests for random paths would grow it without limit.
    /// </summary>
    private void Remember<T>(ConcurrentDictionary<string, (long Expires, T Value)> cache, string path, (long Expires, T Value) entry, long now)
    {
        if (_options.CacheDuration <= TimeSpan.Zero)
        {
            return;
        }

        if (cache.Count >= _options.MaxCacheEntries && !cache.ContainsKey(path))
        {
            foreach (var (key, value) in cache)
            {
                if (value.Expires < now)
                {
                    cache.TryRemove(key, out _);
                }
            }

            if (cache.Count >= _options.MaxCacheEntries)
            {
                cache.Clear();
            }
        }

        cache[path] = entry;
    }

    /// <summary>A token that never changes: SFTP cannot tell when a file changes.</summary>
    public IChangeToken Watch(string filter) => NullChangeToken.Singleton;

    /// <summary>Forgets the cached attributes and listings, so the next lookups ask the server.</summary>
    public void ClearCache()
    {
        _attributes.Clear();
        _listings.Clear();
    }

    /// <summary>
    /// The server path for <paramref name="subpath"/> under <see cref="Root"/>, or null when it would leave the root: <c>/</c> and
    /// <c>\</c> both separate segments, empty and <c>.</c> segments are dropped, and any <c>..</c> is refused.
    /// </summary>
    internal string? RemotePath(string? subpath)
    {
        if (subpath is null || subpath.Contains('\0'))
        {
            return null;
        }

        var segments = subpath.Split('/', '\\').Where(s => s.Length > 0 && s != ".").ToArray();
        if (segments.Contains(".."))
        {
            return null;
        }

        return segments.Length == 0 ? Root : (Root == "/" ? "/" : Root + "/") + string.Join('/', segments);
    }

    /// <summary>The attributes of <paramref name="path"/>, following links; null when it does not exist or may not be read.</summary>
    internal SftpFileAttributes? GetAttributes(string path)
    {
        var now = Environment.TickCount64;
        if (_attributes.TryGetValue(path, out var cached) && cached.Expires >= now)
        {
            return cached.Attributes;
        }

        SftpFileAttributes? attributes;
        try
        {
            attributes = Run((sftp, ct) => sftp.GetAttributesAsync(path, followSymbolicLinks: true, ct));
        }
        catch (SftpException)
        {
            attributes = null; // missing, or not allowed: either way there is no file to serve
        }

        Remember(_attributes, path, (Expiry(now), attributes), now);
        return attributes;
    }

    private List<IFileInfo>? List(string path)
    {
        try
        {
            return Run(async (sftp, ct) =>
            {
                var entries = new List<IFileInfo>();
                await foreach (var entry in sftp.ListDirectoryAsync(path, ct).ConfigureAwait(false))
                {
                    var attributes = entry.Attributes;
                    if (attributes.IsSymbolicLink)
                    {
                        // A listing describes a link itself; serve what it points to, and leave out links that lead nowhere.
                        try
                        {
                            attributes = await sftp.GetAttributesAsync(entry.FullPath, followSymbolicLinks: true, ct).ConfigureAwait(false);
                        }
                        catch (SftpException)
                        {
                            continue;
                        }
                    }

                    entries.Add(new SftpProviderFileInfo(this, path == "/" ? "/" + entry.Name : path + "/" + entry.Name, entry.Name, attributes));
                }

                return entries;
            });
        }
        catch (SftpException)
        {
            return null; // not a directory, missing, or not allowed
        }
    }

    internal Stream OpenRead(string path, long length) =>
        new BlockingReadStream(Run((sftp, ct) => sftp.OpenReadAsync(path, ct)), length, _options.OperationTimeout);

    /// <summary>
    /// Runs an SFTP operation to completion for a synchronous caller, bounded by <see cref="SftpFileProviderOptions.OperationTimeout"/>.
    /// It runs on the thread pool, so a caller with a synchronization context (a UI thread) cannot deadlock it; the calling thread waits
    /// meanwhile, which is why lookups are cached. Every operation only reads, so one that fails because the connection dropped is
    /// tried once more on a new session, when the provider has a session factory.
    /// </summary>
    internal T Run<T>(Func<SftpClient, CancellationToken, Task<T>> operation) =>
        Run(_options.OperationTimeout, ct => _sessions.RunAsync(operation, retry: true, ct));

    /// <summary>
    /// Disposes the SFTP sessions the provider opened from its session factory; later lookups throw <see cref="ObjectDisposedException"/>.
    /// A provider built from one <see cref="SftpClient"/> leaves that session alone: it stays the caller's, and this does nothing.
    /// </summary>
    public ValueTask DisposeAsync() => _sessions.DisposeAsync();

    /// <summary>Disposes the provider as <see cref="DisposeAsync"/> does, waiting for it (on the thread pool, as lookups do).</summary>
    public void Dispose() =>
        Task.Run(() => _sessions.DisposeAsync().AsTask(), CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>Runs <paramref name="operation"/> as <see cref="Run{T}(Func{SftpClient, CancellationToken, Task{T}})"/> does, with the given timeout; a timeout is an <see cref="SshException"/> (<see cref="SshFailureReason.Timeout"/>).</summary>
    internal static T Run<T>(TimeSpan timeout, Func<CancellationToken, Task<T>> operation)
    {
        // The timeout starts when the work does, on the thread pool: started before queueing it, a busy pool's delay would count
        // against the server, and the operation could find its time used up before it began.
        CancellationTokenSource? cancel = null;
        try
        {
            return Task.Run(async () =>
            {
                using var started = new CancellationTokenSource(timeout);
                cancel = started;
                return await operation(started.Token).ConfigureAwait(false);
            }, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException ex) when (cancel?.IsCancellationRequested == true)
        {
            throw new SshException(SshFailureReason.Timeout, $"The SFTP server did not answer within {timeout.TotalSeconds:0.#} s.", ex);
        }
    }

    private sealed class Contents(IReadOnlyList<IFileInfo> entries) : IDirectoryContents
    {
        public bool Exists => true;

        public IEnumerator<IFileInfo> GetEnumerator() => entries.GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

/// <summary>Options for <see cref="SftpFileProvider"/>.</summary>
public sealed class SftpFileProviderOptions
{
    /// <summary>
    /// How long attributes and directory listings are reused before the server is asked again (default 5 seconds); zero turns caching
    /// off. Changes on the server show after at most this long.
    /// </summary>
    public TimeSpan CacheDuration
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            field = value;
        }
    } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How many paths the attribute cache, and separately the listing cache, may hold (default 10,000). Paths that do not exist are cached
    /// too, so this bounds the memory requests for random paths can take; when a cache is full, expired entries are dropped, and if that
    /// is not enough it starts over.
    /// </summary>
    public int MaxCacheEntries
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            field = value;
        }
    } = 10_000;

    /// <summary>
    /// How long one SFTP request may take before the lookup or read fails with an <see cref="SshException"/> (<see cref="SshFailureReason.Timeout"/>;
    /// default 30 seconds, <see cref="Timeout.InfiniteTimeSpan"/> for no limit). Each waiting synchronous lookup holds a thread-pool thread
    /// for up to this long, so keep it short.
    /// </summary>
    public TimeSpan OperationTimeout
    {
        get;
        init
        {
            if (value != Timeout.InfiniteTimeSpan)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value, TimeSpan.FromMilliseconds(int.MaxValue));
            }

            field = value;
        }
    } = TimeSpan.FromSeconds(30);
}
