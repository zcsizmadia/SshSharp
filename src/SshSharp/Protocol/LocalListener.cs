using System.Net;
using System.Net.Sockets;

namespace SshSharp.Protocol;

/// <summary>
/// The local side of port forwarding: listens, and for each accepted connection asks <c>connect</c> for a channel (which may first talk
/// to the socket, as SOCKS does) and relays the two. Stops when disposed or when the SSH connection ends.
/// </summary>
internal sealed class LocalListener : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly Func<Socket, CancellationToken, Task<SshChannel?>> _connect;
    private readonly KeyValuePair<string, object?> _type;
    private readonly CancellationTokenSource _stop;
    private readonly Task _acceptLoop;
    private readonly HashSet<Task> _connections = [];
    private int _disposed;
    private int _active;
    private volatile bool _listening = true;

    private LocalListener(Socket listener, Func<Socket, CancellationToken, Task<SshChannel?>> connect, KeyValuePair<string, object?> type, CancellationToken connectionClosed,
        string? socketPath = null)
    {
        _listener = listener;
        _connect = connect;
        _type = type;
        _endPoint = socketPath is null ? listener.LocalEndPoint! : null;
        SocketPath = socketPath;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
        _acceptLoop = Task.Run(AcceptLoopAsync, CancellationToken.None); // the loop watches _stop itself
    }

    private readonly EndPoint? _endPoint;

    /// <summary>The address and port listened on; only for a TCP listener (see <see cref="SocketPath"/>).</summary>
    public IPEndPoint LocalEndPoint => (IPEndPoint)(_endPoint ?? throw new InvalidOperationException("A Unix-socket listener has no IP endpoint."));

    /// <summary>The Unix socket listened on, which this listener created and removes when it stops; null for a TCP listener.</summary>
    public string? SocketPath { get; }

    /// <summary>Whether the listening socket is still open (for tests: a freed port may be reused by someone else at once).</summary>
    public bool IsListening => _listening;

    public int ActiveConnections
    {
        get
        {
            return Volatile.Read(ref _active);
        }
    }

    /// <summary>
    /// Binds and starts listening; <paramref name="connect"/> returns the channel for a connection, or null to drop it. Connections are
    /// counted in the forwarding instruments under <paramref name="type"/>.
    /// </summary>
    /// <exception cref="SocketException">The endpoint could not be bound.</exception>
    public static LocalListener Start(IPEndPoint localEndPoint, Func<Socket, CancellationToken, Task<SshChannel?>> connect, KeyValuePair<string, object?> type,
        CancellationToken connectionClosed)
    {
        var listener = new Socket(localEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            listener.Bind(localEndPoint);
            listener.Listen(128);
        }
        catch
        {
            listener.Dispose();
            throw;
        }

        return new LocalListener(listener, connect, type, connectionClosed);
    }

    /// <summary>
    /// Creates the Unix socket <paramref name="path"/> and starts listening on it. The socket file gets <paramref name="mode"/> before
    /// anything can connect (0600 unless the caller or <c>StreamLocalBindMask</c> says otherwise; on Windows always an ACL with only the
    /// current user): a socket that is bound but not yet listening refuses connections, so nobody else gets in between. An existing file
    /// at the path fails the bind, unless <paramref name="unlinkExisting"/> (ssh_config's <c>StreamLocalBindUnlink</c>) removes it first.
    /// </summary>
    /// <exception cref="SocketException">The socket could not be created (the file exists, or the directory does not).</exception>
    /// <exception cref="ArgumentException">The path is longer than the platform allows.</exception>
    public static LocalListener StartUnix(string path, bool unlinkExisting, UnixFileMode mode, Func<Socket, CancellationToken, Task<SshChannel?>> connect,
        KeyValuePair<string, object?> type, CancellationToken connectionClosed)
    {
        var endPoint = new UnixDomainSocketEndPoint(path);
        if (unlinkExisting)
        {
            File.Delete(path); // as ssh does: whatever is there, typically a stale socket of an earlier run
        }

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var bound = false;
        try
        {
            listener.Bind(endPoint);
            bound = true;
            SetMode(path, mode);
            listener.Listen(128);
        }
        catch
        {
            listener.Dispose();
            if (bound)
            {
                TryDelete(path); // created here, so removed here
            }

            throw;
        }

        return new LocalListener(listener, connect, type, connectionClosed, path);
    }

    private static void SetMode(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows())
        {
            // A Unix mode has no faithful ACL counterpart (the owner's group means little here), so the socket stays the user's alone:
            // a broader mode is narrowed, never widened by guessing.
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User!,
                System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        else
        {
            File.SetUnixFileMode(path, mode);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left behind: StreamLocalBindUnlink, or removing it by hand, deals with a stale socket file.
        }
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                Socket socket;
                try
                {
                    socket = await _listener.AcceptAsync(_stop.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                if (SocketPath is null)
                {
                    socket.NoDelay = true; // TCP only: a Unix socket has no such option
                }

                Task connection;
                lock (_connections)
                {
                    Interlocked.Increment(ref _active);
                    connection = ServeAsync(socket);
                    _connections.Add(connection);
                }

                _ = connection.ContinueWith(
                    done =>
                    {
                        lock (_connections)
                        {
                            _connections.Remove(done);
                        }
                    },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        finally
        {
            // Stopped (disposed, or the SSH connection ended): stop listening too, so new connections are refused, not left in the backlog.
            _listener.Dispose();
            _listening = false;
            if (SocketPath is { } path)
            {
                TryDelete(path); // the socket file this listener created
            }
        }
    }

    /// <summary>Counts the connection until it has finished, so ActiveConnections is exact once it is awaited.</summary>
    private async Task ServeAsync(Socket socket)
    {
        try
        {
            await ServeCoreAsync(socket).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private async Task ServeCoreAsync(Socket socket)
    {
        await Task.Yield(); // off the accept loop
        using var measurement = new ForwardedConnectionMeasurement(_type, _stop.Token);
        using (socket)
        {
            SshChannel? channel;
            try
            {
                channel = await _connect(socket, _stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException or SocketException or IOException)
            {
                return; // the connector logs refusals; anything else means the connection or the socket went away
            }

            if (channel is not null)
            {
                measurement.Opened();
                await SocketChannelRelay.RunAsync(socket, channel, _stop.Token).ConfigureAwait(false);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Dispose();
        await _acceptLoop.ConfigureAwait(false);

        Task[] open;
        lock (_connections)
        {
            open = [.. _connections];
        }

        await Task.WhenAll(open).ConfigureAwait(false);
        _stop.Dispose();
    }
}
