using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A remote Unix-socket forwarding (<c>ssh -R /remote/socket:target</c>) started by <see cref="SshClient.ForwardRemoteUnixSocketAsync(string, string, int, CancellationToken)"/>:
/// the server listens on the Unix socket <see cref="RemoteSocketPath"/>, and each connection made to it is relayed to a TCP port
/// (<see cref="LocalHost"/>:<see cref="LocalPort"/>) or a Unix socket (<see cref="LocalSocketPath"/>) reached from this machine, or passed
/// to the application's handler (<see cref="SshClient.ForwardRemoteUnixSocketAsync(string, Func{SshForwardedConnection, CancellationToken, Task}, int, CancellationToken)"/>).
/// Dispose it to cancel the forwarding on the server and close the forwarded connections.
/// </summary>
public sealed class SshRemoteSocketForwarder : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly Func<SshRemoteSocketForwarder, CancellationToken, Task> _cancel;
    private readonly ForwardedHandlerSet? _handlers;
    private readonly CancellationTokenSource _stop;

    // Kept apart from _stop: a connection the server forwarded just before disposal may start after _stop is disposed.
    private readonly CancellationToken _stopToken;
    private readonly HashSet<Task> _connections = [];

    // Set under the _connections lock when DisposeAsync takes the connections it waits for (see SshRemotePortForwarder).
    private bool _closing;
    private int _disposed;
    private int _active;

    internal SshRemoteSocketForwarder(string socketPath, string? localHost, int localPort, string? localSocketPath, ILogger logger,
        Func<SshRemoteSocketForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
    {
        RemoteSocketPath = socketPath;
        LocalHost = localHost;
        LocalPort = localPort;
        LocalSocketPath = localSocketPath;
        _logger = logger;
        _cancel = cancel;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
        _stopToken = _stop.Token;
    }

    /// <summary>A forwarding to a handler in this process: each connection is passed to <paramref name="handler"/>.</summary>
    internal SshRemoteSocketForwarder(string socketPath, Func<SshForwardedConnection, CancellationToken, Task> handler, int maxConnections, ILogger logger,
        TimeProvider time, Func<SshRemoteSocketForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
        : this(socketPath, null, 0, null, logger, cancel, connectionClosed)
    {
        _handlers = new ForwardedHandlerSet(handler, maxConnections, logger, time);
    }

    /// <summary>
    /// Whether connections go to a handler in this process (<see cref="SshClient.ForwardRemoteUnixSocketAsync(string, Func{SshForwardedConnection, CancellationToken, Task}, int, CancellationToken)"/>)
    /// rather than to a host and port or a socket.
    /// </summary>
    public bool IsHandler => _handlers is not null;

    /// <summary>
    /// The most connections this forwarding serves at once: a handler's <c>maxConnections</c>, above which the server's channels are
    /// refused until some end; <see cref="int.MaxValue"/> (no limit of its own) for a forwarding to a host and port or a socket.
    /// <see cref="SshClientOptions.MaxForwardedConnections"/> applies across all forwardings either way.
    /// </summary>
    public int MaxConnections => _handlers?.MaxConnections ?? int.MaxValue;

    /// <summary>
    /// For a forwarding to a handler (<see cref="IsHandler"/>): how long <see cref="DisposeAsync"/> waits for the handlers it cancelled to
    /// return before it closes the connections of those still running under them. 5 seconds by default; <see cref="TimeSpan.Zero"/>
    /// closes them at once, and <see cref="Timeout.InfiniteTimeSpan"/> waits as long as they take. Set it before disposing; it does not
    /// apply to other forwardings, whose connections are closed at once.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative (other than <see cref="Timeout.InfiniteTimeSpan"/>), or longer
    /// than <see cref="int.MaxValue"/> milliseconds (about 24 days).</exception>
    public TimeSpan HandlerShutdownTimeout
    {
        get => _handlers?.ShutdownTimeout ?? _handlerShutdownTimeout;
        set
        {
            ForwardedHandlerSet.Validate(value, nameof(value));
            if (_handlers is { } handlers)
            {
                handlers.ShutdownTimeout = value;
            }
            else
            {
                _handlerShutdownTimeout = value; // kept only to be read back: there are no handlers to wait for
            }
        }
    }

    private TimeSpan _handlerShutdownTimeout = ForwardedHandlerSet.DefaultShutdownTimeout;

    /// <summary>The Unix socket the server listens on.</summary>
    public string RemoteSocketPath { get; }

    /// <summary>The host connections go to, from this machine; null when they go to <see cref="LocalSocketPath"/> or a handler.</summary>
    public string? LocalHost { get; }

    /// <summary>The port on <see cref="LocalHost"/>; 0 when connections go to <see cref="LocalSocketPath"/> or a handler.</summary>
    public int LocalPort { get; }

    /// <summary>The Unix socket on this machine connections go to; null when they go to <see cref="LocalHost"/> or a handler.</summary>
    public string? LocalSocketPath { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>
    /// Counts a connection the server is opening, before its channel is confirmed, unless this forwarding already serves its most
    /// (<see cref="MaxConnections"/>): then the server's channel is refused. Undone by <see cref="Release"/>, or when the
    /// connection <see cref="Accept"/> serves ends.
    /// </summary>
    internal bool TryReserve()
    {
        var limit = MaxConnections;
        while (true)
        {
            var active = Volatile.Read(ref _active);
            if (active >= limit)
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref _active, active + 1, active) == active)
            {
                return true;
            }
        }
    }

    /// <summary>Gives back a reservation for a channel that was refused after all.</summary>
    internal void Release() => Interlocked.Decrement(ref _active);

    /// <summary>
    /// Takes a <c>forwarded-streamlocal@openssh.com</c> channel the server opened for a connection to the socket, reserved with
    /// <see cref="TryReserve"/>.
    /// </summary>
    internal Task Accept(SshChannel channel)
    {
        Task connection;
        lock (_connections)
        {
            if (_closing)
            {
                return SshRemotePortForwarder.CloseLateAsync(channel, Release);
            }

            connection = ServeAsync(channel);
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
        return connection;
    }

    /// <summary>Serves one connection; it never faults, so <see cref="DisposeAsync"/> is not left with an exception to rethrow.</summary>
    private async Task ServeAsync(SshChannel channel)
    {
        using var measurement = new ForwardedConnectionMeasurement(ForwardedConnectionMeasurement.Remote, _stopToken);
        try
        {
            await Task.Yield();
            if (_handlers is { } handlers)
            {
                // The handler owns the stream; RunAsync disposes it (closing the channel) when the handler returns.
                var stream = new SshChannelStream(channel);
                measurement.Opened();
                await handlers.RunAsync(SshForwardedConnection.ForUnixSocket(stream, RemoteSocketPath), stream, 0, _stopToken).ConfigureAwait(false);
                return;
            }

            Socket socket;
            try
            {
                socket = await ConnectAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
            {
                // Nothing listens locally: close the channel, as ssh does, so the remote client sees the connection end. The reason is the
                // error code only: socket exception text can name the path.
                SshLog.RemoteForwardingConnectFailed(_logger, LocalPort, ex is SocketException socketError ? socketError.SocketErrorCode.ToString() : ex.GetType().Name);
                await SshRemotePortForwarder.CloseQuietlyAsync(channel).ConfigureAwait(false);
                return;
            }

            using (socket)
            {
                measurement.Opened();
                await SocketChannelRelay.RunAsync(socket, channel, _stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            SshLog.RemoteForwardingConnectFailed(_logger, LocalPort, ex.GetType().Name);
            await SshRemotePortForwarder.CloseQuietlyAsync(channel).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private async Task<Socket> ConnectAsync()
    {
        if (LocalSocketPath is { } path)
        {
            var unix = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await unix.ConnectAsync(new UnixDomainSocketEndPoint(path), _stop.Token).ConfigureAwait(false);
                return unix;
            }
            catch
            {
                unix.Dispose();
                throw;
            }
        }

        var tcp = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(LocalHost!, LocalPort, _stop.Token).ConfigureAwait(false);
            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases a forwarding the server refused: there is nothing to cancel there and no connection was routed to it, so only its
    /// registration on the connection's token is released, without the round trip <see cref="DisposeAsync"/> makes.
    /// </summary>
    internal void Abandon()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stop.Cancel();
        _stop.Dispose();
    }

    /// <summary>
    /// Cancels the forwarding on the server (<c>cancel-streamlocal-forward@openssh.com</c>) and closes every forwarded connection. For a
    /// forwarding to a handler, the token each handler was given is cancelled, and this waits up to <see cref="HandlerShutdownTimeout"/>
    /// (5 seconds by default) for the handlers to return; the connections of any still running then are closed under them, and this
    /// returns without waiting for them further. A connection the server opened before the cancel, but that reaches this forwarder only
    /// after disposal has gathered the connections it waits for, is closed without being served.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _cancel(this, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
        {
            // The connection is gone (so is the forwarding) or the server did not answer in time.
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        Task[] open;
        lock (_connections)
        {
            _closing = true;
            open = [.. _connections];
        }

        var all = Task.WhenAll(open.Select(t => t.ContinueWith(_ => { }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default)));
        // A handler is the application's code: it may ignore its token, so the wait is bounded.
        if (_handlers is { } handlers && !await handlers.StopAsync(all).ConfigureAwait(false))
        {
            return; // handlers still running hold the token: _stop stays undisposed
        }

        await all.ConfigureAwait(false);
        _stop.Dispose();
    }
}
