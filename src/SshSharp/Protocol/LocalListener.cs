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
    private readonly CancellationTokenSource _stop;
    private readonly Task _acceptLoop;
    private readonly HashSet<Task> _connections = [];
    private int _disposed;
    private int _active;
    private volatile bool _listening = true;

    private LocalListener(Socket listener, Func<Socket, CancellationToken, Task<SshChannel?>> connect, CancellationToken connectionClosed)
    {
        _listener = listener;
        _connect = connect;
        LocalEndPoint = (IPEndPoint)listener.LocalEndPoint!;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
        _acceptLoop = Task.Run(AcceptLoopAsync, CancellationToken.None); // the loop watches _stop itself
    }

    public IPEndPoint LocalEndPoint { get; }

    /// <summary>Whether the listening socket is still open (for tests: a freed port may be reused by someone else at once).</summary>
    public bool IsListening => _listening;

    public int ActiveConnections
    {
        get
        {
            return Volatile.Read(ref _active);
        }
    }

    /// <summary>Binds and starts listening; <paramref name="connect"/> returns the channel for a connection, or null to drop it.</summary>
    /// <exception cref="SocketException">The endpoint could not be bound.</exception>
    public static LocalListener Start(IPEndPoint localEndPoint, Func<Socket, CancellationToken, Task<SshChannel?>> connect, CancellationToken connectionClosed)
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

        return new LocalListener(listener, connect, connectionClosed);
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

                socket.NoDelay = true;
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
