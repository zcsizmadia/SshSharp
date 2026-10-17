using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A remote Unix-socket forwarding (<c>ssh -R /remote/socket:target</c>) started by <see cref="SshClient.ForwardRemoteUnixSocketAsync(string, string, int, CancellationToken)"/>:
/// the server listens on the Unix socket <see cref="RemoteSocketPath"/>, and each connection made to it is relayed to a TCP port
/// (<see cref="LocalHost"/>:<see cref="LocalPort"/>) or a Unix socket (<see cref="LocalSocketPath"/>) reached from this machine. Dispose it
/// to cancel the forwarding on the server and close the forwarded connections.
/// </summary>
public sealed class SshRemoteSocketForwarder : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly Func<SshRemoteSocketForwarder, CancellationToken, Task> _cancel;
    private readonly CancellationTokenSource _stop;
    private readonly HashSet<Task> _connections = [];
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
    }

    /// <summary>The Unix socket the server listens on.</summary>
    public string RemoteSocketPath { get; }

    /// <summary>The host connections go to, from this machine; null when they go to <see cref="LocalSocketPath"/>.</summary>
    public string? LocalHost { get; }

    /// <summary>The port on <see cref="LocalHost"/>; 0 when connections go to <see cref="LocalSocketPath"/>.</summary>
    public int LocalPort { get; }

    /// <summary>The Unix socket on this machine connections go to; null when they go to <see cref="LocalHost"/>.</summary>
    public string? LocalSocketPath { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>Takes a <c>forwarded-streamlocal@openssh.com</c> channel the server opened for a connection to the socket.</summary>
    internal Task Accept(SshChannel channel)
    {
        Task connection;
        lock (_connections)
        {
            Interlocked.Increment(ref _active);
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
        try
        {
            await Task.Yield();
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

    /// <summary>Cancels the forwarding on the server (<c>cancel-streamlocal-forward@openssh.com</c>) and closes every forwarded connection.</summary>
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
            open = [.. _connections];
        }

        await Task.WhenAll(open.Select(t => t.ContinueWith(_ => { }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default)))
            .ConfigureAwait(false);
        _stop.Dispose();
    }
}
