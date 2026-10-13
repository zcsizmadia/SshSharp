using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A local port forwarding (<c>ssh -L</c>) started by <see cref="SshClient.ForwardLocalPortAsync"/>: connections to
/// <see cref="LocalEndPoint"/> are relayed through the server to <see cref="RemoteHost"/>:<see cref="RemotePort"/>. Dispose it to stop
/// listening and close the forwarded connections.
/// </summary>
public sealed class SshPortForwarder : IAsyncDisposable
{
    private const int BufferSize = 32 * 1024;

    private readonly Socket _listener;
    private readonly ILogger _logger;
    private readonly Func<IPEndPoint, CancellationToken, Task<SshChannel>> _open;
    private readonly CancellationTokenSource _stop;
    private readonly Task _acceptLoop;
    private readonly HashSet<Task> _connections = [];
    private readonly string _localText;
    private int _disposed;

    private SshPortForwarder(Socket listener, string remoteHost, int remotePort, ILogger logger,
        Func<IPEndPoint, CancellationToken, Task<SshChannel>> open, CancellationToken connectionClosed)
    {
        _listener = listener;
        _logger = logger;
        _open = open;
        LocalEndPoint = (IPEndPoint)listener.LocalEndPoint!;
        _localText = LocalEndPoint.ToString();
        RemoteHost = remoteHost;
        RemotePort = remotePort;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
        _acceptLoop = Task.Run(AcceptLoopAsync, CancellationToken.None); // the loop watches _stop itself
    }

    /// <summary>The local address and port being listened on (with the actual port when 0 was asked for).</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>Where the server connects each forwarded connection to.</summary>
    public string RemoteHost { get; }

    /// <summary>The port on <see cref="RemoteHost"/>.</summary>
    public int RemotePort { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections
    {
        get
        {
            lock (_connections)
            {
                return _connections.Count;
            }
        }
    }

    internal static SshPortForwarder Start(IPEndPoint localEndPoint, string remoteHost, int remotePort, ILogger logger,
        Func<IPEndPoint, CancellationToken, Task<SshChannel>> open, CancellationToken connectionClosed)
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

        var forwarder = new SshPortForwarder(listener, remoteHost, remotePort, logger, open, connectionClosed);
        SshLog.ForwardingStarted(logger, forwarder._localText, remotePort);
        return forwarder;
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            await AcceptConnectionsAsync().ConfigureAwait(false);
        }
        finally
        {
            // Stopped (disposed, or the SSH connection ended): stop listening too, so new connections are refused, not left in the backlog.
            _listener.Dispose();
        }
    }

    private async Task AcceptConnectionsAsync()
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
                connection = ForwardAsync(socket);
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

    /// <summary>Relays one accepted connection over a new channel until both sides have finished or either side fails or closes.</summary>
    private async Task ForwardAsync(Socket socket)
    {
        await Task.Yield(); // off the accept loop
        using (socket)
        {
            SshChannel channel;
            try
            {
                channel = await _open((IPEndPoint)socket.RemoteEndPoint!, _stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
            {
                // Refused by the server (the target is unreachable, or forwarding is not allowed): drop this connection only.
                SshLog.ForwardingRefused(_logger, RemotePort, ex.Message);
                return;
            }

            using var teardown = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            var toServer = GuardAsync(() => ToServerAsync(socket, channel, teardown.Token), teardown);
            var toClient = GuardAsync(() => ToClientAsync(socket, channel, teardown.Token), teardown);

            // Done when both directions have ended, the server closed the channel, or something failed (which cancels teardown).
            var closed = channel.WaitClosedAsync(teardown.Token);
            var first = await Task.WhenAny(Task.WhenAll(toServer, toClient), closed).ConfigureAwait(false);
            _ = closed.Exception; // observed: a failed connection faults it
            if (first == closed && closed.IsCompletedSuccessfully)
            {
                // The server closed: what it sent before CLOSE is still queued, and the queue has ended, so deliver it before tearing down.
                await toClient.ConfigureAwait(false);
            }

            await teardown.CancelAsync().ConfigureAwait(false);
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            socket.Dispose();
            await Task.WhenAll(toServer, toClient).ConfigureAwait(false);
            channel.DiscardUnread();
        }
    }

    private static async Task GuardAsync(Func<Task> pump, CancellationTokenSource teardown)
    {
        try
        {
            await pump().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // A reset socket, a closed channel or the connection ending: stop both directions.
            await teardown.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Local socket to channel; the local end-of-stream becomes channel EOF (a half-close, as ssh relays it).</summary>
    private static async Task ToServerAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false) is var read and > 0)
            {
                await channel.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Channel to local socket, straight from the received packets; channel EOF shuts down the socket's sending side.</summary>
    private static async Task ToClientAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken)
    {
        while (await channel.ReadAsync(cancellationToken).ConfigureAwait(false) is { } chunk)
        {
            using (chunk)
            {
                if (chunk.IsExtended)
                {
                    continue; // a TCP stream has no stderr
                }

                var data = chunk.Data;
                while (!data.IsEmpty)
                {
                    var sent = await socket.SendAsync(data, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    data = data[sent..];
                }
            }
        }

        socket.Shutdown(SocketShutdown.Send);
    }

    /// <summary>Stops listening and closes every forwarded connection.</summary>
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
        SshLog.ForwardingStopped(_logger, _localText);
    }
}
