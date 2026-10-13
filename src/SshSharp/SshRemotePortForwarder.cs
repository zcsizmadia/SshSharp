using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A remote port forwarding (<c>ssh -R</c>) started by <see cref="SshClient.ForwardRemotePortAsync"/>: the server listens on
/// <see cref="BindAddress"/>:<see cref="Port"/>, and each connection made to it is relayed to <see cref="LocalHost"/>:<see cref="LocalPort"/>
/// as reached from this machine. Dispose it to cancel the forwarding on the server and close the forwarded connections.
/// </summary>
public sealed class SshRemotePortForwarder : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly Func<SshRemotePortForwarder, CancellationToken, Task> _cancel;
    private readonly CancellationTokenSource _stop;
    private readonly HashSet<Task> _connections = [];
    private int _disposed;
    private int _active;

    internal SshRemotePortForwarder(string bindAddress, int port, string localHost, int localPort, ILogger logger,
        Func<SshRemotePortForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
    {
        BindAddress = bindAddress;
        Port = port;
        LocalHost = localHost;
        LocalPort = localPort;
        _logger = logger;
        _cancel = cancel;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
    }

    /// <summary>The address the server listens on, as requested (<c>localhost</c> for its loopback, empty for every address).</summary>
    public string BindAddress { get; }

    /// <summary>The port the server listens on (the one it picked when 0 was asked for).</summary>
    public int Port { get; }

    /// <summary>Where each forwarded connection goes, as reached from this machine.</summary>
    public string LocalHost { get; }

    /// <summary>The port on <see cref="LocalHost"/>.</summary>
    public int LocalPort { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections
    {
        get
        {
            return Volatile.Read(ref _active);
        }
    }

    /// <summary>Takes a <c>forwarded-tcpip</c> channel the server opened for a connection to the forwarded port.</summary>
    internal void Accept(SshChannel channel)
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
    }

    /// <summary>Counts the connection until it has finished, so <see cref="ActiveConnections"/> is exact once it is awaited.</summary>
    private async Task ServeAsync(SshChannel channel)
    {
        try
        {
            await ServeCoreAsync(channel).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private async Task ServeCoreAsync(SshChannel channel)
    {
        await Task.Yield();
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(LocalHost, LocalPort, _stop.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Nothing listens locally: close the channel, as ssh does, so the remote client sees the connection end.
            SshLog.RemoteForwardingConnectFailed(_logger, LocalPort, ex.Message);
            socket.Dispose();
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
            return;
        }

        using (socket)
        {
            await SocketChannelRelay.RunAsync(socket, channel, _stop.Token).ConfigureAwait(false);
        }
    }

    /// <summary>Cancels the forwarding on the server (<c>cancel-tcpip-forward</c>) and closes every forwarded connection.</summary>
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

        await Task.WhenAll(open).ConfigureAwait(false);
        _stop.Dispose();
    }
}
