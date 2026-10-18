using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A remote port forwarding (<c>ssh -R</c>) started by <see cref="SshClient.ForwardRemotePortAsync(string, int, string, int, CancellationToken)"/>: the server listens on
/// <see cref="BindAddress"/>:<see cref="RemotePort"/>, and each connection made to it is relayed to <see cref="LocalHost"/>:<see cref="LocalPort"/>
/// as reached from this machine. A remote dynamic forwarding (<see cref="SshClient.ForwardRemoteDynamicPortAsync"/>,
/// <see cref="IsDynamic"/>) instead answers each connection as a SOCKS proxy and connects where it asks, and a forwarding to a handler
/// (<see cref="SshClient.ForwardRemotePortAsync(string, int, Func{SshForwardedConnection, CancellationToken, Task}, int, CancellationToken)"/>)
/// passes each connection to the application's code. Dispose it to cancel the forwarding on the server and close the forwarded
/// connections.
/// </summary>
public sealed class SshRemotePortForwarder : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly Func<SshRemotePortForwarder, CancellationToken, Task> _cancel;
    private readonly Func<string, int, bool>? _allowDestination;
    private readonly ForwardedHandlerSet? _handlers;
    private readonly CancellationTokenSource _stop;

    // Kept apart from _stop: a connection the server forwarded just before disposal may start after _stop is disposed.
    private readonly CancellationToken _stopToken;
    private readonly HashSet<Task> _connections = [];
    private int _disposed;
    private int _active;

    internal SshRemotePortForwarder(string bindAddress, int port, string localHost, int localPort, ILogger logger,
        Func<SshRemotePortForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
    {
        BindAddress = bindAddress;
        RemotePort = port;
        LocalHost = localHost;
        LocalPort = localPort;
        _logger = logger;
        _cancel = cancel;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionClosed);
        _stopToken = _stop.Token;
    }

    /// <summary>A forwarding to a handler in this process: each connection is passed to <paramref name="handler"/>.</summary>
    internal SshRemotePortForwarder(string bindAddress, int port, Func<SshForwardedConnection, CancellationToken, Task> handler, int maxConnections,
        ILogger logger, Func<SshRemotePortForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
        : this(bindAddress, port, string.Empty, 0, logger, cancel, connectionClosed)
    {
        _handlers = new ForwardedHandlerSet(handler, maxConnections, logger);
    }

    /// <summary>Whether connections go to a handler in this process rather than to a host and port.</summary>
    internal bool IsHandler => _handlers is not null;

    /// <summary>A remote dynamic forwarding: no fixed destination; each connection names its own through SOCKS.</summary>
    internal SshRemotePortForwarder(string bindAddress, int port, Func<string, int, bool>? allowDestination, ILogger logger,
        Func<SshRemotePortForwarder, CancellationToken, Task> cancel, CancellationToken connectionClosed)
        : this(bindAddress, port, string.Empty, 0, logger, cancel, connectionClosed)
    {
        IsDynamic = true;
        _allowDestination = allowDestination;
    }

    /// <summary>
    /// Whether this is a remote dynamic forwarding (<c>ssh -R port</c>): each forwarded connection is a SOCKS request answered here, and
    /// <see cref="LocalHost"/> is empty and <see cref="LocalPort"/> 0.
    /// </summary>
    public bool IsDynamic { get; }

    /// <summary>The address the server listens on, as requested (<c>localhost</c> for its loopback, empty for every address).</summary>
    public string BindAddress { get; }

    /// <summary>The port the server listens on (the one it picked when 0 was asked for).</summary>
    public int RemotePort { get; }

    /// <summary>Where each forwarded connection goes, as reached from this machine; empty for a dynamic forwarding or one to a handler.</summary>
    public string LocalHost { get; }

    /// <summary>The port on <see cref="LocalHost"/>; 0 for a dynamic forwarding or one to a handler.</summary>
    public int LocalPort { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections
    {
        get
        {
            return Volatile.Read(ref _active);
        }
    }

    /// <summary>
    /// Counts a connection the server is opening, before its channel is confirmed, unless this forwarding already serves its most
    /// (a handler's <c>maxConnections</c>): then the server's channel is refused. Undone by <see cref="Release"/>, or when the
    /// connection <see cref="Accept"/> serves ends.
    /// </summary>
    internal bool TryReserve()
    {
        var limit = _handlers?.MaxConnections ?? int.MaxValue;
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
    /// Takes a <c>forwarded-tcpip</c> channel the server opened for a connection to the forwarded port, reserved with
    /// <see cref="TryReserve"/>; <paramref name="data"/> is the channel's type-specific data. The task ends with the connection.
    /// </summary>
    internal Task Accept(SshChannel channel, byte[] data)
    {
        Task connection;
        lock (_connections)
        {
            connection = ServeAsync(channel, data);
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

    /// <summary>
    /// Counts the connection until it has finished, so <see cref="ActiveConnections"/> is exact once it is awaited. It never faults: a
    /// connection that fails unexpectedly is closed, so neither the remote application nor <see cref="DisposeAsync"/> is left hanging.
    /// </summary>
    private async Task ServeAsync(SshChannel channel, byte[] data)
    {
        try
        {
            await ServeCoreAsync(channel, data).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            SshLog.RemoteForwardingConnectFailed(_logger, IsDynamic ? RemotePort : LocalPort, ex.GetType().Name);
            await CloseQuietlyAsync(channel).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    internal static async Task CloseQuietlyAsync(SshChannel channel)
    {
        try
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
        }
        catch (Exception ex) when (ex is IOException or SshException or OperationCanceledException or ObjectDisposedException)
        {
            // The connection is going away anyway.
        }
    }

    private async Task ServeCoreAsync(SshChannel channel, byte[] data)
    {
        await Task.Yield();
        if (_handlers is { } handlers)
        {
            // The handler owns the stream; RunAsync disposes it (closing the channel) when the handler returns.
            var stream = new SshChannelStream(channel);
            await handlers.RunAsync(SshForwardedConnection.ForTcp(stream, data), stream, RemotePort, _stopToken).ConfigureAwait(false);
            return;
        }

        if (IsDynamic)
        {
            await ServeDynamicAsync(channel).ConfigureAwait(false);
            return;
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(LocalHost, LocalPort, _stop.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Nothing listens locally: close the channel, as ssh does, so the remote client sees the connection end.
            SshLog.RemoteForwardingConnectFailed(_logger, LocalPort, ex is SocketException socketError ? socketError.SocketErrorCode.ToString() : ex.GetType().Name);
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

    /// <summary>
    /// Answers one forwarded connection as a SOCKS proxy: reads the request from the channel, checks the destination, connects to it from
    /// this machine, tells the remote application whether that worked, then relays.
    /// </summary>
    private async Task ServeDynamicAsync(SshChannel channel)
    {
        var stream = new SshChannelStream(channel);
        SocksRequest? request;
        try
        {
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            handshake.CancelAfter(SshClient.SocksHandshakeTimeout); // a remote application that says nothing does not hold a slot forever
            request = await SocksHandshake.ReadRequestAsync(stream, handshake.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SshException or ObjectDisposedException)
        {
            request = null;
        }

        if (request is not { } target)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            return;
        }

        // The destination is chosen on the server's side, so this is the trust boundary: by default anything this machine reaches, as ssh.
        IPAddress[]? addresses = null;
        if (_allowDestination is { } allow)
        {
            (addresses, var refusal) = await CheckDestinationAsync(allow, target).ConfigureAwait(false);
            if (refusal is not null)
            {
                await RefuseAsync(stream, target, refusal).ConfigureAwait(false);
                return;
            }
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            // With a filter, only the addresses it allowed: the name is not resolved a second time.
            if (addresses is null)
            {
                await socket.ConnectAsync(target.Host, target.Port, _stop.Token).ConfigureAwait(false);
            }
            else
            {
                await socket.ConnectAsync(addresses, target.Port, _stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            socket.Dispose();
            await RefuseAsync(stream, target, ex is SocketException socketError ? socketError.SocketErrorCode.ToString() : ex.Message).ConfigureAwait(false);
            return;
        }

        using (socket)
        {
            try
            {
                await SocksHandshake.ReplyAsync(stream, target, success: true, _stop.Token).ConfigureAwait(false);

                // Anything the application sent right after its request (optimistic data) was read along with it.
                var early = stream.TakeBuffered();
                for (var sent = 0; sent < early.Length;)
                {
                    sent += await socket.SendAsync(early.AsMemory(sent), SocketFlags.None, _stop.Token).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SshException or SocketException or ObjectDisposedException)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                return;
            }

            await SocketChannelRelay.RunAsync(socket, channel, _stop.Token).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Applies the destination filter so that no spelling of an address gets past it. An address literal, in any form the platform
    /// accepts (<c>127.1</c>, <c>2130706433</c>, <c>0x7f.1</c>, <c>[::1]</c>, an IPv4-mapped IPv6 address), is checked in its canonical
    /// form. A name is checked as given, then resolved here, and each address it resolves to is checked too; only the allowed ones are
    /// returned, to be connected to as they are. A filter that throws refuses the destination.
    /// </summary>
    private async Task<(IPAddress[]? Addresses, string? Refusal)> CheckDestinationAsync(Func<string, int, bool> allow, SocksRequest target)
    {
        bool Allowed(string host)
        {
            try
            {
                return allow(host, target.Port);
            }
            catch (Exception)
            {
                // The caller's filter failed: refuse, rather than let its exception end the forwarding.
                return false;
            }
        }

        if (ParseAddressLiteral(target.Host) is { } literal)
        {
            return Allowed(FilterText(literal)) ? ([literal], null) : (null, "the destination is not allowed");
        }

        if (!Allowed(target.Host))
        {
            return (null, "the destination is not allowed");
        }

        IPAddress[] resolved;
        try
        {
            using var lookup = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            lookup.CancelAfter(SshClient.SocksHandshakeTimeout);
            resolved = await Dns.GetHostAddressesAsync(target.Host, lookup.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            return (null, ex is SocketException socketError ? socketError.SocketErrorCode.ToString() : "the name could not be resolved");
        }

        var allowed = resolved.Select(Canonical).Distinct().Where(a => Allowed(FilterText(a))).ToArray();
        return allowed.Length > 0 ? (allowed, null) : (null, "the destination is not allowed");
    }

    /// <summary>The address a host string denotes when it is a literal (brackets allowed), in canonical form; null for a name.</summary>
    internal static IPAddress? ParseAddressLiteral(string host)
    {
        var text = host.Length > 2 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        return IPAddress.TryParse(text, out var address) ? Canonical(address) : null;
    }

    /// <summary>The address to connect to: an IPv4-mapped IPv6 address as plain IPv4; an IPv6 scope is kept (link-local needs it).</summary>
    private static IPAddress Canonical(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>What the filter sees for an address: its canonical text, without an IPv6 zone index (which does not change the host).</summary>
    internal static string FilterText(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0 ? new IPAddress(address.GetAddressBytes()).ToString() : address.ToString();

    private async Task RefuseAsync(SshChannelStream stream, SocksRequest target, string reason)
    {
        // The destination stays out of the log: host names are not logged (see SshLog).
        SshLog.RemoteDynamicConnectFailed(_logger, RemotePort, reason);
        try
        {
            await SocksHandshake.ReplyAsync(stream, target, success: false, _stop.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SshException or ObjectDisposedException)
        {
            // The remote application or the connection went away first.
        }

        await stream.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Cancels the forwarding on the server (<c>cancel-tcpip-forward</c>) and closes every forwarded connection. For a forwarding to a
    /// handler, the token each handler was given is cancelled, and this waits up to 5 seconds for the handlers to return; the
    /// connections of any still running then are closed under them, and this returns without waiting for them further.
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
            open = [.. _connections];
        }

        // The connections never fault (see ServeAsync); this only waits for them.
        var all = Task.WhenAll(open.Select(t => t.ContinueWith(_ => { }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default)));
        if (_handlers is { } handlers)
        {
            // A handler is the application's code: it may ignore its token, so the wait is bounded.
            if (!await handlers.StopAsync(all).ConfigureAwait(false))
            {
                return; // handlers still running hold the token: _stop stays undisposed
            }
        }

        await all.ConfigureAwait(false);
        _stop.Dispose();
    }
}
