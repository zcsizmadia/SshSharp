using System.Net;
using System.Net.Sockets;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    /// <summary>
    /// Opens a TCP connection from the server to <paramref name="host"/>:<paramref name="port"/> (a <c>direct-tcpip</c> channel, what
    /// <c>ssh -L</c> and ProxyJump use) and returns it as a stream. The host name is resolved by the server, so it can name machines only
    /// the server reaches. Disposing the stream closes the connection.
    /// </summary>
    /// <exception cref="SshException">The server refused (for example sshd's <c>AllowTcpForwarding no</c>) or could not connect.</exception>
    public async Task<Stream> OpenTcpTunnelAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ValidateDestination(host, port);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var channel = await _connection.OpenDirectTcpIpAsync(host, port, "127.0.0.1", 0, cancellationToken).ConfigureAwait(false);
        return new SshChannelStream(channel);
    }

    /// <summary>
    /// Opens a connection from the server to the Unix domain socket at <paramref name="path"/> on the server
    /// (<c>direct-streamlocal@openssh.com</c>, what <c>ssh -L port:/path</c> uses), for example a database or Docker socket.
    /// </summary>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowStreamLocalForwarding</c>) or could not connect.</exception>
    public async Task<Stream> OpenUnixSocketTunnelAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (path.Contains('\0'))
        {
            throw new ArgumentException("The socket path must not contain NUL.", nameof(path));
        }

        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var channel = await _connection.OpenDirectStreamLocalAsync(path, cancellationToken).ConfigureAwait(false);
        return new SshChannelStream(channel);
    }

    /// <summary>
    /// Local port forwarding (<c>ssh -L</c>): listens on <paramref name="localEndPoint"/> and forwards every connection made to it through
    /// the server to <paramref name="remoteHost"/>:<paramref name="remotePort"/>. Use a loopback address unless other machines should be
    /// able to use the tunnel, and port 0 to let the system pick a free port (see <see cref="SshPortForwarder.LocalEndPoint"/>).
    /// Forwarding stops when the forwarder or the client is disposed, or the connection ends.
    /// </summary>
    /// <exception cref="SocketException">The local endpoint could not be bound (for example the port is in use).</exception>
    public Task<SshPortForwarder> ForwardLocalPortAsync(IPEndPoint localEndPoint, string remoteHost, int remotePort, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        ValidateDestination(remoteHost, remotePort);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        var listener = LocalListener.Start(localEndPoint, (socket, ct) => OpenForwardedAsync(socket, remoteHost, remotePort, ct), _connection.Closed);
        var bound = listener.LocalEndPoint.ToString();
        SshLog.ForwardingStarted(_logger, bound, remotePort);
        return Task.FromResult(new SshPortForwarder(listener, remoteHost, remotePort));
    }

    /// <summary>
    /// Dynamic port forwarding (<c>ssh -D</c>): runs a SOCKS proxy on <paramref name="localEndPoint"/> (SOCKS 4, 4a and 5, CONNECT,
    /// no authentication). Each application connection names its destination, and the server makes the connection, so host names are
    /// resolved on the server's side. Use a loopback address: the proxy has no authentication, so anyone who can reach it can use the
    /// server's network.
    /// </summary>
    /// <exception cref="SocketException">The local endpoint could not be bound (for example the port is in use).</exception>
    public Task<SshSocksProxy> ForwardDynamicPortAsync(IPEndPoint localEndPoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        var listener = LocalListener.Start(localEndPoint, OpenSocksAsync, _connection.Closed);
        var bound = listener.LocalEndPoint.ToString();
        SshLog.ForwardingStarted(_logger, bound, 0);
        return Task.FromResult(new SshSocksProxy(listener));
    }

    /// <summary>The channel for one locally forwarded connection, or null (logged) when the server refuses it.</summary>
    private async Task<SshChannel?> OpenForwardedAsync(Socket socket, string host, int port, CancellationToken cancellationToken)
    {
        var origin = (IPEndPoint)socket.RemoteEndPoint!;
        try
        {
            return await _connection.OpenDirectTcpIpAsync(host, port, origin.Address.ToString(), origin.Port, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.ChannelClosed)
        {
            // The target is unreachable, or forwarding is not allowed: drop this connection only.
            SshLog.ForwardingRefused(_logger, port, ex.Message);
            return null;
        }
    }

    /// <summary>Reads a SOCKS request, opens the channel it names, and answers the application.</summary>
    private async Task<SshChannel?> OpenSocksAsync(Socket socket, CancellationToken cancellationToken)
    {
        SocksRequest? request;
        using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            handshake.CancelAfter(SocksHandshakeTimeout); // an application that connects and says nothing does not hold a slot forever
            request = await SocksHandshake.ReadRequestAsync(socket, handshake.Token).ConfigureAwait(false);
        }

        if (request is not { } target)
        {
            return null;
        }

        var channel = await OpenForwardedAsync(socket, target.Host, target.Port, cancellationToken).ConfigureAwait(false);
        try
        {
            await SocksHandshake.ReplyAsync(socket, target, success: channel is not null, cancellationToken).ConfigureAwait(false);
        }
        catch when (channel is not null)
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        return channel;
    }

    /// <summary>How long a SOCKS application has to send its request.</summary>
    internal static readonly TimeSpan SocksHandshakeTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Remote port forwarding (<c>ssh -R</c>): asks the server to listen on <paramref name="bindAddress"/>:<paramref name="remotePort"/> and
    /// relays every connection made to it to <paramref name="localHost"/>:<paramref name="localPort"/>, as reached from this machine.
    /// The bind address is <c>localhost</c> for the server's loopback only (what ssh uses by default), an address, or empty for every
    /// address; sshd's <c>GatewayPorts</c> decides whether it honours anything but loopback. Port 0 lets the server pick one
    /// (see <see cref="SshRemotePortForwarder.Port"/>).
    /// </summary>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowTcpForwarding</c>, or the port is in use).</exception>
    public async Task<SshRemotePortForwarder> ForwardRemotePortAsync(string bindAddress, int remotePort, string localHost, int localPort, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bindAddress);
        if (bindAddress.Any(char.IsControl))
        {
            throw new ArgumentException("The bind address must not contain control characters.", nameof(bindAddress));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(remotePort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(remotePort, 65535);
        ValidateDestination(localHost, localPort);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        EnsureChannelDispatch();

        var reply = await _connection.SendGlobalRequestAsync("tcpip-forward", true, w =>
        {
            w.WriteString(bindAddress);
            w.WriteUInt32((uint)remotePort);
        }, cancellationToken).ConfigureAwait(false);
        if (!reply.Success)
        {
            throw new SshException(SshFailureReason.ChannelClosed, $"The server refused to listen on port {remotePort} (forwarding not allowed, or the port is in use).");
        }

        // RFC 4254 section 7.1: with port 0 the reply carries the port the server picked.
        var port = remotePort;
        if (remotePort == 0)
        {
            port = reply.Data.Length >= 4 ? (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(reply.Data) : 0;
            if (port is < 1 or > 65535)
            {
                throw new SshProtocolException("The server accepted a remote forwarding on port 0 but did not say which port it picked.");
            }
        }

        var forwarder = new SshRemotePortForwarder(bindAddress, port, localHost, localPort, _logger, CancelRemoteForwardAsync, _connection.Closed);
        if (!_remoteForwards.TryAdd(port, forwarder))
        {
            throw new InvalidOperationException($"Port {port} is already forwarded on this connection.");
        }

        SshLog.RemoteForwardingStarted(_logger, port, localPort);
        return forwarder;
    }

    private async Task CancelRemoteForwardAsync(SshRemotePortForwarder forwarder, CancellationToken cancellationToken)
    {
        // Stop accepting this port's channels first: anything the server opens from now on is refused.
        _remoteForwards.TryRemove(new KeyValuePair<int, SshRemotePortForwarder>(forwarder.Port, forwarder));
        if (_disposed == 0)
        {
            await _connection.SendGlobalRequestAsync("cancel-tcpip-forward", true, w =>
            {
                w.WriteString(forwarder.BindAddress);
                w.WriteUInt32((uint)forwarder.Port);
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Routes the channels the server opens (installed once, by the first feature that receives them).</summary>
    private void EnsureChannelDispatch() => _connection.AcceptChannel ??= (type, data) =>
    {
        if (type == "auth-agent@openssh.com")
        {
            // Agent forwarding: only when this client forwards an agent (the server asks for it after auth-agent-req@openssh.com).
            return _options.ForwardAgent is { } agent ? channel => _ = RelayAgentAsync(channel, agent) : null;
        }

        if (type != "forwarded-tcpip")
        {
            return null;
        }

        try
        {
            // RFC 4254 section 7.2: the address and port that were connected, then the originator's.
            var reader = new SshReader(data);
            reader.ReadUtf8String();
            var port = (int)reader.ReadUInt32();
            return _remoteForwards.TryGetValue(port, out var forwarder) ? forwarder.Accept : null;
        }
        catch (SshProtocolException)
        {
            return null;
        }
    };

    /// <summary>Relays one forwarded agent connection: the server's requests to the local agent and its answers back.</summary>
    private async Task RelayAgentAsync(SshChannel channel, SshAgent agent)
    {
        Stream stream;
        try
        {
            stream = await agent.OpenStreamAsync(_connection.Closed).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
        {
            SshLog.AgentUnavailable(_logger, ex.Message);
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
            return;
        }

        await using (stream.ConfigureAwait(false))
        {
            await StreamChannelRelay.RunAsync(stream, channel, _connection.Closed).ConfigureAwait(false);
        }
    }

    private readonly List<SshPortForwarder> _localForwardings = [];
    private readonly List<SshRemotePortForwarder> _remoteForwardings = [];
    private readonly List<SshSocksProxy> _dynamicForwardings = [];

    /// <summary>The <c>LocalForward</c> forwardings started from ssh_config (<see cref="SshConfigConnectOptions.StartForwardings"/>); disposed with the client.</summary>
    public IReadOnlyList<SshPortForwarder> LocalForwardings => _localForwardings;

    /// <summary>The <c>RemoteForward</c> forwardings started from ssh_config; disposed with the client.</summary>
    public IReadOnlyList<SshRemotePortForwarder> RemoteForwardings => _remoteForwardings;

    /// <summary>The <c>DynamicForward</c> SOCKS proxies started from ssh_config; disposed with the client.</summary>
    public IReadOnlyList<SshSocksProxy> DynamicForwardings => _dynamicForwardings;

    /// <summary>
    /// Starts the forwardings ssh_config names for this host. One that cannot be set up (a port in use, refused by the server, a form
    /// this library does not support such as Unix sockets) is logged and skipped, or fails the connection with <c>ExitOnForwardFailure</c>.
    /// </summary>
    internal async Task StartConfiguredForwardingsAsync(SshHostConfig hostConfig, CancellationToken cancellationToken)
    {
        foreach (var spec in hostConfig.LocalForwards)
        {
            await TryForwardAsync("LocalForward", spec, async () =>
            {
                var (listen, target) = ForwardSpec.ParseForward(spec) ?? throw new FormatException("only [bind:]port host:hostport is supported");
                _localForwardings.Add(await ForwardLocalPortAsync(LocalBind(listen, hostConfig.GatewayPorts), target.Host, target.Port, cancellationToken).ConfigureAwait(false));
            }).ConfigureAwait(false);
        }

        foreach (var spec in hostConfig.RemoteForwards)
        {
            await TryForwardAsync("RemoteForward", spec, async () =>
            {
                var (listen, target) = ForwardSpec.ParseForward(spec) ?? throw new FormatException("only [bind:]port host:hostport is supported");

                // ssh asks for the server's loopback when no address is given; "*" means every address.
                var bind = listen.Bind switch { null => "localhost", "*" => "", var given => given };
                _remoteForwardings.Add(await ForwardRemotePortAsync(bind, listen.Port, target.Host, target.Port, cancellationToken).ConfigureAwait(false));
            }).ConfigureAwait(false);
        }

        foreach (var spec in hostConfig.DynamicForwards)
        {
            await TryForwardAsync("DynamicForward", spec, async () =>
            {
                var listen = ForwardSpec.ParseListen(spec) ?? throw new FormatException("only [bind:]port is supported");
                _dynamicForwardings.Add(await ForwardDynamicPortAsync(LocalBind(listen, hostConfig.GatewayPorts), cancellationToken).ConfigureAwait(false));
            }).ConfigureAwait(false);
        }

        async Task TryForwardAsync(string keyword, string spec, Func<Task> start)
        {
            try
            {
                await start().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is FormatException or SocketException or SshException or ArgumentException)
            {
                if (hostConfig.ExitOnForwardFailure)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, $"{keyword} {spec} could not be set up: {ex.Message}", ex);
                }

                SshLog.ConfiguredForwardingSkipped(_logger, keyword, spec, ex.Message);
            }
        }
    }

    /// <summary>
    /// The local address a forwarding listens on, as ssh decides it: none given means loopback (or every address with GatewayPorts),
    /// <c>localhost</c> loopback, <c>*</c> or empty every address, otherwise the address given.
    /// </summary>
    internal static IPEndPoint LocalBind(ForwardListen listen, bool gatewayPorts)
    {
        var address = listen.Bind switch
        {
            null => gatewayPorts ? IPAddress.Any : IPAddress.Loopback,
            "localhost" => IPAddress.Loopback,
            "*" or "" => IPAddress.Any,
            var given when IPAddress.TryParse(given, out var parsed) => parsed,
            var given => throw new FormatException($"the bind address '{given}' is not an IP address or localhost"),
        };
        return new IPEndPoint(address, listen.Port);
    }

    /// <summary>Stops the forwardings started from ssh_config (before the connection goes, so remote ones are cancelled on the server).</summary>
    private async Task DisposeConfiguredForwardingsAsync()
    {
        foreach (var forwarding in _localForwardings)
        {
            await forwarding.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var forwarding in _remoteForwardings)
        {
            await forwarding.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var forwarding in _dynamicForwardings)
        {
            await forwarding.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static void ValidateDestination(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (host.Any(char.IsControl))
        {
            throw new ArgumentException("The host name must not contain control characters.", nameof(host));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
    }
}
