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
    /// A <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/> that makes <see cref="System.Net.Http.HttpClient"/>'s connections
    /// through this SSH connection (<see cref="OpenTcpTunnelAsync"/>), so it can reach web services only the server reaches, such as an
    /// internal API behind a bastion. Host names are resolved by the server. TLS still runs end to end, from here to the service. Set
    /// <see cref="System.Net.Http.SocketsHttpHandler.UseProxy"/> to false: with a system proxy configured, HttpClient would otherwise
    /// connect to that proxy, through the server, instead of to the service.
    /// </summary>
    /// <example>
    /// <code>
    /// using var http = new HttpClient(new SocketsHttpHandler { ConnectCallback = client.CreateHttpConnectCallback(), UseProxy = false });
    /// var status = await http.GetStringAsync("https://internal-api.corp/health");
    /// </code>
    /// </example>
    public Func<System.Net.Http.SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> CreateHttpConnectCallback() =>
        async (context, cancellationToken) =>
            await OpenTcpTunnelAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);

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
    /// able to use the tunnel, and port 0 to let the system pick a free port (see <see cref="SshLocalPortForwarder.LocalEndPoint"/>).
    /// Forwarding stops when the forwarder or the client is disposed, or the connection ends.
    /// </summary>
    /// <exception cref="SocketException">The local endpoint could not be bound (for example the port is in use).</exception>
    public Task<SshLocalPortForwarder> ForwardLocalPortAsync(IPEndPoint localEndPoint, string remoteHost, int remotePort, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        ValidateDestination(remoteHost, remotePort);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfConnectionFailed();
        var listener = LocalListener.Start(localEndPoint, (socket, ct) => OpenForwardedAsync(socket, remoteHost, remotePort, ct), _connection.Closed);
        var bound = listener.LocalEndPoint.ToString();
        SshLog.ForwardingStarted(_logger, bound, remotePort);
        return Task.FromResult(new SshLocalPortForwarder(listener, remoteHost, remotePort));
    }

    /// <summary>
    /// Local forwarding to a Unix socket on the server (<c>ssh -L port:/remote/socket</c>): listens on <paramref name="localEndPoint"/> and
    /// forwards every connection made to it to the Unix socket <paramref name="remoteSocketPath"/> on the server
    /// (<c>direct-streamlocal@openssh.com</c>), for example a database or Docker socket there. The forwarder's
    /// <see cref="SshLocalPortForwarder.RemoteSocketPath"/> is the path; its <see cref="SshLocalPortForwarder.RemoteHost"/> is empty and
    /// <see cref="SshLocalPortForwarder.RemotePort"/> 0. sshd's <c>AllowStreamLocalForwarding</c> decides whether the server connects.
    /// </summary>
    /// <exception cref="SocketException">The local endpoint could not be bound (for example the port is in use).</exception>
    public Task<SshLocalPortForwarder> ForwardLocalPortAsync(IPEndPoint localEndPoint, string remoteSocketPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        ValidateSocketPath(remoteSocketPath, nameof(remoteSocketPath));
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfConnectionFailed();
        var listener = LocalListener.Start(localEndPoint, (_, ct) => OpenForwardedSocketAsync(remoteSocketPath, ct), _connection.Closed);
        var bound = listener.LocalEndPoint.ToString();
        SshLog.ForwardingToSocketStarted(_logger, bound);
        return Task.FromResult(new SshLocalPortForwarder(listener, remoteSocketPath));
    }

    /// <summary>
    /// Local forwarding from a Unix socket (<c>ssh -L /local/socket:host:port</c>): creates the Unix socket
    /// <paramref name="localSocketPath"/> here and forwards every connection made to it through the server to
    /// <paramref name="remoteHost"/>:<paramref name="remotePort"/>. The socket file is created owner-only (mode 0600, as ssh's default
    /// <c>StreamLocalBindMask</c> gives; on Windows an ACL with only the current user), and removed when the forwarder stops. Unix
    /// sockets work on Linux, macOS and Windows 10 and later.
    /// </summary>
    /// <exception cref="SocketException">The socket could not be created: a file exists at the path, or its directory does not.</exception>
    /// <exception cref="ArgumentException">The path is longer than the platform allows for a socket (about 104 to 108 bytes).</exception>
    public Task<SshLocalSocketForwarder> ForwardLocalUnixSocketAsync(string localSocketPath, string remoteHost, int remotePort, CancellationToken cancellationToken = default)
    {
        ValidateSocketPath(localSocketPath, nameof(localSocketPath));
        ValidateDestination(remoteHost, remotePort);
        return StartLocalSocketForwardAsync(localSocketPath, unlinkExisting: false, remoteHost, remotePort, remoteSocketPath: null, cancellationToken);
    }

    /// <summary>
    /// Local forwarding from a Unix socket to a Unix socket on the server (<c>ssh -L /local/socket:/remote/socket</c>): creates the Unix
    /// socket <paramref name="localSocketPath"/> here (owner-only, removed when the forwarder stops) and forwards every connection made to
    /// it to <paramref name="remoteSocketPath"/> on the server, for example to use the server's Docker socket with a local client.
    /// </summary>
    /// <exception cref="SocketException">The socket could not be created: a file exists at the path, or its directory does not.</exception>
    /// <exception cref="ArgumentException">The path is longer than the platform allows for a socket (about 104 to 108 bytes).</exception>
    public Task<SshLocalSocketForwarder> ForwardLocalUnixSocketAsync(string localSocketPath, string remoteSocketPath, CancellationToken cancellationToken = default)
    {
        ValidateSocketPath(localSocketPath, nameof(localSocketPath));
        ValidateSocketPath(remoteSocketPath, nameof(remoteSocketPath));
        return StartLocalSocketForwardAsync(localSocketPath, unlinkExisting: false, null, 0, remoteSocketPath, cancellationToken);
    }

    private Task<SshLocalSocketForwarder> StartLocalSocketForwardAsync(string localSocketPath, bool unlinkExisting, string? remoteHost, int remotePort,
        string? remoteSocketPath, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfConnectionFailed();
        var listener = LocalListener.StartUnix(localSocketPath, unlinkExisting,
            remoteSocketPath is null
                ? (socket, ct) => OpenForwardedAsync(socket, remoteHost!, remotePort, ct)
                : (_, ct) => OpenForwardedSocketAsync(remoteSocketPath, ct),
            _connection.Closed);
        SshLog.LocalSocketForwardingStarted(_logger, remotePort);
        return Task.FromResult(new SshLocalSocketForwarder(listener, remoteHost, remotePort, remoteSocketPath));
    }

    /// <summary>The <c>direct-streamlocal</c> channel for one locally forwarded connection, or null (logged) when the server refuses it.</summary>
    private async Task<SshChannel?> OpenForwardedSocketAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await _connection.OpenDirectStreamLocalAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.ChannelClosed)
        {
            // Nothing listens there, or stream-local forwarding is not allowed: drop this connection only. Port 0: a socket path.
            SshLog.ForwardingRefused(_logger, 0, ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Dynamic port forwarding (<c>ssh -D</c>): runs a SOCKS proxy on <paramref name="localEndPoint"/> (SOCKS 4, 4a and 5, CONNECT,
    /// no authentication). Each application connection names its destination, and the server makes the connection, so host names are
    /// resolved on the server's side. Use a loopback address: the proxy has no authentication, so anyone who can reach it can use the
    /// server's network.
    /// </summary>
    /// <exception cref="SocketException">The local endpoint could not be bound (for example the port is in use).</exception>
    public Task<SshDynamicPortForwarder> ForwardDynamicPortAsync(IPEndPoint localEndPoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfConnectionFailed();
        var listener = LocalListener.Start(localEndPoint, OpenSocksAsync, _connection.Closed);
        var bound = listener.LocalEndPoint.ToString();
        SshLog.ForwardingStarted(_logger, bound, 0);
        return Task.FromResult(new SshDynamicPortForwarder(listener));
    }

    /// <summary>
    /// A forwarder started on a connection that has already failed would listen on nothing: its accept loop stops at once, and the caller
    /// would never know. Report the failure instead.
    /// </summary>
    private void ThrowIfConnectionFailed()
    {
        if (_connection.Failure is { } failure)
        {
            throw failure as SshException ?? new SshException(SshFailureReason.ConnectionClosed, "The connection has failed: " + failure.Message, failure);
        }
    }

    /// <summary>The channel for one locally forwarded connection, or null (logged) when the server refuses it.</summary>
    private async Task<SshChannel?> OpenForwardedAsync(Socket socket, string host, int port, CancellationToken cancellationToken)
    {
        // A Unix socket has no address: ssh sends 127.0.0.1 and port 65535 then, for servers that check the originator.
        var (originAddress, originPort) = socket.RemoteEndPoint is IPEndPoint origin ? (origin.Address.ToString(), origin.Port) : ("127.0.0.1", 65535);
        try
        {
            return await _connection.OpenDirectTcpIpAsync(host, port, originAddress, originPort, cancellationToken).ConfigureAwait(false);
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
        // Only for the handshake: it does not own the socket, which the listener relays once the channel is open.
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        SocksRequest? request;
        using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            handshake.CancelAfter(SocksHandshakeTimeout); // an application that connects and says nothing does not hold a slot forever
            request = await SocksHandshake.ReadRequestAsync(stream, handshake.Token).ConfigureAwait(false);
        }

        if (request is not { } target)
        {
            return null;
        }

        var channel = await OpenForwardedAsync(socket, target.Host, target.Port, cancellationToken).ConfigureAwait(false);
        try
        {
            await SocksHandshake.ReplyAsync(stream, target, success: channel is not null, cancellationToken).ConfigureAwait(false);
        }
        catch when (channel is not null)
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
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
    /// (see <see cref="SshRemotePortForwarder.RemotePort"/>).
    /// </summary>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowTcpForwarding</c>, or the port is in use).</exception>
    public Task<SshRemotePortForwarder> ForwardRemotePortAsync(string bindAddress, int remotePort, string localHost, int localPort, CancellationToken cancellationToken = default)
    {
        ValidateRemoteListen(bindAddress, remotePort);
        ValidateDestination(localHost, localPort);
        return StartRemoteForwardAsync(bindAddress, remotePort,
            port => new SshRemotePortForwarder(bindAddress, port, localHost, localPort, _logger, CancelRemoteForwardAsync, _connection.Closed),
            cancellationToken);
    }

    /// <summary>
    /// Remote dynamic port forwarding (<c>ssh -R [bind_address:]port</c> with no destination, OpenSSH 7.6 and later): asks the server to
    /// listen on <paramref name="bindAddress"/>:<paramref name="remotePort"/>, and answers each connection made to it as a SOCKS proxy (4,
    /// 4a and 5, CONNECT, no authentication), connecting to the destination it names from this machine. It gives the server's side
    /// outbound access through this machine's network, for example to reach an internal package mirror from a build host.
    /// </summary>
    /// <param name="bindAddress">Where the server listens: <c>localhost</c> for its loopback only (what ssh uses by default), an address, or
    /// empty for every address (subject to sshd's <c>GatewayPorts</c>).</param>
    /// <param name="remotePort">The port the server listens on; 0 lets it pick one (see <see cref="SshRemotePortForwarder.RemotePort"/>).</param>
    /// <param name="allowDestination">
    /// Decides whether to connect to a requested host and port. The destinations are chosen on the server's side, so whoever can reach
    /// the forwarded port there can use this machine's network: like ssh, everything is allowed when this is null. An address is passed
    /// in its canonical form, whatever spelling was requested (<c>127.1</c>, <c>0x7f.1</c> and <c>::ffff:127.0.0.1</c> all arrive as
    /// <c>127.0.0.1</c>; <c>[::1]</c> as <c>::1</c>). A host name is passed as given, then resolved on this machine and passed again as
    /// each address it resolves to: the name and an address must both be allowed, and only the allowed addresses are connected to, so a
    /// name that resolves to a refused address is refused too. A filter that throws refuses the destination.
    /// </param>
    /// <param name="cancellationToken">Cancels the request to the server.</param>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowTcpForwarding</c>, or the port is in use).</exception>
    public Task<SshRemotePortForwarder> ForwardRemoteDynamicPortAsync(string bindAddress, int remotePort, Func<string, int, bool>? allowDestination = null, CancellationToken cancellationToken = default)
    {
        ValidateRemoteListen(bindAddress, remotePort);
        return StartRemoteForwardAsync(bindAddress, remotePort,
            port => new SshRemotePortForwarder(bindAddress, port, allowDestination, _logger, CancelRemoteForwardAsync, _connection.Closed),
            cancellationToken);
    }

    /// <summary>
    /// Remote port forwarding to a handler in this process (what Go's <c>ssh.Client.Listen</c> gives): asks the server to listen on
    /// <paramref name="bindAddress"/>:<paramref name="remotePort"/> and passes every connection made to it to <paramref name="handler"/>,
    /// as a <see cref="SshForwardedConnection"/> with a duplex <see cref="SshForwardedConnection.Stream"/>. Nothing listens on this
    /// machine: it serves a port on the server from the application, for example a webhook receiver behind NAT, or a test server that
    /// programs on the server connect to.
    /// </summary>
    /// <param name="bindAddress">Where the server listens: <c>localhost</c> for its loopback only (what ssh uses by default), an address, or
    /// empty for every address (subject to sshd's <c>GatewayPorts</c>).</param>
    /// <param name="remotePort">The port the server listens on; 0 lets it pick one (see <see cref="SshRemotePortForwarder.RemotePort"/>).</param>
    /// <param name="handler">
    /// Serves one connection; it runs concurrently for concurrent connections. It owns the connection's stream: disposing it closes
    /// the connection, and it is disposed when the handler returns. Its token is cancelled when the forwarder is disposed or the SSH
    /// connection ends. A handler that throws closes its own connection only; the exception is logged by type, and the forwarding goes
    /// on. Anyone who can reach the port on the server can connect, so treat what arrives as untrusted input.
    /// </param>
    /// <param name="maxConnections">
    /// The most connections served at once by this forwarding; the server's channels above it are refused (resource shortage) until
    /// some end. <see cref="SshClientOptions.MaxForwardedConnections"/> still applies across all forwardings. Default 100.
    /// </param>
    /// <param name="cancellationToken">Cancels the request to the server.</param>
    /// <returns>The forwarding; dispose it to stop. <see cref="SshRemotePortForwarder.LocalHost"/> is empty and
    /// <see cref="SshRemotePortForwarder.LocalPort"/> 0.</returns>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowTcpForwarding</c>, or the port is in use).</exception>
    public Task<SshRemotePortForwarder> ForwardRemotePortAsync(string bindAddress, int remotePort, Func<SshForwardedConnection, CancellationToken, Task> handler,
        int maxConnections = 100, CancellationToken cancellationToken = default)
    {
        ValidateRemoteListen(bindAddress, remotePort);
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConnections, 1);
        return StartRemoteForwardAsync(bindAddress, remotePort,
            port => new SshRemotePortForwarder(bindAddress, port, handler, maxConnections, _logger, CancelRemoteForwardAsync, _connection.Closed),
            cancellationToken);
    }

    /// <summary>
    /// Remote Unix-socket forwarding (<c>ssh -R /remote/socket:host:port</c>, <c>streamlocal-forward@openssh.com</c>): asks the server
    /// to listen on the Unix socket <paramref name="remoteSocketPath"/> and relays every connection made to it to
    /// <paramref name="localHost"/>:<paramref name="localPort"/>, as reached from this machine. For example, a database here becomes a socket
    /// that programs on the server can open. sshd's <c>StreamLocalBindUnlink</c> decides whether a stale socket file is replaced.
    /// </summary>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowStreamLocalForwarding</c>, or the socket exists).</exception>
    public Task<SshRemoteSocketForwarder> ForwardRemoteUnixSocketAsync(string remoteSocketPath, string localHost, int localPort, CancellationToken cancellationToken = default)
    {
        ValidateSocketPath(remoteSocketPath, nameof(remoteSocketPath));
        ValidateDestination(localHost, localPort);
        return StartRemoteSocketForwardAsync(remoteSocketPath,
            path => new SshRemoteSocketForwarder(path, localHost, localPort, null, _logger, CancelRemoteSocketForwardAsync, _connection.Closed), cancellationToken);
    }

    /// <summary>
    /// Remote Unix-socket forwarding to a Unix socket here (<c>ssh -R /remote/socket:/local/socket</c>): for example, a local
    /// <c>gpg-agent</c> or Docker socket that programs on the server can use.
    /// </summary>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowStreamLocalForwarding</c>, or the socket exists).</exception>
    public Task<SshRemoteSocketForwarder> ForwardRemoteUnixSocketAsync(string remoteSocketPath, string localSocketPath, CancellationToken cancellationToken = default)
    {
        ValidateSocketPath(remoteSocketPath, nameof(remoteSocketPath));
        ValidateSocketPath(localSocketPath, nameof(localSocketPath));
        return StartRemoteSocketForwardAsync(remoteSocketPath,
            path => new SshRemoteSocketForwarder(path, null, 0, localSocketPath, _logger, CancelRemoteSocketForwardAsync, _connection.Closed), cancellationToken);
    }

    /// <summary>
    /// Remote Unix-socket forwarding to a handler in this process: asks the server to listen on the Unix socket
    /// <paramref name="remoteSocketPath"/> (<c>streamlocal-forward@openssh.com</c>) and passes every connection made to it to
    /// <paramref name="handler"/>, as a <see cref="SshForwardedConnection"/> with a duplex <see cref="SshForwardedConnection.Stream"/>.
    /// sshd's <c>StreamLocalBindUnlink</c> decides whether a stale socket file is replaced.
    /// </summary>
    /// <param name="remoteSocketPath">The Unix socket the server listens on.</param>
    /// <param name="handler">
    /// Serves one connection; it runs concurrently for concurrent connections. It owns the connection's stream: disposing it closes
    /// the connection, and it is disposed when the handler returns. Its token is cancelled when the forwarder is disposed or the SSH
    /// connection ends. A handler that throws closes its own connection only; the exception is logged by type, and the forwarding goes
    /// on. Anyone who can open the socket on the server can connect, so treat what arrives as untrusted input.
    /// </param>
    /// <param name="maxConnections">
    /// The most connections served at once by this forwarding; the server's channels above it are refused (resource shortage) until
    /// some end. <see cref="SshClientOptions.MaxForwardedConnections"/> still applies across all forwardings. Default 100.
    /// </param>
    /// <param name="cancellationToken">Cancels the request to the server.</param>
    /// <returns>The forwarding; dispose it to stop. <see cref="SshRemoteSocketForwarder.LocalHost"/> and
    /// <see cref="SshRemoteSocketForwarder.LocalSocketPath"/> are null.</returns>
    /// <exception cref="SshException">The server refused (sshd's <c>AllowStreamLocalForwarding</c>, or the socket exists).</exception>
    public Task<SshRemoteSocketForwarder> ForwardRemoteUnixSocketAsync(string remoteSocketPath, Func<SshForwardedConnection, CancellationToken, Task> handler,
        int maxConnections = 100, CancellationToken cancellationToken = default)
    {
        ValidateSocketPath(remoteSocketPath, nameof(remoteSocketPath));
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConnections, 1);
        return StartRemoteSocketForwardAsync(remoteSocketPath,
            path => new SshRemoteSocketForwarder(path, handler, maxConnections, _logger, CancelRemoteSocketForwardAsync, _connection.Closed), cancellationToken);
    }

    private static void ValidateSocketPath(string path, string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(path, name);
        if (path.Any(char.IsControl))
        {
            throw new ArgumentException("A socket path must not contain control characters.", name);
        }
    }

    private async Task<SshRemoteSocketForwarder> StartRemoteSocketForwardAsync(string remoteSocketPath, Func<string, SshRemoteSocketForwarder> create, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        EnsureChannelDispatch();
        var forwarder = create(remoteSocketPath);
        if (!_remoteSocketForwards.TryAdd(remoteSocketPath, forwarder))
        {
            throw new SshException(SshFailureReason.ChannelClosed, $"The socket '{remoteSocketPath}' is already forwarded on this connection.");
        }

        GlobalReply reply;
        try
        {
            reply = await _connection.SendGlobalRequestAsync("streamlocal-forward@openssh.com", true, w => w.WriteString(remoteSocketPath), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or SshException or ObjectDisposedException)
        {
            // Not started: drop the registration, so a later attempt with this path is not "already forwarded". After a cancellation the
            // server may have accepted the request all the same; disposing the forwarder withdraws it there (cancel-streamlocal-forward,
            // answered after the request it follows) and refuses anything forwarded meanwhile. Its first step, the removal, runs at once.
            _ = forwarder.DisposeAsync().AsTask();
            throw;
        }

        if (!reply.Success)
        {
            _remoteSocketForwards.TryRemove(remoteSocketPath, out _);
            throw new SshException(SshFailureReason.ChannelClosed, "The server refused to listen on the Unix socket (stream-local forwarding not allowed, or the socket exists).");
        }

        if (forwarder.IsHandler)
        {
            SshLog.RemoteSocketHandlerForwardingStarted(_logger);
        }
        else
        {
            SshLog.RemoteSocketForwardingStarted(_logger);
        }

        return forwarder;
    }

    private async Task CancelRemoteSocketForwardAsync(SshRemoteSocketForwarder forwarder, CancellationToken cancellationToken)
    {
        _remoteSocketForwards.TryRemove(new KeyValuePair<string, SshRemoteSocketForwarder>(forwarder.RemoteSocketPath, forwarder));
        if (_disposed == 0)
        {
            await _connection.SendGlobalRequestAsync("cancel-streamlocal-forward@openssh.com", true, w => w.WriteString(forwarder.RemoteSocketPath), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static void ValidateRemoteListen(string bindAddress, int remotePort)
    {
        ArgumentNullException.ThrowIfNull(bindAddress);
        if (bindAddress.Any(char.IsControl))
        {
            throw new ArgumentException("The bind address must not contain control characters.", nameof(bindAddress));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(remotePort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(remotePort, 65535);
    }

    /// <summary>Asks the server to listen (<c>tcpip-forward</c>), then routes the port's channels to the forwarder <paramref name="create"/> makes.</summary>
    private async Task<SshRemotePortForwarder> StartRemoteForwardAsync(string bindAddress, int remotePort, Func<int, SshRemotePortForwarder> create, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        EnsureChannelDispatch();

        GlobalReply reply;
        try
        {
            reply = await _connection.SendGlobalRequestAsync("tcpip-forward", true, w =>
            {
                w.WriteString(bindAddress);
                w.WriteUInt32((uint)remotePort);
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (remotePort != 0)
        {
            // The server may have accepted it anyway: withdraw it, so it does not listen with nothing here to take its connections (with
            // port 0 the port it picked is unknown, and its connections are refused as unrouted).
            _ = WithdrawAsync();
            throw;
        }

        async Task WithdrawAsync()
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await _connection.SendGlobalRequestAsync("cancel-tcpip-forward", true, w =>
                {
                    w.WriteString(bindAddress);
                    w.WriteUInt32((uint)remotePort);
                }, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SshException or ObjectDisposedException)
            {
                // The connection is gone, and the forwarding with it.
            }
        }

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

        var forwarder = create(port);
        if (!_remoteForwards.TryAdd(port, forwarder))
        {
            // The server accepted it (another bind address for the same port), but this connection routes channels by port: withdraw the
            // new one on the server too, rather than leave it listening with nothing here to take its connections.
            await forwarder.DisposeAsync().ConfigureAwait(false);
            throw new SshException(SshFailureReason.ChannelClosed, $"Port {port} is already forwarded on this connection.");
        }

        if (forwarder.IsHandler)
        {
            SshLog.RemoteHandlerForwardingStarted(_logger, port);
        }
        else if (forwarder.IsDynamic)
        {
            SshLog.RemoteDynamicForwardingStarted(_logger, port);
        }
        else
        {
            SshLog.RemoteForwardingStarted(_logger, port, forwarder.LocalPort);
        }

        return forwarder;
    }

    private async Task CancelRemoteForwardAsync(SshRemotePortForwarder forwarder, CancellationToken cancellationToken)
    {
        // Stop accepting this port's channels first: anything the server opens from now on is refused.
        _remoteForwards.TryRemove(new KeyValuePair<int, SshRemotePortForwarder>(forwarder.RemotePort, forwarder));
        if (_disposed == 0)
        {
            await _connection.SendGlobalRequestAsync("cancel-tcpip-forward", true, w =>
            {
                w.WriteString(forwarder.BindAddress);
                w.WriteUInt32((uint)forwarder.RemotePort);
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Routes the channels the server opens (installed once, by the first feature that receives them).</summary>
    private void EnsureChannelDispatch() => _connection.AcceptChannel ??= (type, data) =>
    {
        if (type is "auth-agent@openssh.com" or "agent-connect")
        {
            // Agent forwarding: only when this client forwards an agent (the server asks for it after the agent request). RFC 9987 calls
            // the channel "agent-connect"; OpenSSH's older name is accepted too, whichever request the server answered.
            return _options.ForwardAgent is { } agent ? channel => _ = RelayAgentAsync(channel, agent) : null;
        }

        Func<SshChannel, Task>? accept = null;
        Func<bool>? reserve = null;
        Action? release = null;
        try
        {
            if (type == "forwarded-streamlocal@openssh.com")
            {
                // The socket path that was connected, then a reserved string; only sockets this client asked for are served.
                var reader = new SshReader(data);
                if (_remoteSocketForwards.TryGetValue(reader.ReadUtf8String(), out var socketForwarder))
                {
                    (accept, reserve, release) = (socketForwarder.Accept, socketForwarder.TryReserve, socketForwarder.Release);
                }
            }
            else if (type == "forwarded-tcpip")
            {
                // RFC 4254 section 7.2: the address and port that were connected, then the originator's.
                var reader = new SshReader(data);
                reader.ReadUtf8String();
                var port = (int)reader.ReadUInt32();
                if (_remoteForwards.TryGetValue(port, out var forwarder))
                {
                    (accept, reserve, release) = (channel => forwarder.Accept(channel, data), forwarder.TryReserve, forwarder.Release);
                }
            }
        }
        catch (SshProtocolException)
        {
            return null;
        }

        if (accept is null || reserve is null || release is null)
        {
            return null;
        }

        // Each one is a local connection (or a SOCKS exchange, or a handler's work) on this machine: a server cannot make this client
        // open without limit, over all forwardings, nor beyond a handler forwarding's own limit. Both counts are taken now, before the
        // channel is confirmed, so concurrent opens cannot overshoot. (Should the confirmation fail to go out, the connection is ending,
        // and its forwardings with it.)
        if (Interlocked.Increment(ref _forwardedConnections) > _options.MaxForwardedConnections)
        {
            Interlocked.Decrement(ref _forwardedConnections);
            return SshConnection.RefuseResourceShortage;
        }

        if (!reserve())
        {
            Interlocked.Decrement(ref _forwardedConnections);
            return SshConnection.RefuseResourceShortage;
        }

        return channel => _ = accept(channel).ContinueWith(
            _ => Interlocked.Decrement(ref _forwardedConnections), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    };

    private int _forwardedConnections;

    /// <summary>How many connections the server has forwarded to this client that are still open (all remote forwardings together).</summary>
    internal int ForwardedConnections => Volatile.Read(ref _forwardedConnections);

    /// <summary>
    /// Serves one forwarded agent connection. An in-process agent answers it here; a real agent's connection is relayed byte for byte,
    /// or, with <see cref="SshClientOptions.ForwardAgentFilter"/>, request by request through the filter.
    /// </summary>
    private async Task RelayAgentAsync(SshChannel channel, SshAgent agent)
    {
        var filter = _options.ForwardAgentFilter;
        if (agent.Keyring is { } keyring)
        {
            await AgentChannelServer.RunAsync(channel, NewAgentServer(keyring, filter), _connection.Closed).ConfigureAwait(false);
            return;
        }

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
            // As ssh -A does: bind the agent connection to this session as a forwarding one, so the agent can apply destination
            // constraints to what the server's side asks of it. An agent without the extension refuses, and the relay goes ahead.
            if (AgentBinding is { } binding)
            {
                try
                {
                    await SshAgent.BindAsync(stream, binding, forwarding: true, _connection.Closed).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or SshException or OperationCanceledException)
                {
                    SshLog.AgentUnavailable(_logger, ex.Message);
                    await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                    channel.DiscardUnread();
                    return;
                }
            }

            if (filter is null)
            {
                await StreamChannelRelay.RunAsync(stream, channel, _connection.Closed).ConfigureAwait(false);
            }
            else
            {
                await AgentChannelServer.RunAsync(channel, NewAgentServer(new RelayedAgent(stream), filter), _connection.Closed).ConfigureAwait(false);
            }
        }
    }

    /// <summary>An agent protocol server for one forwarded channel, knowing this connection's server as the first forwarding hop.</summary>
    private AgentServer NewAgentServer(AgentBackend backend, Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? filter)
    {
        var server = new AgentServer(backend, filter, _logger);
        if (AgentBinding is { } binding)
        {
            server.AddForwardingHop(binding);
        }

        return server;
    }

    private readonly List<SshLocalPortForwarder> _localForwardings = [];
    private readonly List<SshRemotePortForwarder> _remoteForwardings = [];
    private readonly List<SshDynamicPortForwarder> _dynamicForwardings = [];

    /// <summary>The <c>LocalForward</c> forwardings started from ssh_config (<see cref="SshConfigConnectOptions.StartForwardings"/>); disposed with the client.</summary>
    public IReadOnlyList<SshLocalPortForwarder> LocalForwardings => _localForwardings.AsReadOnly();

    /// <summary>The <c>RemoteForward</c> forwardings started from ssh_config; disposed with the client.</summary>
    public IReadOnlyList<SshRemotePortForwarder> RemoteForwardings => _remoteForwardings.AsReadOnly();

    private readonly List<SshRemoteSocketForwarder> _remoteSocketForwardings = [];

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, SshRemoteSocketForwarder> _remoteSocketForwards = new(StringComparer.Ordinal);

    /// <summary>The <c>RemoteForward</c> forwardings of a Unix socket on the server (<c>RemoteForward /path target</c>) started from ssh_config.</summary>
    public IReadOnlyList<SshRemoteSocketForwarder> RemoteSocketForwardings => _remoteSocketForwardings.AsReadOnly();

    /// <summary>The <c>DynamicForward</c> SOCKS proxies started from ssh_config; disposed with the client.</summary>
    public IReadOnlyList<SshDynamicPortForwarder> DynamicForwardings => _dynamicForwardings.AsReadOnly();

    private readonly List<SshLocalSocketForwarder> _localSocketForwardings = [];

    /// <summary>
    /// The <c>LocalForward</c> forwardings that listen on a Unix socket here (<c>LocalForward /path target</c>) started from ssh_config;
    /// disposed with the client. Those that listen on a port, to a Unix socket on the server too, are in <see cref="LocalForwardings"/>.
    /// </summary>
    public IReadOnlyList<SshLocalSocketForwarder> LocalSocketForwardings => _localSocketForwardings.AsReadOnly();

    /// <summary>A Unix socket path from a forwarding specification, with ssh_config's tokens, <c>~</c> and <c>${VAR}</c> expanded, as ssh does.</summary>
    private static string ExpandSocketPath(string path, SshHostConfig hostConfig) =>
        hostConfig.Tokens is { } tokens ? tokens.ExpandPath(tokens.ExpandTokens(path)) : path;

    /// <summary>
    /// Starts the forwardings ssh_config names for this host. One that cannot be set up (a port or socket path in use, refused by the
    /// server, a form this library does not support) is logged and skipped, or fails the connection with <c>ExitOnForwardFailure</c>.
    /// </summary>
    internal async Task StartConfiguredForwardingsAsync(SshHostConfig hostConfig, CancellationToken cancellationToken)
    {
        foreach (var spec in hostConfig.LocalForwards)
        {
            await TryForwardAsync("LocalForward", spec, async () =>
            {
                // As in ssh, a field with a '/' in it is a Unix socket path: /local/socket host:hostport, [bind:]port /remote/socket, or
                // /local/socket /remote/socket. The local one may be written with '\' too, as Windows paths are (no bind address or
                // port has either). Paths take ssh_config's tokens, ~ and ${VAR}, as ssh expands them.
                var parts = spec.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                var localIsSocket = parts.Length == 2 && parts[0].AsSpan().IndexOfAny('/', '\\') >= 0;
                if (parts.Length == 2 && (localIsSocket || parts[1].Contains('/')))
                {
                    var remoteSocket = parts[1].Contains('/') ? ExpandSocketPath(parts[1], hostConfig) : null;
                    var socketTarget = remoteSocket is null
                        ? ForwardSpec.ParseTarget(parts[1]) ?? throw new FormatException("the target must be host:hostport or a socket path")
                        : default;
                    if (localIsSocket)
                    {
                        var localSocket = ExpandSocketPath(parts[0], hostConfig);
                        ValidateSocketPath(localSocket, nameof(spec));
                        _localSocketForwardings.Add(await StartLocalSocketForwardAsync(localSocket, hostConfig.StreamLocalBindUnlink,
                            remoteSocket is null ? socketTarget.Host : null, socketTarget.Port, remoteSocket, cancellationToken).ConfigureAwait(false));
                    }
                    else
                    {
                        var socketListen = ForwardSpec.ParseListen(parts[0]) ?? throw new FormatException("the listening side must be [bind:]port or a socket path");
                        _localForwardings.Add(await ForwardLocalPortAsync(LocalBind(socketListen, hostConfig.GatewayPorts), remoteSocket!, cancellationToken)
                            .ConfigureAwait(false));
                    }

                    return;
                }

                var (listen, target) = ForwardSpec.ParseForward(spec) ?? throw new FormatException("only [bind:]port host:hostport is supported");
                _localForwardings.Add(await ForwardLocalPortAsync(LocalBind(listen, hostConfig.GatewayPorts), target.Host, target.Port, cancellationToken).ConfigureAwait(false));
            }).ConfigureAwait(false);
        }

        foreach (var spec in hostConfig.RemoteForwards)
        {
            await TryForwardAsync("RemoteForward", spec, async () =>
            {
                // /remote/socket host:hostport or /remote/socket /local/socket: a Unix socket on the server. As in ssh, a field
                // with a '/' in it is a socket path (so C:/run/agent.sock is one on Windows).
                var parts = spec.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && parts[0].StartsWith('/'))
                {
                    _remoteSocketForwardings.Add(parts[1].Contains('/')
                        ? await ForwardRemoteUnixSocketAsync(parts[0], parts[1], cancellationToken).ConfigureAwait(false)
                        : ForwardSpec.ParseTarget(parts[1]) is { } socketTarget
                            ? await ForwardRemoteUnixSocketAsync(parts[0], socketTarget.Host, socketTarget.Port, cancellationToken).ConfigureAwait(false)
                            : throw new FormatException("the target must be host:hostport or a socket path"));
                    return;
                }

                // [bind:]port host:hostport, or [bind:]port alone for remote dynamic forwarding (a SOCKS proxy on this side).
                var forward = ForwardSpec.ParseForward(spec);
                var listen = forward?.Listen ?? ForwardSpec.ParseListen(spec)
                    ?? throw new FormatException("only [bind:]port host:hostport and [bind:]port are supported");

                // ssh asks for the server's loopback when no address is given; "*" means every address.
                var bind = listen.Bind switch { null => "localhost", "*" => "", var given => given };
                _remoteForwardings.Add(forward is { Target: var target }
                    ? await ForwardRemotePortAsync(bind, listen.Port, target.Host, target.Port, cancellationToken).ConfigureAwait(false)
                    : await ForwardRemoteDynamicPortAsync(bind, listen.Port, cancellationToken: cancellationToken).ConfigureAwait(false));
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
            // Which one, by position: the specification and the exception text can name hosts, addresses and socket paths, which stay
            // out of logs and error messages (see SshLog); the inner exception keeps the details for the caller.
            var index = (keyword switch
            {
                "LocalForward" => hostConfig.LocalForwards,
                "RemoteForward" => hostConfig.RemoteForwards,
                _ => hostConfig.DynamicForwards,
            }).ToList().IndexOf(spec) + 1;
            try
            {
                await start().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is FormatException or SocketException or SshException or ArgumentException or IOException or UnauthorizedAccessException)
            {
                var reason = ex switch
                {
                    FormatException => "this form is not supported",
                    SocketException socketError => "the local address could not be used (" + socketError.SocketErrorCode + ")",
                    SshException sshError => "the server did not set it up (" + sshError.Reason + ")",
                    IOException or UnauthorizedAccessException => "the local socket file could not be created or replaced",
                    _ => "the specification is invalid",
                };
                if (hostConfig.ExitOnForwardFailure)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, $"{keyword} number {index} could not be set up: {reason}.", ex);
                }

                SshLog.ConfiguredForwardingSkipped(_logger, keyword, index, reason);
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

        foreach (var forwarding in _localSocketForwardings)
        {
            await forwarding.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var forwarding in _remoteForwardings)
        {
            await forwarding.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var forwarding in _remoteSocketForwardings)
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
