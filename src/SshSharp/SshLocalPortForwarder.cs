using System.Net;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A local port forwarding (<c>ssh -L</c>) started by <see cref="SshClient.ForwardLocalPortAsync(IPEndPoint, string, int, CancellationToken)"/> or its overload: connections to
/// <see cref="LocalEndPoint"/> are relayed through the server to <see cref="RemoteHost"/>:<see cref="RemotePort"/>, or to the Unix socket <see cref="RemoteSocketPath"/> there. Dispose it to stop
/// listening and close the forwarded connections.
/// </summary>
public sealed class SshLocalPortForwarder : IAsyncDisposable
{
    private readonly LocalListener _listener;

    internal SshLocalPortForwarder(LocalListener listener, string remoteHost, int remotePort)
    {
        _listener = listener;
        RemoteHost = remoteHost;
        RemotePort = remotePort;
    }

    /// <summary>A forwarding to the Unix socket <paramref name="remoteSocketPath"/> on the server.</summary>
    internal SshLocalPortForwarder(LocalListener listener, string remoteSocketPath)
        : this(listener, string.Empty, 0)
    {
        RemoteSocketPath = remoteSocketPath;
    }

    /// <summary>The local address and port being listened on (with the actual port when 0 was asked for).</summary>
    public IPEndPoint LocalEndPoint => _listener.LocalEndPoint;

    /// <summary>Where the server connects each forwarded connection to; empty when it connects to <see cref="RemoteSocketPath"/>.</summary>
    public string RemoteHost { get; }

    /// <summary>The port on <see cref="RemoteHost"/>; 0 when the server connects to <see cref="RemoteSocketPath"/>.</summary>
    public int RemotePort { get; }

    /// <summary>
    /// The Unix socket on the server each forwarded connection goes to (<c>ssh -L port:/remote/socket</c>), or null when it goes to
    /// <see cref="RemoteHost"/>:<see cref="RemotePort"/>.
    /// </summary>
    public string? RemoteSocketPath { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections => _listener.ActiveConnections;

    internal bool IsListening => _listener.IsListening;

    /// <summary>Stops listening and closes every forwarded connection.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}

/// <summary>
/// A local forwarding that listens on a Unix socket (<c>ssh -L /local/socket:host:port</c> or <c>ssh -L /local/socket:/remote/socket</c>),
/// started by <see cref="SshClient.ForwardLocalUnixSocketAsync(string, string, int, CancellationToken)"/> or its overload: connections to
/// the socket <see cref="LocalSocketPath"/> are relayed through the server to <see cref="RemoteHost"/>:<see cref="RemotePort"/>, or to
/// the Unix socket <see cref="RemoteSocketPath"/> on the server. The socket file is owner-only. Dispose it to stop listening, close the
/// forwarded connections and remove the socket file.
/// </summary>
public sealed class SshLocalSocketForwarder : IAsyncDisposable
{
    private readonly LocalListener _listener;

    internal SshLocalSocketForwarder(LocalListener listener, string? remoteHost, int remotePort, string? remoteSocketPath)
    {
        _listener = listener;
        RemoteHost = remoteHost;
        RemotePort = remotePort;
        RemoteSocketPath = remoteSocketPath;
    }

    /// <summary>The Unix socket being listened on, which this forwarder created.</summary>
    public string LocalSocketPath => _listener.SocketPath!;

    /// <summary>Where the server connects each forwarded connection to; null when it connects to <see cref="RemoteSocketPath"/>.</summary>
    public string? RemoteHost { get; }

    /// <summary>The port on <see cref="RemoteHost"/>; 0 when the server connects to <see cref="RemoteSocketPath"/>.</summary>
    public int RemotePort { get; }

    /// <summary>The Unix socket on the server each forwarded connection goes to; null when it goes to <see cref="RemoteHost"/>.</summary>
    public string? RemoteSocketPath { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections => _listener.ActiveConnections;

    internal bool IsListening => _listener.IsListening;

    /// <summary>Stops listening, closes every forwarded connection, and removes the socket file.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}

/// <summary>
/// A SOCKS proxy (dynamic forwarding, <c>ssh -D</c>) started by <see cref="SshClient.ForwardDynamicPortAsync"/>: applications connect to
/// <see cref="LocalEndPoint"/> as a SOCKS 4, 4a or 5 proxy (CONNECT, no authentication), and each connection is made by the server to
/// the address the application asked for. Dispose it to stop listening and close the connections.
/// </summary>
public sealed class SshDynamicPortForwarder : IAsyncDisposable
{
    private readonly LocalListener _listener;

    internal SshDynamicPortForwarder(LocalListener listener) => _listener = listener;

    /// <summary>The local address and port being listened on (with the actual port when 0 was asked for).</summary>
    public IPEndPoint LocalEndPoint => _listener.LocalEndPoint;

    /// <summary>How many proxied connections are open now.</summary>
    public int ActiveConnections => _listener.ActiveConnections;

    internal bool IsListening => _listener.IsListening;

    /// <summary>Stops listening and closes every proxied connection.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}
