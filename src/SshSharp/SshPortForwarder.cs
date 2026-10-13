using System.Net;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A local port forwarding (<c>ssh -L</c>) started by <see cref="SshClient.ForwardLocalPortAsync"/>: connections to
/// <see cref="LocalEndPoint"/> are relayed through the server to <see cref="RemoteHost"/>:<see cref="RemotePort"/>. Dispose it to stop
/// listening and close the forwarded connections.
/// </summary>
public sealed class SshPortForwarder : IAsyncDisposable
{
    private readonly LocalListener _listener;

    internal SshPortForwarder(LocalListener listener, string remoteHost, int remotePort)
    {
        _listener = listener;
        RemoteHost = remoteHost;
        RemotePort = remotePort;
    }

    /// <summary>The local address and port being listened on (with the actual port when 0 was asked for).</summary>
    public IPEndPoint LocalEndPoint => _listener.LocalEndPoint;

    /// <summary>Where the server connects each forwarded connection to.</summary>
    public string RemoteHost { get; }

    /// <summary>The port on <see cref="RemoteHost"/>.</summary>
    public int RemotePort { get; }

    /// <summary>How many forwarded connections are open now.</summary>
    public int ActiveConnections => _listener.ActiveConnections;

    internal bool IsListening => _listener.IsListening;

    /// <summary>Stops listening and closes every forwarded connection.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}

/// <summary>
/// A SOCKS proxy (dynamic forwarding, <c>ssh -D</c>) started by <see cref="SshClient.ForwardDynamicPortAsync"/>: applications connect to
/// <see cref="LocalEndPoint"/> as a SOCKS 4, 4a or 5 proxy (CONNECT, no authentication), and each connection is made by the server to
/// the address the application asked for. Dispose it to stop listening and close the connections.
/// </summary>
public sealed class SshSocksProxy : IAsyncDisposable
{
    private readonly LocalListener _listener;

    internal SshSocksProxy(LocalListener listener) => _listener = listener;

    /// <summary>The local address and port being listened on (with the actual port when 0 was asked for).</summary>
    public IPEndPoint LocalEndPoint => _listener.LocalEndPoint;

    /// <summary>How many proxied connections are open now.</summary>
    public int ActiveConnections => _listener.ActiveConnections;

    internal bool IsListening => _listener.IsListening;

    /// <summary>Stops listening and closes every proxied connection.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}
