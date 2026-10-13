using System.Net;
using System.Net.Sockets;
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
        var forwarder = SshPortForwarder.Start(
            localEndPoint, remoteHost, remotePort, _logger,
            (origin, ct) => _connection.OpenDirectTcpIpAsync(remoteHost, remotePort, origin.Address.ToString(), origin.Port, ct),
            _connection.Closed);
        return Task.FromResult(forwarder);
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
