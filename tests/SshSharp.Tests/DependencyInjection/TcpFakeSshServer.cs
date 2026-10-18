using System.Net;
using System.Net.Sockets;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.DependencyInjection;

/// <summary>
/// <see cref="FakeSessionServer"/> behind a loopback TCP port, for code that connects by host and port: each accepted connection gets
/// its own server, all with the same host key (so a reconnection meets a known host). It can refuse new connections (close them at
/// once, as a server that is down) and drop the live ones.
/// </summary>
internal sealed class TcpFakeSshServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly FakeServerOptions _options = new() { HostKey = FakeHostKey.Ed25519() };
    private readonly List<(Socket Socket, FakeSessionServer Server)> _live = [];
    private int _connections;

    public TcpFakeSshServer()
    {
        _listener.Start();
        _ = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>The server's host key fingerprint (<c>SHA256:...</c>), the same for every connection.</summary>
    public string HostKeyFingerprint => _options.HostKey.Fingerprint;

    /// <summary>
    /// Public keys (SSH wire format) every connection's server accepts. When set, the servers offer only public key authentication;
    /// otherwise only the password.
    /// </summary>
    public List<byte[]> AuthorizedKeys { get; init; } = [];

    /// <summary>How many TCP connections were accepted, refused ones included.</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>Close new connections at once, before the server's identification, as a server that is down does.</summary>
    public bool Refuse { get; set; }

    /// <summary>Resets every live connection (RST), as a network failure or a restarted server does.</summary>
    public void DropAll()
    {
        lock (_live)
        {
            foreach (var (socket, _) in _live)
            {
                try
                {
                    socket.LingerState = new LingerOption(true, 0);
                }
                catch (ObjectDisposedException)
                {
                    continue; // that connection has ended already
                }

                socket.Dispose();
            }
        }
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }

            Interlocked.Increment(ref _connections);
            if (Refuse)
            {
                socket.Dispose();
                continue;
            }

            var server = AuthorizedKeys.Count > 0
                ? new FakeSessionServer(_options) { AdvertisedMethods = ["publickey"], AuthorizedKeys = AuthorizedKeys }
                : new FakeSessionServer(_options);
            _ = server.StartAsync();
            lock (_live)
            {
                _live.Add((socket, server));
            }

            var network = new NetworkStream(socket, ownsSocket: false);
            _ = PumpAsync(network, server.ClientStream, socket);
            _ = PumpAsync(server.ClientStream, network, socket);
        }
    }

    private static async Task PumpAsync(Stream from, Stream to, Socket socket)
    {
        try
        {
            await from.CopyToAsync(to);
        }
        catch (Exception)
        {
            // Dropped, or stopped.
        }
        finally
        {
            socket.Dispose(); // either direction ending ends the connection
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        DropAll();
        List<FakeSessionServer> servers;
        lock (_live)
        {
            servers = [.. _live.Select(l => l.Server)];
        }

        foreach (var server in servers)
        {
            await server.DisposeAsync();
        }

        _stop.Dispose();
    }
}
