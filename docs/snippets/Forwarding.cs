using System.Net;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/port-forwarding.md.</summary>
internal static class Forwarding
{
    public static async Task LocalAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <local>
        // ssh -L 15432:db.internal:5432: connections to 127.0.0.1:15432 here reach db.internal:5432 from the server.
        await using var forwarder = await client.ForwardLocalPortAsync(
            new IPEndPoint(IPAddress.Loopback, 15432), "db.internal", 5432, cancellationToken);
        Console.WriteLine($"Listening on {forwarder.LocalEndPoint}");

        await Task.Delay(Timeout.Infinite, cancellationToken);  // forwarding runs until the forwarder is disposed
        // </local>
    }

    public static async Task LocalEphemeralAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <local-ephemeral>
        // Port 0: the system picks a free port, so parallel jobs never collide.
        await using var forwarder = await client.ForwardLocalPortAsync(
            new IPEndPoint(IPAddress.Loopback, 0), "metrics.internal", 9090, cancellationToken);
        var url = $"http://127.0.0.1:{forwarder.LocalEndPoint.Port}/metrics";
        // </local-ephemeral>
        _ = url;
    }

    public static async Task TunnelAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <tunnel>
        // No local port at all: a Stream to the far end, for code that takes a Stream.
        await using var redis = await client.OpenTcpTunnelAsync("cache.internal", 6379, cancellationToken);
        await redis.WriteAsync("PING\r\n"u8.ToArray(), cancellationToken);
        var reply = new byte[64];
        var read = await redis.ReadAsync(reply, cancellationToken);

        // A Unix socket on the server: the Docker API, for example.
        await using var docker = await client.OpenUnixSocketTunnelAsync("/var/run/docker.sock", cancellationToken);
        // </tunnel>
        _ = read;
    }

    public static async Task HttpAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <http>
        // HttpClient whose connections are opened by the server: internal web services, no local listener.
        using var http = new HttpClient(new SocketsHttpHandler
        {
            ConnectCallback = client.CreateHttpConnectCallback(),
            UseProxy = false,
        });
        var health = await http.GetStringAsync(new Uri("http://grafana.internal:3000/api/health"), cancellationToken);
        // </http>
        _ = health;
    }

    public static async Task RemoteAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <remote>
        // ssh -R 8080:127.0.0.1:3000: the server listens on its loopback port 8080, and each connection reaches port 3000 here.
        await using var remote = await client.ForwardRemotePortAsync("localhost", 8080, "127.0.0.1", 3000, cancellationToken);
        Console.WriteLine($"The server forwards its port {remote.RemotePort} to {remote.LocalHost}:{remote.LocalPort}");
        // </remote>
    }

    public static async Task RemoteHandlerAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <remote-handler>
        // ssh -R 8080, served by this process: each connection to the server's localhost:8080 arrives here as a Stream.
        // Nothing listens on this machine.
        await using var remote = await client.ForwardRemotePortAsync("localhost", 8080, async (connection, ct) =>
        {
            // The handler owns the stream; it is disposed (closing the connection) when the handler returns.
            using var reader = new StreamReader(connection.Stream, leaveOpen: true);
            var line = await reader.ReadLineAsync(ct);
            await connection.Stream.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"you said: {line}\n"), ct);
        }, maxConnections: 20, cancellationToken);
        Console.WriteLine($"Serving the server's port {remote.RemotePort}");

        await Task.Delay(Timeout.Infinite, cancellationToken);  // disposing the forwarder cancels and closes the handlers' connections
        // </remote-handler>
    }

    public static async Task RemoteHandlerSocketAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <remote-handler-socket>
        // The same for a Unix socket on the server: programs there open /run/user/1000/app.sock and reach the handler here.
        await using var socket = await client.ForwardRemoteUnixSocketAsync("/run/user/1000/app.sock", async (connection, ct) =>
        {
            await connection.Stream.WriteAsync("ready\n"u8.ToArray(), ct);
            await connection.Stream.CopyToAsync(Stream.Null, ct);  // read until the program closes its side
        }, cancellationToken: cancellationToken);
        // </remote-handler-socket>
    }

    public static async Task DynamicAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <dynamic>
        // ssh -D 1080: a SOCKS 4/4a/5 proxy here; the server makes each connection and resolves the names.
        await using var socks = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 1080), cancellationToken);

        // Any SOCKS-aware client can use it, HttpClient included.
        using var http = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy("socks5://127.0.0.1:1080") });
        var page = await http.GetStringAsync(new Uri("http://intranet.internal/"), cancellationToken);
        // </dynamic>
        _ = page;
    }

    public static async Task RemoteDynamicAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <remote-dynamic>
        // ssh -R 1080: the server listens, and this machine is the SOCKS proxy. Allow only what the server's side should reach.
        await using var socks = await client.ForwardRemoteDynamicPortAsync("localhost", 1080,
            allowDestination: (host, port) => host == "mirror.internal" && port == 443, cancellationToken);
        // </remote-dynamic>
    }
}
