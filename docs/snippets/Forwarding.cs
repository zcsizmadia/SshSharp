using System.Net;
using SshSharp;
using SshSharp.Config;

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

    public static async Task LocalUnixSocketsAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <local-unix-socket>
        // ssh -L 15432:/run/postgresql/.s.PGSQL.5432: a port here, the server's PostgreSQL socket there.
        await using var database = await client.ForwardLocalPortAsync(
            new IPEndPoint(IPAddress.Loopback, 15432), "/run/postgresql/.s.PGSQL.5432", cancellationToken);

        // ssh -L /tmp/docker.sock:/var/run/docker.sock: a socket here for the local Docker CLI, the server's daemon there
        // (DOCKER_HOST=unix:///tmp/docker.sock). The socket file is owner-only, and removed when the forwarder is disposed.
        await using var docker = await client.ForwardLocalUnixSocketAsync("/tmp/docker.sock", "/var/run/docker.sock", cancellationToken);

        // ssh -L /tmp/db.sock:db.internal:5432: a socket here, a host and port the server reaches.
        await using var socketToTcp = await client.ForwardLocalUnixSocketAsync("/tmp/db.sock", "db.internal", 5432, cancellationToken);
        // </local-unix-socket>
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

    public static async Task RemoteHandlerHalfCloseAsync(SshClient client, Stream upload, CancellationToken cancellationToken)
    {
        // <remote-handler-half-close>
        // A protocol where the end of a message is the end of the stream: the program on the server reads the whole greeting, then
        // sends its upload on the same connection.
        await using var remote = await client.ForwardRemotePortAsync("localhost", 7000, async (connection, ct) =>
        {
            await connection.Stream.WriteAsync("ready\n"u8.ToArray(), ct);
            await connection.ShutdownSendAsync(ct);             // end-of-file for the program; the connection stays open
            await connection.Stream.CopyToAsync(upload, ct);    // what it sends, until it closes its side
        }, maxConnections: 1, cancellationToken);
        // </remote-handler-half-close>

        // <remote-handler-shutdown>
        // Disposing cancels the handlers' tokens, then waits this long for them before closing their connections (5 s by default).
        remote.HandlerShutdownTimeout = TimeSpan.FromSeconds(30);
        Console.WriteLine($"handler: {remote.IsHandler}, at most {remote.MaxConnections} at once");   // handler: True, at most 1 at once
        // </remote-handler-shutdown>
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

    public static async Task DynamicWithPasswordAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <dynamic-auth>
        // A SOCKS proxy for other machines on the build network: it listens beyond loopback, so give it a user name and password
        // (SOCKS 5, RFC 1929). SOCKS 4 and clients without credentials are refused.
        var credentials = new NetworkCredential("builds",
            Environment.GetEnvironmentVariable("SOCKS_PASSWORD") ?? throw new InvalidOperationException("Set SOCKS_PASSWORD."));
        await using var socks = await client.ForwardDynamicPortAsync(
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 1080), credentials, cancellationToken);

        // On a build agent: curl --proxy socks5h://builds:$SOCKS_PASSWORD@192.0.2.1:1080 https://mirror.internal/
        // </dynamic-auth>
    }

    public static async Task LocalUnixSocketModeAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <local-unix-socket-mode>
        // The socket file 0660 (StreamLocalBindMask 0117) instead of 0600: members of the owner's group may connect too, for
        // example a service account that shares the group. Windows keeps it to the current user whatever the mode.
        await using var docker = await client.ForwardLocalUnixSocketAsync("/run/app/docker.sock", "/var/run/docker.sock",
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite, cancellationToken);
        // </local-unix-socket-mode>
    }

    public static async Task RemoteDynamicAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <remote-dynamic>
        // ssh -R 1080: the server listens, and this machine is the SOCKS proxy. Allow only what the server's side should reach.
        await using var socks = await client.ForwardRemoteDynamicPortAsync("localhost", 1080,
            allowDestination: (host, port) => host == "mirror.internal" && port == 443, cancellationToken);
        // </remote-dynamic>
    }

    public static async Task RemoteDynamicFromConfigAsync(CancellationToken cancellationToken)
    {
        // <remote-dynamic-config>
        // RemoteForward with only a port is remote dynamic forwarding; PermitRemoteOpen lists where it may connect.
        var config = SshConfig.Parse("""
            Host build
              HostName build.example.com
              User deploy
              RemoteForward 1080
              PermitRemoteOpen mirror.example.com:443 192.0.2.10:*
              ExitOnForwardFailure yes
            """);

        await using var client = await SshClient.ConnectAsync("build", new SshConfigConnectOptions
        {
            Config = config,
            StartForwardings = true,
        }, cancellationToken);
        // </remote-dynamic-config>
    }
}
