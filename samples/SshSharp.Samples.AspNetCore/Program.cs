using SshSharp;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.FileProviders;
using SshSharp.Sftp;

// SshSharp in an ASP.NET Core minimal API, through SshSharp.Extensions.DependencyInjection. The server is the "Ssh:Server" section of
// appsettings.json; keep its password or key passphrase in user secrets (dotnet user-secrets set "Ssh:Server:Password" "..."). In a
// container, the key itself and the pinned host key come from the environment instead (Ssh__Server__PrivateKeys__0__Key,
// Ssh__Server__HostKeyFingerprints__0; see README.md).
//
//   GET /uptime          runs a command over the shared connection
//   GET /disk            the same, through the endpoint injected by name (a keyed ISshEndpoint)
//   GET /connection      the shared connection's last change (Connected, Disconnected, Reconnected), followed with WatchAsync
//   GET /files/{path}    streams a file from Ssh:FilesRoot on the server, through SFTP
//   GET /static/...      static files served from Ssh:StaticRoot on the server (SshSharp.FileProviders)
//   GET /tunnel          an HTTP service only the server reaches (Ssh:TunnelUrl), through an HttpClient tunnelled over SSH
//   GET /healthz         the SSH health check
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSshClient("server")
    .BindConfiguration("Ssh:Server")
    .ValidateOnStart();
builder.Services.AddHealthChecks().AddSsh("server");

// Follows the shared connection's changes in the background, for logging and for GET /connection.
builder.Services.AddSingleton<ConnectionStatus>();
builder.Services.AddHostedService<ConnectionWatcher>();

// An HttpClient whose connections are direct-tcpip channels from the server (as ssh -L), so it reaches what only the server reaches,
// such as an internal API. The server resolves the host name; TLS, if the URL is https, runs end to end.
var tunnelUrl = builder.Configuration["Ssh:TunnelUrl"];
if (tunnelUrl is { Length: > 0 })
{
    builder.Services.AddHttpClient("behind-server", http => http.BaseAddress = new Uri(tunnelUrl)).UseSshTunnel("server");
}

var app = builder.Build();

// A command over the shared connection: one SSH connection serves every request, and it is opened again if it drops.
app.MapGet("/uptime", async (ISshConnectionProvider connections, CancellationToken cancellationToken) =>
{
    var client = await connections.GetClientAsync("server", cancellationToken); // owned by the provider: not disposed here
    var result = await client.RunCommandAsync("uptime", cancellationToken);
    return result.ExitStatus == 0 ? Results.Text(result.StandardOutputText) : Results.Problem("uptime failed on the server."); // not its stderr
});

// The endpoint injected by its name: an ISshEndpoint keyed "server", so the handler names the endpoint once, where it is injected,
// rather than in every call. It is the same shared connection as /uptime's.
app.MapGet("/disk", async ([FromKeyedServices("server")] ISshEndpoint server, CancellationToken cancellationToken) =>
{
    var client = await server.GetClientAsync(cancellationToken); // owned by the provider: not disposed here
    var result = await client.RunCommandAsync("df -h .", cancellationToken);
    return result.ExitStatus == 0 ? Results.Text(result.StandardOutputText) : Results.Problem("df failed on the server.");
});

// What the watcher saw last. The event's Error can hold the server's disconnect text, so it is logged, not returned.
app.MapGet("/connection", (ConnectionStatus status) => status.Last is { } last
    ? Results.Ok(new { state = last.Kind.ToString(), since = last.Timestamp })
    : Results.Ok(new { state = "NotConnectedYet", since = (DateTimeOffset?)null }));

// A file from one directory on the server, streamed as it arrives. The path comes from the client, so it must stay inside that
// directory: an empty or "/" root would expose the whole file system, and a Windows server (Win32-OpenSSH) takes '\' as a separator
// too. This endpoint has no authentication: add it before serving anything that is not public. The server follows symbolic links.
var filesRoot = (app.Configuration["Ssh:FilesRoot"] is { Length: > 0 } configured ? configured : "files").TrimEnd('/');
if (filesRoot.Length == 0)
{
    throw new InvalidOperationException("Ssh:FilesRoot must name a directory, not the root of the file system.");
}

app.MapGet("/files/{**path}", async (string path, ISshConnectionProvider connections, HttpContext http, CancellationToken cancellationToken) =>
{
    if (path.Split('/', '\\').Any(segment => segment is "" or "." or "..") || path.Contains('\0'))
    {
        return Results.BadRequest();
    }

    await using var sftp = await connections.OpenSftpAsync("server", cancellationToken); // a session per request; the connection is shared
    try
    {
        await using var file = await sftp.OpenReadAsync($"{filesRoot}/{path}", cancellationToken);
        http.Response.ContentType = "application/octet-stream";
        await file.CopyToAsync(http.Response.Body, cancellationToken);
        return Results.Empty;
    }
    catch (SftpException ex) when (ex.Status is SftpStatusCode.NoSuchFile)
    {
        return Results.NotFound();
    }
});

// Static files from a directory on the server: an IFileProvider over SFTP, so UseStaticFiles serves them as if they were local.
// The provider gets its SFTP session from the shared connection, and opens a new one there after the connection drops. It owns that
// session, so it is disposed when the application stops; the connection stays the provider's.
if (app.Configuration["Ssh:StaticRoot"] is { Length: > 0 } staticRoot)
{
    var connections = app.Services.GetRequiredService<ISshConnectionProvider>();
    var files = new SftpFileProvider(ct => connections.OpenSftpAsync("server", ct), staticRoot);
    app.UseStaticFiles(new StaticFileOptions { FileProvider = files, RequestPath = "/static" });
    app.Lifetime.ApplicationStopped.Register(files.Dispose);
}

// An HTTP service behind the server. This endpoint has no authentication: add it before exposing anything that is not public.
if (tunnelUrl is { Length: > 0 })
{
    app.MapGet("/tunnel", async (IHttpClientFactory httpClients, CancellationToken cancellationToken) =>
        Results.Text(await httpClients.CreateClient("behind-server").GetStringAsync(string.Empty, cancellationToken)));
}

app.MapHealthChecks("/healthz");

app.Run();

/// <summary>The shared connection's last change, as <see cref="ConnectionWatcher"/> saw it.</summary>
internal sealed class ConnectionStatus
{
    private SshConnectionEvent? _last;

    public SshConnectionEvent? Last
    {
        get => Volatile.Read(ref _last);
        set => Volatile.Write(ref _last, value);
    }
}

/// <summary>
/// Logs the shared connection's changes and keeps the last one. Watching does not connect: the first request or health check opens
/// the connection, and after a drop the next one opens it again (then Reconnected follows). An application that keeps something on
/// the connection, such as a forwarding, sets it up again here on Connected and Reconnected.
/// </summary>
internal sealed partial class ConnectionWatcher([FromKeyedServices("server")] ISshEndpoint server, ConnectionStatus status, ILogger<ConnectionWatcher> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The first event is the current state, when there is one; then each change as it happens. Events name the endpoint, never
        // the host or user.
        await foreach (var change in server.WatchAsync(stoppingToken))
        {
            status.Last = change;
            Changed(logger, change.EndpointName, change.Kind, change.Error);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "SSH endpoint {Endpoint}: {Kind}")]
    private static partial void Changed(ILogger logger, string endpoint, SshConnectionEventKind kind, Exception? error);
}
