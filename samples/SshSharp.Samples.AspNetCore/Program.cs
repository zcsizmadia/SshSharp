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
//   GET /files/{path}    streams a file from Ssh:FilesRoot on the server, through SFTP
//   GET /static/...      static files served from Ssh:StaticRoot on the server (SshSharp.FileProviders)
//   GET /healthz         the SSH health check
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSshClient("server")
    .BindConfiguration("Ssh:Server")
    .ValidateOnStart();
builder.Services.AddHealthChecks().AddSsh("server");

var app = builder.Build();

// A command over the shared connection: one SSH connection serves every request, and it is opened again if it drops.
app.MapGet("/uptime", async (ISshConnectionProvider connections, CancellationToken cancellationToken) =>
{
    var client = await connections.GetClientAsync("server", cancellationToken); // owned by the provider: not disposed here
    var result = await client.RunCommandAsync("uptime", cancellationToken);
    return result.ExitStatus == 0 ? Results.Text(result.StandardOutputText) : Results.Problem("uptime failed on the server."); // not its stderr
});

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

    var client = await connections.GetClientAsync("server", cancellationToken);
    await using var sftp = await client.OpenSftpAsync(cancellationToken); // a session per request; the connection is shared
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
// The provider keeps one SFTP session for the application's lifetime, so it uses a connection of its own from the factory.
if (app.Configuration["Ssh:StaticRoot"] is { Length: > 0 } staticRoot)
{
    var ssh = await app.Services.GetRequiredService<ISshClientFactory>().ConnectAsync("server");
    var sftp = await ssh.OpenSftpAsync();
    app.UseStaticFiles(new StaticFileOptions { FileProvider = new SftpFileProvider(sftp, staticRoot), RequestPath = "/static" });
    app.Lifetime.ApplicationStopped.Register(() =>
    {
        sftp.DisposeAsync().AsTask().GetAwaiter().GetResult();
        ssh.DisposeAsync().AsTask().GetAwaiter().GetResult();
    });
}

app.MapHealthChecks("/healthz");

app.Run();
