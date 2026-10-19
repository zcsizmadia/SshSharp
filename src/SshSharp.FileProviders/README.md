# SshSharp.FileProviders

An `IFileProvider` over SFTP, built on [SshSharp](https://www.nuget.org/packages/SshSharp): serve the files under a directory on an
SSH server to ASP.NET Core static files, Razor views, configuration, and anything else that reads through
`Microsoft.Extensions.FileProviders`. Nothing is mounted, so only your application sees the files.

```csharp
using SshSharp;
using SshSharp.FileProviders;
using SshSharp.Sftp;

var ssh = await SshClient.ConnectAsync("deploy@assets.example.com");
var sftp = await ssh.OpenSftpAsync();

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new SftpFileProvider(sftp, "/srv/www"),
});
```

To keep serving after the connection drops, give the provider a session factory instead of one session: it opens a session on
the first lookup, and a new one after the session or its connection fails. With `SshSharp.Extensions.DependencyInjection`, the
shared connection's `OpenSftpAsync` is that factory:

```csharp
var connections = app.Services.GetRequiredService<ISshConnectionProvider>();
var provider = new SftpFileProvider(ct => connections.OpenSftpAsync("assets", ct), "/srv/www"); // owns its sessions
app.UseStaticFiles(new StaticFileOptions { FileProvider = provider });
app.Lifetime.ApplicationStopped.Register(provider.Dispose);
```

Read-only. `IFileProvider` is synchronous, so each lookup waits for the server (bounded by
`SftpFileProviderOptions.OperationTimeout`); attributes and listings are cached briefly (`CacheDuration`), in a cache of at most
`MaxCacheEntries` paths, so requests for paths that do not exist cannot grow it without limit. Paths cannot leave the root.
Documentation: https://zcsizmadia.github.io/SshSharp/
