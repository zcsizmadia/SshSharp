# SshSharp.FileProviders

An `IFileProvider` over SFTP, built on [SshSharp](https://www.nuget.org/packages/SshSharp): serve the files under a directory on an
SSH server to ASP.NET Core static files, Razor views, configuration, and anything else that reads through
`Microsoft.Extensions.FileProviders`. Nothing is mounted, so only your application sees the files.

The API is experimental: using it reports diagnostic `SSHSHARP001`, which is an error until you acknowledge it in the project file:

```xml
<PropertyGroup>
  <NoWarn>$(NoWarn);SSHSHARP001</NoWarn>
</PropertyGroup>
```

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

Read-only. `IFileProvider` is synchronous, so each lookup waits for the server (bounded by
`SftpFileProviderOptions.OperationTimeout`); attributes and listings are cached briefly (`CacheDuration`), in a cache of at most
`MaxCacheEntries` paths, so requests for paths that do not exist cannot grow it without limit. Paths cannot leave the root.
Documentation: https://zcsizmadia.github.io/SshSharp/
