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

Read-only, with attributes and listings cached briefly (`SftpFileProviderOptions.CacheDuration`). Paths cannot leave the root.
The API is experimental (diagnostic `SSHSHARP001`). Documentation: https://zcsizmadia.github.io/SshSharp/
