# SshSharp.IO.Abstractions

An `IFileSystem` ([System.IO.Abstractions](https://github.com/TestableIO/System.IO.Abstractions)) over SFTP, built on
[SshSharp](https://www.nuget.org/packages/SshSharp): code written against `IFileSystem` instead of `File`, `Directory` and `Path`
reads and writes files on an SSH server. Nothing is mounted, so only your application sees them.

```csharp
using System.IO.Abstractions;
using SshSharp;
using SshSharp.IO.Abstractions;
using SshSharp.Sftp;

await using var ssh = await SshClient.ConnectAsync("deploy@files.example.com");
await using var sftp = await ssh.OpenSftpAsync();
IFileSystem fs = new SftpFileSystem(sftp);

fs.Directory.CreateDirectory("reports/2026");
fs.File.WriteAllText("reports/2026/summary.txt", "All green.");
foreach (var path in fs.Directory.EnumerateFiles("reports", "*.txt", SearchOption.AllDirectories))
{
    Console.WriteLine($"{path}: {fs.FileInfo.New(path).Length} bytes");
}
```

Paths are POSIX paths on the server (`fs.Path` uses `/` on every OS), relative to the login directory. Errors are the usual
`System.IO` exceptions. Not supported: `FileSystemWatcher`, `DriveInfo`, `FileVersionInfo`, `RandomAccess`, handles,
encryption and `Replace`. The API is experimental (diagnostic `SSHSHARP001`). Documentation: https://zcsizmadia.github.io/SshSharp/
