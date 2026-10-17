# Samples

Runnable projects, built with the solution in CI, so they keep compiling as the API changes.

| Sample | Shows |
|---|---|
| [SshSharp.Samples](SshSharp.Samples) | An `ssh`-like command-line tool, connecting through `~/.ssh/config` (aliases, ProxyJump, keys and the agent): commands, a streamed `tail`, a shell, port forwarding, a SOCKS proxy, SCP, SFTP transfers (times and permissions kept, progress, parallel ranges, resuming), a remote tree through `IFileSystem` (`SshSharp.IO.Abstractions`), and logging in with a Windows CNG key through a login-only `SshKeySigner` |
| [SshSharp.Samples.AspNetCore](SshSharp.Samples.AspNetCore) | ASP.NET Core with `SshSharp.Extensions.DependencyInjection`: endpoints on the shared connection, a file streamed through SFTP, static files from the server (`SshSharp.FileProviders`), and a health check |
| [SshSharp.Samples.Worker](SshSharp.Samples.Worker) | A worker service that follows a remote log file across dropped connections |

The console tool's commands:

```
dotnet run --project samples/SshSharp.Samples -- run myserver "uname -a"
dotnet run --project samples/SshSharp.Samples -- get myserver /var/backups/db.dump db.dump
dotnet run --project samples/SshSharp.Samples -- put myserver ./site /srv/www
dotnet run --project samples/SshSharp.Samples -- tree myserver /srv/www
```

`myserver` is an `~/.ssh/config` alias, `user@host`, or `ssh://user@host:port`; the full list of commands is at the top of its
`Program.cs`. A password, if the server asks for one, comes from `SSHSHARP_PASSWORD`.
