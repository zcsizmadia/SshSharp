# ASP.NET Core with SshSharp

A minimal API that uses an SSH server through `SshSharp.Extensions.DependencyInjection` and `SshSharp.FileProviders`.

| Endpoint | Shows |
|---|---|
| `GET /uptime` | A command over the shared connection (`ISshConnectionProvider`), which is opened again when it drops |
| `GET /files/{path}` | A file streamed through SFTP from one directory on the server (`Ssh:FilesRoot`) |
| `GET /static/...` | Static files from a directory on the server (`Ssh:StaticRoot`), through `SftpFileProvider` |
| `GET /healthz` | The SSH health check (`AddHealthChecks().AddSsh("server")`) |

## Running it

1. Set the server in `appsettings.json` (`Ssh:Server`: `Host`, `UserName`, `PrivateKeyFiles`), or connect through an
   `~/.ssh/config` alias with `"ConfigAlias": "myserver"` instead.
2. Put secrets in user secrets, not in the file:
   `dotnet user-secrets set "Ssh:Server:Password" "..."` or `"Ssh:Server:PrivateKeyPassphrase"`.
3. The server's host key must be in `~/.ssh/known_hosts` (connect once with `ssh`), or set `"AcceptNewHostKeys": true` to record it
   on first use.
4. `dotnet run`, then open `/uptime`, `/files/<name>` or `/healthz`.

The settings are checked when the application starts (`ValidateOnStart`), so a missing host or user name fails at once.

The static file provider keeps one SFTP session for the application's lifetime, on a connection of its own; it does not reconnect
by itself, unlike the shared connection the other endpoints use.
