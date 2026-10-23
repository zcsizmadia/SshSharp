# ASP.NET Core with SshSharp

A minimal API that uses an SSH server through `SshSharp.Extensions.DependencyInjection` and `SshSharp.FileProviders`.

| Endpoint | Shows |
|---|---|
| `GET /uptime` | A command over the shared connection (`ISshConnectionProvider`), which is opened again when it drops |
| `GET /disk` | The same, through the endpoint injected by name: `[FromKeyedServices("server")] ISshEndpoint` |
| `GET /connection` | The shared connection's last change (`Connected`, `Disconnected`, `Reconnected`), which a hosted service follows with `WatchAsync` and logs |
| `GET /files/{path}` | A file streamed through SFTP from one directory on the server (`Ssh:FilesRoot`) |
| `GET /static/...` | Static files from a directory on the server (`Ssh:StaticRoot`), through `SftpFileProvider` |
| `GET /tunnel` | An HTTP service only the server reaches (`Ssh:TunnelUrl`, for example `http://localhost:8080/` on the server), through an `HttpClient` made with `UseSshTunnel("server")` |
| `GET /healthz` | The SSH health check (`AddHealthChecks().AddSsh("server")`) |

## Running it

1. Set the server in `appsettings.json` (`Ssh:Server`: `Host`, `UserName`, `PrivateKeyFiles`), or connect through an
   `~/.ssh/config` alias with `"ConfigAlias": "myserver"` instead.
2. Put secrets in user secrets, not in the file:
   `dotnet user-secrets set "Ssh:Server:Password" "..."` or `"Ssh:Server:PrivateKeyPassphrase"`.
3. The server's host key must be in `~/.ssh/known_hosts` (connect once with `ssh`), or set `"AcceptNewHostKeys": true` to record it
   on first use.
4. `dotnet run`, then open `/uptime`, `/disk`, `/connection`, `/files/<name>` or `/healthz`. Set `Ssh:TunnelUrl` to try `/tunnel`
   (the server must allow forwarding, sshd's `AllowTcpForwarding`).

### In a container

A container has no `~/.ssh`: give it the key as a value and pin the host key instead, through environment variables (or any other
configuration source, such as a Kubernetes secret mapped to them). Remove `PrivateKeyFiles` from `appsettings.json` first, or
point it at a key file the container has.

```shell
Ssh__Server__PrivateKeys__0__Key=...          # the key file's text, from the secret store
Ssh__Server__PrivateKeys__0__Passphrase=...   # only for an encrypted key
Ssh__Server__HostKeyFingerprints__0=SHA256:... # ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub, on the server
```

In development, the same go in user secrets: `dotnet user-secrets set "Ssh:Server:PrivateKeys:0:Key" "$(cat ~/.ssh/id_ed25519)"`.
See [Dependency injection: containers and Kubernetes](https://zcsizmadia.github.io/SshSharp/dependency-injection.html#containers-and-kubernetes).

The settings are checked when the application starts (`ValidateOnStart`), so a missing host or user name fails at once.

`/connection` and the log show the shared connection's changes. Watching does not connect: the first request or health check opens
the connection, and after a drop the next one opens it again. The events name the endpoint (`server`), never the host or user, and
the reason for a drop (which can hold the server's text) is logged but not returned.

The static file provider keeps one SFTP session on the shared connection (`ISshConnectionProvider.OpenSftpAsync` as its session
factory), and opens a new one after the connection drops, so `/static` keeps working when the server comes back.
