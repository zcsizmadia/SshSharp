# Worker service with SshSharp

A `BackgroundService` that follows a log file on an SSH server (`tail -n 0 -F`) and logs each line, for as long as the host runs.

It shows the shared connection from `SshSharp.Extensions.DependencyInjection` surviving failures:

- **Dropped connections:** keep-alives (`KeepAliveInterval`) notice a dead connection; the worker catches the error, waits, and
  asks the provider again, which opens a new connection.
- **A server that is down:** the provider waits longer after each failed attempt (`ReconnectDelay`, doubling up to
  `MaxReconnectDelay`), so the loop does not hammer it.
- **Log rotation:** `tail -F` follows the file by name.

## Running it

1. Set the server in `appsettings.json` (`Ssh:Server`) and the file to follow (`Tail:File`). To connect through an `~/.ssh/config`
   alias, set `"ConfigAlias": "myserver"` instead of `Host`, `UserName` and `PrivateKeyFiles`.
2. Keep secrets in user secrets: `dotnet user-secrets set "Ssh:Server:Password" "..."`.
3. The server's host key must be in `~/.ssh/known_hosts`, or set `"AcceptNewHostKeys": true`.
4. `dotnet run`. Stop the server's sshd, or unplug the network, to watch it reconnect.
