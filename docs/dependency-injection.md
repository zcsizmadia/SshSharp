# Dependency injection

`SshSharp.Extensions.DependencyInjection` registers SSH endpoints with `Microsoft.Extensions.DependencyInjection`, the way
`AddHttpClient` registers HTTP clients: named endpoints from configuration, a factory for new connections, one shared connection per
endpoint that is opened again when it drops, and a health check.

```
dotnet add package SshSharp.Extensions.DependencyInjection
```

## Registering endpoints

```csharp
builder.Services.AddSshClient("deploy")
    .BindConfiguration("Ssh:Deploy")   // the endpoint's settings, from appsettings.json, environment variables, a secret store ...
    .ValidateOnStart();                // checked when the host starts, not on first use

builder.Services.AddSshClient("db", o => o.ConfigAlias = "prod-db"); // everything from ~/.ssh/config
```

```json
{
  "Ssh": {
    "Deploy": {
      "Host": "deploy.example.com",
      "UserName": "deployer",
      "PrivateKeyFiles": [ "~/.ssh/deploy_ed25519" ],
      "KnownHostsFiles": [ "/etc/myapp/known_hosts" ],
      "KeepAliveInterval": "00:00:30"
    }
  }
}
```

`AddSshClient(name)` returns the endpoint's `OptionsBuilder<SshEndpointOptions>`, so the usual options calls apply (`Configure`,
`PostConfigure`, `Validate`, `BindConfiguration`). The settings:

| Setting | Meaning |
|---|---|
| `Host`, `Port` | The server (port 22 by default). Required unless `ConfigAlias` is set. |
| `UserName` | The user. Required unless `ConfigAlias` is set. |
| `Password` | A password, tried after any keys. Bind it from a secret store, not from a checked-in file. |
| `PrivateKeyFiles`, `PrivateKeyPassphrase` | Keys to authenticate with (OpenSSH, PEM or PuTTY files; `~/` is the user's home). |
| `KnownHostsFiles` | Where the server's host key is checked (default `~/.ssh/known_hosts`). |
| `AcceptNewHostKeys` | Record the key of a host not in those files yet (`StrictHostKeyChecking accept-new`). Off by default: an unknown host fails the connection, and a changed key always does. |
| `ConfigAlias` | Connect through ssh_config by this alias instead: ProxyJump, IdentityFile, known_hosts and the rest come from there. |
| `KeepAliveInterval` | Keep-alives, so a dead connection is noticed. |
| `ConnectTimeout` | How long one attempt may take, authentication included (default 30 s); then a `TimeoutException`. |
| `ReconnectDelay`, `MaxReconnectDelay` | The shared connection's wait after a failed attempt (default 1 s, doubling up to 1 min). |
| `ConfigureClientOptions` | A function from the services and the built `SshClientOptions` to the options to use: an agent, a custom host key verifier, keys held elsewhere (`SshPrivateKey.FromSigner`), a proxy. Not used with `ConfigAlias`. |

## New connections: `ISshClientFactory`

```csharp
public sealed class Deployer(ISshClientFactory ssh)
{
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await using var client = await ssh.ConnectAsync("deploy", cancellationToken);
        await client.RunCommandAsync("systemctl restart myapp", cancellationToken);
    }
}
```

Each call opens a new connection, which the caller owns and disposes.

## The shared connection: `ISshConnectionProvider`

```csharp
public sealed class Status(ISshConnectionProvider connections)
{
    public async Task<string> UptimeAsync(CancellationToken cancellationToken)
    {
        var client = await connections.GetClientAsync("deploy", cancellationToken); // do not dispose: the provider owns it
        return (await client.RunCommandAsync("uptime", cancellationToken)).StandardOutputText;
    }
}
```

`GetClientAsync` returns one long-lived client per endpoint, opened on first use and shared by every caller; SSH runs many commands
and channels over one connection at once.

- When it has dropped, the next call opens a new one. Callers at the same moment share that attempt.
- After a failed attempt, the next one waits (`ReconnectDelay`, doubling, up to `MaxReconnectDelay`), so a server that is down is not
  hammered; a call during that wait fails at once with the last error.
- Nothing is retried for you: a command that was running when the connection dropped fails, and the application decides whether
  running it again is safe.
- The provider disposes the clients when the container is disposed.

## Health checks

```csharp
builder.Services.AddHealthChecks().AddSsh("deploy");
```

The check pings the endpoint's shared connection, opening it if needed: healthy when it answers, otherwise the registration's failure
status (unhealthy by default) with the error. Its options are those of any health check: a name (default `ssh-` and the endpoint), the
failure status, tags and a timeout.

## Logging and testing

Clients log through the container's `ILoggerFactory`, under the category `SshSharp` (see [Errors and diagnostics](diagnostics.md)).

`ISshClientFactory` and `ISshConnectionProvider` are interfaces, so code that takes them can be given a fake in its tests.
