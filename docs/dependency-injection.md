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
| `PrivateKeys` | Keys given as values, not files: a list of entries, each with `Key` (the key's text, OpenSSH, PEM or PuTTY) and an optional `Passphrase`. Offered after `PrivateKeyFiles`. See [Containers and Kubernetes](#containers-and-kubernetes). |
| `KnownHostsFiles` | Where the server's host key is checked (default `~/.ssh/known_hosts`). |
| `AcceptNewHostKeys` | Record the key of a host not in those files yet (`StrictHostKeyChecking accept-new`). Off by default: an unknown host fails the connection, and a changed key always does. |
| `HostKeyFingerprints` | Trust only host keys with these SHA-256 fingerprints (`SHA256:...`, as `ssh-keygen -lf` prints), instead of known_hosts. Cannot be combined with `KnownHostsFiles` or `AcceptNewHostKeys`. |
| `Proxy` | An HTTP or SOCKS proxy as a URI (`http://proxy.example.com:3128`, `socks5://...`), with optional `user:password@`. |
| `ConfigAlias` | Connect through ssh_config by this alias instead: ProxyJump, IdentityFile, known_hosts and the rest come from there, and `Host`, `Port`, `UserName`, `PrivateKeyFiles`, `KnownHostsFiles`, `AcceptNewHostKeys` and `KeepAliveInterval` are ignored (ssh_config's `ServerAliveInterval` applies). `Password` is still offered, to the destination only, never to a ProxyJump hop. `PrivateKeys`, `HostKeyFingerprints` and `Proxy` fail validation with it, rather than being ignored. |
| `KeepAliveInterval` | Keep-alives, so a dead connection is noticed. |
| `ConnectTimeout` | How long one attempt may take, authentication included (default 30 s); then a `TimeoutException`. It is also the built `SshClientOptions.ConnectTimeout`, which `ConfigureClientOptions` may shorten but not extend. |
| `ReconnectDelay`, `MaxReconnectDelay` | The shared connection's wait after a failed attempt (default 1 s, doubling up to 1 min). |
| `ConfigureClientOptions` | A function from the services and the built `SshClientOptions` to the options to use: an agent, a custom host key verifier, keys held elsewhere (`SshPrivateKey.FromSigner`), a proxy. Not used with `ConfigAlias`. |

## Containers and Kubernetes

A container usually gets its secrets as values (environment variables, a mounted Kubernetes secret, Key Vault), not as files in
`~/.ssh`, and has no `known_hosts` worth trusting. Two settings cover that without code:

- **`PrivateKeys`**: the key's text itself, with its passphrase if it has one.
- **`HostKeyFingerprints`**: the server's host key, pinned by fingerprint.

Keep the non-secret part in `appsettings.json`. A fingerprint is not a secret, but it decides what is trusted, so it belongs with the
deployment's configuration, not in code:

```json
{
  "Ssh": {
    "Deploy": {
      "Host": "deploy.example.com",
      "UserName": "deploy",
      "HostKeyFingerprints": [ "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" ]
    }
  }
}
```

The key and its passphrase come from elsewhere. Any configuration source works, because they are ordinary settings:

| Source | Key | Passphrase |
|---|---|---|
| Environment variables | `Ssh__Deploy__PrivateKeys__0__Key` | `Ssh__Deploy__PrivateKeys__0__Passphrase` |
| User secrets (development) | `dotnet user-secrets set "Ssh:Deploy:PrivateKeys:0:Key" "$(cat ~/.ssh/deploy_ed25519)"` | `Ssh:Deploy:PrivateKeys:0:Passphrase` |
| Azure Key Vault (configuration provider) | secret `Ssh--Deploy--PrivateKeys--0--Key` | secret `Ssh--Deploy--PrivateKeys--0--Passphrase` |

The registration is the usual one; `ValidateOnStart` checks the fingerprints' format and reads each key with its passphrase when the
host starts:

[!code-csharp[](snippets/DependencyInjection.cs#containers)]

In Kubernetes, put the key in a secret and map its entries to those variables:

```shell
kubectl create secret generic deploy-ssh \
  --from-file=key=./deploy_ed25519 \
  --from-file=passphrase=./deploy_ed25519.passphrase
```

```yaml
# In the Deployment's container spec.
env:
  - name: Ssh__Deploy__PrivateKeys__0__Key
    valueFrom:
      secretKeyRef: { name: deploy-ssh, key: key }
  - name: Ssh__Deploy__PrivateKeys__0__Passphrase
    valueFrom:
      secretKeyRef: { name: deploy-ssh, key: passphrase }
  - name: Ssh__Deploy__HostKeyFingerprints__0
    value: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
```

A multi-line key is fine in an environment variable, and white space around a fingerprint (the trailing newline of a file) is
ignored. A secret mounted as files works too, through the key-per-file configuration provider
(`AddKeyPerFile("/run/secrets/ssh")` with files named `Ssh__Deploy__PrivateKeys__0__Key`, and so on).

### How the host key is checked

| Settings | The host key is trusted when |
|---|---|
| Neither `HostKeyFingerprints` nor `KnownHostsFiles` | it is in `~/.ssh/known_hosts` |
| `KnownHostsFiles` (with or without `AcceptNewHostKeys`) | it is in those files (or, with `AcceptNewHostKeys`, the host is not in them yet: then it is recorded) |
| `HostKeyFingerprints` | its fingerprint is one of them; known_hosts is not read, and nothing is recorded |
| `HostKeyFingerprints` with `KnownHostsFiles`, `AcceptNewHostKeys` or `ConfigAlias` | never: validation fails, so it is never unclear which one decided |

Pinned fingerprints replace known_hosts rather than add to it. Trusting a key that either allows would make the trust as wide as the
looser of the two (a stale or writable known_hosts could let in a key the pin excludes); requiring both would bring back the file
that pinning is meant to remove. List several fingerprints to roll a host key over: the old and the new, until the server has
changed. Get a server's fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, or see
[Get a new server's keys](how-to/verify-host-keys.md#get-a-new-servers-keys).

### Keys given as values

- Each entry's `Key` is the whole key file's text: OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), PEM (PKCS#8, PKCS#1 or SEC1)
  or PuTTY (`.ppk`). `Passphrase` is ignored for an unencrypted key.
- Keys are offered in order: `PrivateKeyFiles` first, then `PrivateKeys`, then `Password`.
- Validation reads each key, so a key that cannot be read, or a wrong or missing passphrase, fails at startup with
  `ValidateOnStart`. The error names the entry (`PrivateKeys[0]`) and the problem, never the key or the passphrase.
- Each connection reads the keys again, as it reads key files, and does not keep them after authenticating.
- Neither keys nor passphrases are logged, and `SshEndpointPrivateKey.ToString()` and the debugger show only whether they are set.
  `Password`, `PrivateKeyPassphrase` and `Proxy` (which may hold a password) are hidden from the debugger too.

The same settings can be set in code, from configuration you read yourself:

[!code-csharp[](snippets/DependencyInjection.cs#pin-in-code)]

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

`OpenSftpAsync(name)` opens an SFTP session on the shared connection, connecting first if needed; the caller disposes the session,
never the connection. As the session factory of `SftpFileProvider` or `SftpFileSystem`, it makes the adapter follow the shared
connection across drops:

[!code-csharp[](snippets/DependencyInjection.cs#file-system)]

See [IFileSystem and IFileProvider: follow a connection that drops](how-to/file-system-adapters.md#follow-a-connection-that-drops).

## Health checks

```csharp
builder.Services.AddHealthChecks().AddSsh("deploy");
```

The check pings the endpoint's shared connection, opening it if needed: healthy when it answers, otherwise the registration's failure
status (unhealthy by default). Its description names no server software and holds no server text, as health endpoints are often
public; the exception is attached for logging, so keep it out of public responses. Its options are those of any health check: a name (default `ssh-` and the endpoint), the
failure status, tags and a timeout.

## Logging and testing

Clients log through the container's `ILoggerFactory`, under the category `SshSharp` (see [Errors and diagnostics](diagnostics.md)).

`ISshClientFactory` and `ISshConnectionProvider` are interfaces, so code that takes them can be given a fake in its tests.

Runnable examples: [an ASP.NET Core minimal API](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples.AspNetCore)
and [a worker service](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples.Worker).

## See also

- [ASP.NET Core and dependency injection](how-to/aspnetcore-and-di.md): how the pieces fit together, with a diagram
- [A background worker](scenarios/background-worker.md)
- [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md)
