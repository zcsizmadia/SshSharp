# Dependency injection

`SshSharp.Extensions.DependencyInjection` registers SSH endpoints with `Microsoft.Extensions.DependencyInjection`, the way
`AddHttpClient` registers HTTP clients: named endpoints from configuration, a factory for new connections, one shared connection per
endpoint that is opened again when it drops (with notifications when it does), keyed services by endpoint name, `HttpClient`s that
connect through an endpoint, and a health check.

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
| `HostKeyFingerprints` | Trust only these host keys, instead of known_hosts: SHA-256 fingerprints (`SHA256:...`, as `ssh-keygen -lf` prints), public key lines (`ssh-ed25519 AAAA...`, as a `.pub` file holds) or known_hosts lines (as `ssh-keyscan` prints). Cannot be combined with `KnownHostsFiles` or `AcceptNewHostKeys`. |
| `UseAgent` | `true` also offers the SSH agent's keys, after `PrivateKeyFiles` and `PrivateKeys`. See [The SSH agent](#the-ssh-agent). |
| `Proxy` | An HTTP or SOCKS proxy as a URI (`http://proxy.example.com:3128`, `socks5://...`), with optional `user:password@`. |
| `JumpHosts` | Bastions to reach `Host` through, first to last, each with its own user, credentials and host keys. See [Jump hosts](#jump-hosts). |
| `ConfigAlias` | Connect through ssh_config by this alias instead: ProxyJump, IdentityFile, known_hosts and the rest come from there, and `Host`, `Port`, `UserName`, `PrivateKeyFiles`, `PrivateKeyPassphrase`, `KnownHostsFiles`, `AcceptNewHostKeys` and `KeepAliveInterval` are ignored (ssh_config's `ServerAliveInterval` applies). `Password` is still offered, to the destination only, never to a ProxyJump hop; `UseAgent`, `AddressFamily`, `Compression` and `ConnectTimeout` still apply. `PrivateKeys`, `HostKeyFingerprints`, `Proxy` and `JumpHosts` fail validation with it, rather than being ignored. |
| `KeepAliveInterval` | Keep-alives, so a dead connection is noticed. Unset, zero or infinite (`-00:00:00.001`, `Timeout.InfiniteTimeSpan`) sends none, as in `SshClientOptions`; any other negative value fails validation. |
| `AddressFamily` | `Inet` (IPv4 only) or `Inet6` (IPv6 only): which of the server's addresses are tried, as `ssh -4` and `-6`. Unset tries any. It is the built `SshClientOptions.AddressFamily`; with `ConfigAlias`, it overrides `ssh_config`'s `AddressFamily`. |
| `Compression` | `true` asks for OpenSSH's delayed compression (`zlib@openssh.com`), for a slow link carrying text; see [Compress a slow link](how-to/tune-and-inspect-connections.md#compress-a-slow-link). Unset does not compress. It is the built `SshClientOptions.Compression`; with `ConfigAlias`, it overrides `ssh_config`'s `Compression`. |
| `ConnectTimeout` | How long one attempt may take, authentication included (default 30 s, at most about 24 days, as `SshClientOptions.ConnectTimeout` allows; validation fails above that); then a `TimeoutException`. It is also the built `SshClientOptions.ConnectTimeout`, which `ConfigureClientOptions` may shorten but not extend. |
| `ReconnectDelay`, `MaxReconnectDelay` | The shared connection's wait after a failed attempt (default 1 s, doubling up to 1 min). |
| `ConfigureClientOptions` | A function from the services and the built `SshClientOptions` to the options to use: a custom host key verifier, keys held elsewhere (`SshPrivateKey.FromSigner`), a custom proxy (`SshProxy.FromConnector`). The options it receives already hold the jump hosts and the agent's keys: copy them into the new options. Not used with `ConfigAlias`. |

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
| `HostKeyFingerprints` | it is one of them (by fingerprint, or by the key a `.pub` or known_hosts line holds); known_hosts is not read, and nothing is recorded |
| `HostKeyFingerprints` with `KnownHostsFiles`, `AcceptNewHostKeys` or `ConfigAlias` | never: validation fails, so it is never unclear which one decided |

Pinned fingerprints replace known_hosts rather than add to it. Trusting a key that either allows would make the trust as wide as the
looser of the two (a stale or writable known_hosts could let in a key the pin excludes); requiring both would bring back the file
that pinning is meant to remove. List several entries to roll a host key over: the old and the new, until the server has
changed. Get a server's fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, or see
[Get a new server's keys](how-to/verify-host-keys.md#get-a-new-servers-keys).

An entry can also be the key itself, so the server's `.pub` file or `ssh-keyscan`'s output can be used as it is:

```json
"HostKeyFingerprints": [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... root@deploy",
  "deploy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB..."
]
```

- A known_hosts line's host field is not checked: the line pins its key, wherever it came from.
- Marked lines (`@cert-authority`, `@revoked`) fail validation, as does an entry with more than one line: give each key as an entry of
  its own.
- Validation errors name the entry (`HostKeyFingerprints[1]`), never its text, since a key's comment is often a user and host name.

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

### Watching the shared connection

`WatchAsync(name)` is an `IAsyncEnumerable<SshConnectionEvent>` of the shared connection's changes, for an application that keeps
something on the connection (a forwarding, a long-running command) and must set it up again on a new one. Each event also has the
`EndpointName` and a `Timestamp`, and `Kind` is an `SshConnectionEventKind`:

| `Kind` | When | `Client` | `Error` |
|---|---|---|---|
| `Connected` | The first connection opened, or the connection was up when watching began | the connection | null |
| `Disconnected` | The connection ended (the network, the server, an unanswered keep-alive), or had ended when watching began | the one that ended | why (`SshClient.ConnectionError`) |
| `Reconnected` | A new connection replaced one that had ended | the new connection | why the old one ended |

```mermaid
stateDiagram-v2
    [*] --> Up: Connected (GetClientAsync connects)
    Up --> Down: Disconnected (the connection ends)
    Down --> Up: Reconnected (the next GetClientAsync connects)
```

- **The current state first.** A watcher starts with the connection's state, when there is one, so connecting first and then
  watching misses nothing.
- **Watching does not connect.** After `Disconnected`, the provider waits for the next `GetClientAsync`; call it from the watcher to
  reconnect at once (its delay after failures still applies).
- **No event is lost or repeated.** Each enumeration has its own queue; a slow reader delays only itself. Each connection's end is
  reported once, before the `Reconnected` that follows it.
- **Privacy.** An event names the endpoint by its registered name only, with no host or user name. `Error` can hold the server's
  disconnect text: log it, but keep it out of public responses.
- **The event's client may be gone.** Events arrive after the fact: by the time one is handled, its `Client` may have ended, and
  a later `GetClientAsync` may already have disposed it to replace it. Using it can then throw `ObjectDisposedException` as well as
  `SshException`; catch both when `IsConnected` is false, and wait for the next event.
- Disposing the container ends every enumeration, without a `Disconnected` event. An `ISshConnectionProvider` of your own (a test
  fake) need not implement it: the interface's default throws `NotSupportedException`.

See [ASP.NET Core and dependency injection: restore a forwarding after a reconnect](how-to/aspnetcore-and-di.md#restore-a-forwarding-after-a-reconnect)
for a hosted service that does this.

## An endpoint by name: keyed services

`AddSshClient(name)` also registers an `ISshEndpoint` keyed by the name, so a service can take its endpoint with
`[FromKeyedServices("deploy")]` (or `GetRequiredKeyedService<ISshEndpoint>("deploy")`) instead of a name string in every call:

[!code-csharp[](snippets/DependencyInjection.cs#keyed)]

`ISshEndpoint` is `ISshConnectionProvider` and `ISshClientFactory` for that one name, with the same lifetimes: `GetClientAsync` is
the shared connection (the provider's), `ConnectAsync` a new one (the caller's), `WatchAsync` its changes, and `OpenSftpAsync` a session
on the shared connection. The keyed service is a singleton and owns nothing. It is not an `SshClient`: resolving a service cannot wait
for a connection without blocking a thread.

## `HttpClient` through an endpoint

`UseSshTunnel(name)` on an `IHttpClientBuilder` makes a named or typed `HttpClient` connect through the endpoint's shared connection:
each TCP connection it opens is a `direct-tcpip` channel from the server (as `ssh -L`), so it reaches APIs only the server reaches.

[!code-csharp[](snippets/DependencyInjection.cs#http-client)]

[!code-csharp[](snippets/DependencyInjection.cs#http-client-use)]

- Host names are resolved by the SSH server. TLS runs end to end, from the application to the service.
- The primary handler becomes a `SocketsHttpHandler` with `UseProxy = false` (a system proxy would otherwise be reached through the
  server instead of the service). The optional second argument adjusts it (TLS settings, pool lifetimes); leave `ConnectCallback`
  and `UseProxy` as they are.
- The shared connection is opened by the first request, and again after a drop. A channel that fails because the connection had just
  dropped is opened once more on the new one, before anything is sent; a request already running on the dropped connection fails.
- An endpoint name that is not registered fails when the client is created, not inside every request.
- The server must allow forwarding (sshd's `AllowTcpForwarding`).

The same tunnel without `IHttpClientFactory` is `SshClient.CreateHttpConnectCallback()`; see
[Port forwarding: HttpClient through the server](how-to/port-forwarding.md#httpclient-through-the-server).

## Jump hosts

`JumpHosts` reaches `Host` through one or more bastions, first to last, as `ssh -J` does. Each hop is a settings object of its own
(`SshEndpointJumpHost`), bound from configuration like the endpoint:

```json
{
  "Ssh": {
    "App": {
      "Host": "app1.internal.example.com",
      "UserName": "deploy",
      "PrivateKeyFiles": [ "~/.ssh/deploy_ed25519" ],
      "HostKeyFingerprints": [ "SHA256:..." ],
      "JumpHosts": [
        {
          "Host": "bastion.example.com",
          "UserName": "jump",
          "PrivateKeyFiles": [ "~/.ssh/jump_ed25519" ],
          "HostKeyFingerprints": [ "SHA256:..." ]
        }
      ]
    }
  }
}
```

```mermaid
flowchart LR
    app["Application"] -->|"TCP (or Proxy)"| bastion["bastion.example.com<br/>user jump, its own key,<br/>its own host key check"]
    bastion -->|"direct-tcpip"| target["app1.internal.example.com<br/>user deploy, the endpoint's keys,<br/>the endpoint's host key check"]
```

| Hop setting | Meaning |
|---|---|
| `Host`, `Port` | The jump host (port 22 by default). The first is resolved locally (or by the endpoint's `Proxy`); each next one, and `Host`, by the hop before. Required. |
| `UserName` | The user on the jump host. Required: the endpoint's user is the destination's. |
| `Password`, `PrivateKeyFiles`, `PrivateKeyPassphrase`, `PrivateKeys`, `UseAgent` | The hop's own credentials, as the endpoint's settings of the same names. |
| `HostKeyFingerprints` | Pins for the jump host's key, as the endpoint's. |
| `KnownHostsFiles`, `AcceptNewHostKeys` | known_hosts files for the jump host. Without these and without `HostKeyFingerprints`, the hop is checked against the endpoint's `KnownHostsFiles` (default `~/.ssh/known_hosts`), and the endpoint's `AcceptNewHostKeys` applies too, as ssh checks a ProxyJump host. |

- **Credentials never cross hops.** A hop is offered only its own password and keys; the endpoint's go to `Host` alone.
- **Host keys are checked at every hop.** When the endpoint pins `HostKeyFingerprints`, each hop must have its own pins or
  `KnownHostsFiles` (validation fails otherwise): the endpoint's pins are the destination's keys.
- **Timeouts and keep-alives.** `ConnectTimeout` bounds the whole chain; `KeepAliveInterval` applies to every hop.
- **Validation** checks each hop as it checks the endpoint, and names it (`JumpHosts[0]: set UserName.`). `JumpHosts` cannot be
  combined with `ConfigAlias`, where ssh_config's `ProxyJump` applies.
- `ConfigureClientOptions` receives the options with the hops in `JumpHosts`: copy them into the options it returns.

See [Jump hosts](how-to/jump-hosts.md) for jump hosts without dependency injection.

## The SSH agent

`UseAgent = true` (`"UseAgent": true` in configuration) offers the keys of the user's SSH agent, after `PrivateKeyFiles` and
`PrivateKeys`. The private keys stay in the agent, which signs.

[!code-csharp[](snippets/DependencyInjection.cs#agent)]

- **Which agent.** An `SshAgent` registered in the container, if there is one; otherwise the environment's (`SSH_AUTH_SOCK`, or on
  Windows the OpenSSH agent service, else Pageant), found with `SshAgent.FromEnvironmentAsync`, which does not block a thread.
  Registering one serves keys held in the process, for example behind a cloud KMS:

  [!code-csharp[](snippets/DependencyInjection.cs#agent-in-process)]

- **No agent is not an error.** When the agent is not running, the endpoint connects with its other credentials, as ssh does (logged at
  `Debug`, with the reason only).
- **Per hop.** A jump host's `UseAgent` offers the agent to that hop; the endpoint's offers it to `Host` only.
- **With `ConfigAlias`**, ssh_config decides when `UseAgent` is not set (`IdentityAgent`, as ssh does); `false` turns the agent off,
  and `true` uses the same agent as without it, in place of `IdentityAgent`: the one registered in the container, else the user's.
  Only when there is neither does `IdentityAgent` decide.
- The agent is listed once per connection, however many hops use it.

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

`ISshClientFactory`, `ISshConnectionProvider` and `ISshEndpoint` are interfaces, so code that takes them can be given a fake in its
tests.

Runnable examples: [an ASP.NET Core minimal API](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples.AspNetCore)
and [a worker service](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples.Worker).

## See also

- [ASP.NET Core and dependency injection](how-to/aspnetcore-and-di.md): how the pieces fit together, with a diagram
- [A background worker](scenarios/background-worker.md)
- [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md)
