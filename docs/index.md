---
_layout: landing
title: SshSharp
---

<div class="text-center py-4">
  <img src="images/sshsharp.svg" alt="SshSharp logo" width="72" height="72">
  <h1 class="display-5 fw-bold mt-3">SshSharp</h1>
  <p class="lead mx-auto" style="max-width: 46rem">
    A managed, async-first SSH client library for .NET 8 and .NET 10. It reads <code>ssh_config</code> and
    <code>known_hosts</code> the way OpenSSH does, so your application connects the way <code>ssh</code> would:
    same host names, keys, agent, jump hosts and host key policy.
  </p>
  <p>
    <a class="btn btn-primary btn-lg m-1" href="getting-started.md">Get started</a>
    <a class="btn btn-outline-secondary btn-lg m-1" href="how-to/index.md">How-to guides</a>
    <a class="btn btn-outline-secondary btn-lg m-1" href="api/index.md">API reference</a>
  </p>
</div>

## Install and connect

```
dotnet add package SshSharp
```

```csharp
using SshSharp;

// An alias from ~/.ssh/config: host name, user, keys, agent, ProxyJump and known_hosts all come from there.
await using var client = await SshClient.ConnectAsync("prod-db");

var result = await client.RunCommandAsync("uptime");
Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
```

No `ssh_config`? Pass the host, the credentials and a host key policy in [`SshClientOptions`](getting-started.md#connect-with-explicit-options).

## What it does

<div class="row row-cols-1 row-cols-md-3 g-3 my-2">
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Connects like <code>ssh</code></h5>
    <p class="card-text"><code>ssh_config</code> aliases with <code>Match</code> and <code>Include</code>, <code>ProxyJump</code> chains,
    <code>ProxyCommand</code>, HTTP and SOCKS proxies, or any <code>Stream</code>.</p>
    <a href="how-to/ssh-config-and-known-hosts.md" class="card-link">ssh_config and known_hosts</a>
    <a href="how-to/jump-hosts.md" class="card-link">Jump hosts</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Verified by default</h5>
    <p class="card-text">A host key verifier is required: <code>known_hosts</code> with OpenSSH's policies, host certificates,
    revocation lists, pinning or your own rule. Nothing is accepted silently.</p>
    <a href="how-to/verify-host-keys.md" class="card-link">Verify host keys</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Commands and shells</h5>
    <p class="card-text">Collect a command's output and exit status, stream it, drive an interactive shell with
    <code>SshExpect</code>, or start a subsystem.</p>
    <a href="how-to/run-a-command.md" class="card-link">Run a command</a>
    <a href="how-to/interactive-shell.md" class="card-link">Shells</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">SFTP and SCP</h5>
    <p class="card-text">Pipelined transfers, resume, segmented downloads and uploads, server-side hashes, directories, remote file streams, and SCP for servers
    without SFTP.</p>
    <a href="how-to/transfer-files-sftp.md" class="card-link">SFTP</a>
    <a href="how-to/transfer-files-scp.md" class="card-link">SCP</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Tunnels and forwarding</h5>
    <p class="card-text">Local, remote and dynamic (SOCKS) forwarding, Unix-socket tunnels, and <code>HttpClient</code> through the
    connection.</p>
    <a href="how-to/port-forwarding.md" class="card-link">Port forwarding</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Keys, agents, certificates</h5>
    <p class="card-text">OpenSSH, PEM and PuTTY keys, <code>ssh-agent</code> and Pageant, FIDO keys through the agent, keys in a
    TPM or KMS, OpenSSH certificates and Kerberos.</p>
    <a href="how-to/agent-and-keys.md" class="card-link">Keys and the agent</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Modern cryptography</h5>
    <p class="card-text">Post-quantum hybrid key exchange, ChaCha20-Poly1305 and AES-GCM, strict key exchange always on, and a FIPS
    mode. No legacy algorithms.</p>
    <a href="reference/algorithms.md" class="card-link">Algorithms</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Fits .NET applications</h5>
    <p class="card-text">Dependency injection with a shared reconnecting connection and health checks; SFTP as
    <code>IFileSystem</code> or <code>IFileProvider</code>; trimming and Native AOT.</p>
    <a href="how-to/aspnetcore-and-di.md" class="card-link">ASP.NET Core</a>
    <a href="how-to/file-system-adapters.md" class="card-link">IFileSystem</a>
  </div></div></div>
  <div class="col"><div class="card h-100"><div class="card-body">
    <h5 class="card-title">Observable</h5>
    <p class="card-text"><code>ILogger</code> logging, <code>ActivitySource</code> traces and <code>Meter</code> metrics that follow
    OpenTelemetry's conventions, with no secrets recorded.</p>
    <a href="how-to/logging-and-diagnostics.md" class="card-link">Logging and diagnostics</a>
  </div></div></div>
</div>

## Packages

| Package | What it adds |
|---|---|
| [`SshSharp`](https://www.nuget.org/packages/SshSharp) | The client: connections, authentication, host keys, commands and shells, forwarding, SFTP and SCP, `ssh_config` and `known_hosts`, keys and signatures. |
| [`SshSharp.Extensions.DependencyInjection`](https://www.nuget.org/packages/SshSharp.Extensions.DependencyInjection) | Named endpoints from configuration, `ISshClientFactory`, a shared reconnecting `ISshConnectionProvider`, and a health check. |
| [`SshSharp.IO.Abstractions`](https://www.nuget.org/packages/SshSharp.IO.Abstractions) | `SftpFileSystem`: SFTP as a System.IO.Abstractions `IFileSystem`. |
| [`SshSharp.FileProviders`](https://www.nuget.org/packages/SshSharp.FileProviders) | `SftpFileProvider`: a remote directory as an `IFileProvider`, for static files, Razor views and configuration. |

All four are released together with the same version, target .NET 8 and .NET 10, and have no native dependencies.

## Where to go next

- **New to SshSharp:** [Getting started](getting-started.md), then the [tutorial](tutorial.md).
- **A specific task:** the [how-to guides](how-to/index.md), each a short page with focused examples.
- **A complete program:** the [scenarios](scenarios/index.md): a deployment script, a fleet health check, a file sync job, a
  database through a jump host, a background worker.
- **How it works:** [architecture and connection lifecycle](concepts/architecture.md), [channels](concepts/channels.md),
  [threading](concepts/threading.md) and the [security model](concepts/security-model.md).
- **Coming from SSH.NET:** [the migration guide](migrating-from-sshnet.md), the same tasks side by side.
- **Something is wrong:** [troubleshooting](reference/troubleshooting.md) and the [FAQ](reference/faq.md).

> [!NOTE]
> SshSharp 1.x follows semantic versioning: breaking changes wait for a major version. The managed cryptography has had an
> internal constant-time review but not yet an outside one; see the [cryptography review](crypto-review.md) and the
> [security policy](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md).
