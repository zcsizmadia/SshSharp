# Getting started

This page takes you from an empty project to a verified, authenticated SSH connection that runs a command and copies a file.
It takes about five minutes. For a longer walk-through that builds a small tool step by step, see the [tutorial](tutorial.md).

## Requirements

- .NET 8, .NET 10 or .NET 11, on Windows, Linux or macOS (x64 and Arm64). SshSharp is pure managed code: no native libraries to deploy.
- An SSH server: OpenSSH (Linux, BSD, macOS or the one built into Windows), Dropbear, or any server that speaks modern
  algorithms (see [Algorithms](reference/algorithms.md)).

## Install

```
dotnet add package SshSharp
```

Three optional packages build on it:

```
dotnet add package SshSharp.Extensions.DependencyInjection # named endpoints, a shared connection, health checks
dotnet add package SshSharp.IO.Abstractions                # SFTP as an IFileSystem
dotnet add package SshSharp.FileProviders                  # SFTP as an IFileProvider
```

## Connect with explicit options

`SshClient.ConnectAsync` connects, exchanges keys, verifies the server's host key and authenticates, and returns a client that is
ready to use. Dispose it to disconnect.

```csharp
using SshSharp;
using SshSharp.Config;

await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "user",
    Password = Environment.GetEnvironmentVariable("SSH_PASSWORD"),   // from the environment, never the source code
    // Trust what ~/.ssh/known_hosts says; record hosts seen for the first time.
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.AcceptNew),
});

var result = await client.RunCommandAsync("uname -a");
Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
```

> [!IMPORTANT]
> There is no default host key verifier on purpose: accepting unknown keys silently would defeat host authentication, and is how
> man-in-the-middle attacks succeed. `AcceptNew` trusts a host on first contact, as `ssh -o StrictHostKeyChecking=accept-new` does;
> use `Yes` once the hosts are in `known_hosts`. See [Verify host keys](how-to/verify-host-keys.md) for the choices.

## Connect the way `ssh` does

If `ssh prod-db` works from a terminal, this works too. The host name, port, user, identity files, the SSH agent, `known_hosts`,
`StrictHostKeyChecking`, algorithms, `ProxyJump`, `ProxyCommand`, keep-alive and timeouts all come from `~/.ssh/config`:

```csharp
await using var client = await SshClient.ConnectAsync("prod-db");
```

The destination can also be `user@host` or `ssh://user@host:port`. See [Use ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md).

## Use a key or the agent

```csharp
using var key = await SshPrivateKey.LoadAsync(
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "id_ed25519"));

await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "user",
    PrivateKeys = [key],
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
});
```

With `ssh-agent` (or the Windows OpenSSH agent, or Pageant), the private keys never enter your process:

```csharp
var agent = SshAgent.FromEnvironment();
var keys = agent is null ? [] : await agent.GetKeysAsync();
// then: PrivateKeys = keys
```

See [Keys and the SSH agent](how-to/agent-and-keys.md).

## Copy a file

SFTP runs over the same connection as your commands:

```csharp
using SshSharp.Sftp;

await using var sftp = await client.OpenSftpAsync();
await sftp.UploadFileAsync("report.pdf", "incoming/report.pdf");
await sftp.DownloadFileAsync("outgoing/data.csv", "data.csv");
```

See [Transfer files with SFTP](how-to/transfer-files-sftp.md).

## Handle failures

Every SSH-level failure is an `SshException` with a `Reason`; the common ones have their own types:

```csharp
try
{
    await using var client = await SshClient.ConnectAsync("prod-db");
}
catch (SshHostKeyException ex)          // the host key is unknown, changed or revoked
{
    Console.Error.WriteLine($"Host key not trusted: {ex.Message}");
}
catch (SshAuthenticationException ex)   // no credential was accepted
{
    Console.Error.WriteLine($"Login failed; the server accepts {string.Join(", ", ex.AllowedMethods)}.");
}
catch (SshException ex)                 // everything else: ex.Reason says what
{
    Console.Error.WriteLine($"{ex.Reason}: {ex.Message}");
}
```

See [Errors and failure reasons](reference/errors.md).

## Testing code that uses SshSharp

`SshClient` and the other types are sealed, and SshSharp has no interfaces for them: an interface can be added later without
breaking anyone, but changing one after it ships breaks everyone who implements it. Put the few operations your code needs behind
an interface of your own and fake that in tests. [Unit-test code that uses SshSharp](how-to/unit-testing.md) shows the pattern.

## Where next

- [Tutorial: a server check tool](tutorial.md): a small program, built up step by step.
- [How-to guides](how-to/index.md): short pages for specific tasks.
- [Scenarios](scenarios/index.md): complete programs for common jobs.
- In-depth guides: [Connecting](connecting.md), [Authentication](authentication.md), [Host keys](host-keys.md),
  [Commands and shells](sessions.md), [SFTP](sftp.md), [SCP](scp.md), [Signing](signing.md),
  [Configuration files](config-files.md), [Dependency injection](dependency-injection.md),
  [Errors and diagnostics](diagnostics.md).
