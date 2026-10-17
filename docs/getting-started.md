# Getting started

## Install

```
dotnet add package SshSharp
```

SshSharp targets .NET 8 and .NET 10 and has no native dependencies.

## Run a command

```csharp
using SshSharp;
using SshSharp.Config;

await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    Password = Environment.GetEnvironmentVariable("DEPLOY_PASSWORD"),
    // Trust what ~/.ssh/known_hosts says; record hosts seen for the first time.
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.AcceptNew),
});

var result = await client.RunCommandAsync("uname -a");
Console.WriteLine($"exit {result.ExitStatus}: {result.StandardOutputText}");
```

There is no default host key verifier on purpose: accepting unknown keys silently would defeat host authentication.
See [Host keys](host-keys.md) for the choices.

## Connect the way `ssh` does

With an `ssh_config` alias, everything else comes from the configuration: host name, port, user, identity files, the SSH
agent, `known_hosts`, `StrictHostKeyChecking`, algorithms, `ProxyJump`, `ProxyCommand`, keep-alive and timeouts.

```csharp
await using var client = await SshClient.ConnectAsync("prod-db");
```

## Use a key

```csharp
using var key = await SshPrivateKey.LoadAsync(
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "id_ed25519"));

await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key],
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
});
```

## Testing code that uses SshSharp

`SshClient`, `SshSession` and the other types are sealed, and SshSharp has no interfaces for them: an interface can be added later
without breaking anyone, but changing one after it ships breaks everyone who implements it. To substitute SSH in your tests, put
the few operations your code needs behind an interface of your own, and implement it once with SshSharp:

```csharp
public interface IRemoteRunner
{
    Task<string> RunAsync(string command, CancellationToken cancellationToken);
}

public sealed class SshRunner(SshClient client) : IRemoteRunner
{
    public async Task<string> RunAsync(string command, CancellationToken cancellationToken) =>
        (await client.RunCommandAsync(command, cancellationToken)).StandardOutputText;
}
```

Your tests then use a fake `IRemoteRunner`. For integration tests, `SshClient.ConnectAsync` also takes any `Stream`, so a test can
connect to a server it runs in the same process; a package with such an in-memory test server is planned
([#240](https://github.com/zcsizmadia/SshSharp/issues/240)).

## Where next

- [Connecting](connecting.md): TCP, any `Stream`, `ssh_config` aliases, ProxyJump and ProxyCommand, keep-alive.
- [Authentication](authentication.md): passwords, keys, certificates, the SSH agent, keyboard-interactive.
- [Host keys](host-keys.md): `known_hosts`, policies, pinning, certificate authorities.
- [Commands and shells](sessions.md): `RunCommandAsync`, streamed commands, interactive shells with a terminal.
- [File transfer (SFTP)](sftp.md): browse, read and write remote files, and transfer files and directories; also as an
  `IFileSystem` or `IFileProvider`.
- [File transfer (SCP)](scp.md): files, streams and directories, where a server has no SFTP.
- [Signing files and commits](signing.md): SSH signatures, as `ssh-keygen -Y` and git make them.
- [Configuration files](config-files.md): reading `ssh_config` and `known_hosts` directly.
- [Errors and diagnostics](diagnostics.md): exceptions, logging, tracing and metrics.
