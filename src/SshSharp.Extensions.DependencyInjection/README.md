# SshSharp.Extensions.DependencyInjection

Dependency injection for [SshSharp](https://github.com/zcsizmadia/SshSharp): named SSH endpoints from configuration, a factory for
new connections, a shared connection that is opened again when it drops, and a health check.

```csharp
builder.Services.AddSshClient("deploy").BindConfiguration("Ssh:Deploy").ValidateOnStart();
builder.Services.AddHealthChecks().AddSsh("deploy");

// A new connection the caller owns:
await using var client = await clientFactory.ConnectAsync("deploy", cancellationToken);

// The shared one, which the provider owns and reconnects:
var shared = await connections.GetClientAsync("deploy", cancellationToken);

// An SFTP session on the shared connection, which the caller owns (also the session factory of SftpFileProvider and SftpFileSystem):
await using var sftp = await connections.OpenSftpAsync("deploy", cancellationToken);
```

Unknown hosts fail by default (`AcceptNewHostKeys` opts in to recording them). In containers, pin the server's host key with
`HostKeyFingerprints` and give private keys as values with `PrivateKeys` (for example `Ssh__Deploy__PrivateKeys__0__Key` from a
secret), with no files in `~/.ssh`. See the
[dependency injection guide](https://zcsizmadia.github.io/SshSharp/dependency-injection.html).
