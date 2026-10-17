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
```

Unknown hosts fail by default (`AcceptNewHostKeys` opts in to recording them). See the
[dependency injection guide](https://zcsizmadia.github.io/SshSharp/dependency-injection.html).
