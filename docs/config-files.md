# Configuration files

The `SshSharp.Config` namespace reads OpenSSH's `ssh_config` and `known_hosts` with the same semantics as `ssh`, for
applications that want the values without connecting.

## `ssh_config`

```csharp
using SshSharp.Config;

var config = SshConfig.LoadDefault();         // ~/.ssh/config, then the system file
SshHostConfig host = config.Resolve("prod-db");
Console.WriteLine($"{host.User}@{host.HostName}:{host.Port}");
Console.WriteLine(string.Join(", ", host.IdentityFiles));
Console.WriteLine(string.Join(" -> ", host.ProxyJump));
```

Resolution follows `ssh -G`: first value wins, `Host` and `Match` (`host`, `originalhost`, `user`, `localuser`,
`canonical`, `final`, `all`, `exec`, `tagged`), `Include` with globs, `%` tokens, `~` and environment
variables, and algorithm lists with `+`, `-` and `^`. `Match` blocks with criteria this library cannot evaluate
(`localnetwork`, `version`, `sessiontype`, `command`) never apply, negated or not, rather than guess. `SshConfig.Parse(text)` reads a configuration from a string, and
`SshConfigResolveOptions` supplies the home directory, environment, local user and host name (for tests, or another user).

`Match exec` runs a local command, so it is evaluated only when `SshConfigResolveOptions.ExecMatcher` is set (for example
to `SshExecMatcher.RunShell`, for configuration files you trust); without it, `Match exec` does not match. `ProxyCommand` and `Match exec` inputs from the caller (host and user names) are validated so
they cannot inject shell syntax.

## `known_hosts`

```csharp
var knownHosts = await KnownHostsFile.LoadAsync(Path.Combine(home, ".ssh", "known_hosts"));
foreach (var entry in knownHosts.Find("example.com", 22))
{
    Console.WriteLine($"{entry.Marker} {entry.KeyType}");
}

KnownHostsCheckResult check = knownHosts.Check("example.com", 22, client.HostKey.KeyType, client.HostKey.PublicKey.Span);
// Match, Unknown, Changed or Revoked

await KnownHostsFile.AppendAsync(path, "new.example.com", 22, client.HostKey.KeyType, client.HostKey.PublicKey, hash: true);
```

Hashed host names (`|1|salt|hash`), `[host]:port`, wildcards and negation, `@cert-authority` and `@revoked` are supported.
`AppendAsync` only appends, so comments and the order of existing lines are kept.
