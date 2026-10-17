# Use ssh_config and known_hosts

SshSharp reads OpenSSH's `ssh_config` and `known_hosts` with the same semantics as `ssh`. Connecting by alias applies everything
the configuration says; the `SshSharp.Config` types also read the files directly, for tools that only want the values.

## When to use

- Your users already have working `~/.ssh/config` entries, and your tool should behave like `ssh` with them.
- Operations teams manage host names, users, keys, bastions and host key policy in configuration, not in code.
- You need to inspect or update `known_hosts` yourself.

## Connect by alias

[!code-csharp[](../snippets/Connecting.cs#alias)]

What the configuration decides: `HostName`, `Port`, `User`, `IdentityFile`, `CertificateFile`, the agent (`IdentityAgent`,
`IdentitiesOnly`), `known_hosts` files and `StrictHostKeyChecking`, algorithms, `ProxyJump` and `ProxyCommand`, keep-alive,
`ConnectTimeout`, and more; the [ssh_config reference](../reference/ssh-config.md) lists every directive and how it is used.

## Supply what a configuration file cannot

Passphrases, answers to prompts, and policy for things a file should not decide alone go in `SshConfigConnectOptions`:

[!code-csharp[](../snippets/Connecting.cs#alias-options)]

## Ship a configuration with your application

`SshConfig.Parse` (or `SshConfig.Load` for a file) gives the application its own configuration, independent of the user's:

[!code-csharp[](../snippets/Connecting.cs#custom-config)]

## Read the configuration without connecting

`Resolve` returns what `ssh -G` would print for a host: `Host` and `Match` blocks, `Include`, tokens and environment variables
applied.

[!code-csharp[](../snippets/Connecting.cs#resolve)]

The verifier `ssh` would use for that host comes from the same resolution:

[!code-csharp[](../snippets/Connecting.cs#verifier-from-config)]

## Read and update known_hosts

[!code-csharp[](../snippets/Connecting.cs#known-hosts)]

Hashed host names (`|1|salt|hash`), `[host]:port`, wildcards and negation, `@cert-authority` and `@revoked` are understood.
`AppendAsync` only appends, so comments and the order of existing lines are kept.

## Notes and pitfalls

- **Commands in configuration files.** `ProxyCommand` runs a local program (allowed by default, as in `ssh`; turn it off with
  `AllowProxyCommand = false`). `KnownHostsCommand` decides which host keys are trusted, so it runs only with
  `AllowKnownHostsCommand = true`. `Match exec` runs only when `SshConfigResolveOptions.ExecMatcher` is set. Only enable these for
  configuration files you trust.
- **`Match exec` and canonicalization are asynchronous.** A configuration that needs them must be resolved with `ResolveAsync`;
  `Resolve` throws `NotSupportedException`. Connecting by alias always resolves asynchronously.
- **`BatchMode yes`** turns off every prompt: `AskHostKey`, `ConfirmHostKeyUpdate`, `PassphraseProvider` and the
  keyboard-interactive handler are not used.
- **Session settings are yours to apply.** `SendEnv`, `SetEnv` and `RequestTTY` are resolved (`SshHostConfig.SendEnv`, `SetEnv`,
  `RequestTty`) but not applied by connecting, since sessions are started by your code: pass them in `SshSessionOptions`.
- **Which file.** `SshConfig.LoadDefault()` reads `~/.ssh/config`, then the system file; `SshConfigConnectOptions.Config`
  replaces both.

## See also

- [Configuration files](../config-files.md) (in-depth: `Match` criteria, `KnownHostsCommand`, tokens)
- [Connecting: by ssh_config alias](../connecting.md#by-ssh_config-alias)
- [ssh_config directives](../reference/ssh-config.md)
- [Verify host keys](verify-host-keys.md)
