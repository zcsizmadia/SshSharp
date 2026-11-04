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

## Override what the configuration says

Some transport settings belong to the application rather than to the file: a port from its own settings, a timeout that fits its
work, retries for a server that may be restarting. Set them in `SshConfigConnectOptions` and they win over `ssh_config`, as
`ssh -p` and `ssh -o` do; everything else still comes from the configuration:

[!code-csharp[](../snippets/Connecting.cs#alias-overrides)]

- `Port` is the destination's, never a `ProxyJump` hop's, and resolution sees it (`%p`, `Match`). A port written in an
  `ssh://host:port` destination still wins.
- `ConnectTimeout`, `ConnectionAttempts` and the keep-alive settings apply to the destination and every `ProxyJump` hop.
  `Timeout.InfiniteTimeSpan` removes the time limit and `KeepAliveInterval = TimeSpan.Zero` (or `Timeout.InfiniteTimeSpan`, as
  `SshClientOptions` takes it) the keep-alives, whatever the file says.
- An algorithm directive that leaves nothing SshSharp implements (`Ciphers aes128-cbc`: `ssh` still has CBC, SshSharp does not)
  fails right after the file is read, before anything is sent, naming the directive. `PubkeyAcceptedKeyTypes ssh-rsa` (SHA-1 only)
  is the exception: no key is offered, a warning says why, and a password still logs in.
- `AddressFamily` applies to the one TCP connection this machine makes: to the destination, or to the first `ProxyJump` hop.
  So does `StaggeredConnectDelay`, which races that connection's addresses (see
  [Race the server's addresses](../connecting.md#race-the-servers-addresses)); `ssh_config` has no directive for it.
- `Compression` is the destination's, as `ssh -C`: `true` or `false` wins over its `Compression` line, and each `ProxyJump` hop
  keeps its own (see [Compress a slow link](tune-and-inspect-connections.md#compress-a-slow-link)).
- `ConnectionAttempts` tries again only when the server could not be reached (refused, unreachable, timed out), one second
  apart, within the same `ConnectTimeout`; a host key or authentication failure is never retried.
- `ConfigureSocket` sets socket options on that same connection after `TCPKeepAlive` and `IPQoS` have been applied, so what it
  sets wins (see [`TCPKeepAlive` and `IPQoS`](tune-and-inspect-connections.md#tcpkeepalive-and-ipqos-from-ssh_config)).

## Ship a configuration with your application

`SshConfig.Parse` (or `SshConfig.Load` for a file) gives the application its own configuration, independent of the user's:

[!code-csharp[](../snippets/Connecting.cs#custom-config)]

## Read the configuration without connecting

`Resolve` returns what `ssh -G` would print for a host: `Host` and `Match` blocks, `Include`, tokens and environment variables
applied.

[!code-csharp[](../snippets/Connecting.cs#resolve)]

The verifier `ssh` would use for that host comes from the same resolution:

[!code-csharp[](../snippets/Connecting.cs#verifier-from-config)]

## Canonicalize host names

`CanonicalizeHostname yes` turns a short name into a fully qualified one before connecting: `ssh web` becomes
`web.corp.example.com`, and `Host` blocks written for full names apply. Turn on the built-in DNS canonicalizer with
`SshConfigResolveOptions.UseDnsCanonicalizer`:

[!code-csharp[](../snippets/Connecting.cs#canonicalize)]

- **It follows `ssh`.** `CanonicalDomains` are tried in order, each as an absolute name (`web.corp.example.com.`, so the system's
  search list does not apply), and `none` among them stops the list. A name with more dots than `CanonicalizeMaxDots` (default 1),
  a name ending in a dot (looked up as it is), and an IP address are handled as `ssh` handles them. `CanonicalizeFallbackLocal no`
  fails when nothing is found. Through `ProxyJump` or `ProxyCommand`, only `CanonicalizeHostname always` canonicalizes.
- **CNAMEs are followed only when `CanonicalizePermittedCNAMEs` allows the pair**, as in `ssh`: a found name becomes its CNAME
  target if a rule's source domains match the name and its target domains match the target.
- **Limits.** The lookups use the system resolver (`System.Net.Dns`): the hosts file and DNS, as `getaddrinfo` does for `ssh`. It
  reports the end of a CNAME chain, not the names in between, so rules are checked against the final target. When the platform
  reports no canonical name, there is nothing for a rule to act on and the name stays as found. `CanonicalizePermittedCNAMEs` with
  `CanonicalizeHostname no` does not follow CNAMEs (`ssh` does).
- **Off by default.** Resolving then makes DNS queries, which the application should choose. `Resolve` throws
  `NotSupportedException` when lookups are needed; use `ResolveAsync`, as connecting by alias does. `HostCanonicalizer` still
  replaces the built-in one, for a resolver of your own.

## Read and update known_hosts

[!code-csharp[](../snippets/Connecting.cs#known-hosts)]

Hashed host names (`|1|salt|hash`), `[host]:port`, wildcards and negation, `@cert-authority` and `@revoked` are understood.
`AppendAsync` only appends, so comments and the order of existing lines are kept.

## Notes and pitfalls

- **Commands in configuration files.** `ProxyCommand` runs a local program (allowed by default, as in `ssh`; turn it off with
  `AllowProxyCommand = false`). `KnownHostsCommand` decides which host keys are trusted, so it runs only with
  `AllowKnownHostsCommand = true`. `Match exec` runs only when `SshConfigResolveOptions.ExecMatcher` is set. Only enable these for
  configuration files you trust.
- **`Match exec` and canonicalization are asynchronous** (`HostCanonicalizer`, or the DNS lookups of `UseDnsCanonicalizer`). A
  configuration that needs them must be resolved with `ResolveAsync`;
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
