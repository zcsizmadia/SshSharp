# ssh_config directives

SshSharp resolves `ssh_config` with OpenSSH's rules (first value wins, `Host` and `Match` blocks, `Include`, `%` tokens, `~` and
environment variables, algorithm lists with `+`, `-` and `^`), and `SshClient.ConnectAsync(destination)` applies the result. This
page lists what each directive does in SshSharp. Directives not listed are parsed and available in `SshHostConfig.Options`, but
have no effect.

Keywords are case-insensitive, as in OpenSSH. The **Property** column is the `SshHostConfig` property that holds the resolved
value.

## Structure

| Directive | Notes |
|---|---|
| `Host` | Patterns with `*`, `?` and `!` negation. |
| `Match` | `all`, `host`, `originalhost`, `user`, `localuser`, `canonical`, `final`, `exec`, `tagged`, `localnetwork`, `sessiontype`, `command`; negation with `!`. `exec` runs only with `SshConfigResolveOptions.ExecMatcher`; `sessiontype` and `command` match only when `SessionType` (and `Command`) are given; `version` never matches. |
| `Include` | Globs, relative to `~/.ssh` (user file) or the system directory; at most 16 levels and 1,024 files. |
| `Tag` | Matched by `Match tagged`; `SshConfigResolveOptions.Tag` overrides it. |

## Destination and transport

| Directive | Property | Applied when connecting by alias |
|---|---|---|
| `HostName` | `HostName` | Yes, with `%h` and other tokens. |
| `Port` | `Port` | Yes. |
| `User` | `User` | Yes; `user@` in the destination wins. |
| `ProxyJump` | `ProxyJump` | Yes: each hop resolved, verified and authenticated with its own settings. |
| `ProxyCommand` | `ProxyCommand` | Yes, unless `SshConfigConnectOptions.AllowProxyCommand = false`. |
| `ConnectTimeout` | `ConnectTimeout` | Yes, per hop, from before the identity files are loaded through authentication; fails with `SshFailureReason.Timeout`, as `SshClientOptions.ConnectTimeout` does. `0` means no limit, as in OpenSSH. |
| `AddressFamily` | `AddressFamily` | Yes (`any`, `inet`, `inet6`), as `SshClientOptions.AddressFamily`. Not with a `ProxyCommand` or a proxy, which make the connection. |
| `BindAddress`, `BindInterface` | `BindAddress`, `BindInterface` | Yes: the local address of the connection (and of the connection to a proxy). |
| `ServerAliveInterval`, `ServerAliveCountMax` | same names | Yes: `KeepAliveInterval` and `KeepAliveCountMax`. |
| `ChannelTimeout` | `ChannelTimeouts` | Yes: `SshClientOptions.ChannelTimeouts`. |
| `ObscureKeystrokeTiming` | `ObscureKeystrokeTiming` | Yes; on (20 ms) unless `no` or another interval, as in `ssh`. |
| `RefuseConnection` | `RefuseConnection` | Yes: the connection fails before any network activity. |
| `CanonicalizeHostname`, `CanonicalDomains`, `CanonicalizeMaxDots`, `CanonicalizeFallbackLocal` | (in `Options`) | Only when `SshConfigResolveOptions.HostCanonicalizer` is set. |

## Algorithms

| Directive | Property | Applied |
|---|---|---|
| `KexAlgorithms` | `KexAlgorithms` | Yes, applied to the [defaults](algorithms.md); names SshSharp does not implement are dropped. `SshClientOptions.KexAlgorithms` in code. |
| `HostKeyAlgorithms` | `HostKeyAlgorithms` | Yes. `SshClientOptions.HostKeyAlgorithms` in code. |
| `Ciphers` | `Ciphers` | Yes. `SshClientOptions.Ciphers` in code. |
| `MACs` | `Macs` | Yes. `SshClientOptions.Macs` in code. |
| `PubkeyAcceptedAlgorithms` (`PubkeyAcceptedKeyTypes`) | `PubkeyAcceptedAlgorithms` | Yes. |
| `RequiredRSASize` | `RequiredRsaSize` | Yes: the smallest RSA host key accepted (default 2048; values under 1024 are ignored, as `ssh` refuses them). `SshClientOptions.RequiredRsaSize` in code. |

The `SshClientOptions` lists take an `SshAlgorithmList` in the same `+`, `-`, `^` and plain forms; see
[Choose algorithms and authentication methods](../how-to/algorithms-and-authentication-order.md).

## Host keys

| Directive | Property | Applied |
|---|---|---|
| `StrictHostKeyChecking` | `StrictHostKeyChecking` | Yes (`yes`, `accept-new`, `ask`, `no`). `ask` uses `SshConfigConnectOptions.AskHostKey`. |
| `UserKnownHostsFile`, `GlobalKnownHostsFile` | `UserKnownHostsFiles`, `GlobalKnownHostsFiles` | Yes. |
| `HashKnownHosts` | `HashKnownHosts` | Yes, for entries the client adds. |
| `UpdateHostKeys` | `UpdateHostKeys` | Yes; `ask` uses `ConfirmHostKeyUpdate`. |
| `HostKeyAlias` | `HostKeyAlias` | Yes. |
| `RevokedHostKeys` | `RevokedHostKeys` | Yes: key lists and OpenSSH KRLs. |
| `KnownHostsCommand` | `KnownHostsCommand` | Only with `AllowKnownHostsCommand = true`; otherwise the connection fails (unless `HostKeyVerifier` is given). |

## Authentication

| Directive | Property | Applied |
|---|---|---|
| `IdentityFile` | `IdentityFiles` | Yes; encrypted files need `PassphraseProvider`. Missing files are skipped. |
| `CertificateFile` | `CertificateFiles` | Yes; `<identity>-cert.pub` is found too. |
| `IdentityAgent` | `IdentityAgent` | Yes (`SSH_AUTH_SOCK`, a path, or `none`). |
| `IdentitiesOnly` | `IdentitiesOnly` | Yes: only the agent keys that match an `IdentityFile`. |
| `AddKeysToAgent` | `AddKeysToAgent` | Yes (`yes`, `confirm`, a lifetime); `ask` is treated as `no`. |
| `PreferredAuthentications` | `PreferredAuthentications` | Yes. `SshClientOptions.PreferredAuthentications` in code. |
| `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication` (`ChallengeResponseAuthentication`) | same names | Yes. |
| `NumberOfPasswordPrompts` | `NumberOfPasswordPrompts` | Yes: how many times `SshConfigConnectOptions.PasswordProvider` is asked (default 3). `SshClientOptions.NumberOfPasswordPrompts` in code. |
| `GSSAPIAuthentication`, `GSSAPIDelegateCredentials` | `GssapiAuthentication`, `GssapiDelegateCredentials` | Yes (.NET 10). |
| `BatchMode` | `BatchMode` | Yes: no prompts or passphrase requests. |
| `ForwardAgent` | `ForwardAgent` | Yes: the agent used for authentication is forwarded; `SshConfigConnectOptions.ForwardAgentFilter` decides what the server may do with it. |

## Forwarding

Applied only with `SshConfigConnectOptions.StartForwardings = true`, since they open listening ports.

| Directive | Property | Notes |
|---|---|---|
| `LocalForward` | `LocalForwards` | TCP; the Unix-socket form is not supported yet (logged and skipped). |
| `RemoteForward` | `RemoteForwards` | TCP, remote dynamic (port only), and Unix-socket forms. |
| `DynamicForward` | `DynamicForwards` | SOCKS 4/4a/5. |
| `GatewayPorts` | `GatewayPorts` | Default bind address for forwardings without one. |
| `ExitOnForwardFailure` | `ExitOnForwardFailure` | A forwarding that cannot start fails the connection. |
| `ClearAllForwardings` | (in `Options`) | Starts none. |

## Resolved but not applied

These describe sessions, which your code starts; read them from `SshHostConfig` and pass them in `SshSessionOptions` if you want
`ssh`'s behavior:

| Directive | Property |
|---|---|
| `SendEnv` | `SendEnv` |
| `SetEnv` | `SetEnv` |
| `RequestTTY` | `RequestTty` |

## See also

- [Use ssh_config and known_hosts](../how-to/ssh-config-and-known-hosts.md)
- [Configuration files](../config-files.md) (in-depth: `Match`, tokens, `KnownHostsCommand`)
- <xref:SshSharp.Config.SshHostConfig> in the API reference
