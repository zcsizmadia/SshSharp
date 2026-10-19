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
| `ConnectionAttempts` | `ConnectionAttempts` | Yes: the host's TCP connection (or its connection to a proxy) is tried this many times, one second apart (default 1). Only failures to reach it are tried again (refused, unreachable, timed out), never a failed handshake or authentication, and `ConnectTimeout` bounds all the attempts together, as in OpenSSH. A host reached through `ProxyJump` makes no TCP connection of its own (the first hop's setting applies to the first hop), and a `ProxyCommand` is not run again. |
| `AddressFamily` | `AddressFamily` | Yes (`any`, `inet`, `inet6`), as `SshClientOptions.AddressFamily`. Not with a `ProxyCommand` or a proxy, which make the connection. |
| `BindAddress`, `BindInterface` | `BindAddress`, `BindInterface` | Yes: the local address of the connection (and of the connection to a proxy). |
| `ServerAliveInterval`, `ServerAliveCountMax` | same names | Yes: `KeepAliveInterval` and `KeepAliveCountMax`. |
| `ChannelTimeout` | `ChannelTimeouts` | Yes: `SshClientOptions.ChannelTimeouts`. |
| `ObscureKeystrokeTiming` | `ObscureKeystrokeTiming` | Yes; on (20 ms) unless `no` or another interval, as in `ssh`. |
| `RefuseConnection` | `RefuseConnection` | Yes: the connection fails before any network activity. |
| `CanonicalizeHostname`, `CanonicalDomains`, `CanonicalizeMaxDots`, `CanonicalizeFallbackLocal` | (in `Options`) | Only when `SshConfigResolveOptions.HostCanonicalizer` is set. |

## Overriding in code

A few transport settings can be given in `SshConfigConnectOptions` instead, and then win over the configuration (null leaves
them to it):

| Option | Overrides | For |
|---|---|---|
| `Port` | `Port` | The destination only, as `ssh -p` (a port in an `ssh://` destination still wins). Resolution sees it (`%p`, `Match`). |
| `ConnectTimeout` | `ConnectTimeout` | Every host; `Timeout.InfiniteTimeSpan` for no limit. |
| `ConnectionAttempts` | `ConnectionAttempts` | Every host. |
| `AddressFamily` | `AddressFamily` | The connection this machine makes (the destination, or the first `ProxyJump` hop). |
| `KeepAliveInterval`, `KeepAliveCountMax` | `ServerAliveInterval`, `ServerAliveCountMax` | Every host; `TimeSpan.Zero` turns keep-alives off. |

`HostKeyVerifier` and `Proxy` replace the configured host key checking and connection the same way. See
[Override what the configuration says](../how-to/ssh-config-and-known-hosts.md#override-what-the-configuration-says).

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
| `LocalForward` | `LocalForwards` | TCP, and Unix sockets on either side: `/local.sock host:port`, `[bind:]port /remote.sock`, `/local.sock /remote.sock` (a field with a `/` is a path, as in `ssh`; a local one may use `\` on Windows). Paths take tokens, `~` and `${VAR}`. The local socket is created owner-only and removed when the forwarding stops. |
| `RemoteForward` | `RemoteForwards` | TCP, remote dynamic (port only), and Unix-socket forms. |
| `PermitRemoteOpen` | `PermitRemoteOpen` | The destinations remote dynamic forwarding (`RemoteForward` with a port only) may connect to: `host:port` entries (`[address]:port` for IPv6), with `*` for any host or any port; `any` (the default) or `none`. As in OpenSSH, names are compared as given, with no pattern matching and no address lookup: `localhost:8080` does not allow `127.0.0.1:8080`. Entries that do not parse allow nothing. |
| `DynamicForward` | `DynamicForwards` | SOCKS 4/4a/5. |
| `GatewayPorts` | `GatewayPorts` | Default bind address for forwardings without one. |
| `StreamLocalBindUnlink` | `StreamLocalBindUnlink` | `yes` removes an existing file where `LocalForward` creates its Unix socket (a stale socket); without it, that forwarding fails, as in `ssh`. `StreamLocalBindMask` is not read: the socket is always owner-only (`ssh`'s default `0177`). |
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

## Directives and typed options

Code that does not read `ssh_config` sets the same things in code. This table maps each directive SshSharp applies to its typed
equivalent, where one exists:

- **`SshClientOptions`**: `SshClient.ConnectAsync(host, port, options)`, with no configuration file.
- **`SshConfigConnectOptions`**: connecting by alias, where the option overrides or supplements what the configuration says.
- **`SshEndpointOptions`**: a named endpoint in the dependency injection package. With `Host` set it builds an `SshClientOptions`
  (and `ConfigureClientOptions` can set anything in the first column); with `ConfigAlias` set, the configuration decides, and only
  `Password`, `AddressFamily` and `ConnectTimeout` are used.

A dash means there is no typed equivalent. The "Applied" tables above say how each directive behaves.

| Directive | `SshClientOptions` (or code) | `SshConfigConnectOptions` | `SshEndpointOptions` |
|---|---|---|---|
| `HostName`, `Port` | The `host` and `port` arguments of `ConnectAsync` | `Port` | `Host`, `Port` |
| `User` | `UserName` | `user@` in the destination | `UserName` |
| `ProxyJump` | `JumpHosts` (one `SshJumpHost` per hop, each with its own options) | - | `JumpHosts` through `ConfigureClientOptions` |
| `ProxyCommand` | `Proxy = SshProxy.FromConnector(...)`, a connection you make in code | `AllowProxyCommand` (whether it may run) | - |
| `ConnectTimeout` | `ConnectTimeout` | `ConnectTimeout` | `ConnectTimeout` |
| `ConnectionAttempts` | - | `ConnectionAttempts` | - |
| `AddressFamily` | `AddressFamily` | `AddressFamily` | `AddressFamily` |
| `BindAddress` | `LocalEndPoint` | - | - |
| `ServerAliveInterval` | `KeepAliveInterval` | `KeepAliveInterval` | `KeepAliveInterval` (with `Host`) |
| `ServerAliveCountMax` | `KeepAliveCountMax` | `KeepAliveCountMax` | - |
| `ChannelTimeout` | `ChannelTimeouts` | - | - |
| `ObscureKeystrokeTiming` | `ObscureKeystrokeTiming` | - | - |
| `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs` | `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `Macs` | - | - |
| `RequiredRSASize` | `RequiredRsaSize` | - | - |
| `StrictHostKeyChecking` | `HostKeyVerifier = new KnownHostsVerifier(...) { Policy = ... }` | `HostKeyVerifier` (replaces it), `AskHostKey` (answers `ask`) | `AcceptNewHostKeys` (`accept-new`; otherwise `yes`), `HostKeyFingerprints` (pinned keys instead) |
| `UserKnownHostsFile`, `GlobalKnownHostsFile` | The `KnownHostsVerifier` constructor's two lists | - | `KnownHostsFiles` |
| `HashKnownHosts` | `KnownHostsVerifier.HashNewEntries` | - | - |
| `UpdateHostKeys` | `KnownHostsVerifier.UpdateHostKeys`, `ConfirmHostKeyUpdate` | `ConfirmHostKeyUpdate` (answers `ask`) | - |
| `HostKeyAlias` | `HostKeyAlias` | - | - |
| `RevokedHostKeys` | `KnownHostsVerifier.RevokedHostKeys` | - | - |
| `KnownHostsCommand` | - | `AllowKnownHostsCommand` (whether it may run) | - |
| `IdentityFile` | `PrivateKeys` (`SshPrivateKey.LoadAsync`) | `PassphraseProvider` (encrypted files); `PrivateKeys` are offered first | `PrivateKeyFiles`, `PrivateKeyPassphrase`, `PrivateKeys` |
| `CertificateFile` | `PrivateKeys` with `SshPrivateKey.WithCertificate` | - | - |
| `IdentityAgent` | `PrivateKeys` from `SshAgent.GetKeysAsync` | `Agent`, `UseAgent` | - |
| `AddKeysToAgent` | `SshAgent.AddKeyAsync` with `SshAgentKeyConstraints` | - | - |
| `PreferredAuthentications` | `PreferredAuthentications` | - | - |
| `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication` | Give or leave out `PrivateKeys`, `Password`, `KeyboardInteractive`, or list the methods in `PreferredAuthentications` | - | - |
| `NumberOfPasswordPrompts` | `NumberOfPasswordPrompts` (with `PasswordProvider`) | - | - |
| `GSSAPIAuthentication`, `GSSAPIDelegateCredentials` | `Gssapi`, `SshGssapiOptions.DelegateCredentials` | - | - |
| `BatchMode` | - (leave the prompting callbacks unset) | - | - |
| `ForwardAgent` | `ForwardAgent`, `ForwardAgentFilter` | `Agent` (the one forwarded), `ForwardAgentFilter` | - |
| `LocalForward` | `ForwardLocalPortAsync`, `ForwardLocalUnixSocketAsync` | `StartForwardings` | - |
| `RemoteForward` | `ForwardRemotePortAsync`, `ForwardRemoteDynamicPortAsync`, `ForwardRemoteUnixSocketAsync` | `StartForwardings` | - |
| `PermitRemoteOpen` | `ForwardRemoteDynamicPortAsync`'s `allowDestination` | - | - |
| `DynamicForward` | `ForwardDynamicPortAsync` | `StartForwardings` | - |
| `GatewayPorts` | The bind address given to each forwarding | - | - |
| `SendEnv`, `SetEnv` | `SshSessionOptions.Environment` | - | - |
| `RequestTTY` | `SshSessionOptions.Terminal` | - | - |

Some options have no directive: `VersionAddendum`, `ConfigureSocket`, `ChannelWindowSize` and `ChannelMaxPacketSize` (see
[Tune and inspect a connection](../how-to/tune-and-inspect-connections.md)), `FipsMode`, `MaxForwardedConnections`, and the
`Proxy` for an HTTP or SOCKS proxy (`SshClientOptions.Proxy`, `SshConfigConnectOptions.Proxy`, `SshEndpointOptions.Proxy`).

## See also

- [Use ssh_config and known_hosts](../how-to/ssh-config-and-known-hosts.md)
- [Configuration files](../config-files.md) (in-depth: `Match`, tokens, `KnownHostsCommand`)
- <xref:SshSharp.Config.SshHostConfig> in the API reference
