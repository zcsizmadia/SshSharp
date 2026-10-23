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
| `Match` | `all`, `host`, `originalhost`, `user`, `localuser`, `canonical`, `final`, `exec`, `tagged`, `localnetwork`, `sessiontype`, `command`; negation with `!`. `exec` runs only with `SshConfigResolveOptions.ExecMatcher`; `sessiontype` and `command` match only when `SessionType` (and `Command`) are given; `version` never matches. `canonical` differs from `ssh` in edge cases (see [Host name canonicalization](../config-files.md#host-name-canonicalization)). |
| `Include` | Globs, relative to `~/.ssh` (user file) or the system directory; at most 16 levels and 1,024 files. |
| `Tag` | Matched by `Match tagged`; `SshConfigResolveOptions.Tag` overrides it. |

## Destination and transport

| Directive | Property | Applied when connecting by alias |
|---|---|---|
| `HostName` | `HostName` | Yes, with `%h` and other tokens. |
| `Port` | `Port` | Yes. |
| `User` | `User` | Yes; `user@` in the destination wins. |
| `ProxyJump` | `ProxyJump` | Yes: each hop resolved, verified and authenticated with its own settings. A hop that refuses to log in fails with "Authentication to ProxyJump hop N failed", N being its place in the list. Names after the first hop are resolved by the hop before them, so `CanonicalizeHostname` does not look them up here. |
| `ProxyCommand` | `ProxyCommand` | Yes, unless `SshConfigConnectOptions.AllowProxyCommand = false`. |
| `ConnectTimeout` | `ConnectTimeout` | Yes, per hop, from before the identity files are loaded through authentication; fails with `SshFailureReason.Timeout`, as `SshClientOptions.ConnectTimeout` does. `0` means no limit, as in OpenSSH, and so does a time longer than a timer can wait (about 49.7 days). |
| `ConnectionAttempts` | `ConnectionAttempts` | Yes: the host's TCP connection (or its connection to a proxy) is tried this many times, one second apart (default 1). Only failures to reach it are tried again (refused, unreachable, timed out), never a failed handshake or authentication, and `ConnectTimeout` bounds all the attempts together, as in OpenSSH. A host reached through `ProxyJump` makes no TCP connection of its own (the first hop's setting applies to the first hop), and a `ProxyCommand` is not run again. |
| `AddressFamily` | `AddressFamily` | Yes (`any`, `inet`, `inet6`), as `SshClientOptions.AddressFamily`. Not with a `ProxyCommand` or a proxy, which make the connection. |
| `BindAddress`, `BindInterface` | `BindAddress`, `BindInterface` | Yes: the local address of the connection (and of the connection to a proxy). |
| `TCPKeepAlive` | `TcpKeepAlive` | Yes: TCP keep-alive (`SO_KEEPALIVE`) on the connection this machine makes, on unless `no`, as in `ssh`. Not with a `ProxyCommand` or a proxy. |
| `IPQoS` | `IPQoSInteractive`, `IPQoSBulk` | Yes: the type of service (DSCP) of that connection, from the second value (or the only one): a name (`af11` to `af43`, `cs0` to `cs7`, `ef`, `le`, `lowdelay`, `throughput`, `reliability`), 0 to 255, or `none`. Unset, nothing is marked. Best effort: Windows ignores it unless a policy allows it. |
| `ServerAliveInterval`, `ServerAliveCountMax` | same names | Yes: `KeepAliveInterval` and `KeepAliveCountMax`. `0` (the default) sends none, and so does an interval longer than about 49.7 days. |
| `ChannelTimeout` | `ChannelTimeouts` | Yes: `SshClientOptions.ChannelTimeouts`. |
| `ObscureKeystrokeTiming` | `ObscureKeystrokeTiming` | Yes; on (20 ms) unless `no` or another interval, as in `ssh`. |
| `RefuseConnection` | `RefuseConnection` | Yes: the connection fails before any network activity. |
| `CanonicalizeHostname`, `CanonicalDomains`, `CanonicalizeMaxDots`, `CanonicalizeFallbackLocal`, `CanonicalizePermittedCNAMEs` | (in `Options`; the result is `HostName`) | When `SshConfigResolveOptions.UseDnsCanonicalizer` is on (DNS, with `ssh`'s rules, CNAMEs followed only as `CanonicalizePermittedCNAMEs` allows) or `HostCanonicalizer` is set (your own lookup, which gets the host and `CanonicalDomains`). Neither is on by default. As with `ProxyJump` and `ProxyCommand`, a host reached through `SshConfigConnectOptions.Proxy` is canonicalized only with `always`, so its name is not looked up here; the lookups use `SshConfigConnectOptions.AddressFamily` when it is set. See [Host name canonicalization](../config-files.md#host-name-canonicalization). |

## Overriding in code

A few transport settings can be given in `SshConfigConnectOptions` instead, and then win over the configuration (null leaves
them to it):

| Option | Overrides | For |
|---|---|---|
| `Port` | `Port` | The destination only, as `ssh -p` (a port in an `ssh://` destination still wins). Resolution sees it (`%p`, `Match`). |
| `ConnectTimeout` | `ConnectTimeout` | Every host; `Timeout.InfiniteTimeSpan` for no limit. |
| `ConnectionAttempts` | `ConnectionAttempts` | Every host. |
| `AddressFamily` | `AddressFamily` | The connection this machine makes (the destination, or the first `ProxyJump` hop). |
| `ConfigureSocket` | `TCPKeepAlive`, `IPQoS` | The same connection: it runs after those two are applied, so what it sets wins. |
| `KeepAliveInterval`, `KeepAliveCountMax` | `ServerAliveInterval`, `ServerAliveCountMax` | Every host; `TimeSpan.Zero` or `Timeout.InfiniteTimeSpan` turns keep-alives off (as in `SshClientOptions.KeepAliveInterval`). |
| `PrivateKeys` | (adds to `IdentityFile`) | The destination only: offered before its identity files, never to a `ProxyJump` hop, which logs in with its own identity files and the agent. |
| `Compression` | `Compression` | The destination only, as `ssh -C`; each `ProxyJump` hop keeps its own. |

`HostKeyVerifier` and `Proxy` replace the configured host key checking and connection the same way. See
[Override what the configuration says](../how-to/ssh-config-and-known-hosts.md#override-what-the-configuration-says).

## Algorithms

| Directive | Property | Applied |
|---|---|---|
| `KexAlgorithms` | `KexAlgorithms` | Yes, applied to the [defaults](algorithms.md); names SshSharp does not implement are dropped. `SshClientOptions.KexAlgorithms` in code. |
| `HostKeyAlgorithms` | `HostKeyAlgorithms` | Yes. When a certificate authority is trusted for the host, the certificate algorithms are asked for first with the defaults or a `+` or `-` list, as `ssh` orders them by known_hosts; a plain or `^` list is used as written, so list the certificate algorithms in it (`HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com` accepts only the host's certificate). As in `ssh`, whose defaults hold the certificate algorithms, a `-` pattern removes a certificate algorithm only when it matches it: `-ssh-ed25519` keeps `ssh-ed25519-cert-v01@openssh.com`, `-ssh-ed25519*` removes both. `SshClientOptions.HostKeyAlgorithms` in code. |
| `Ciphers` | `Ciphers` | Yes. `SshClientOptions.Ciphers` in code. |
| `MACs` | `Macs` | Yes. `SshClientOptions.Macs` in code. |
| `PubkeyAcceptedAlgorithms` (`PubkeyAcceptedKeyTypes`) | `PubkeyAcceptedAlgorithms` | Yes, as in `ssh`: a key (an identity file's, the agent's, or one in `SshConfigConnectOptions.PrivateKeys`) is offered only with an algorithm the list allows, and is skipped when it allows none of the key's (a key with a certificate needs the certificate's algorithm, such as `ssh-ed25519-cert-v01@openssh.com`). An RSA key signs with the list's first RSA algorithm (`rsa-sha2-512` or `rsa-sha2-256`) that the server lists in `server-sig-algs` (RFC 8308). SHA-1 `ssh-rsa` is never used, so `+ssh-rsa` changes nothing. A list that leaves nothing SshSharp can use (`PubkeyAcceptedKeyTypes ssh-rsa`, common in older configurations) offers no key: each is reported as `NoAcceptedAlgorithm`, a warning names the directive, and password, keyboard-interactive and GSSAPI logins still work. Unset, every key is offered with its own algorithms. `SshClientOptions.PubkeyAcceptedAlgorithms` in code. |
| `RequiredRSASize` | `RequiredRsaSize` | Yes: the smallest RSA host key accepted (default 2048; values under 1024 are ignored, as `ssh` refuses them). `SshClientOptions.RequiredRsaSize` in code. |
| `Compression` | `Compression` | Yes: `yes` offers `zlib@openssh.com` (OpenSSH's delayed compression, which starts after authentication) before `none`; `no`, the default, offers only `none`. `SshClientOptions.Compression` in code. See [Compress a slow link](../how-to/tune-and-inspect-connections.md#compress-a-slow-link). |

Each list is applied as `ssh` applies it: `+` adds names after the defaults (one that is already a default stays where it is),
`^` puts them first, `-` removes what its patterns match, and in every form a wildcard stands for the names it matches
(`Ciphers aes*-ctr` is `aes256-ctr,aes192-ctr,aes128-ctr`). A `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` or `MACs` list that
leaves no algorithm SshSharp can use fails the connection before anything is sent (right after the configuration is read), with an
`SshException` (`ConnectFailed`) that names the directive: the connection could not work. A `PubkeyAcceptedAlgorithms` list that
leaves nothing only means no key is offered, as above, since the other authentication methods may still log in.

The `SshClientOptions` lists take an `SshAlgorithmList` in the same `+`, `-`, `^` and plain forms (wildcards in `Remove` only); see
[Choose algorithms and authentication methods](../how-to/algorithms-and-authentication-order.md).

## Host keys

| Directive | Property | Applied |
|---|---|---|
| `StrictHostKeyChecking` | `StrictHostKeyChecking` | Yes (`yes`, `accept-new`, `ask`, `no`). `ask` uses `SshConfigConnectOptions.AskHostKey`. |
| `UserKnownHostsFile`, `GlobalKnownHostsFile` | `UserKnownHostsFiles`, `GlobalKnownHostsFiles` | Yes. |
| `HashKnownHosts` | `HashKnownHosts` | Yes, for entries the client adds. |
| `UpdateHostKeys` | `UpdateHostKeys` | Yes; `ask` uses `ConfirmHostKeyUpdate`. |
| `HostKeyAlias` | `HostKeyAlias` | Yes. |
| `RevokedHostKeys` | `RevokedHostKeys` | Yes: key lists and OpenSSH KRLs. In a key list, certificate lines of types SshSharp never accepts (DSA) are skipped, and a malformed certificate of an accepted type refuses the list (see [Host keys](../host-keys.md)). |
| `KnownHostsCommand` | `KnownHostsCommand` | Only with `AllowKnownHostsCommand = true`; otherwise the connection fails (unless `HostKeyVerifier` is given). |

## Authentication

| Directive | Property | Applied |
|---|---|---|
| `IdentityFile` | `IdentityFiles` | Yes; encrypted files need `PassphraseProvider`. Missing files are skipped. |
| `CertificateFile` | `CertificateFiles` | Yes; `<identity>-cert.pub` is found too. |
| `IdentityAgent` | `IdentityAgent` | Yes (`SSH_AUTH_SOCK`, a path, or `none`). |
| `IdentitiesOnly` | `IdentitiesOnly` | Yes: only the agent keys that match an `IdentityFile`. |
| `AddKeysToAgent` | `AddKeysToAgent`, `AddKeysToAgentAsk` | Yes (`yes`, `confirm`, a lifetime); `ask` asks `SshConfigConnectOptions.ConfirmAddKeyToAgent` for each key, and adds nothing without it or in `BatchMode`. |
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
| `LocalForward` | `LocalForwards` | TCP, and Unix sockets on either side: `/local.sock host:port`, `[bind:]port /remote.sock`, `/local.sock /remote.sock` (a field with a `/` is a path, as in `ssh`; a local one may use `\` on Windows). Paths take tokens and `${VAR}`; only the local one takes `~`, since on the server's side it would name this machine's home directory. The local socket is created owner-only and removed when the forwarding stops. |
| `RemoteForward` | `RemoteForwards` | TCP, remote dynamic (port only), and Unix-socket forms (the local socket path may use `\` on Windows). Socket paths take tokens and `${VAR}`, expanded here as in `ssh`; the local one takes `~` too. |
| `PermitRemoteOpen` | `PermitRemoteOpen` | The destinations remote dynamic forwarding (`RemoteForward` with a port only) may connect to: `host:port` entries (`[address]:port` for IPv6), with `*` for any host or any port; `any` (the default) or `none`. As in OpenSSH, names are compared as given, with no pattern matching and no address lookup: `localhost:8080` does not allow `127.0.0.1:8080`. Entries that do not parse allow nothing. |
| `DynamicForward` | `DynamicForwards` | SOCKS 4/4a/5, without authentication, as in `ssh`. In code, `ForwardDynamicPortAsync` can require a SOCKS 5 user name and password. |
| `GatewayPorts` | `GatewayPorts` | Default bind address for forwardings without one. |
| `StreamLocalBindUnlink` | `StreamLocalBindUnlink` | `yes` removes an existing file where `LocalForward` creates its Unix socket (a stale socket); without it, that forwarding fails, as in `ssh`. |
| `StreamLocalBindMask` | `StreamLocalBindMask` | The permissions cleared from a Unix socket `LocalForward` creates here, in octal: `0177` (the default) gives 0600, owner-only; `0117` gives 0660. On Windows the socket stays the current user's whatever the mask. |
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
  `Password`, `AddressFamily`, `UseAgent`, `Compression` and `ConnectTimeout` are used.

A dash means there is no typed equivalent. The "Applied" tables above say how each directive behaves.

| Directive | `SshClientOptions` (or code) | `SshConfigConnectOptions` | `SshEndpointOptions` |
|---|---|---|---|
| `HostName`, `Port` | The `host` and `port` arguments of `ConnectAsync` | `Port` | `Host`, `Port` |
| `User` | `UserName` | `user@` in the destination | `UserName` |
| `ProxyJump` | `JumpHosts` (one `SshJumpHost` per hop, each with its own options) | - | `JumpHosts` (one `SshEndpointJumpHost` per hop, each with its own credentials and host keys) |
| `ProxyCommand` | `Proxy = SshProxy.FromConnector(...)`, a connection you make in code | `AllowProxyCommand` (whether it may run) | - |
| `ConnectTimeout` | `ConnectTimeout` | `ConnectTimeout` | `ConnectTimeout` |
| `ConnectionAttempts` | `ConnectionAttempts` | `ConnectionAttempts` | - |
| `AddressFamily` | `AddressFamily` | `AddressFamily` | `AddressFamily` |
| `BindAddress`, `BindInterface` | `LocalEndPoint` (for `BindInterface`, an address of that interface) | - | - |
| `TCPKeepAlive`, `IPQoS` | `ConfigureSocket` (`SocketOptionName.KeepAlive`, `SocketOptionName.TypeOfService`) | `ConfigureSocket` (runs after them, so what it sets wins) | - |
| `ServerAliveInterval` | `KeepAliveInterval` | `KeepAliveInterval` | `KeepAliveInterval` (with `Host`) |
| `ServerAliveCountMax` | `KeepAliveCountMax` | `KeepAliveCountMax` | - |
| `ChannelTimeout` | `ChannelTimeouts` | - | - |
| `ObscureKeystrokeTiming` | `ObscureKeystrokeTiming` | - | - |
| `RefuseConnection` | - | - | - |
| `CanonicalizeHostname` and the other `Canonicalize*` directives | - (pass the fully qualified name as `host`) | `ResolveOptions` with `UseDnsCanonicalizer` (`ssh`'s DNS rules) or `HostCanonicalizer` (your own lookup) | - |
| `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs` | `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `Macs` | - | - |
| `PubkeyAcceptedAlgorithms` | `PubkeyAcceptedAlgorithms` | - | - |
| `RequiredRSASize` | `RequiredRsaSize` | - | - |
| `Compression` | `Compression` | `Compression` (the destination only) | `Compression` |
| `StrictHostKeyChecking` | `HostKeyVerifier = new KnownHostsVerifier(...) { Policy = ... }` | `HostKeyVerifier` (replaces it), `AskHostKey` (answers `ask`) | `AcceptNewHostKeys` (`accept-new`; otherwise `yes`), `HostKeyFingerprints` (pinned keys instead) |
| `UserKnownHostsFile`, `GlobalKnownHostsFile` | The `KnownHostsVerifier` constructor's two lists | - | `KnownHostsFiles` |
| `HashKnownHosts` | `KnownHostsVerifier.HashNewEntries` | - | - |
| `UpdateHostKeys` | `KnownHostsVerifier.UpdateHostKeys`, `ConfirmHostKeyUpdate` | `ConfirmHostKeyUpdate` (answers `ask`) | - |
| `HostKeyAlias` | `HostKeyAlias` | - | - |
| `RevokedHostKeys` | `KnownHostsVerifier.RevokedHostKeys` | - | - |
| `KnownHostsCommand` | - | `AllowKnownHostsCommand` (whether it may run) | - |
| `IdentityFile` | `PrivateKeys` (`SshPrivateKey.LoadAsync`) | `PassphraseProvider` (encrypted files); `PrivateKeys` are offered first, to the destination only (never to a `ProxyJump` hop) | `PrivateKeyFiles`, `PrivateKeyPassphrase`, `PrivateKeys` |
| `CertificateFile` | `PrivateKeys` with `SshPrivateKey.WithCertificate` | - | - |
| `IdentityAgent` | `PrivateKeys` from `SshAgent.GetKeysAsync` | `Agent`, `UseAgent` | `UseAgent` (with `ConfigAlias`, `true` uses the registered or the environment's agent in its place) |
| `IdentitiesOnly` | Only the `PrivateKeys` you give are offered | - | Without `ConfigAlias`, the agent's keys are offered only with `UseAgent = true` |
| `AddKeysToAgent` | `SshAgent.AddKeyAsync` with `SshAgentKeyConstraints` | `ConfirmAddKeyToAgent` (answers `ask`) | - |
| `PreferredAuthentications` | `PreferredAuthentications` | - | - |
| `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication` | Give or leave out `PrivateKeys`, `Password`, `KeyboardInteractive`, or list the methods in `PreferredAuthentications` | - | - |
| `NumberOfPasswordPrompts` | `NumberOfPasswordPrompts` (with `PasswordProvider`) | - | - |
| `GSSAPIAuthentication`, `GSSAPIDelegateCredentials` | `Gssapi`, `SshGssapiOptions.DelegateCredentials` | - | - |
| `BatchMode` | - (leave the prompting callbacks unset) | - | - |
| `ForwardAgent` | `ForwardAgent`, `ForwardAgentFilter` | `Agent` (the one forwarded), `ForwardAgentFilter` | - |
| `LocalForward` | `ForwardLocalPortAsync`, `ForwardLocalUnixSocketAsync` | `StartForwardings` | - |
| `RemoteForward` | `ForwardRemotePortAsync`, `ForwardRemoteDynamicPortAsync`, `ForwardRemoteUnixSocketAsync` | `StartForwardings` | - |
| `PermitRemoteOpen` | `ForwardRemoteDynamicPortAsync`'s `allowDestination` | `StartForwardings` | - |
| `DynamicForward` | `ForwardDynamicPortAsync` (with a `NetworkCredential` for a SOCKS 5 password) | `StartForwardings` | - |
| `GatewayPorts` | The bind address given to each forwarding | `StartForwardings` | - |
| `StreamLocalBindMask` | `ForwardLocalUnixSocketAsync` with a `UnixFileMode socketMode` | `StartForwardings` | - |
| `StreamLocalBindUnlink` | - (remove a stale socket file before `ForwardLocalUnixSocketAsync`) | `StartForwardings` | - |
| `ExitOnForwardFailure`, `ClearAllForwardings` | - (your code decides which forwardings to start, and what a failure means) | `StartForwardings` | - |
| `SendEnv`, `SetEnv` | `SshSessionOptions.Environment` | - | - |
| `RequestTTY` | `SshSessionOptions.Terminal` | - | - |

Some options have no directive: `VersionAddendum`, `ChannelWindowSize` and `ChannelMaxPacketSize` (see
[Tune and inspect a connection](../how-to/tune-and-inspect-connections.md)), `FipsMode`, `MaxForwardedConnections`, and the
`Proxy` for an HTTP or SOCKS proxy (`SshClientOptions.Proxy`, `SshConfigConnectOptions.Proxy`, `SshEndpointOptions.Proxy`).

## See also

- [Use ssh_config and known_hosts](../how-to/ssh-config-and-known-hosts.md)
- [Configuration files](../config-files.md) (in-depth: `Match`, tokens, `KnownHostsCommand`)
- <xref:SshSharp.Config.SshHostConfig> in the API reference
