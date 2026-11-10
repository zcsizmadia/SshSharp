# OpenSSH compatibility

SshSharp behaves as OpenSSH's `ssh` does wherever a library can, and says where it does not. Its behavior has been reviewed
against OpenSSH releases through **10.6p2** ([#419](https://github.com/zcsizmadia/SshSharp/issues/419)). This page covers
behavior: protocol extensions, host key rules, authentication, and what is left out. For what each `ssh_config` option does,
directive by directive, see [ssh_config directives](ssh-config.md).

- **Same**: behaves as `ssh` does.
- **Differs**: deliberately different, for the reason given.
- **Not supported**: not available.

## Host keys

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| `StrictHostKeyChecking`: `yes`, `accept-new`, `ask` and `no` | Same | [Host keys](../host-keys.md) |
| Hashed `known_hosts` lines, `HashKnownHosts` | Same | |
| Host certificates (`@cert-authority`), `CASignatureAlgorithms` | Same | `CASignatureAlgorithms` since 1.2 |
| A certificate from a trusted authority that cannot be used falls back to the plain key | Same (1.2) | Logged as a warning; [Host certificates that cannot be used](../host-keys.md#host-certificates-that-cannot-be-used) |
| `@revoked` lines; one without a port applies on every port | Same (1.2) | As OpenSSH 10.6p2; [Revoked host keys](../host-keys.md#revoked-host-keys) |
| `RequiredRsaSize` also applies to a host certificate's RSA authority | Same (1.2) | As OpenSSH 10.6p2 |
| A changed key accepted under `StrictHostKeyChecking no` gets no password, agent or port forwarding | Same (1.2) | [A changed key under `No`](../how-to/verify-host-keys.md#a-changed-key-under-no) |
| `UpdateHostKeys` (`hostkeys-00@openssh.com`, `hostkeys-prove-00@openssh.com`), and the cases where it leaves `known_hosts` alone | Same | The cases follow OpenSSH 9.2p1 (1.2); a second announcement fails the connection |
| `RevokedHostKeys` (KRLs and key lists), `KnownHostsCommand` | Same | |
| `CheckHostIP` | Not supported | Parsed, with no effect |
| `VerifyHostKeyDNS` (SSHFP records) | Differs | Decided against ([Design notes](../design.md)) |

## Key exchange and transport

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| Strict key exchange (`kex-strict-c-v00@openssh.com`, the Terrapin fix) | Same | Always offered |
| `ext-info-c` and `server-sig-algs` | Same | |
| Post-quantum `mlkem768x25519-sha256` and `sntrup761x25519-sha512` | Same | ML-KEM needs .NET 10 or later with platform ML-KEM; `sntrup761x25519-sha512` is managed and available everywhere |
| `ping@openssh.com` and `keepalive@openssh.com` | Same | `SshClient.PingAsync`, keep-alive |
| Delayed compression (`zlib@openssh.com`) | Same | Off by default, as in `ssh` |
| SHA-1, CBC, 3DES, `ssh-dss`, the SHA-1 key exchanges, plain `zlib` | Differs | Left out by design ([Algorithms](algorithms.md)) |

## Authentication and agents

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| Host-bound authentication (`publickey-hostbound-v00@openssh.com`) and agent session binding (`session-bind@openssh.com`) | Same | Automatic |
| Agent keys limited to some hosts (`ssh-add -h`, `restrict-destination-v00@openssh.com`) | Same | `SshAgentKeyConstraints.Destinations` |
| FIDO security keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) | Differs | Through an agent only; there is no `SecurityKeyProvider` ([Keys and the SSH agent](../how-to/agent-and-keys.md)) |
| `PKCS11Provider` | Not supported | Use an agent, or an `SshKeySigner` for a KMS or HSM |
| Credentials and `ProxyJump` hops | Differs | Each hop is offered only its own credentials; the destination's never reach a hop |

## Configuration

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| The first value wins; `Host` and `Match` blocks, `Include`, algorithm lists with `+`, `-` and `^` | Same | [ssh_config directives](ssh-config.md) |
| `%C` hashes each field with its NUL terminator; `%j` is the whole `ProxyJump` specification | Same (1.2) | As OpenSSH 10.6p2: every `%C` value changed from 1.1 |
| `Match canonical`, `Match final` and the second pass | Same (1.2) | |
| `Match exec`, `localnetwork`, `sessiontype`, `command` and `tagged` | Same | `exec` runs only with `SshConfigResolveOptions.ExecMatcher` |
| Directives that neither this page nor [ssh_config directives](ssh-config.md) lists | Differs | Parsed into `SshHostConfig.Options`, with no effect |

## Channels and forwarding

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| Local, remote, dynamic (SOCKS) and remote dynamic forwarding; `PermitRemoteOpen` | Same | [Port forwarding](../how-to/port-forwarding.md) |
| Unix socket forwarding (`streamlocal`) | Same | |
| Agent forwarding (`auth-agent@openssh.com` and `agent-connect`) | Same | |
| `no-more-sessions@openssh.com` | Same | `SshClient.PreventNewSessionsAsync` |
| `ChannelTimeout`, `ObscureKeystrokeTiming` | Same | |
| A limit on the channels a server opens | Differs | `MaxForwardedConnections` (1,000 by default), agent channels included; `ssh` has no such limit |
| X11 forwarding | Not supported | Can be added if users ask |
| `ControlMaster` multiplexing | Not supported | Within a process, one `SshClient` multiplexes any number of channels ([FAQ](faq.md)) |
| `tun` forwarding | Differs | Decided against ([Design notes](../design.md)) |
| Escape characters, `LocalCommand`, `ForkAfterAuthentication` | Differs | Features of the `ssh` program, not of the protocol: a library has no terminal or process of its own to manage |

## SFTP

| OpenSSH behavior | SshSharp | Notes |
|---|---|---|
| SFTP version 3 with OpenSSH's extensions: `posix-rename`, `statvfs`, `fsync`, `hardlink`, `lsetstat`, `copy-data`, `limits`, `expand-path`, `home-directory` and `users-groups-by-id` | Same | Each used when the server announces it ([SFTP](../sftp.md)) |
| SFTP versions 4 to 6 | Differs | Decided against ([Design notes](../design.md)) |

## Each new OpenSSH release

Every OpenSSH release is reviewed for client-side changes ([#419](https://github.com/zcsizmadia/SshSharp/issues/419)). The review
updates this page, including the release named at the top.
