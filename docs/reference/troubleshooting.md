# Troubleshooting

Start with a `Debug` log ([Logging and diagnostics](../how-to/logging-and-diagnostics.md)): it shows the key exchange, the host key,
and each authentication attempt, much as `ssh -vvv` does. Then find the symptom below.

## Connecting

### `ConnectFailed`

The TCP connection (or a proxy, `ProxyJump` hop or `ProxyCommand`) failed before SSH started.

- Check the host name, port and firewall: does `ssh -p <port> <host>` connect from the same machine?
- Through a proxy: the message says what the proxy answered (a 407 means proxy credentials are needed).
- With `BindAddress` or `LocalEndPoint`: an IPv4 bind address reaches only IPv4 destinations, and the reverse.
- `RefuseConnection yes` in `ssh_config` refuses on purpose.

### `Timeout` while connecting

`ConnectTimeout` passed. A server that accepts TCP but does not answer the SSH version exchange (a busy sshd hitting
`MaxStartups`, a port that is not SSH) looks like this. Check that the port speaks SSH (`nc host 22` shows `SSH-2.0-...`).

### No common algorithms

`KeyExchangeFailed`: the server offers only algorithms SshSharp does not implement (CBC ciphers, SHA-1 MACs, `ssh-rsa`, DH group 1
or group exchange). Typical for old network equipment and very old servers. The fix is on the server: enable a modern algorithm
(any OpenSSH since 6.5 has `curve25519-sha256`, `aes*-ctr` and `hmac-sha2-*`). With `FipsMode`, a server that has only an Ed25519
host key fails the same way. See [Algorithms](algorithms.md).

### The connection drops after a while

- Idle connections through NAT or firewalls get dropped: set `KeepAliveInterval` (`ServerAliveInterval`).
- Against OpenSSH for Windows, keep-alives often go unanswered and the connection ends after `KeepAliveCountMax` intervals: leave
  keep-alive off, or use a long interval with a generous count.
- `ChannelTimeouts` closes idle channels by design; check the configuration's `ChannelTimeout`.

## Host keys

### `HostKeyRejected`: not in known_hosts

With `StrictHostKeyChecking.Yes`, an unknown host is refused. Add its key (compare the fingerprint first):
`ssh-keyscan host >> ~/.ssh/known_hosts`, or [`ScanHostKeysAsync`](../how-to/verify-host-keys.md#get-a-new-servers-keys), or use
`AcceptNew` for first contact.

### `HostKeyRejected`: the key changed

The server presented a different key than `known_hosts` has. It may be a reinstalled server, or an interception. Find out which
before removing the old line (`ssh-keygen -R host`). `UpdateHostKeys` avoids this for planned rotations.

### Over a stream: "There is no host name to look up in known_hosts"

A connection over your own `Stream` has no host name. Set `SshClientOptions.HostKeyAlias`.

## Authentication

### `AuthenticationFailed`

`SshAuthenticationException.AllowedMethods` lists what the server would accept. Compare it with what you gave:

| `AllowedMethods` has | But you gave | Then |
|---|---|---|
| `publickey` only | a password | The server takes keys only: pass `PrivateKeys` or use the agent. |
| `publickey` | keys | None of them is in the server's `authorized_keys` for this user, or the server's `MaxAuthTries` was reached first: put the right key first, or use `IdentitiesOnly`. |
| `keyboard-interactive` | a password | Normal for PAM servers; `Password` answers a single hidden prompt. Multiple prompts (a one-time code) need a `KeyboardInteractive` handler. |
| `publickey,keyboard-interactive` after a partial success | | The server requires both (multi-factor): give both. |
| `gssapi-with-mic` | | Needs `SshClientOptions.Gssapi` and .NET 10. |

Also check the user name, and the server's log (`journalctl -u ssh` / `/var/log/auth.log`), which says why it refused.

### An encrypted key file is skipped

When connecting by alias, encrypted `IdentityFile`s need `SshConfigConnectOptions.PassphraseProvider` (and are skipped in
`BatchMode`). The `Information` log names skipped identity files and why.

### The agent is not used

- `SshAgent.FromEnvironment()` returns null: `SSH_AUTH_SOCK` is not set, and on Windows neither the OpenSSH agent service nor
  Pageant is running.
- On Windows, an agent pipe owned by another user is ignored on purpose.
- With `ssh_config`, `IdentityAgent none` or `UseAgent = false` turns it off; `IdentitiesOnly yes` limits it to matching keys.

## Commands and sessions

### A command hangs

- Its output is not being read: read both `StandardOutput` and `StandardError` ([flow control](../concepts/channels.md#flow-control)).
- It waits for input: call `CloseInputAsync` to send end-of-file.
- It waits for a password (`sudo`): configure `NOPASSWD`, or use a terminal and [SshExpect](../how-to/interactive-shell.md).

### `InvalidOperationException`: output exceeded the limit

`RunCommandAsync` collects at most `MaxCommandOutputBytes` (128 MiB). Stream large output with `StartCommandAsync`.

### `ChannelClosed` when starting a command or opening SFTP

The server refused the session: too many open sessions on this connection (`MaxSessions`), sessions not permitted for this user
or key, or no `Subsystem sftp` configured. The connection itself is still usable.

### Environment variables are not set

The server accepts only the variables its `AcceptEnv` lists. Pass values on the command line instead (`FOO=bar command`).

## Files

### `NotSupportedException` from SFTP

The server lacks an OpenSSH extension the operation needs: an overwriting rename (`posix-rename@openssh.com`), hard links, server-side
copy. `sftp.Extensions` lists what it has. Or a synchronous `Read`/`Write` on an SFTP stream: use the async methods.

### SCP fails on a Windows server

Remote paths are single-quoted for a POSIX shell. A Windows OpenSSH server whose default shell is `cmd.exe` or PowerShell reads
them differently: use SFTP, which OpenSSH for Windows provides by default.

## Forwarding

### Forwarded connections are refused

The server does not allow forwarding (`AllowTcpForwarding no`, `PermitOpen`, `AllowStreamLocalForwarding no`). For remote
forwarding to an address other than loopback, the server needs `GatewayPorts`.

### "Address already in use"

Another process (or an earlier run) holds the local port. Use port 0 and read `LocalEndPoint.Port`.

## Still stuck?

Open an issue on [GitHub](https://github.com/zcsizmadia/SshSharp/issues) with the SshSharp version, the .NET version and OS, the
server software (`client.ServerIdentification`, or `ssh -v` output), and a `Debug` log. Logs contain no passwords, keys, user
names or host names, but check them before posting. Report security problems privately, as the
[security policy](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md) describes.
