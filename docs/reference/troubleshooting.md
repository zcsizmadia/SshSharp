# Troubleshooting

Start with a `Debug` log ([Logging and diagnostics](../how-to/logging-and-diagnostics.md)): it shows the key exchange, the host key,
and each authentication attempt, much as `ssh -vvv` does. Then find the symptom below.

## Connecting

### `ConnectFailed`

The TCP connection (or a proxy, `ProxyJump` hop or `ProxyCommand`) failed before SSH started.

- Check the host name, port and firewall: does `ssh -p <port> <host>` connect from the same machine?
- Through a proxy: the message says what the proxy answered (a 407 means proxy credentials are needed).
- With `BindAddress` or `LocalEndPoint`: an IPv4 bind address reaches only IPv4 destinations, and the reverse.
- With `AddressFamily` (`SshClientOptions` or `ssh_config`): only addresses of that family are tried.
- `RefuseConnection yes` in `ssh_config` refuses on purpose.

### `Timeout` while connecting

`ConnectTimeout` passed (`SshClientOptions.ConnectTimeout`, or `ssh_config`'s). A server that accepts TCP but does not answer the
SSH version exchange (a busy sshd hitting `MaxStartups`, a port that is not SSH) looks like this. Check that the port speaks SSH
(`nc host 22` shows `SSH-2.0-...`). A host name whose IPv6 address does not answer can use up the whole timeout before its IPv4
address is tried: set `AddressFamily = SshAddressFamily.Inet` (`AddressFamily inet`) where the IPv6 route is broken.

### No common algorithms

`KeyExchangeFailed`: the server offers only algorithms SshSharp does not implement (CBC ciphers, SHA-1 MACs, `ssh-rsa`, DH group 1,
`diffie-hellman-group14-sha1` or `diffie-hellman-group-exchange-sha1`). Typical for old network equipment and very old servers.
SshSharp has the SHA-2 finite-field methods such equipment often offers alone: `diffie-hellman-group-exchange-sha256` and
`diffie-hellman-group14-sha256`, `group16-sha512` and `group18-sha512`. The fix is on the server: enable a modern algorithm (any
OpenSSH since 6.5 has `curve25519-sha256`, `aes*-ctr` and `hmac-sha2-*`). With `FipsMode`, a server that has only an Ed25519 host
key fails the same way. See [Algorithms](algorithms.md).

**"No matching key exchange algorithm".** The message lists what each side offered. A `KexAlgorithms` line in `ssh_config` (or
`SshClientOptions.KexAlgorithms = SshAlgorithmList.Remove("diffie-hellman-*")`) that removes the finite-field methods leaves
nothing in common with a server that offers only those. The same goes for the other lists.

**`ArgumentException` naming `SshClientOptions.Ciphers` (or another list).** The list leaves no algorithm SshSharp can use here:
`FipsMode` removed everything in it, or it names only `mlkem*` methods on a platform without ML-KEM. It is thrown before anything
is sent. See [Choose algorithms and authentication methods](../how-to/algorithms-and-authentication-order.md).

**The server's group is refused.** With `diffie-hellman-group-exchange-sha256`, a group outside 2048 to 8192 bits, or one that fails
the primality and shape checks, fails with `KeyExchangeFailed` and a message naming the check (for example "The server's group
exchange prime has 1024 bits, outside the 2048 to 8192 requested."). The server's moduli file (`/etc/ssh/moduli` for OpenSSH) holds
a weak or corrupt group: remove the groups under 2048 bits there (the size column counts one bit less, so lines under 2047), or skip
the method with `KexAlgorithms -diffie-hellman-group-exchange-sha256`.

**"No matching MAC".** SshSharp has both the encrypt-then-MAC `hmac-sha2-*-etm@openssh.com` and the plain `hmac-sha2-256` and
`hmac-sha2-512`, which routers, switches and appliances often offer alone with `aes*-ctr`. If the MAC still does not match:

- The server offers only `hmac-sha1`, `hmac-md5` or `umac-*`. SshSharp does not implement them; enable an HMAC-SHA2 MAC on the
  server, or an AEAD cipher (`aes*-gcm@openssh.com`, `chacha20-poly1305@openssh.com`), which needs no MAC.
- A `MACs` line in `ssh_config` removed the plain ones (`MACs -hmac-sha2-256,...`) or lists only `-etm` MACs. The error message shows
  both sides' lists.

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

### The forwarded agent lists no keys or refuses to sign on the server

- `ForwardAgentFilter` refused: refused requests are logged at `Information` with the key's fingerprint, and anything the filter
  throws at `Warning`.
- A filter that relies on `DestinationHostKey` refuses everything when `ssh` on the server is older than OpenSSH 8.9: it does not
  bind its sessions, so the destination is not known.
- An RSA signature requested as SHA-1 `ssh-rsa` is refused by an in-process agent and by any agent behind a filter.
- A program that signs its own format (pam_ssh_agent_auth, for `sudo`) is refused by a filter that allows only known purposes: such
  requests reach the filter with a null `Purpose`. Allow them explicitly if the program needs them.
- `ssh-add` on the server cannot add, remove or lock keys of an in-process agent, or of any agent behind a filter: the forwarded
  agent is read-only then.
- Keys whose type `SshPublicKey` does not read (DSA, security-key certificates) are hidden behind a filter.

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

### An SFTP call never returns

The server stopped answering while the connection stayed up (a stuck disk or NFS mount on the server, a firewall that drops packets
silently). Set `SftpClient.OperationTimeout`, which then fails the request with `SshException` (`Reason = Timeout`), and keep-alives
(`KeepAliveInterval`) for a connection that died. See
[Fail when the server stops answering](../how-to/transfer-files-sftp.md#fail-when-the-server-stops-answering).

### A recursive delete stopped part way

`DeleteDirectoryAsync(path, recursive: true)` stops at the first entry it cannot delete and throws that `SftpException` (its `Path`
says which; usually `PermissionDenied`: on Unix, deleting needs write permission on the directory that holds the entry). What it
deleted stays deleted. Fix the cause and call it again; it carries on with what is left.

### `SftpException` from `FlushAsync`, `DisposeAsync` or a later `WriteAsync`

SFTP file streams write behind: `WriteAsync` returns before the server answers, so a write it refused (a full disk, a quota) is
thrown by a later call on the stream. The file is incomplete; the stream is faulted and every later call throws the same exception.
See [Writes in flight](../sftp.md#writes-in-flight).

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
