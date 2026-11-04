# Troubleshooting

Start with a `Debug` log (see [Get a verbose log](#get-a-verbose-log)): it shows the key exchange, the host key, and each
authentication attempt, much as `ssh -vvv` does. Then find the symptom below.

## Get a verbose log

Give the client an `ILogger` at `Debug`: `SshClientOptions.Logger`, or `SshConfigConnectOptions.Logger` when connecting by alias (it
covers every `ProxyJump` hop too). With dependency injection, set the `SshSharp` category to `Debug` in the logging configuration.

[!code-csharp[](../snippets/Diagnostics.cs#logging)]

At `Debug` the log has the algorithms each side offered and the ones chosen, the host key and how it was verified, each
authentication method tried and its outcome, and channels as they open and close. It never has passwords, keys, command text, user
names or host names, so it is safe to attach to an issue (check it anyway). See
[Logging and diagnostics](../how-to/logging-and-diagnostics.md) for traces and metrics.

## Connecting

### `ConnectFailed`

The TCP connection (or a proxy, `ProxyJump` or `JumpHosts` hop or `ProxyCommand`) failed before SSH started. A custom proxy (`SshProxy.FromConnector`) that threw has its exception as the `InnerException`.

- Check the host name, port and firewall: does `ssh -p <port> <host>` connect from the same machine?
- Through a proxy: the message says what the proxy answered (see [The proxy answers 407](#the-proxy-answers-407)).
- With `BindAddress` or `LocalEndPoint`: an IPv4 bind address reaches only IPv4 destinations, and the reverse.
- With `AddressFamily` (`SshClientOptions` or `ssh_config`): only addresses of that family are tried.
- `RefuseConnection yes` in `ssh_config` refuses on purpose.
- A server that is restarting refuses for a moment: `ConnectionAttempts` (`ssh_config`, `SshConfigConnectOptions` or `SshClientOptions`) tries again,
  one second apart.

### The proxy answers 407

`ConnectFailed` with "The HTTP proxy requires authentication (407), or refused the credentials.": the HTTP proxy wants credentials,
or did not accept the ones given. Give them with the proxy (`SshProxy.Http(host, port, new NetworkCredential(user, password))`, or
`user:password@` in a proxy URI for `SshProxy.FromUri` and the DI package's `SshEndpointOptions.Proxy`), read from configuration or
a secret store. SshSharp sends HTTP proxy credentials with Basic authentication only: a proxy that accepts only NTLM or Negotiate
refuses them. Reach such a proxy with a connection of your own through `SshProxy.FromConnector`. Basic credentials are readable
by anyone between you and the proxy, so prefer a proxy on a trusted network.

### `Timeout` while connecting

`ConnectTimeout` passed (`SshClientOptions.ConnectTimeout`, or `ssh_config`'s). A server that accepts TCP but does not answer the
SSH version exchange (a busy sshd hitting `MaxStartups`, a port that is not SSH) looks like this. Check that the port speaks SSH
(`nc host 22` shows `SSH-2.0-...`). A host name whose IPv6 address does not answer can use up the whole timeout before its IPv4
address is tried: set `AddressFamily = SshAddressFamily.Inet` (`AddressFamily inet`) where the IPv6 route is broken, or
`StaggeredConnectDelay = TimeSpan.FromMilliseconds(250)` to race the addresses (see
[Race the server's addresses](../connecting.md#race-the-servers-addresses)).

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

**"ssh_config's Ciphers leaves no cipher algorithm that SshSharp can use"** (`ConnectFailed`, before anything is sent): every
name in that directive is one SshSharp does not implement, or a `-` list removed them all. `Ciphers aes128-cbc` is the usual case:
`ssh` still supports CBC ciphers, but SshSharp leaves them out by design, so a host that `ssh` reaches with that line fails here.
Add a cipher SshSharp implements (`Ciphers aes128-cbc,aes128-ctr`), in a `Host` block SshSharp's connections use. The message
names the directive (`KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` or `MACs`).

**A key is never offered** (`NoAcceptedAlgorithm` in `SshAuthenticationException.Attempts`): the server's `server-sig-algs` has
none of its algorithms, or `PubkeyAcceptedAlgorithms` allows none of them. A key with a certificate needs the certificate's
algorithm (`ssh-ed25519-cert-v01@openssh.com`) in that list, not only the plain one.

**Every key is `NoAcceptedAlgorithm`, and the log warns "ssh_config's PubkeyAcceptedAlgorithms leaves no public key signature
algorithm that SshSharp can use".** The list (or its old name, `PubkeyAcceptedKeyTypes`) names only algorithms SshSharp never uses,
typically `PubkeyAcceptedKeyTypes ssh-rsa` from an older configuration: SHA-1 RSA. No key is offered; a password,
keyboard-interactive or GSSAPI login still works. To log in with an RSA key, list `rsa-sha2-512,rsa-sha2-256` (the same RSA key
signs with them), or remove the line.

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
- A firewall drops idle TCP flows faster than keep-alives come: shorten `KeepAliveInterval`, or turn on TCP keep-alive with
  `ConfigureSocket` (see [Tune and inspect a connection](../how-to/tune-and-inspect-connections.md#set-socket-options)).

### Transfers are slow over a long-distance link

One channel moves at most one window per round trip: with the default 2 MiB window, about 20 MiB/s at 100 ms, whatever the
bandwidth. Raise `ChannelWindowSize` (for example to 16 MiB), or use SFTP's `Segments` for downloads and uploads. See
[Move more data per round trip on long links](../how-to/tune-and-inspect-connections.md#move-more-data-per-round-trip-on-long-links).

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

### "The RSA public key has ... bits; at most 16384 are accepted"

The server's RSA host key (or a key you parsed with `SshPublicKey`, or a certificate's) is larger than 16384 bits, the most OpenSSH
accepts too. A connection fails with `ProtocolError` (`HostKeyRejected` for a host certificate), `SshPublicKey.Parse` with
`FormatException`. Give the server an Ed25519 or
ECDSA host key, or an RSA key of 3072 or 4096 bits.

## Authentication

### `AuthenticationFailed` ("Permission denied")

What `ssh` reports as "Permission denied (publickey,password)" is an `SshAuthenticationException` here.
`SshAuthenticationException.AllowedMethods` lists what the server would accept. Compare it with what you gave:

| `AllowedMethods` has | But you gave | Then |
|---|---|---|
| `publickey` only | a password | The server takes keys only: pass `PrivateKeys` or use the agent. |
| `publickey` | keys | None of them is in the server's `authorized_keys` for this user, or the server's `MaxAuthTries` was reached first: put the right key first, or use `IdentitiesOnly`. |
| `keyboard-interactive` | a password | Normal for PAM servers; `Password` answers a single hidden prompt. Multiple prompts (a one-time code) need a `KeyboardInteractive` handler. |
| `publickey,keyboard-interactive` after a partial success | | The server requires both (multi-factor): give both. |
| `gssapi-with-mic` | | Needs `SshClientOptions.Gssapi` and .NET 10. |

`SshAuthenticationException.Attempts` (and the message) lists what was tried, in order, with an outcome for each:

| `Attempts` shows | Then |
|---|---|
| `publickey <fingerprint> (Rejected)` for every key | The server does not know these keys for this user. Check `authorized_keys` against the fingerprints (`ssh-keygen -lf`). |
| `publickey (NotOffered)`, `password (NotOffered)` | You gave credentials the server does not take; `AllowedMethods` says what it does take. |
| `publickey <fingerprint> (NoAcceptedAlgorithm)` | The server accepts no signature algorithm the key makes (an RSA key, and a server without `rsa-sha2-*`), or `PubkeyAcceptedAlgorithms` allows none (see [Connecting](#connecting)). |
| `publickey <fingerprint> (SigningFailed)` | The agent did not sign: the key was removed, or a confirmation was declined. |
| `password (PasswordChangeRequired)` | The password is right but has expired: set `ChangePassword`, or change it another way. See [Change an expired password](../how-to/passwords.md#change-an-expired-password). |
| `password (Declined)` | `PasswordProvider` returned null. |
| `keyboard-interactive (Declined)` | The server asked something the password does not answer (a one-time code): it needs a `KeyboardInteractive` handler. |
| nothing | No credentials for any method the client tries were given. |

Also check the user name, and the server's log (`journalctl -u ssh` / `/var/log/auth.log`), which says why it refused.

### "Authentication to ProxyJump hop N failed"

A jump host refused to log in, not the destination: N is its place in the `ProxyJump` list (1 for the first), or in the list of the
host that names it, for a hop with a `ProxyJump` of its own. The exception is still an `SshAuthenticationException`, with the hop's
`AllowedMethods` and `Attempts`; its `InnerException` is the hop's own failure. Host names stay out of the message.

A hop never gets the destination's credentials: `SshConfigConnectOptions.Password`, the keyboard-interactive handler and
`SshConfigConnectOptions.PrivateKeys` are offered to the destination only, as `ssh` asks for each host's password separately. A hop
logs in with its own `IdentityFile`s and the agent. To give a hop a key the application holds, serve it as an agent
(`SshConfigConnectOptions.Agent = SshAgent.FromKeys(key)`). A hop with `IdentitiesOnly yes` takes from the agent only keys that
match one of its `IdentityFile` lines, by the public key in `<file>.pub`: write the key's public key to a file (`key.PublicKey`) and
name it in the hop's `IdentityFile` (without the `.pub`), or the agent's key is not offered. See
[Jump hosts](../how-to/jump-hosts.md#notes-and-pitfalls).

### An encrypted key file is skipped

When connecting by alias, encrypted `IdentityFile`s need `SshConfigConnectOptions.PassphraseProvider` (and are skipped in
`BatchMode`). The `Information` log names skipped identity files and why.

### "The private key is encrypted with DES-EDE3-CBC, a legacy cipher SshSharp does not read"

The key file is traditional PEM (`Proc-Type: 4,ENCRYPTED`) encrypted with 3DES or DES, which SshSharp leaves out by design. Re-encrypt
it once with `ssh-keygen -p -f <file>`: it asks for the old passphrase and a new one, and writes the key in the OpenSSH format with AES.
See [Encrypted key files](../how-to/agent-and-keys.md#encrypted-key-files).

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

The server lacks an extension the operation needs: an overwriting rename (`posix-rename@openssh.com`), hard links, server-side
copy, a file hash (`check-file`; OpenSSH has none, check `SupportsFileHash`). `sftp.Extensions` lists what it has. A file hash
asked for with the default SHA-2 algorithms from a server that lists only `md5` or `sha1` is refused too: name those explicitly.
Or a synchronous `Read`/`Write` on an SFTP stream: use the async methods.

### A segmented upload is no faster

The server took the file over fewer sessions: it allows one writer per file, or takes writes in order only (object storage behind
SFTP), and the upload fell back without failing. It may also cap sessions (sshd's `MaxSessions`). Use `Segments = 1` with such
servers, or raise `ChannelWindowSize` instead. See [Transfer large files faster](../how-to/transfer-files-sftp.md#transfer-large-files-faster).

### ProFTPD closes the connection during a segmented upload

The server answers "Invalid handle" and the connection closes (reason 11, "Application disconnected") while several SFTP sessions
of one connection write at once: a segmented upload (`Segments` above 1), or several `SftpClient`s uploading in parallel. ProFTPD's
`mod_sftp` (1.3.9) keeps one buffer per connection for an SFTP request that arrives in several pieces, not one per session, so
writes larger than a piece sent over several sessions at the same time are mixed up. Use `Segments = 1` against ProFTPD, and one
session per connection for parallel transfers (more files at once in one session, with `MaxConcurrentFiles`, are fine).

### An SFTP call never returns

The server stopped answering while the connection stayed up (a stuck disk or NFS mount on the server, a firewall that drops packets
silently). Set `SftpClient.OperationTimeout`, which then fails the request with `SshException` (`Reason = Timeout`), and keep-alives
(`KeepAliveInterval`) for a connection that died. An upload or a write stream can also hang while it sends, when `sftp-server`
stops reading and the channel's window fills: `OperationTimeout` bounds that too, and then closes the SFTP session
(`SftpClient.IsConnected` is false; open a new one). See
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

The server decides what may be forwarded. How a refusal shows depends on the direction:

| What you see | Cause |
|---|---|
| `OpenTcpTunnelAsync` or `OpenUnixSocketTunnelAsync` throws `SshException` (`ChannelClosed`), "The server refused to open the channel (reason AdministrativelyProhibited)" | The server does not allow it: `AllowTcpForwarding no`, a `PermitOpen` list without the destination, or `AllowStreamLocalForwarding no` for a Unix socket. |
| The same, with reason `ConnectFailed` | Forwarding is allowed, but the server could not connect to the destination: nothing listens there, or the name does not resolve from the server. |
| A local forwarding accepts a connection and closes it at once; the log has a `Warning` "A connection forwarded to remote port ... was refused" | The same two causes, for one connection at a time: the forwarder keeps listening. |
| `ForwardRemotePortAsync` (or `ForwardRemoteUnixSocketAsync`) throws `SshException` (`ChannelClosed`), "The server refused to listen on port ..." | `AllowTcpForwarding` (or `AllowStreamLocalForwarding`) does not allow it, `PermitListen` does not list the port, the port is in use on the server, or (a port under 1024) the user may not bind it. |
| A remote forwarding listens, but other machines cannot reach it | The server bound it to loopback: binding to another address needs `GatewayPorts yes` (or `clientspecified`) on the server. |
| A remote dynamic forwarding refuses some destinations | The `allowDestination` filter (`PermitRemoteOpen` in `ssh_config`) does not allow them. |

The server's log (`journalctl -u ssh`, `/var/log/auth.log`) says which rule refused it.

### "Address already in use"

Another process (or an earlier run) holds the local port. Use port 0 and read `LocalEndPoint.Port`.

## Still stuck?

Open an issue on [GitHub](https://github.com/zcsizmadia/SshSharp/issues) with the SshSharp version, the .NET version and OS, the
server software (`client.ServerIdentification`, or `ssh -v` output), and a `Debug` log. Logs contain no passwords, keys, user
names or host names, but check them before posting. Report security problems privately, as the
[security policy](https://github.com/zcsizmadia/SshSharp/blob/main/SECURITY.md) describes.
