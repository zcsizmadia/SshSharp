# Connecting

`SshClient` is one authenticated SSH connection. Every way of connecting returns it after the key exchange and
authentication have succeeded; dispose it to disconnect.

## Over TCP

```csharp
await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    Password = password,
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
});
```

Socket errors surface as `SshException` with `SshFailureReason.ConnectFailed`.

## Over any stream

SSH can run over anything duplex: a WebSocket wrapper, a named pipe, a tunnel of your own. Without a host name there is
nothing to look up in `known_hosts`, so give one with `HostKeyAlias` (or pin the key).

```csharp
Stream transport = await OpenMyTransportAsync();
await using var client = await SshClient.ConnectAsync(transport, new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key],
    HostKeyAlias = "build-agent-7",
    HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
}, leaveOpen: false);
```

## By `ssh_config` alias

`SshClient.ConnectAsync(destination, options)` resolves the destination like `ssh` does. The destination is an alias or host,
optionally `user@host`, or `ssh://user@host:port`.

```csharp
await using var client = await SshClient.ConnectAsync("deploy@prod-db", new SshConfigConnectOptions
{
    // Optional. Asked for the passphrase of an encrypted IdentityFile (not in BatchMode).
    PassphraseProvider = (path, ct) => ValueTask.FromResult<string?>(Prompt($"Passphrase for {Path.GetFileName(path)}: ")),
    // Optional. Asked about unknown host keys under StrictHostKeyChecking ask.
    AskHostKey = (prompt, ct) => ValueTask.FromResult(Confirm($"Trust {prompt.Context.HostKey.Fingerprint}?")),
});
```

What is taken from the configuration: `HostName`, `Port`, `User`, `IdentityFile`, `CertificateFile`, `IdentityAgent`,
`IdentitiesOnly`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`, `HashKnownHosts`,
`UpdateHostKeys`, `HostKeyAlias`, `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, `PubkeyAcceptedAlgorithms`,
`PreferredAuthentications`, `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication`, `BatchMode`,
`ProxyJump`, `ProxyCommand`, `ServerAliveInterval`, `ServerAliveCountMax`, `ConnectTimeout` and `AddressFamily`.
`Match` (including `Match exec`, which needs an opt-in) and `Include` work as in OpenSSH.

`SshConfigConnectOptions` also takes a `Config` (default: the user's and the system's files), `ResolveOptions` (home
directory, environment, local user), a `Password`, extra `PrivateKeys`, `KeyboardInteractive`, a `HostKeyVerifier` that
replaces the configured one, `UseAgent`/`Agent`, `AllowProxyCommand`, `AuthenticationBanner` and a `Logger`.

### Jump hosts and proxy commands

`ProxyJump a,b` connects to `a`, then to `b` through `a`, then to the target through `b`; each hop is verified and
authenticated with its own configuration. `ProxyCommand` runs a local command and speaks SSH over its standard input and
output, as `ssh` does; set `AllowProxyCommand = false` to refuse configurations that name one.

## Tunnels and port forwarding

A tunnel is a connection the server makes on your behalf, returned as a `Stream`. The server resolves the host name, so it
can name machines only the server can reach.

```csharp
// TCP, as ssh -L uses (direct-tcpip).
await using var database = await client.OpenTcpTunnelAsync("db.internal", 5432);

// A Unix domain socket on the server (direct-streamlocal@openssh.com), for example the Docker socket.
await using var docker = await client.OpenUnixSocketTunnelAsync("/var/run/docker.sock");
```

Local port forwarding (`ssh -L 15432:db.internal:5432`) listens locally and tunnels every connection made to it:

```csharp
await using var forwarder = await client.ForwardLocalPortAsync(
    new IPEndPoint(IPAddress.Loopback, 0), "db.internal", 5432);   // port 0: the system picks a free one
Console.WriteLine($"Connect to {forwarder.LocalEndPoint}");
```

Each forwarded connection gets its own channel, and a half-close travels both ways as it does with `ssh`. Bind to a loopback
address unless other machines should use the tunnel. Forwarding stops when the forwarder or the client is disposed, or the
connection ends. A server that does not allow forwarding (sshd's `AllowTcpForwarding no`) refuses each connection, and
`OpenTcpTunnelAsync` throws an `SshException` with `SshFailureReason.ChannelClosed`.

## Keep-alive and connection state

```csharp
var options = new SshClientOptions
{
    UserName = "deploy",
    Password = password,
    HostKeyVerifier = verifier,
    KeepAliveInterval = TimeSpan.FromSeconds(30), // ServerAliveInterval
    KeepAliveCountMax = 3,                        // ServerAliveCountMax
};
await using var client = await SshClient.ConnectAsync("example.com", 22, options);

// Cancelled when the connection ends for any reason; ConnectionError says why.
client.ConnectionClosed.Register(() => Console.WriteLine($"Disconnected: {client.ConnectionError?.Message}"));
```

`IsConnected` turns false once the server disconnects, the connection fails (including missed keep-alives) or the client
is disposed.

## Algorithms

The defaults prefer modern algorithms: `curve25519-sha256` and `ecdh-sha2-nistp*` (plus `diffie-hellman-group14/16`)
for key exchange; `chacha20-poly1305@openssh.com`, `aes*-gcm@openssh.com` and `aes*-ctr` with `hmac-sha2-*-etm` for
ciphers; `ssh-ed25519`, `ecdsa-sha2-*` and `rsa-sha2-256/512` host keys, and OpenSSH host certificates. Strict key exchange
(the Terrapin fix) is always on. `FipsMode = true` limits negotiation to FIPS-approved algorithms. Keys are renewed after
`RekeyAfterBytes` (default 1 GiB) or `RekeyAfterTime` (default 1 hour).
