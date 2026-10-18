# Connecting

`SshClient` is one authenticated SSH connection. Every way of connecting returns it after the key exchange and
authentication have succeeded; dispose it to disconnect. [Architecture and connection lifecycle](concepts/architecture.md) shows
the handshake step by step.

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

### Connect timeout

`ConnectTimeout` bounds the whole attempt: name resolution, the TCP connection (or the proxy), the key exchange, host key
verification and authentication. When it passes, the attempt fails with `SshException` and `SshFailureReason.Timeout`; cancelling
your token is still an `OperationCanceledException`. It is null (no limit) by default.

[!code-csharp[](snippets/Resilience.cs#connect-timeout)]

Over a stream it bounds the key exchange and authentication. See [Cancellation and timeouts](how-to/cancellation-and-timeouts.md).

### IPv4 or IPv6 only

`AddressFamily` chooses which of the server's addresses are tried, as `ssh -4` and `ssh -6` (`AddressFamily inet` and `inet6` in
`ssh_config`) do: `Any` (the default), `Inet` (IPv4) or `Inet6` (IPv6).

[!code-csharp[](snippets/Connecting.cs#address-family)]

An address literal of the other family, or a name with no address of the allowed one, fails with `ConnectFailed`. Through a `Proxy`
it does not apply, since the proxy resolves the name. With `LocalEndPoint`, both restrictions apply.

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
`IdentitiesOnly`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `RevokedHostKeys`, `StrictHostKeyChecking`, `HashKnownHosts`,
`UpdateHostKeys`, `HostKeyAlias`, `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, `PubkeyAcceptedAlgorithms`,
`PreferredAuthentications`, `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication`, `BatchMode`,
`ProxyJump`, `ProxyCommand`, `ServerAliveInterval`, `ServerAliveCountMax`, `ConnectTimeout`, `AddressFamily`,
`BindAddress`, `BindInterface`, `ForwardAgent`, `AddKeysToAgent`, `GSSAPIAuthentication`, `GSSAPIDelegateCredentials`,
`ChannelTimeout`, `ObscureKeystrokeTiming`, `RefuseConnection` and `KnownHostsCommand` (with `AllowKnownHostsCommand`); with `StartForwardings`, also `LocalForward`, `RemoteForward`,
`DynamicForward`, `GatewayPorts`, `ExitOnForwardFailure` and `ClearAllForwardings`.
`Match` (including `Match exec`, which needs an opt-in) and `Include` work as in OpenSSH.

`SshConfigConnectOptions` also takes a `Config` (default: the user's and the system's files), `ResolveOptions` (home
directory, environment, local user), a `Password`, extra `PrivateKeys`, a `PassphraseProvider` for encrypted identity files,
`KeyboardInteractive`, a `HostKeyVerifier` that replaces the configured one, `AskHostKey` and `ConfirmHostKeyUpdate`,
`UseAgent`/`Agent`, `AllowProxyCommand`, `AllowKnownHostsCommand`, a `Proxy` (HTTP or SOCKS), `StartForwardings`, `AuthenticationBanner` and a
`Logger`.

### Jump hosts and proxy commands

`ProxyJump a,b` connects to `a`, then to `b` through `a`, then to the target through `b`; each hop is verified and
authenticated with its own configuration. `ProxyCommand` runs a local command and speaks SSH over its standard input and
output, as `ssh` does; set `AllowProxyCommand = false` to refuse configurations that name one.

## From a chosen local address

On a machine with several networks (a VPN, a management network), `LocalEndPoint` picks the address the connection comes from, as
`ssh -b` does:

```csharp
var options = new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key],
    HostKeyVerifier = verifier,
    LocalEndPoint = new IPEndPoint(IPAddress.Parse("10.20.0.5"), 0), // port 0: any local port
};
```

With `ssh_config`, `BindAddress 10.20.0.5` does the same, and `BindInterface eth1` (`ssh -B`) uses that interface's addresses.
An IPv4 address reaches only IPv4 destinations and an IPv6 one only IPv6: the server's addresses are filtered to match, and
the error says so when none is left. The connection to a proxy is made from the same address.

## Through an HTTP or SOCKS proxy

Where outbound connections must go through a proxy, set `Proxy`:

```csharp
await using var client = await SshClient.ConnectAsync("ssh.example.com", 22, new SshClientOptions
{
    UserName = "deploy",
    PrivateKeys = [key],
    HostKeyVerifier = verifier,
    Proxy = SshProxy.Http("proxy.corp", 3128, new NetworkCredential("me", proxyPassword)),
});
```

`SshProxy.Http` uses `CONNECT` (with Basic credentials if given), `SshProxy.Socks5` SOCKS 5 (with username and password
if given), and `SshProxy.Socks4` SOCKS 4, or 4a for host names. `SshProxy.FromUri(new Uri("socks5://user:pass@proxy:1080"))`
reads the usual URI form (`http`, `socks5`, `socks5h`, `socks4`, `socks4a`). The server's host name is sent to the proxy, which
resolves it. A refusal, such as a 407 or a SOCKS error code, is an `SshException` with `Reason = ConnectFailed` saying what
the proxy answered. A proxy that does not finish its handshake within 30 seconds fails the same way. Host names must be ASCII
(use the punycode form of an internationalized name), since the proxy protocols cannot carry anything else.

With `ssh_config`, `SshConfigConnectOptions.Proxy` applies to the first network hop: the destination, or the first
`ProxyJump` host (later hops go through SSH). `proxy.ConnectAsync(host, port)` returns the proxied stream itself, for
`SshClient.ConnectAsync(stream, ...)` or anything else.

Basic and SOCKS 5 credentials cross the network to the proxy unencrypted, as with every client of these protocols; the SSH
connection inside is encrypted end to end as usual.

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

### `HttpClient` through the connection

`CreateHttpConnectCallback()` plugs the tunnels into `HttpClient`, so it reaches web services only the server can reach, without
a local listener or port:

```csharp
using var http = new HttpClient(new SocketsHttpHandler
{
    ConnectCallback = client.CreateHttpConnectCallback(),
    UseProxy = false, // otherwise a system proxy setting would be the destination, reached through the server
});
var health = await http.GetStringAsync("https://internal-api.corp/health");
```

Host names are resolved by the server, and TLS runs from here to the service as usual. The same handler works with
`IHttpClientFactory` (`ConfigurePrimaryHttpMessageHandler`).

Dynamic forwarding (`ssh -D 1080`) runs a SOCKS proxy: applications name their destination, and the server makes each
connection (and resolves the host names). SOCKS 4, 4a and 5 are supported, with CONNECT and no authentication.

```csharp
await using var proxy = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 1080));
// for example: curl --socks5-hostname 127.0.0.1:1080 http://intranet.internal/
```

The proxy has no authentication, so anyone who can reach it can use the server's network: keep it on a loopback address.

Remote port forwarding (`ssh -R 8080:localhost:3000`) is the other direction: the server listens, and each connection made
to it is relayed to a host and port reached from this machine.

```csharp
await using var remote = await client.ForwardRemotePortAsync(
    "localhost", 8080,          // where the server listens: "localhost" (its loopback), an address, or "" for every address
    "127.0.0.1", 3000);         // where its connections go, from here
Console.WriteLine($"The server forwards its port {remote.RemotePort}");
```

Port 0 asks the server to pick a free port (`remote.RemotePort` has it). Whether the server honours a bind address other than its
loopback is up to it (sshd's `GatewayPorts`). Disposing the forwarder cancels the forwarding on the server and closes its
connections; a connection the server forwards while nothing listens locally is closed straight away.

Remote dynamic forwarding (`ssh -R 1080`, OpenSSH 7.6 and later) combines the two: the server listens, and this machine
answers each connection as a SOCKS proxy (4, 4a and 5), connecting to whatever destination the server's side asks for. It gives a
remote machine outbound access through this machine's network, for example a build host reaching an internal package mirror.

```csharp
await using var socks = await client.ForwardRemoteDynamicPortAsync("localhost", 1080,
    allowDestination: (host, port) => host == "mirror.internal" && port == 443);
// on the server: curl --socks5-hostname localhost:1080 https://mirror.internal/
```

The destinations come from the server's side, so anyone who can reach the forwarded port there can use this machine's network.
Like ssh, every destination is allowed when `allowDestination` is null; pass a filter unless you trust everyone on the server.
The filter cannot be sidestepped by spelling: an address in any form (`127.1`, `0x7f.1`, `::ffff:127.0.0.1`, `[::1]`) reaches it
in canonical form (`127.0.0.1`, `::1`), and a host name is checked as given, then resolved on this machine and each address it
resolves to is checked as well; the connection goes only to an address that passed. A filter that throws refuses that
connection. `IsDynamic` (`socks.IsDynamic` here) tells the two kinds of remote forwarding apart.

Remote forwarding can also serve the server's connections from your own code, with no local port: pass a handler instead of a
host and port. Each connection made to the forwarded port on the server arrives as an `SshForwardedConnection`, whose `Stream`
the handler reads and writes, with the address and port that were connected and the originator's, as the server reports them.

```csharp
await using var remote = await client.ForwardRemotePortAsync("localhost", 8080, async (connection, ct) =>
{
    // connection.Stream is this one connection; it is disposed (closed) when the handler returns
    await connection.Stream.WriteAsync("hello from the client side\n"u8.ToArray(), ct);
}, maxConnections: 20);
```

Handlers run concurrently, one per connection. One that throws closes its own connection only (the exception is logged by type).
A handler that stops reading holds the server back at the channel window. `maxConnections` (100 by default) caps the connections
served at once by the forwarding, and the server's channels above it are refused. The handler's token is cancelled when the
forwarder is disposed or the connection ends; disposal cancels the forwarding on the server, cancels the handlers, waits up to 5
seconds for them, and then closes the connections of any still running. `ForwardRemoteUnixSocketAsync` takes a handler in the same
way. See [Serving a remote port from your app](how-to/port-forwarding.md#serving-a-remote-port-from-your-app).

The server can open at most `SshClientOptions.MaxForwardedConnections` (1,000) forwarded connections at a time over all remote
forwardings; more are refused until some close.

Remote Unix-socket forwarding (`ssh -R /remote/socket:target`, `streamlocal-forward@openssh.com`, OpenSSH 6.7 and later) has
the server listen on a Unix socket instead of a port, and relays each connection to a host and port, or to a Unix socket on this
machine. It lets a program on the server use a local agent, for example gpg-agent, or a service that only this machine reaches.

```csharp
// Programs on the server connect to /run/user/1000/app.sock and reach port 3000 here.
await using var app = await client.ForwardRemoteUnixSocketAsync("/run/user/1000/app.sock", "127.0.0.1", 3000);

// gpg-agent forwarding: the server's agent socket goes to this machine's extra socket.
await using var gpg = await client.ForwardRemoteUnixSocketAsync(
    "/run/user/1000/gnupg/S.gpg-agent", "/run/user/1000/gnupg/S.gpg-agent.extra");
```

sshd creates the socket readable only by the user, and does not replace a file that is already there unless
`StreamLocalBindUnlink yes` is set on the server. Disposing the forwarder cancels it (`cancel-streamlocal-forward@openssh.com`);
`client.RemoteSocketForwardings` lists the ones started from `ssh_config`. A server with `AllowStreamLocalForwarding no`
refuses the request, and the call throws an `SshException`.

> [!NOTE]
> **Known issue on Windows:** when the target is a local Unix socket, Windows sometimes fails to deliver the end of stream to the
> local program after SshSharp shuts down its sending side. A program that is waiting in a receive at that moment may never see it
> (about 1 exchange in 10,000 with plain Winsock, more often through .NET's sockets). A protocol that half-closes and then waits for
> the answer can stall in that case. SshSharp can do nothing about it once it has shut down its side. Protocols that frame their
> messages (a length or a delimiter) are not affected, and neither are TCP targets.

### Forwardings from `ssh_config`

`LocalForward`, `RemoteForward` and `DynamicForward` are started when connecting by alias with
`SshConfigConnectOptions.StartForwardings = true` (off by default: they open listening ports). They are disposed with the
client, and `client.LocalForwardings`, `RemoteForwardings` and `DynamicForwardings` list them. `RemoteForward` with just a
port (`RemoteForward 1080`) is remote dynamic forwarding, with every destination allowed, as in ssh. `RemoteForward` with a
socket path (`RemoteForward /run/app.sock 127.0.0.1:3000` or `RemoteForward /remote.sock /local.sock`) is remote Unix-socket
forwarding, listed in `client.RemoteSocketForwardings`; as in ssh, a target with a `/` in it is a socket path.

```
Host db-tunnel
  HostName bastion.example.com
  LocalForward 15432 db.internal:5432
  DynamicForward 1080
  ExitOnForwardFailure yes
```

Bind addresses follow ssh: none means loopback (every address with `GatewayPorts yes`), `localhost` loopback, `*` every
address. A forwarding that cannot be set up (a port in use, refused by the server, or a Unix-socket form of `LocalForward`,
which is not supported yet) is logged and skipped, or fails the connection with `ExitOnForwardFailure yes`. `ClearAllForwardings yes` starts none.

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

Keep-alive probes are OpenSSH transport pings (`ping@openssh.com`) where the server announces them (OpenSSH 9.5 and later), and
`keepalive@openssh.com` requests otherwise, as OpenSSH's client sends. Any packet from the server counts as an answer.
`client.PingAsync()` measures a round trip the same way, and also proves the connection is alive:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)); // otherwise a silent server is waited for until the connection ends
var roundTrip = await client.PingAsync(cts.Token);
Console.WriteLine($"{roundTrip.TotalMilliseconds:F1} ms");
```

> [!WARNING]
> **OpenSSH for Windows:** the server built into Windows (OpenSSH for Windows 9.5) often fails to answer keep-alives, and the
> connection then ends after `KeepAliveCountMax` intervals, as it does with OpenSSH's own `ssh -o ServerAliveInterval`. It announces
> `ping@openssh.com`, so SshSharp probes it with pings, but those go unanswered at times too: the server stops sending on the
> connection. Against it, leave `KeepAliveInterval` unset or use a long interval with a generous `KeepAliveCountMax`.

## Channel idle timeouts

`ChannelTimeouts` closes channels that carry no data for a while, by channel type, as OpenSSH's `ChannelTimeout` (9.2 and later)
does on the client side. The first entry whose type pattern matches applies; a zero timeout means none for that type:

```csharp
var options = new SshClientOptions
{
    // ...
    ChannelTimeouts =
    [
        new SshChannelTimeout("session", TimeSpan.Zero),            // shells and commands: never
        new SshChannelTimeout("direct-*", TimeSpan.FromMinutes(10)), // local forwardings and tunnels
        new SshChannelTimeout("*", TimeSpan.FromHours(1)),           // everything else
    ],
};
```

The types are `session`, `direct-tcpip`, `direct-streamlocal@openssh.com`, `forwarded-tcpip`, `forwarded-streamlocal@openssh.com`
and `agent-connection` (patterns such as `direct-*` and `*` work; names are case-sensitive). OpenSSH's `x11-connection` and
`tun-connection` are accepted but never match: SshSharp has no X11 or tunnel-device forwarding, so it has no such channels.
Data sent or received in either direction resets a channel's clock. An idle channel is closed with an ordinary channel close: the
connection stays up, a session's output streams end, and a forwarded connection's local socket is closed. In `ssh_config`, write
`ChannelTimeout session=0 direct-*=10m *=1h` (`none` turns it off); connecting by alias applies it.

## Algorithms

The defaults prefer modern algorithms: the post-quantum hybrid `mlkem768x25519-sha256` (in OpenSSH since 9.9 and its default since 10.0; offered on
.NET 10 where the platform has ML-KEM: OpenSSL 3.5+ or a recent Windows), followed by the RFC 10042 hybrids with NIST curves,
`mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384`, then `sntrup761x25519-sha512` (and its older name
`sntrup761x25519-sha512@openssh.com`; managed, so offered on every platform and on .NET 8, and the only post-quantum method of
OpenSSH 8.5 to 9.8, for example Ubuntu 24.04's 9.6), then `curve25519-sha256` and `ecdh-sha2-nistp*` (plus
the finite-field `diffie-hellman-group-exchange-sha256` and `diffie-hellman-group16/18/14`, last, as OpenSSH orders them) for
key exchange; `chacha20-poly1305@openssh.com`, `aes*-gcm@openssh.com` and `aes*-ctr` with `hmac-sha2-*-etm` for
ciphers, then `aes*-ctr` with the plain `hmac-sha2-256` and `hmac-sha2-512` for servers, often network equipment, that offer no
`-etm` MAC; `ssh-ed25519`, `ecdsa-sha2-*` and `rsa-sha2-256/512` host keys, and OpenSSH host certificates. Strict key exchange
(the Terrapin fix) is always on. `FipsMode = true` limits negotiation to FIPS-approved algorithms, led by the two NIST-curve ML-KEM hybrids,
so FIPS mode keeps a post-quantum key exchange where the server offers one. Keys are renewed after
`RekeyAfterBytes` (default 1 GiB) or `RekeyAfterTime` (default 1 hour).

`client.Algorithms` shows what a connection negotiated: key exchange, host key algorithm, ciphers and MACs (empty for AEAD
ciphers), and whether strict key exchange is on. `client.Algorithms.IsPostQuantum` tells whether the key exchange resists a
future quantum computer. When it does not, the client logs it at `Information` level, the counterpart of OpenSSH 10.1's
`WarnWeakCrypto`, and traces and the connect-duration metric carry `ssh.kex.post_quantum`, so the hosts that still negotiate
a classical key exchange are easy to find:

```csharp
if (!client.Algorithms.IsPostQuantum)
{
    Console.WriteLine($"{host} uses {client.Algorithms.KeyExchange}; upgrade it to OpenSSH 8.5 or later for post-quantum key exchange.");
}
```

[Algorithms](reference/algorithms.md) lists every algorithm, its order and whether FIPS mode keeps it.

## See also

- How-to guides: [Port forwarding and tunnels](how-to/port-forwarding.md), [Jump hosts](how-to/jump-hosts.md),
  [Use ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md),
  [Keep-alive and reconnecting](how-to/keepalive-and-reconnect.md), [Cancellation and timeouts](how-to/cancellation-and-timeouts.md)
- [ssh_config directives](reference/ssh-config.md)
- [Channels and flow control](concepts/channels.md)
