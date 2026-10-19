# Port forwarding and tunnels

An SSH connection can carry other connections. The server opens them on your behalf (to reach services only it can reach), or
accepts them and hands them to you (to give the server a way back). SshSharp does what `ssh -L`, `-R` and `-D` do, and also returns
a tunnel as a plain `Stream` or plugs it into `HttpClient`.

## When to use

| You want to | Use |
|---|---|
| Reach a service behind the server from a program that connects to a port (a database client, a browser) | [Local forwarding](#local-forwarding-ssh--l), `ssh -L` |
| Reach a Unix socket on the server (Docker, PostgreSQL), or offer a Unix socket here | [Local forwarding with Unix sockets](#local-forwarding-with-unix-sockets) |
| Reach it from your own code, without opening a port | [A tunnel stream](#tunnels-without-a-local-port) or [`HttpClient`](#httpclient-through-the-server) |
| Let programs reach many destinations through the server | [Dynamic forwarding](#dynamic-forwarding-a-socks-proxy-ssh--d), `ssh -D` |
| Let other machines or containers use that proxy | [Dynamic forwarding with a password](#with-a-password-beyond-loopback) |
| Let the server reach a service on your side | [Remote forwarding](#remote-forwarding-ssh--r), `ssh -R` |
| Serve a port (or Unix socket) on the server from your own code, without a local port | [Serving a remote port from your app](#serving-a-remote-port-from-your-app) |

## How each kind flows

Every forwarded connection is its own channel inside the one encrypted SSH connection. What differs is who listens and who makes
the final TCP connection:

```mermaid
flowchart LR
    subgraph here["This machine"]
        lApp["Database client"] -- "127.0.0.1:15432" --> lFwd["Local forwarder (-L)"]
        dApp["Browser, curl"] -- "SOCKS to 127.0.0.1:1080" --> dFwd["SOCKS proxy (-D)"]
        rFwd["Remote forwarder (-R)"] -- "TCP" --> rSvc["127.0.0.1:3000"]
    end
    subgraph server["The server and its network"]
        lSrv["sshd"] -- "TCP" --> lDb[("db.internal:5432")]
        dSrv["sshd"] -- "TCP" --> dAny["any destination"]
        rProg["Program on the server"] -- "localhost:8080" --> rSrv["sshd listener"]
    end
    lFwd == "direct-tcpip channel" ==> lSrv
    dFwd == "direct-tcpip channel" ==> dSrv
    rSrv == "forwarded-tcpip channel" ==> rFwd
```

## Local forwarding (`ssh -L`)

[!code-csharp[](../snippets/Forwarding.cs#local)]

Port 0 lets the system pick a free port, which avoids collisions when several jobs run at once:

[!code-csharp[](../snippets/Forwarding.cs#local-ephemeral)]

The server resolves `db.internal`, so names that only the server's network knows work.

### Local forwarding with Unix sockets

Either end can be a Unix socket instead, as with `ssh -L`: a port here to a socket on the server (`-L port:/remote.sock`), a
socket here to a host and port (`-L /local.sock:host:port`), or a socket to a socket (`-L /local.sock:/remote.sock`):

[!code-csharp[](../snippets/Forwarding.cs#local-unix-socket)]

- **The socket file here is owner-only**: mode 0600 on Linux and macOS, as `ssh`'s default `StreamLocalBindMask 0177` gives, and on
  Windows an ACL with only the current user. It is set before the socket accepts connections, so nobody else gets in first.
- **A wider mode, when another account must connect.** The overloads that take a `UnixFileMode` set it instead, as
  `StreamLocalBindMask` does in `ssh_config` (`0117` gives 0660). Connecting takes write permission. On Windows the socket stays
  the current user's whatever the mode:

  [!code-csharp[](../snippets/Forwarding.cs#local-unix-socket-mode)]

- **An existing file is not replaced**: `ForwardLocalUnixSocketAsync` throws a `SocketException`, as `ssh` fails without
  `StreamLocalBindUnlink yes`. The forwarder removes its socket file when it is disposed.
- **The server decides** with sshd's `AllowStreamLocalForwarding`; a refused connection is closed, and the forwarding goes on.
- **Platforms.** Unix sockets work on Linux, macOS and Windows 10 and later. A socket path is limited to about 104 bytes (macOS) or
  108 (Linux, Windows); a longer one throws `ArgumentOutOfRangeException`.

## Tunnels without a local port

A tunnel is one forwarded connection, returned as a `Stream`. Nothing listens locally, so no other process on this machine can use
it:

[!code-csharp[](../snippets/Forwarding.cs#tunnel)]

## `HttpClient` through the server

`CreateHttpConnectCallback()` opens each of `HttpClient`'s connections as a tunnel, so web services that only the server can reach
work with the usual HTTP stack. TLS still runs end to end, from this machine to the service:

[!code-csharp[](../snippets/Forwarding.cs#http)]

The same handler works with `IHttpClientFactory` (`ConfigurePrimaryHttpMessageHandler`). With the dependency injection package,
`AddHttpClient(...).UseSshTunnel("name")` does it on an endpoint's shared connection, and follows it across drops; see
[Call an internal API through the server](aspnetcore-and-di.md#call-an-internal-api-through-the-server).

## Dynamic forwarding: a SOCKS proxy (`ssh -D`)

[!code-csharp[](../snippets/Forwarding.cs#dynamic)]

### With a password, beyond loopback

Like `ssh -D`, the proxy has no authentication: anyone who can reach its port can use the server's network. When other machines,
containers or VMs must use it, pass credentials. The proxy then takes SOCKS 5 with username/password authentication (RFC 1929)
only, and turns away SOCKS 4 and 4a, which have no passwords, and SOCKS 5 clients that do not authenticate:

[!code-csharp[](../snippets/Forwarding.cs#dynamic-auth)]

A password keeps out those who do not know it. It does not protect the traffic to the proxy:

```mermaid
flowchart LR
    app["Application on another machine"] -- "SOCKS 5: user name and password,<br/>then the traffic, in clear text" --> proxy["SOCKS proxy (this machine)"]
    proxy == "SSH: encrypted" ==> sshd["sshd"]
    sshd -- "TCP" --> dest["Destination"]
```

- **Clear text on the local network.** RFC 1929 sends the user name and password unencrypted, and the application's connection to
  the proxy is plain TCP: anyone who can watch that network can read the password and the traffic, and reuse the password. Only
  the hop from this machine to the server is encrypted. Use TLS end to end (HTTPS) for anything sensitive.
- **Prefer loopback.** When the applications run on this machine, bind to `IPAddress.Loopback` (with or without a password):
  nothing then crosses a network. Beyond loopback, bind to the one address the clients use (not `IPAddress.Any`), and restrict
  the port with a firewall too.
- **Use a long random password**, from a secret store or the environment, never written in code or configuration files. Failed
  attempts are logged (at warning level, without the client's address), but not rate limited.
- **How they are checked.** The forwarder keeps keyed digests of the user name and password, not the password itself, and compares
  each attempt in constant time, so the time to answer does not reveal how close a guess was. Each is 1 to 255 bytes in UTF-8;
  `NetworkCredential.Domain` is not used.
- **Clients.** `curl --proxy socks5h://user:password@host:port`, `HttpClient` with
  `new WebProxy("socks5://host:port") { Credentials = new NetworkCredential(...) }`, and SshSharp's own
  `SshProxy.Socks5(host, port, credentials)` all speak it.

## Remote forwarding (`ssh -R`)

The direction is reversed: the server listens, and each connection made to it there is relayed to a host and port reached from
this machine.

[!code-csharp[](../snippets/Forwarding.cs#remote)]

Remote dynamic forwarding (`ssh -R 1080`, OpenSSH 7.6+) makes this machine the SOCKS proxy for programs on the server. Restrict
what they may reach:

[!code-csharp[](../snippets/Forwarding.cs#remote-dynamic)]

From `ssh_config`, `RemoteForward` with only a port starts it, and `PermitRemoteOpen` is its filter, as in `ssh`:

[!code-csharp[](../snippets/Forwarding.cs#remote-dynamic-config)]

`PermitRemoteOpen` takes `host:port` entries (`[2001:db8::1]:22` for IPv6), with `*` for any host or any port, or `any` (the
default) or `none`. Unlike `allowDestination`, which also sees every address a name resolves to, it compares the requested name as
given and makes no lookup, as `ssh_config(5)` says: `mirror.example.com:443` allows that name, and the connection goes to whatever it
resolves to here; `192.0.2.10:*` allows that address only, not a name that resolves to it.

## Serving a remote port from your app

Remote forwarding can also hand each connection to your code instead of relaying it to a host and port: the server listens, and
every connection made to it there arrives in a handler as an `SshForwardedConnection` with a duplex `Stream`. Nothing listens on
this machine. It is what Go's `ssh.Client.Listen` and AsyncSSH's handler form give.

Use it for:

- **a webhook receiver behind NAT:** a public server's reverse proxy passes requests to a port on its loopback, and your
  application, which has no public address, serves them (see the [webhook receiver scenario](../scenarios/webhook-receiver.md));
- **an in-process test server:** a program under test on a remote machine connects to `localhost:<port>` there and talks to a fake
  service in your test;
- **a protocol of your own,** with no local listener for other processes on this machine to find.

```mermaid
sequenceDiagram
    participant P as Program on the server
    participant S as sshd (listens on localhost:8080)
    participant C as SshClient (this process)
    participant H as Your handler
    P->>S: connect to localhost:8080
    S->>C: forwarded-tcpip channel (connected address, originator)
    C->>H: handler(connection, token), concurrently per connection
    P-->>H: bytes, through connection.Stream
    H-->>P: bytes, through connection.Stream
    H->>C: handler returns: the stream is disposed
    C->>S: EOF and CLOSE: the program sees the connection end
```

[!code-csharp[](../snippets/Forwarding.cs#remote-handler)]

The same works for a Unix socket on the server:

[!code-csharp[](../snippets/Forwarding.cs#remote-handler-socket)]

How the handler runs:

- **It owns the stream.** Disposing `connection.Stream` closes the connection; when the handler returns, the stream is disposed
  for it if it has not been already.
- **Where the connection came from.** For a port, `BoundAddress` and `BoundPort` are the address and port that were connected on
  the server, and `OriginatorAddress` and `OriginatorPort` the program's, all as the server reports them. For a Unix socket,
  `RemoteSocketPath` is set and the originator is null (the server does not say who connected).
- **Errors stay with their connection.** A handler that throws closes its own connection only. The exception is logged by type,
  never with its message, and other connections and the forwarding go on.
- **Back-pressure.** A handler that stops reading stops the server from sending more than the channel's window (2 MiB): the window
  is only opened again as the handler reads.
- **A cap.** `maxConnections` (100 by default) is the most connections served at once by this forwarding. The server's channels
  above it are refused (resource shortage) until some end, as are those above `SshClientOptions.MaxForwardedConnections` over all
  forwardings.
- **Stopping.** The handler's token is cancelled when the forwarder is disposed or the SSH connection ends. Disposing the forwarder
  sends the cancel request to the server, so it stops listening; it then cancels the handlers and waits up to
  `HandlerShutdownTimeout` (5 seconds by default) for them to return. The connections of any still running then are closed under
  them, and disposal returns without waiting further.

The forwarder is the usual `SshRemotePortForwarder` (or `SshRemoteSocketForwarder`), with `RemotePort` set when port 0 was
requested; its `LocalHost` is empty and `LocalPort` 0. `IsHandler` is true for a forwarding to a handler, and `MaxConnections` is
its cap (`int.MaxValue` for the other kinds, which have none of their own).

### End your side and keep reading

Some protocols mark the end of a request or a response by the end of the stream. `connection.ShutdownSendAsync()` sends the
server end-of-file (`SSH_MSG_CHANNEL_EOF`) without closing the connection, as `Socket.Shutdown(SocketShutdown.Send)` does: the
program on the server reads to the end of what the handler wrote, and the handler can go on reading what the program sends.

[!code-csharp[](../snippets/Forwarding.cs#remote-handler-half-close)]

```mermaid
sequenceDiagram
    participant P as Program on the server
    participant S as sshd
    participant H as Handler (this process)
    S->>H: forwarded-tcpip channel
    H->>S: data "ready"
    H->>S: CHANNEL_EOF (ShutdownSendAsync)
    S->>P: "ready", then end of stream (shutdown SHUT_WR)
    P->>S: upload
    S->>H: data (the handler still reads)
    P->>S: closes its side
    S->>H: CHANNEL_EOF, CHANNEL_CLOSE
```

Call it once the handler's writes have completed: writes after it throw `InvalidOperationException`, and a second call does
nothing. The connection still closes when the stream is disposed or the handler returns.

### Give handlers longer to stop

[!code-csharp[](../snippets/Forwarding.cs#remote-handler-shutdown)]

`HandlerShutdownTimeout` is how long disposal waits for the handlers it cancelled: `TimeSpan.Zero` closes their connections at
once, and `Timeout.InfiniteTimeSpan` waits as long as they take (a handler that ignores its token then holds disposal up). Set it
before disposing; forwardings to a host and port, or dynamic ones, close their connections at once and do not use it.

> [!IMPORTANT]
> Anyone who can reach the forwarded port on the server (every user and process there, or every machine with a bind address other
> than loopback and `GatewayPorts`) can open connections into your handler. Treat what arrives as untrusted input: bound how much
> you read and how long you wait, validate before acting, authenticate requests where it matters, and keep `maxConnections` low.

## Notes and pitfalls

- **Bind to loopback.** A local forwarder has no authentication, nor does a SOCKS proxy started without credentials: anyone who can
  reach its port can use the server's network. Use `IPAddress.Loopback` unless other machines should use it, and then give the SOCKS
  proxy [a password](#with-a-password-beyond-loopback).
- **Server policy.** sshd's `AllowTcpForwarding no` refuses tunnels: each forwarded connection is closed, and `OpenTcpTunnelAsync`
  throws `SshException` with `ChannelClosed`. A bind address other than loopback for remote forwarding needs `GatewayPorts`.
- **Lifetime.** Forwarding runs until the forwarder is disposed, the client is disposed, or the connection ends. Watch
  `client.ConnectionClosed` if you need to know (see [Keep-alive and reconnecting](keepalive-and-reconnect.md)).
- **Remote destinations come from the server's side.** With remote dynamic forwarding, every destination is allowed when
  `allowDestination` is null (or, from `ssh_config`, without `PermitRemoteOpen`), as with `ssh`. Pass a filter unless you trust
  everyone on the server.
- **Limits.** The server can open at most `SshClientOptions.MaxForwardedConnections` (1,000) forwarded connections at a time, and a
  forwarding to a handler at most its `maxConnections`.
- **From `ssh_config`.** `LocalForward`, `RemoteForward` and `DynamicForward` start with the connection when
  `SshConfigConnectOptions.StartForwardings` is true, Unix-socket forms included (`LocalForward /tmp/docker.sock /var/run/docker.sock`).
  Socket paths take `ssh_config`'s `%` tokens and `${VAR}` on both sides (`RemoteForward /home/%r/app.sock /run/app.sock`), and the
  local one `~` too; `StreamLocalBindMask` sets the mode of a local socket.

## See also

- [Connecting: tunnels and port forwarding](../connecting.md#tunnels-and-port-forwarding) (in-depth: Unix sockets, remote Unix-socket
  forwarding, forwardings from `ssh_config`)
- [A database through a jump host](../scenarios/database-tunnel.md)
- [A webhook receiver behind NAT](../scenarios/webhook-receiver.md)
- [Channels and flow control](../concepts/channels.md)
