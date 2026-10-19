# Tune and inspect a connection

A few connection settings matter only in some environments: socket options for a network that drops idle flows or marks traffic,
a comment that tells your application's connections apart in the server's logs, and a larger channel window for fast links with a
long round trip. Once connected, `SshClient` tells you where the connection goes, how much it has carried, and lets you renew its
keys on demand.

## When to use

- A firewall or load balancer drops idle TCP flows, and you want the operating system's TCP keep-alive as well as (or instead of)
  SSH keep-alive.
- Your network marks traffic by DSCP, or the socket's buffer sizes need raising.
- Server administrators need to tell which application or job a connection comes from.
- Downloads, command output or tunnels are slow over a fast link with a long round trip (another continent, a satellite link).
- You report on connections: their endpoints, age, traffic, session id and algorithms.
- A policy asks for new keys before a sensitive transfer, or at times of your choosing.

## Set socket options

`ConfigureSocket` is called with the TCP socket before it connects, after it is bound to `LocalEndPoint` if one is set:

[!code-csharp[](../snippets/ConnectionTuning.cs#configure-socket)]

Setting options before the connection is made matters for buffer sizes: TCP agrees on window scaling in its handshake, from the
receive buffer the socket has then. Keep-alive and the type of service can be set at any time, so setting them here is simply the
earliest point.

`ConfigureSocket` is called once for each socket SshSharp creates. That is once, unless a `LocalEndPoint` is set and the server's
name has several addresses: then each address that is tried gets a socket of its own. Anything the callback throws ends the
connection attempt and is thrown from `ConnectAsync` unchanged, not wrapped as a failure to connect.

It applies only to the TCP connection that `SshClient.ConnectAsync(host, port, options)` opens itself:

- **With `JumpHosts`** it is called for the connection to the first jump host, which is the only TCP connection made from this
  machine; the later hops are channels through it.
- **Through a `Proxy`** (HTTP or SOCKS) it is not called. The socket goes to the proxy, not the server.
- **Over a stream you opened** (`ConnectAsync(stream, options)`) there is no socket for SshSharp to configure: set the options on
  your own socket before you pass its stream.
- **By `ssh_config` alias** it is not available yet. `SshConfigConnectOptions` has no such option.

## Identify your application to the server

`VersionAddendum` adds a comment to the identification line the client sends first, as sshd's `VersionAddendum` does on the
server side:

[!code-csharp[](../snippets/ConnectionTuning.cs#version-addendum)]

OpenSSH's sshd shows the client's software version and comment in its debug log (`Remote protocol version 2.0, remote software
version ...`), and many servers and network monitors record the line. The comment is checked
when the option is set: printable US-ASCII (spaces allowed inside it), not starting or ending with a space, and short enough for the
whole line to fit RFC 4253's 255 bytes. Anything else is an `ArgumentException`.

> [!WARNING]
> The identification line is sent before encryption starts. Anyone on the network path can read it, and servers keep it in their
> logs. Put a product name and version in it, never a secret, a user name or a host name.

## Move more data per round trip on long links

Each channel (a command's session, an SFTP session, a tunnel) has a flow-control window: how much the server may send before
SshSharp has consumed some. One channel therefore moves at most one window per round trip. With the default 2 MiB, that is about
20 MiB/s at 100 ms, whatever the bandwidth. On a link whose bandwidth-delay product is larger, raise `ChannelWindowSize`. A larger
`ChannelMaxPacketSize` also lets the server send bigger packets, so there are fewer of them to process:

[!code-csharp[](../snippets/ConnectionTuning.cs#channel-window)]

To size the window, multiply the bandwidth by the round trip: 1 Gbit/s × 100 ms is 12.5 MB, so 16 MiB keeps such a link busy.

| Option | Default | Range | What it does |
|---|---|---|---|
| `ChannelWindowSize` | 2 MiB | 1 KiB to 1 GiB | How much the server may send on a channel before it waits for SshSharp to consume it. |
| `ChannelMaxPacketSize` | 32 KiB | 1 KiB to 255 KiB | The most data the server may put in one packet. Capped at the window. |

Both apply to every channel of the connection: sessions, SFTP and SCP, tunnels, and connections the server forwards to you. They
govern what SshSharp receives. What it sends is bounded by the window and packet size the server grants, which SshSharp follows.

```mermaid
sequenceDiagram
    participant S as Server
    participant C as SshSharp
    S->>C: CHANNEL_DATA ... up to ChannelWindowSize
    Note over S: window used up: the server waits
    C->>S: WINDOW_ADJUST (as your code reads)
    S->>C: CHANNEL_DATA continues
    Note over S,C: one window per round trip at most
```

Notes:

- **Memory.** Each channel can hold up to its window of data your code has not read yet. With many channels and a large window,
  that adds up: 100 channels with a 16 MiB window may buffer up to 1.6 GiB if nothing reads them.
- **The server's side matters too.** For uploads, the server's window limits the client the same way, and only the server can
  raise it. OpenSSH's sshd uses 2 MiB.
- **SFTP.** A larger window helps a single download as `Segments` does, without opening more sessions. The two combine.
- **TCP.** The operating system's TCP window has to keep up as well. Modern systems scale it automatically. Where they do not,
  raise the receive buffer with `ConfigureSocket`.

## Inspect a connection

[!code-csharp[](../snippets/ConnectionTuning.cs#inspect-connection)]

| Member | What it is |
|---|---|
| `RemoteEndPoint`, `LocalEndPoint` | The TCP connection's endpoints, when there is a socket: a connection SshSharp made, or a `NetworkStream` you passed. Through an HTTP or SOCKS proxy, the remote one is the proxy. Null over other streams (a ProxyJump tunnel, a ProxyCommand). |
| `ConnectedAt` | When authentication succeeded, in UTC. |
| `SessionId` | The session identifier: the exchange hash of the first key exchange (RFC 4253 section 7.2). It stays the same across re-exchanges. It is not secret, and both sides know it, so it can correlate a connection with the server's records. A copy, readable after the client is disposed. |
| `BytesSent`, `BytesReceived` | SSH message bytes so far: each packet's payload before encryption, padding and MAC, as the `sshsharp.bytes.*` metrics count them. |
| `ServerIdentification` | The server's identification line, for example `SSH-2.0-OpenSSH_9.9`. |
| `Algorithms` | The negotiated key exchange, host key algorithm, ciphers and MACs; a re-exchange can change them. |
| `HostKey` | The host key the server proved. |

All of them are cheap to read from any thread: the byte counters are read atomically, and the rest is fixed at connect time.

## Re-key on demand

[!code-csharp[](../snippets/ConnectionTuning.cs#rekey)]

`RekeyAsync` starts a key re-exchange, as ssh's `~R` escape does, and completes once the new keys are in use in both directions.
Open channels stay open: data waits while the keys change and then continues. If a re-exchange is already running (the server asked
for one, or `RekeyAfterBytes` or `RekeyAfterTime` was reached), it waits for that one instead of starting another. The server must
prove the same host key as at the start, or the connection fails. Keys are renewed automatically anyway, after `RekeyAfterBytes`
(1 GiB) or `RekeyAfterTime` (1 hour), so most applications never need to call it.

## Notes and pitfalls

- **TCP keep-alive is not SSH keep-alive.** TCP keep-alive keeps a firewall's state and finds a dead peer at the TCP level, but
  intervals are coarse on some systems, and a server that is up but stuck still answers it. `KeepAliveInterval` probes the SSH server
  itself. See [Keep-alive and reconnecting](keepalive-and-reconnect.md).
- **The type of service** (`SocketOptionName.TypeOfService`) is an IPv4 option. A dual-mode socket, which SshSharp uses for a host
  name when `AddressFamily` is `Any`, may refuse it. Set `AddressFamily = SshAddressFamily.Inet` to get an IPv4 socket. Windows
  ignores it by default and marks traffic through QoS policies instead.
- **A larger window does not help when bandwidth is the limit,** only when the round trip is.
- **Counters cover the whole connection,** every channel together. For one transfer, take the difference before and after.

## See also

- [Tune for throughput](performance-tuning.md)
- [Connecting](../connecting.md)
- [Channels and flow control](../concepts/channels.md)
- [Transfer files with SFTP](transfer-files-sftp.md#download-large-files-faster)
- [Logging and diagnostics](logging-and-diagnostics.md)
- <xref:SshSharp.SshClientOptions> and <xref:SshSharp.SshClient> in the API reference
