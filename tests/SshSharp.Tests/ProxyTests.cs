using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary><see cref="SshProxy"/> and <see cref="SshClient.CreateHttpConnectCallback"/> (#94), against small fake proxies.</summary>
public class ProxyTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>
    /// A one-connection proxy on loopback: <paramref name="handshake"/> reads the client's request and answers, returning whether to go
    /// on; then the connection is relayed to <paramref name="target"/> (or just held, when null).
    /// </summary>
    private sealed class FakeProxy : IAsyncDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly Task _serve;

        public FakeProxy(Func<NetworkStream, Task<bool>> handshake, Stream? target = null)
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen();
            _serve = Task.Run(async () =>
            {
                using var socket = await _listener.AcceptAsync();
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                if (!await handshake(stream) || target is null)
                {
                    return;
                }

                var up = stream.CopyToAsync(target);
                var down = target.CopyToAsync(stream);
                await Task.WhenAny(up, down);
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        public async ValueTask DisposeAsync()
        {
            _listener.Dispose();
            try
            {
                await _serve.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception)
            {
                // Ended with the test.
            }
        }
    }

    private static async Task<string> ReadHeaderAsync(Stream stream)
    {
        var text = new StringBuilder();
        var one = new byte[1];
        while (!text.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            await stream.ReadExactlyAsync(one);
            text.Append((char)one[0]);
        }

        return text.ToString();
    }

    private static async Task<byte[]> ReadAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer);
        return buffer;
    }

    // ---- HTTP CONNECT ----

    [Test]
    public async Task HttpConnect_SendsTheRequestAndCredentials_AndLeavesTheServersBytesInTheStream()
    {
        string? request = null;
        await using var proxy = new FakeProxy(async stream =>
        {
            request = await ReadHeaderAsync(stream);

            // The answer and the SSH server's first line in one write: the client must not swallow the latter with the header.
            await stream.WriteAsync("HTTP/1.1 200 Connection established\r\nVia: fake\r\n\r\nSSH-2.0-Behind_1.0\r\n"u8.ToArray());
            return true;
        });

        // Basic authentication allows a colon in the password, after the one that ends the user name.
        var password = TestSecrets.New() + ":x";
        var sshProxy = SshProxy.Http("127.0.0.1", proxy.Port, new NetworkCredential("alice", password));
        await using var stream = await sshProxy.ConnectAsync("ssh.internal", 2222, Timeout());

        await Assert.That(request).IsEqualTo(
            "CONNECT ssh.internal:2222 HTTP/1.1\r\nHost: ssh.internal:2222\r\nProxy-Authorization: Basic " +
            Convert.ToBase64String(Encoding.ASCII.GetBytes("alice:" + password)) + "\r\n\r\n");
        await Assert.That(Encoding.ASCII.GetString(await ReadAsync(stream, 20))).IsEqualTo("SSH-2.0-Behind_1.0\r\n");
    }

    [Test]
    public async Task HttpConnect_BracketsAnIpv6Destination()
    {
        string? request = null;
        await using var proxy = new FakeProxy(async stream =>
        {
            request = await ReadHeaderAsync(stream);
            await stream.WriteAsync("HTTP/1.0 200 OK\r\n\r\n"u8.ToArray());
            return true;
        });

        await using var _ = await SshProxy.Http("127.0.0.1", proxy.Port).ConnectAsync("::1", 22, Timeout());

        await Assert.That(request).StartsWith("CONNECT [::1]:22 HTTP/1.1\r\nHost: [::1]:22\r\n\r\n");
    }

    [Test]
    [Arguments("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "requires authentication")]
    [Arguments("HTTP/1.1 403 Forbidden\r\n\r\n", "403 Forbidden")]
    [Arguments("SSH-2.0-NotAProxy\r\n\r\n", "did not answer as an HTTP proxy")]
    public async Task HttpConnect_ARefusal_IsAConnectFailure(string answer, string expected)
    {
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadHeaderAsync(stream);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(answer));
            return false;
        });

        var ex = await Assert.That(async () => await SshProxy.Http("127.0.0.1", proxy.Port).ConnectAsync("host", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.Message).Contains(expected);
    }

    // ---- SOCKS 5 ----

    [Test]
    public async Task Socks5_WithCredentials_SendsTheNameForTheProxyToResolve()
    {
        var password = TestSecrets.New();
        byte[]? login = null, connect = null;
        await using var proxy = new FakeProxy(async stream =>
        {
            await Assert.That(await ReadAsync(stream, 4)).IsEquivalentTo(new byte[] { 5, 2, 0, 2 }); // no auth, or user/password
            await stream.WriteAsync(new byte[] { 5, 2 });
            var header = await ReadAsync(stream, 2);
            var user = await ReadAsync(stream, header[1]);
            var passwordLength = await ReadAsync(stream, 1);
            var sent = await ReadAsync(stream, passwordLength[0]);
            login = [.. header, .. user, .. passwordLength, .. sent];
            await stream.WriteAsync(new byte[] { 1, 0 });
            connect = await ReadAsync(stream, 4 + 1 + "ssh.internal".Length + 2);

            // Bound address as a name (atyp 3), then the SSH server's first bytes.
            await stream.WriteAsync((byte[])[5, 0, 0, 3, 3, (byte)'a', (byte)'b', (byte)'c', 0, 22, .. "SSH-2.0-x\r\n"u8]);
            return true;
        });

        await using var stream = await SshProxy.Socks5("127.0.0.1", proxy.Port, new NetworkCredential("bob", password)).ConnectAsync("ssh.internal", 22, Timeout());

        await Assert.That(login).IsEquivalentTo((byte[])[1, 3, .. "bob"u8, (byte)password.Length, .. Encoding.ASCII.GetBytes(password)]);
        await Assert.That(connect).IsEquivalentTo((byte[])[5, 1, 0, 3, 12, .. "ssh.internal"u8, 0, 22]);
        await Assert.That(Encoding.ASCII.GetString(await ReadAsync(stream, 11))).IsEqualTo("SSH-2.0-x\r\n");
    }

    [Test]
    public async Task Socks5_AnIpv6Address_IsSentAsSuch()
    {
        byte[]? connect = null;
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadAsync(stream, 3);
            await stream.WriteAsync(new byte[] { 5, 0 });
            connect = await ReadAsync(stream, 4 + 16 + 2);
            await stream.WriteAsync((byte[])[5, 0, 0, 4, .. new byte[16], 0, 0]);
            return true;
        });

        await using var _ = await SshProxy.Socks5("127.0.0.1", proxy.Port).ConnectAsync("::1", 2222, Timeout());

        await Assert.That(connect).IsEquivalentTo((byte[])[5, 1, 0, 4, .. IPAddress.IPv6Loopback.GetAddressBytes(), 0x08, 0xAE]);
    }

    [Test]
    [Arguments(new byte[] { 5, 0xFF }, "requires authentication")]
    [Arguments(new byte[] { 5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, "connection refused")]
    [Arguments(new byte[] { 4, 0 }, "did not answer as a SOCKS 5 proxy")]
    public async Task Socks5_ARefusal_IsAConnectFailure(byte[] answer, string expected)
    {
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadAsync(stream, 3);
            await stream.WriteAsync(answer.AsMemory(0, 2));
            if (answer.Length > 2)
            {
                await ReadAsync(stream, 4 + 1 + 4 + 2);
                await stream.WriteAsync(answer.AsMemory(2));
            }

            return false;
        });

        var ex = await Assert.That(async () => await SshProxy.Socks5("127.0.0.1", proxy.Port).ConnectAsync("host", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Message).Contains(expected);
    }

    [Test]
    public async Task Socks5_WrongCredentials_AreReported()
    {
        var password = TestSecrets.New();
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadAsync(stream, 4);
            await stream.WriteAsync(new byte[] { 5, 2 });
            await ReadAsync(stream, 1 + 1 + 1 + 1 + password.Length);
            await stream.WriteAsync(new byte[] { 1, 1 });
            return false;
        });

        var ex = await Assert.That(async () => await SshProxy.Socks5("127.0.0.1", proxy.Port, new NetworkCredential("u", password)).ConnectAsync("h", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Message).Contains("refused the user name or password");
    }

    [Test]
    public async Task Socks5_AnAuthenticationReplyWithTheWrongVersion_IsRefused()
    {
        var password = TestSecrets.New();
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadAsync(stream, 4);
            await stream.WriteAsync(new byte[] { 5, 2 });
            await ReadAsync(stream, 1 + 1 + 1 + 1 + password.Length);
            await stream.WriteAsync(new byte[] { 5, 0 }); // "success", but not an RFC 1929 reply (version 1)
            return false;
        });

        var ex = await Assert.That(async () => await SshProxy.Socks5("127.0.0.1", proxy.Port, new NetworkCredential("u", password)).ConnectAsync("h", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Message).Contains("wrong version");
    }

    [Test]
    [Arguments(SshProxyType.Http)]
    [Arguments(SshProxyType.Socks4)]
    [Arguments(SshProxyType.Socks5)]
    public async Task ANonAsciiHostName_IsRejected_BeforeTheProxyIsContacted(SshProxyType type)
    {
        var contacted = false;
        await using var proxy = new FakeProxy(_ =>
        {
            contacted = true;
            return Task.FromResult(false);
        });
        var client = type switch
        {
            SshProxyType.Http => SshProxy.Http("127.0.0.1", proxy.Port),
            SshProxyType.Socks4 => SshProxy.Socks4("127.0.0.1", proxy.Port),
            _ => SshProxy.Socks5("127.0.0.1", proxy.Port),
        };

        // As ASCII, "bücher.example" would have reached the proxy as "b?cher.example": another name.
        await Assert.That(async () => await client.ConnectAsync("bücher.example", 22, Timeout())).Throws<ArgumentException>();
        await Assert.That(contacted).IsFalse();
        await Assert.That(() => SshProxy.Socks4("127.0.0.1", 1080, "jürgen")).Throws<ArgumentException>();
    }

    [Test]
    public async Task AProxyThatSaysNothing_TimesOut()
    {
        var release = new TaskCompletionSource();
        await using var proxy = new FakeProxy(async _ =>
        {
            await release.Task; // accepts, then never answers
            return false;
        });
        var client = SshProxy.Socks5("127.0.0.1", proxy.Port);
        client.HandshakeTimeout = TimeSpan.FromMilliseconds(300);

        try
        {
            var ex = await Assert.That(async () => await client.ConnectAsync("h", 22, Timeout())).Throws<SshException>();
            await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        }
        finally
        {
            release.SetResult();
        }
    }

    // ---- SOCKS 4 / 4a ----

    [Test]
    public async Task Socks4a_SendsTheNameAfterTheUserId_AndSocks4AnAddress()
    {
        byte[]? named = null, addressed = null;
        await using (var proxy = new FakeProxy(async stream =>
        {
            named = await ReadAsync(stream, 8 + 3 + 1 + "ssh.internal".Length + 1);
            await stream.WriteAsync(new byte[] { 0, 0x5A, 0, 0, 0, 0, 0, 0 });
            return true;
        }))
        {
            await using var _ = await SshProxy.Socks4("127.0.0.1", proxy.Port, "joe").ConnectAsync("ssh.internal", 22, Timeout());
        }

        await using (var proxy = new FakeProxy(async stream =>
        {
            addressed = await ReadAsync(stream, 8 + 1);
            await stream.WriteAsync(new byte[] { 0, 0x5A, 0, 0, 0, 0, 0, 0 });
            return true;
        }))
        {
            await using var _ = await SshProxy.Socks4("127.0.0.1", proxy.Port).ConnectAsync("10.1.2.3", 22, Timeout());
        }

        await Assert.That(named).IsEquivalentTo((byte[])[4, 1, 0, 22, 0, 0, 0, 1, .. "joe"u8, 0, .. "ssh.internal"u8, 0]);
        await Assert.That(addressed).IsEquivalentTo(new byte[] { 4, 1, 0, 22, 10, 1, 2, 3, 0 });
    }

    [Test]
    public async Task Socks4_ARefusal_IsAConnectFailure()
    {
        await using var proxy = new FakeProxy(async stream =>
        {
            await ReadAsync(stream, 9);
            await stream.WriteAsync(new byte[] { 0, 0x5B, 0, 0, 0, 0, 0, 0 });
            return false;
        });

        var ex = await Assert.That(async () => await SshProxy.Socks4("127.0.0.1", proxy.Port).ConnectAsync("10.0.0.1", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Message).Contains("0x5B");
    }

    // ---- through to an SSH server ----

    [Test]
    public async Task ConnectAsync_WithAProxy_ReachesTheServerThroughIt()
    {
        await using var server = new FakeSessionServer();
        _ = server.StartAsync();
        string? request = null;
        await using var proxy = new FakeProxy(async stream =>
        {
            request = await ReadHeaderAsync(stream);
            await stream.WriteAsync("HTTP/1.1 200 OK\r\n\r\n"u8.ToArray());
            return true;
        }, server.ClientStream);

        await using var client = await SshClient.ConnectAsync("ssh.behind.proxy", 22, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Proxy = SshProxy.FromUri(new Uri($"http://127.0.0.1:{proxy.Port}")),
        }, Timeout());

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(request).StartsWith("CONNECT ssh.behind.proxy:22 ");
    }

    [Test]
    public async Task AnUnreachableProxy_IsAConnectFailure()
    {
        // Port 1 on loopback: nothing listens there. A port bound and released could be taken by another test's listener before it is
        // used (a stress run saw a SOCKS proxy answer on one).
        const int unused = 1;

        var ex = await Assert.That(async () => await SshProxy.Socks5("127.0.0.1", unused).ConnectAsync("h", 22, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Message).Contains("Could not connect to the proxy");
    }

    // ---- FromUri ----

    [Test]
    [Arguments("http://proxy.corp:3128", SshProxyType.Http, "proxy.corp", 3128, null)]
    [Arguments("http://proxy.corp", SshProxyType.Http, "proxy.corp", 8080, null)]
    [Arguments("socks5://u%40corp:p%3Ass@10.0.0.1", SshProxyType.Socks5, "10.0.0.1", 1080, "u@corp")]
    [Arguments("socks5h://127.0.0.1:9050", SshProxyType.Socks5, "127.0.0.1", 9050, null)]
    [Arguments("socks4a://gw:1081", SshProxyType.Socks4, "gw", 1081, null)]
    public async Task FromUri_ReadsTheUsualForms(string uri, SshProxyType type, string host, int port, string? user)
    {
        var proxy = SshProxy.FromUri(new Uri(uri));

        await Assert.That(proxy.Type).IsEqualTo(type);
        await Assert.That(proxy.Host).IsEqualTo(host);
        await Assert.That(proxy.Port).IsEqualTo(port);
        await Assert.That(proxy.Credentials?.UserName).IsEqualTo(user);
        if (user is not null)
        {
            await Assert.That(proxy.Credentials!.Password).IsEqualTo("p:ss");
        }

        await Assert.That(proxy.ToString()).DoesNotContain("p:ss");
    }

    [Test]
    [Arguments("https://proxy:443")]
    [Arguments("ftp://proxy")]
    [Arguments("http://proxy:3128/path")]
    [Arguments("socks4://user:password@proxy")]
    public async Task FromUri_RejectsWhatIsNotAProxy(string uri) =>
        await Assert.That(() => SshProxy.FromUri(new Uri(uri))).Throws<ArgumentException>();

    // ---- HttpClient through the SSH connection ----

    [Test]
    public async Task TheHttpConnectCallback_SendsHttpClientsRequestsThroughTheServer()
    {
        await using var server = new FakeSessionServer
        {
            DirectTcpIp = (host, port) =>
            {
                var (near, far) = DuplexStream.CreatePair();
                _ = Task.Run(async () =>
                {
                    await ReadHeaderAsync(far);
                    var body = $"{host}:{port}";
                    await far.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}"));
                    await far.DisposeAsync();
                });
                return near;
            },
        };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());

        // UseProxy = false: otherwise a system proxy setting would make HttpClient connect to the proxy, through the server.
        using var http = new HttpClient(new SocketsHttpHandler { ConnectCallback = client.CreateHttpConnectCallback(), UseProxy = false });
        var body = await http.GetStringAsync("http://internal-api.corp:8080/health", Timeout());

        await Assert.That(body).IsEqualTo("internal-api.corp:8080");
        await Assert.That(server.DirectTcpIpRequests).Contains("internal-api.corp:8080");
    }
}
