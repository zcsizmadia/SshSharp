using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Dynamic forwarding with SOCKS 5 username/password authentication (RFC 1929): raw clients that get it right and wrong, and
/// <see cref="SshProxy.Socks5(string, int, NetworkCredential?)"/> as a real client.
/// </summary>
public sealed class SocksAuthenticationTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    // Generated per run, as CI does: no password is written down.
    private static readonly string ProxyUser = "app-" + Guid.NewGuid().ToString("N")[..8];
    private static readonly string ProxyPassword = Guid.NewGuid().ToString("N");
    private static readonly string ServerPassword = Guid.NewGuid().ToString("N");

    private static async Task<(FakeSessionServer Server, SshClient Client, SshDynamicPortForwarder Proxy)> StartAsync(NetworkCredential? credentials)
    {
        var server = new FakeSessionServer { Password = ServerPassword, DirectTcpIp = (_, _) => UpperCase() };
        _ = server.StartAsync();
        var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = ServerPassword,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
        var proxy = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), credentials, Timeout());
        return (server, client, proxy);
    }

    /// <summary>A service that answers each request with its upper-case form, once the request has ended.</summary>
    private static DuplexStream UpperCase()
    {
        var (near, far) = DuplexStream.CreatePair();
        _ = Task.Run(async () =>
        {
            using var buffer = new MemoryStream();
            await far.CopyToAsync(buffer);
            await far.WriteAsync(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(buffer.ToArray()).ToUpperInvariant()));
            await far.DisposeAsync();
        });
        return near;
    }

    private static async Task<Socket> OpenAsync(SshDynamicPortForwarder proxy)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy.LocalEndPoint, Timeout());
        return socket;
    }

    private static async Task SendAsync(Socket socket, byte[] data) => await socket.SendAsync(data, SocketFlags.None, Timeout());

    /// <summary>Reads up to <paramref name="count"/> bytes, fewer if the proxy closes the connection first.</summary>
    private static async Task<byte[]> ReceiveAsync(Socket socket, int count)
    {
        var buffer = new byte[count];
        var read = 0;
        try
        {
            while (read < count && await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, Timeout()) is var n and > 0)
            {
                read += n;
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            // Closed with our data still unread, which resets the connection instead of ending it: the same "go away".
        }

        return buffer[..read];
    }

    /// <summary>RFC 1929's request: VER=1 | ULEN | UNAME | PLEN | PASSWD.</summary>
    private static byte[] UserNamePassword(string userName, string password)
    {
        var user = Encoding.UTF8.GetBytes(userName);
        var pass = Encoding.UTF8.GetBytes(password);
        return [1, (byte)user.Length, .. user, (byte)pass.Length, .. pass];
    }

    private static byte[] Connect(string host, int port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        return [5, 1, 0, 3, (byte)name.Length, .. name, (byte)(port >> 8), (byte)port];
    }

    private static NetworkCredential Credentials => new(ProxyUser, ProxyPassword);

    [Test]
    public async Task TheRightCredentials_LetTheClientThrough()
    {
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [5, 2, 0, 2]); // offers "none" and username/password: username/password is chosen
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 2 });
            await SendAsync(socket, UserNamePassword(ProxyUser, ProxyPassword));
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 1, 0 });
            await SendAsync(socket, Connect("db.internal", 5432));
            var reply = await ReceiveAsync(socket, 10);
            await Assert.That(reply[1]).IsEqualTo((byte)0);

            await SendAsync(socket, "select"u8.ToArray());
            socket.Shutdown(SocketShutdown.Send);
            await Assert.That(Encoding.ASCII.GetString(await ReceiveAsync(socket, 6))).IsEqualTo("SELECT");
            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });
        }
    }

    [Test]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(false, false)]
    public async Task WrongCredentials_AreRefused_AndTheConnectionClosed(bool rightUser, bool rightPassword)
    {
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [5, 1, 2]);
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 2 });

            // Same lengths as the right ones, so only the content is wrong.
            await SendAsync(socket, UserNamePassword(rightUser ? ProxyUser : ProxyUser.ToUpperInvariant(), rightPassword ? ProxyPassword : new string('x', ProxyPassword.Length)));
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 1, 1 });

            // RFC 1929: the server closes the connection; a CONNECT sent anyway goes nowhere.
            try
            {
                await SendAsync(socket, Connect("db.internal", 5432));
            }
            catch (SocketException)
            {
                // Already closed.
            }

            await Assert.That(await ReceiveAsync(socket, 10)).IsEmpty();
            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
        }
    }

    [Test]
    public async Task AClientThatDoesNotAuthenticate_IsTurnedAway()
    {
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [5, 1, 0]); // "no authentication" only
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 0xFF });
            await Assert.That(await ReceiveAsync(socket, 1)).IsEmpty();
            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
        }
    }

    [Test]
    public async Task Socks4_WhichHasNoPasswords_IsRefused()
    {
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [4, 1, 0x15, 0x38, 0, 0, 0, 1, .. Encoding.ASCII.GetBytes(ProxyUser), 0, .. "db.internal"u8.ToArray(), 0]);
            var reply = await ReceiveAsync(socket, 8);
            await Assert.That(reply.Length).IsEqualTo(8);
            await Assert.That(reply[1]).IsEqualTo((byte)0x5B); // rejected
            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
        }
    }

    [Test]
    [Arguments((byte)2, 0x15)] // BIND, which the proxy does not do
    [Arguments((byte)1, 0)] // CONNECT to port 0
    public async Task Socks4_ARequestRefusedAnyway_GetsOneRefusal(byte command, int port)
    {
        // The parse refuses such a request itself; the refusal for asking without a password must not follow it as a second reply.
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [4, command, 0, (byte)port, 192, 0, 2, 10, .. Encoding.ASCII.GetBytes(ProxyUser), 0]);
            var reply = await ReceiveAsync(socket, 16); // all the proxy sends before it closes the connection
            await Assert.That(reply.Length).IsEqualTo(8);
            await Assert.That(reply[1]).IsEqualTo((byte)0x5B);
            await Assert.That(server.DirectTcpIpRequests).IsEmpty();
        }
    }

    [Test]
    public async Task SshSharpsOwnSocksClient_Authenticates()
    {
        var (server, client, proxy) = await StartAsync(Credentials);
        await using (server)
        await using (client)
        await using (proxy)
        {
            await using (var stream = await SshProxy.Socks5("127.0.0.1", proxy.LocalEndPoint.Port, Credentials).ConnectAsync("db.internal", 5432, Timeout()))
            {
                await stream.WriteAsync("ping"u8.ToArray(), Timeout());
                await stream.FlushAsync(Timeout());
            }

            var wrong = SshProxy.Socks5("127.0.0.1", proxy.LocalEndPoint.Port, new NetworkCredential(ProxyUser, "not-" + ProxyPassword));
            var ex = await Assert.ThrowsAsync<SshException>(async () => await wrong.ConnectAsync("db.internal", 5432, Timeout()));
            await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);

            var none = SshProxy.Socks5("127.0.0.1", proxy.LocalEndPoint.Port);
            await Assert.ThrowsAsync<SshException>(async () => await none.ConnectAsync("db.internal", 5432, Timeout()));
            await Assert.That(server.DirectTcpIpRequests).IsEquivalentTo(new[] { "db.internal:5432" });
        }
    }

    [Test]
    public async Task NullCredentials_MeanNoAuthentication_AsBefore()
    {
        var (server, client, proxy) = await StartAsync(credentials: null);
        await using (server)
        await using (client)
        await using (proxy)
        {
            using var socket = await OpenAsync(proxy);
            await SendAsync(socket, [5, 1, 0]);
            await Assert.That(await ReceiveAsync(socket, 2)).IsEquivalentTo(new byte[] { 5, 0 });
        }
    }

    [Test]
    public async Task CredentialsOutsideRfc1929_AreRejected()
    {
        await using var server = new FakeSessionServer { Password = ServerPassword };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = ServerPassword,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
        var loopback = new IPEndPoint(IPAddress.Loopback, 0);

        foreach (var credentials in new[]
        {
            new NetworkCredential("", ProxyPassword),
            new NetworkCredential(ProxyUser, ""),
            new NetworkCredential(new string('u', 256), ProxyPassword),
            new NetworkCredential(ProxyUser, new string('p', 256)),
            new NetworkCredential(ProxyUser, new string('é', 128)), // 256 bytes in UTF-8
        })
        {
            await Assert.That(async () => await client.ForwardDynamicPortAsync(loopback, credentials, Timeout())).Throws<ArgumentException>();
        }

        // The longest that fit.
        await using var longest = await client.ForwardDynamicPortAsync(loopback, new NetworkCredential(new string('u', 255), new string('p', 255)), Timeout());
        await Assert.That(longest.LocalEndPoint.Port).IsNotEqualTo(0);
    }

    [Test]
    public async Task TheComparison_DependsOnTheValuesOnly()
    {
        var expected = new SocksCredentials(new NetworkCredential("user", "pass"), "credentials");
        await Assert.That(expected.Matches("user"u8, "pass"u8)).IsTrue();
        await Assert.That(expected.Matches("user"u8, "pass "u8)).IsFalse();
        await Assert.That(expected.Matches("user"u8, "pas"u8)).IsFalse();
        await Assert.That(expected.Matches("User"u8, "pass"u8)).IsFalse();
        await Assert.That(expected.Matches("pass"u8, "user"u8)).IsFalse();
        await Assert.That(expected.Matches(""u8, ""u8)).IsFalse();
        await Assert.That(new SocksCredentials(new NetworkCredential("ü", "ß"), "credentials").Matches("ü"u8, "ß"u8)).IsTrue();
    }
}
