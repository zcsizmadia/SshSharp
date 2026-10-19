using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;
using SshSharp.Tests.Sftp;

namespace SshSharp.Tests;

/// <summary>
/// The connection options and introspection of #266: <see cref="SshClientOptions.ConfigureSocket"/>,
/// <see cref="SshClientOptions.VersionAddendum"/>, <see cref="SshClientOptions.ChannelWindowSize"/> and
/// <see cref="SshClientOptions.ChannelMaxPacketSize"/>, and the session id, endpoints, byte counters and <see cref="SshClient.RekeyAsync"/>.
/// </summary>
public sealed class ConnectionOptionsTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    // Generated per run, as CI does: no password is written down.
    private static readonly string Password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static SshClientOptions Options(string? versionAddendum = null, int? window = null, int? maxPacket = null, Action<Socket>? configureSocket = null)
    {
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            VersionAddendum = versionAddendum,
            ConfigureSocket = configureSocket,
        };
        return (window, maxPacket) switch
        {
            ({ } w, { } p) => Copy(options, w, p),
            ({ } w, null) => Copy(options, w, options.ChannelMaxPacketSize),
            (null, { } p) => Copy(options, options.ChannelWindowSize, p),
            _ => options,
        };

        static SshClientOptions Copy(SshClientOptions o, int w, int p) => new()
        {
            UserName = o.UserName,
            Password = o.Password,
            HostKeyVerifier = o.HostKeyVerifier,
            VersionAddendum = o.VersionAddendum,
            ConfigureSocket = o.ConfigureSocket,
            ChannelWindowSize = w,
            ChannelMaxPacketSize = p,
        };
    }

    private static FakeSessionServer Server() => new() { Password = Password };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions options)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>Output whose every byte depends on its position, so a lost, repeated or reordered chunk shows.</summary>
    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        for (var i = 0; i < length; i++)
        {
            data[i] = (byte)((i * 31) ^ (i >> 8));
        }

        return data;
    }

    // ---- VersionAddendum ----

    [Test]
    public async Task VersionAddendum_FollowsTheSoftwareVersion_OnTheIdentificationLine()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options(versionAddendum: "deploy-bot/2.1 (nightly)"));

        var identification = server.Raw.ClientIdentification!;
        await Assert.That(identification.SoftwareVersion).IsEqualTo(SshSharpInfo.SoftwareVersion);
        await Assert.That(identification.Comments).IsEqualTo("deploy-bot/2.1 (nightly)");
        await Assert.That(identification.Line).IsEqualTo($"SSH-2.0-{SshSharpInfo.SoftwareVersion} deploy-bot/2.1 (nightly)");

        // The exchange hash covers the line as sent: the key exchange succeeding proves both sides hashed the same one.
        await Assert.That((await client.RunCommandAsync("true", Timeout())).ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task WithoutAnAddendum_TheLineHasNoComment()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options());
        await Assert.That(server.Raw.ClientIdentification!.Comments).IsNull();
        await Assert.That(server.Raw.ClientIdentification.Line).IsEqualTo($"SSH-2.0-{SshSharpInfo.SoftwareVersion}");
    }

    [Test]
    [Arguments("")]
    [Arguments(" leading")]
    [Arguments("trailing ")]
    [Arguments("line\r\nbreak")]
    [Arguments("tab\there")]
    [Arguments("nul\0")]
    [Arguments("café")]
    [Arguments("del\u007f")]
    public async Task AnAddendumOutsideRfc4253_IsRejected(string addendum)
    {
        await Assert.That(() => Options(versionAddendum: addendum)).Throws<ArgumentException>();
    }

    [Test]
    public async Task TheAddendum_MayFillTheLine_To255Bytes_AndNoFurther()
    {
        var longest = SshIdentification.MaxClientCommentsLength;
        var options = Options(versionAddendum: new string('x', longest));
        await Assert.That($"SSH-2.0-{SshSharpInfo.SoftwareVersion} {options.VersionAddendum}\r\n".Length).IsEqualTo(255);
        await Assert.That(() => Options(versionAddendum: new string('x', longest + 1))).Throws<ArgumentException>();

        // The longest line is one the transport writes (and a parser reads back).
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        SshIdentification.ForClient(options.VersionAddendum).Write(buffer);
        await Assert.That(buffer.WrittenCount).IsEqualTo(255);
        await Assert.That(SshIdentification.TryParse(Encoding.ASCII.GetString(buffer.WrittenSpan)[..^2], out var parsed)).IsTrue();
        await Assert.That(parsed!.Comments).IsEqualTo(options.VersionAddendum);
    }

    // ---- introspection ----

    [Test]
    public async Task TheSessionId_IsTheFirstExchangeHash_AsACopy_ThatOutlivesTheClient()
    {
        await using var server = Server();
        var client = await ConnectAsync(server, Options());
        var sessionId = client.SessionId;
        await Assert.That(sessionId.Length).IsEqualTo(32); // curve25519-sha256
        await Assert.That(sessionId.ToArray().SequenceEqual(server.SessionId!)).IsTrue();

        // A re-exchange keeps it.
        await client.RekeyAsync(Timeout());
        await Assert.That(client.SessionId.ToArray().SequenceEqual(server.SessionId!)).IsTrue();

        // The transport wipes its own copy on disposal; the client's stays as it was.
        await client.DisposeAsync();
        await Assert.That(client.SessionId.ToArray().SequenceEqual(server.SessionId!)).IsTrue();
        await Assert.That(client.SessionId.ToArray().Any(b => b != 0)).IsTrue();
    }

    [Test]
    public async Task ConnectedAt_IsWhenTheConnectFinished()
    {
        await using var server = Server();
        var before = DateTimeOffset.UtcNow;
        await using var client = await ConnectAsync(server, Options());
        var after = DateTimeOffset.UtcNow;
        await Assert.That(client.ConnectedAt).IsGreaterThanOrEqualTo(before);
        await Assert.That(client.ConnectedAt).IsLessThanOrEqualTo(after);
        await Assert.That(client.ConnectedAt.Offset).IsEqualTo(TimeSpan.Zero);
    }

    [Test]
    public async Task TheByteCounters_CountWhatGoesEachWay()
    {
        var output = Pattern(300_000);
        var input = Pattern(100_000);
        await using var server = Server();
        server.OnExec = async script =>
        {
            while (await script.ReadInputAsync() is not null)
            {
            }

            await script.StdoutAsync(output);
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server, Options());

        // The key exchange and authentication already moved some.
        var sent = client.BytesSent;
        var received = client.BytesReceived;
        await Assert.That(sent).IsGreaterThan(0);
        await Assert.That(received).IsGreaterThan(0);

        var result = await client.RunCommandAsync("cat; produce", null, SshCommandInput.FromBytes(input), Timeout());
        await Assert.That(result.StandardOutput.ToArray().SequenceEqual(output)).IsTrue();

        // The payloads plus their messages' headers: more than the data, and not by much.
        var sentNow = client.BytesSent - sent;
        var receivedNow = client.BytesReceived - received;
        await Assert.That(sentNow).IsGreaterThanOrEqualTo(input.Length);
        await Assert.That(sentNow).IsLessThan(input.Length + 4096);
        await Assert.That(receivedNow).IsGreaterThanOrEqualTo(output.Length);
        await Assert.That(receivedNow).IsLessThan(output.Length + 4096);
    }

    [Test]
    public async Task OverAStreamThatIsNoSocket_ThereAreNoEndpoints()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options());
        await Assert.That(client.RemoteEndPoint).IsNull();
        await Assert.That(client.LocalEndPoint).IsNull();
    }

    /// <summary>A loopback listener that relays its one connection to a fake SSH server, and records where it came from.</summary>
    private sealed class Bridge : IAsyncDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly Task _serve;

        public Bridge(FakeSessionServer server)
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen();
            _serve = Task.Run(async () =>
            {
                using var socket = await _listener.AcceptAsync();
                Remote = (IPEndPoint)socket.RemoteEndPoint!;
                _ = server.StartAsync();
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                await Task.WhenAny(stream.CopyToAsync(server.ClientStream), server.ClientStream.CopyToAsync(stream));
            });
        }

        public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndPoint!;

        public IPEndPoint? Remote { get; private set; }

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

    [Test]
    public async Task OverTcp_TheEndpointsAreTheConnections()
    {
        await using var server = Server();
        await using var bridge = new Bridge(server);
        await using var client = await SshClient.ConnectAsync("127.0.0.1", bridge.EndPoint.Port, Options(), Timeout());

        await Assert.That(client.RemoteEndPoint).IsEqualTo(bridge.EndPoint);
        await Assert.That(client.LocalEndPoint).IsEqualTo(bridge.Remote);
    }

    [Test]
    public async Task ConfigureSocket_IsCalledOnce_WithTheSocket_BeforeItConnects()
    {
        await using var server = Server();
        await using var bridge = new Bridge(server);
        var calls = 0;
        Socket? configured = null;
        var connectedWhenCalled = true;
        var options = Options(configureSocket: socket =>
        {
            Interlocked.Increment(ref calls);
            configured = socket;
            connectedWhenCalled = socket.Connected;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.ReceiveBufferSize = 1024 * 1024;
        });
        await using var client = await SshClient.ConnectAsync("127.0.0.1", bridge.EndPoint.Port, options, Timeout());

        await Assert.That(calls).IsEqualTo(1);
        await Assert.That(connectedWhenCalled).IsFalse();

        // The socket it was given is the one that connected, and keeps what was set on it.
        await Assert.That(configured!.Connected).IsTrue();
        var remote = (IPEndPoint)configured.RemoteEndPoint!; // IPv4-mapped on a dual-mode socket
        await Assert.That(remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address).IsEqualTo(IPAddress.Loopback);
        await Assert.That(remote.Port).IsEqualTo(bridge.EndPoint.Port);
        await Assert.That((int)configured.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)!).IsNotEqualTo(0);
        await Assert.That(configured.NoDelay).IsTrue();
    }

    [Test]
    public async Task WithALocalEndPoint_ConfigureSocket_GetsTheBoundSocket()
    {
        await using var server = Server();
        await using var bridge = new Bridge(server);
        EndPoint? boundWhenCalled = null;
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ConfigureSocket = socket => boundWhenCalled = socket.LocalEndPoint,
        };
        await using var client = await SshClient.ConnectAsync("127.0.0.1", bridge.EndPoint.Port, options, Timeout());

        await Assert.That(((IPEndPoint)boundWhenCalled!).Address).IsEqualTo(IPAddress.Loopback);
        await Assert.That(client.LocalEndPoint).IsEqualTo(bridge.Remote);
    }

    [Test]
    public async Task WhatConfigureSocketThrows_EndsTheAttempt_AsItIs()
    {
        await using var server = Server();
        await using var bridge = new Bridge(server);

        // Not reported as a failure to connect: the caller's own code failed, and says why.
        var failing = Options(configureSocket: _ => throw new InvalidOperationException("no such option here"));
        var error = await Assert.That(async () => { await SshClient.ConnectAsync("127.0.0.1", bridge.EndPoint.Port, failing, Timeout()); })
            .Throws<InvalidOperationException>();
        await Assert.That(error!.Message).IsEqualTo("no such option here");

        var socketError = Options(configureSocket: _ => throw new SocketException((int)SocketError.ProtocolOption));
        await Assert.That(async () => { await SshClient.ConnectAsync("127.0.0.1", bridge.EndPoint.Port, socketError, Timeout()); })
            .Throws<SocketException>();
    }

    // ---- RekeyAsync ----

    [Test]
    public async Task RekeyAsync_ExchangesKeys_AndTheConnectionCarriesOn()
    {
        await using var server = Server();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(Encoding.ASCII.GetBytes(script.Command));
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server, Options());
        await Assert.That(client.Connection.KeyExchangeCount).IsEqualTo(1);

        await client.RekeyAsync(Timeout());
        await Assert.That(client.Connection.KeyExchangeCount).IsEqualTo(2);
        // The server counts its side when our NEWKEYS arrives, which may be after the client has finished: wait for it.
        await WaitUntilAsync(() => server.Raw.KeyExchangeCount == 2);
        await Assert.That((await client.RunCommandAsync("after one", Timeout())).StandardOutputText).IsEqualTo("after one");

        await client.RekeyAsync(Timeout());
        await Assert.That(client.Connection.KeyExchangeCount).IsEqualTo(3);
        await Assert.That((await client.RunCommandAsync("after two", Timeout())).StandardOutputText).IsEqualTo("after two");
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task RekeyAsync_WhileOutputStreams_LosesNothing()
    {
        var output = Pattern(8 * 1024 * 1024);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = Server();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(output.AsMemory(0, 1024 * 1024).ToArray());
            started.SetResult();
            await script.StdoutAsync(output.AsMemory(1024 * 1024).ToArray());
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server, Options());

        var running = client.RunCommandAsync("produce", Timeout());
        await started.Task.WaitAsync(Timeout());
        await client.RekeyAsync(Timeout());
        var result = await running;
        await Assert.That(result.StandardOutput.ToArray().SequenceEqual(output)).IsTrue();
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task ConcurrentRekeyAsync_Calls_AllComplete_WithNewKeys()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options());

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.RekeyAsync(Timeout())));

        // Calls that found an exchange running joined it: at least one exchange, at most one each.
        var count = client.Connection.KeyExchangeCount;
        await Assert.That(count).IsGreaterThanOrEqualTo(2);
        await Assert.That(count).IsLessThanOrEqualTo(9);
        await WaitUntilAsync(() => server.Raw.KeyExchangeCount == count); // the server's side may finish just after ours
        await Assert.That((await client.RunCommandAsync("true", Timeout())).ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task RekeyAsync_OnADisposedClient_Throws()
    {
        await using var server = Server();
        var client = await ConnectAsync(server, Options());
        await client.DisposeAsync();
        await Assert.That(() => client.RekeyAsync(Timeout())).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task RekeyAsync_OnAFailedConnection_ThrowsWhyItFailed()
    {
        var server = Server();
        await using var client = await ConnectAsync(server, Options());
        await server.DisposeAsync(); // the server goes away
        await WaitUntilAsync(() => !client.IsConnected);

        var error = await Assert.That(() => client.RekeyAsync(Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("The condition did not become true.");
            }

            await Task.Delay(10);
        }
    }

    // ---- channel window and maximum packet ----

    [Test]
    public async Task TheDefaults_AreOpenSsh_s()
    {
        var options = Options();
        await Assert.That(options.ChannelWindowSize).IsEqualTo(2 * 1024 * 1024);
        await Assert.That(options.ChannelMaxPacketSize).IsEqualTo(32 * 1024);

        await using var server = Server();
        await using var client = await ConnectAsync(server, options);
        await client.RunCommandAsync("true", Timeout());
        var channel = server.Channels.Single();
        await Assert.That(channel.ClientMaxPacket).IsEqualTo(32u * 1024);
        await Assert.That(FakeSessionServer.ClientWindowOf(channel)).IsEqualTo(2L * 1024 * 1024);
    }

    [Test]
    public async Task ALargerWindowAndPacket_AreWhatTheChannelOpenAsksFor_AndCarryData()
    {
        const int window = 16 * 1024 * 1024;
        const int maxPacket = 255 * 1024;
        var output = Pattern(20 * 1024 * 1024);
        await using var server = Server();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(output);
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server, Options(window: window, maxPacket: maxPacket));

        var result = await client.RunCommandAsync("produce", Timeout());
        await Assert.That(result.StandardOutput.ToArray().SequenceEqual(output)).IsTrue();

        // The fake server sends as large packets as the client allows: 255 KiB ones were accepted.
        var channel = server.Channels.Single();
        await Assert.That(channel.ClientMaxPacket).IsEqualTo((uint)maxPacket);
    }

    [Test]
    public async Task ASmallWindow_StillCarriesEverything_InManyRounds()
    {
        var output = Pattern(300_000);
        await using var server = Server();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(output);
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server, Options(window: 4096, maxPacket: 1024));

        await using (var session = await client.StartCommandAsync("produce", cancellationToken: Timeout()))
        {
            using var all = new MemoryStream();
            await session.StandardOutput.CopyToAsync(all, Timeout());
            await Assert.That(all.ToArray().SequenceEqual(output)).IsTrue();
        }

        var channel = server.Channels.Single();
        await Assert.That(channel.ClientMaxPacket).IsEqualTo(1024u);
    }

    [Test]
    public async Task TheMaximumPacket_IsCappedAtTheWindow()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options(window: 4096, maxPacket: 64 * 1024));
        await client.RunCommandAsync("true", Timeout());
        var channel = server.Channels.Single();
        await Assert.That(channel.ClientMaxPacket).IsEqualTo(4096u);
        await Assert.That(FakeSessionServer.ClientWindowOf(channel)).IsEqualTo(4096L);
    }

    [Test]
    public async Task ChannelsTheServerOpens_AreConfirmedWithTheSameSizes()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, Options(window: 8 * 1024 * 1024, maxPacket: 128 * 1024));
        var payload = Pattern(1_000_000);
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 0, async (connection, ct) =>
        {
            using var all = new MemoryStream();
            await connection.Stream.CopyToAsync(all, ct);
            received.SetResult(all.ToArray());
        }, cancellationToken: Timeout());

        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        var channel = server.LastChannelToClient!;
        await Assert.That(channel.ClientMaxPacket).IsEqualTo(128u * 1024);
        await Assert.That(FakeSessionServer.ClientWindowOf(channel)).IsEqualTo(8L * 1024 * 1024);

        await remote.WriteAsync(payload, Timeout());
        ((DuplexStream)remote).CloseWrite();
        await Assert.That((await received.Task.WaitAsync(Timeout())).SequenceEqual(payload)).IsTrue();
    }

    [Test]
    public async Task Sftp_UsesTheSizes_AndReadsAFileWhole()
    {
        var data = Pattern(3 * 1024 * 1024);
        await using var server = Server();
        var files = new FakeSftpServer();
        files.AddFile(FakeSftpServer.Home + "/big.bin", data);
        files.Install(server);
        await using var client = await ConnectAsync(server, Options(window: 8 * 1024 * 1024, maxPacket: 128 * 1024));
        await using var sftp = await client.OpenSftpAsync(Timeout());

        var read = await sftp.ReadAllBytesAsync(FakeSftpServer.Home + "/big.bin", Timeout());
        await Assert.That(read.SequenceEqual(data)).IsTrue();
        await Assert.That(server.Channels.Single().ClientMaxPacket).IsEqualTo(128u * 1024);
    }

    [Test]
    public async Task OutOfRangeSizes_AreRejected()
    {
        await Assert.That(() => Options(window: 1023)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(window: (1 << 30) + 1)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(maxPacket: 1023)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(maxPacket: (255 * 1024) + 1)).Throws<ArgumentOutOfRangeException>();

        // The bounds themselves are allowed.
        await Assert.That(Options(window: 1024, maxPacket: 1024).ChannelWindowSize).IsEqualTo(1024);
        await Assert.That(Options(window: 1 << 30, maxPacket: 255 * 1024).ChannelMaxPacketSize).IsEqualTo(255 * 1024);
    }
}
