using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// Delayed compression in the transport, against the fake server: negotiated in KEXINIT, started in both directions exactly at
/// USERAUTH_SUCCESS, a new stream at each key exchange (as OpenSSH), off again when a re-exchange negotiates <c>none</c>, and a hostile
/// server's compressed data failing the connection cleanly.
/// </summary>
public class SshTransportCompressionTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static readonly string[] ServerOffers = ["none", SshAlgorithms.CompressionZlibOpenSsh];

    /// <summary>What the client compresses with, where it can (zlib@openssh.com on .NET 10, none on .NET 8).</summary>
    private static string ClientToServer => SshAlgorithms.CanCompressOutgoing ? SshAlgorithms.CompressionZlibOpenSsh : SshAlgorithms.CompressionNone;

    private static async Task<(SshTransport Client, FakeSshServer Server)> StartAsync(FakeServerOptions? server = null, bool compression = true)
    {
        var fake = new FakeSshServer(server ?? new FakeServerOptions { Compression = ServerOffers });
        var transport = new SshTransport(fake.ClientStream, new SshTransportOptions
        {
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
            Preferences = new AlgorithmPreferences { Compression = compression ? SshAlgorithms.EnabledCompression : SshAlgorithms.DefaultCompression },
        });
        var token = Timeout();
        var serverTask = fake.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;
        return (transport, fake);
    }

    private static byte[] Message(byte type, int size, int seed)
    {
        var data = new byte[size];
        data[0] = type;
        for (var i = 1; i < size; i++)
        {
            data[i] = (byte)("abcdefgh\n"[(i * seed) % 9]);
        }

        return data;
    }

    private static async Task<byte[]> ClientReceivesAsync(SshTransport client)
    {
        using var packet = await client.ReceiveAsync(Timeout());
        return packet.Payload.ToArray();
    }

    private static async Task<byte[]> ServerReceivesAsync(FakeSshServer server)
    {
        using var packet = await server.ReceiveAsync(Timeout());
        return packet.Payload.ToArray();
    }

    /// <summary>A user authentication as the transport sees it: a failed request, then one that succeeds.</summary>
    private static async Task AuthenticateAsync(SshTransport client, FakeSshServer server)
    {
        await client.SendAsync(Message(SshMessage.UserAuthRequest, 40, 1), Timeout());
        await Assert.That((await ServerReceivesAsync(server))[0]).IsEqualTo(SshMessage.UserAuthRequest);
        await server.SendAsync(Message(SshMessage.UserAuthFailure, 30, 2), Timeout());
        await Assert.That((await ClientReceivesAsync(client))[0]).IsEqualTo(SshMessage.UserAuthFailure);
        await client.SendAsync(Message(SshMessage.UserAuthRequest, 60, 3), Timeout());
        await Assert.That((await ServerReceivesAsync(server))[0]).IsEqualTo(SshMessage.UserAuthRequest);
        await server.SendAsync(new byte[] { SshMessage.UserAuthSuccess }, Timeout());
        await Assert.That((await ClientReceivesAsync(client))[0]).IsEqualTo(SshMessage.UserAuthSuccess);
    }

    /// <summary>One message each way, checked byte for byte.</summary>
    private static async Task ExchangeAsync(SshTransport client, FakeSshServer server, int size, int seed)
    {
        var up = Message(94, size, seed);
        await client.SendAsync(up, Timeout());
        await Assert.That((await ServerReceivesAsync(server)).AsSpan().SequenceEqual(up)).IsTrue();
        var down = Message(94, size, seed + 1);
        await server.SendAsync(down, Timeout());
        await Assert.That((await ClientReceivesAsync(client)).AsSpan().SequenceEqual(down)).IsTrue();
    }

    /// <summary>Runs a re-exchange the server starts, and waits until both sides have finished it.</summary>
    private static async Task<(Task<byte[]> ClientNext, Task<byte[]> ServerNext)> RekeyAsync(SshTransport client, FakeSshServer server)
    {
        // Both receive loops run: each carries out its half of the exchange and then waits for the next application message.
        var serverNext = ServerReceivesAsync(server);
        await server.RekeyAsync(Timeout());
        var clientNext = ClientReceivesAsync(client);
        var token = Timeout();
        while (server.KeyExchangeCount < 2 || client.KeyExchangeCount < 2)
        {
            await Task.Delay(10, token);
        }

        return (clientNext, serverNext);
    }

    [Test]
    public async Task Negotiated_WhenBothOfferIt_ButNothingIsCompressedBeforeAuthentication()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await Assert.That(client.Algorithms!.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);
            await Assert.That(client.Algorithms.CompressionClientToServer).IsEqualTo(ClientToServer);

            // Before USERAUTH_SUCCESS: application-level traffic flows uncompressed both ways.
            await client.SendAsync(Message(SshMessage.UserAuthRequest, 50, 1), Timeout());
            await Assert.That((await ServerReceivesAsync(server))[0]).IsEqualTo(SshMessage.UserAuthRequest);
            await server.SendAsync(Message(SshMessage.UserAuthFailure, 50, 2), Timeout());
            await Assert.That((await ClientReceivesAsync(client))[0]).IsEqualTo(SshMessage.UserAuthFailure);
            await Assert.That(server.ReceivedPackets.All(p => !p.Compressed)).IsTrue();
            await Assert.That(server.SentPackets.All(p => !p.Compressed)).IsTrue();
        }
    }

    [Test]
    public async Task CompressionStarts_ExactlyAfterUserAuthSuccess_InEachDirection()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);
            await ExchangeAsync(client, server, 20_000, 3);
            await ExchangeAsync(client, server, 100, 5);

            // The server's side: USERAUTH_SUCCESS and everything before it went out plain, everything after compressed.
            var sent = server.SentPackets.ToArray();
            var success = Array.FindIndex(sent, p => p.Type == SshMessage.UserAuthSuccess);
            await Assert.That(success).IsGreaterThan(0);
            await Assert.That(sent.Take(success + 1).All(p => !p.Compressed)).IsTrue();
            await Assert.That(sent.Skip(success + 1).All(p => p.Compressed)).IsTrue();

            // The client's: its requests plain, its first packet after the success compressed (where it compresses at all).
            var received = server.ReceivedPackets.ToArray();
            await Assert.That(received.Where(p => p.Type is SshMessage.UserAuthRequest or SshMessage.ExtInfo).All(p => !p.Compressed)).IsTrue();
            await Assert.That(received.Where(p => p.Type == 94).All(p => p.Compressed == SshAlgorithms.CanCompressOutgoing)).IsTrue();
            await Assert.That(received.Count(p => p.Type == 94)).IsEqualTo(2);

            // The byte counters count message payloads as the application sees them, uncompressed.
            await Assert.That(client.BytesSent).IsGreaterThanOrEqualTo(20_000 + 100 + 40 + 60);
            await Assert.That(client.BytesReceived).IsGreaterThanOrEqualTo(20_000 + 100 + 30 + 1);
        }
    }

    [Test]
    public async Task OffByDefault_EvenWhenTheServerOffersIt()
    {
        var (client, server) = await StartAsync(compression: false);
        await using (client)
        await using (server)
        {
            await Assert.That(client.Algorithms!.CompressionClientToServer).IsEqualTo(SshAlgorithms.CompressionNone);
            await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);
            await AuthenticateAsync(client, server);
            await ExchangeAsync(client, server, 5000, 3);
            await Assert.That(server.ReceivedPackets.Any(p => p.Compressed) || server.SentPackets.Any(p => p.Compressed)).IsFalse();
        }
    }

    [Test]
    public async Task AServerWithoutIt_NegotiatesNone()
    {
        var (client, server) = await StartAsync(new FakeServerOptions { Compression = ["none"] });
        await using (client)
        await using (server)
        {
            await Assert.That(client.Algorithms!.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);
            await AuthenticateAsync(client, server);
            await ExchangeAsync(client, server, 5000, 3);
        }
    }

    [Test]
    public async Task AServerThatOnlyCompresses_IsRefusedWhenCompressionIsOff()
    {
        var fake = new FakeSshServer(new FakeServerOptions { Compression = [SshAlgorithms.CompressionZlibOpenSsh] });
        await using (fake)
        {
            var transport = new SshTransport(fake.ClientStream, new SshTransportOptions { VerifyHostKey = (_, _) => ValueTask.FromResult(true) });
            await using (transport)
            {
                _ = fake.StartAsync(Timeout());
                var error = await Assert.That(async () => await transport.ConnectAsync(Timeout())).Throws<SshException>();
                await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
                await Assert.That(error.Message).Contains("compression");
            }
        }
    }

    [Test]
    public async Task AReexchange_StartsNewStreams_AsOpenSshDoes()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);
            await ExchangeAsync(client, server, 10_000, 3);

            var (clientNext, serverNext) = await RekeyAsync(client, server);

            // The server's first packet after its NEWKEYS starts a new zlib stream (a header of its own): read with the old inflater,
            // it would be garbage. And the server inflates the client's first packet with a new inflater.
            var up = Message(94, 10_000, 7);
            await client.SendAsync(up, Timeout());
            await Assert.That((await serverNext).AsSpan().SequenceEqual(up)).IsTrue();
            var down = Message(94, 10_000, 8);
            await server.SendAsync(down, Timeout());
            await Assert.That((await clientNext).AsSpan().SequenceEqual(down)).IsTrue();

            // The exchange's own messages were compressed too: compression covers every packet once it has started.
            var afterSuccess = server.SentPackets.SkipWhile(p => p.Type != SshMessage.UserAuthSuccess).Skip(1).ToArray();
            await Assert.That(afterSuccess.Count(p => p.Type is SshMessage.KexInit or SshMessage.NewKeys)).IsEqualTo(2);
            await Assert.That(afterSuccess.Where(p => p.Type is SshMessage.KexInit or SshMessage.NewKeys).All(p => p.Compressed)).IsTrue();
            await Assert.That(server.ReceivedPackets.Where(p => p.Type is SshMessage.KexInit or SshMessage.NewKeys)
                .All(p => p.Compressed == SshAlgorithms.CanCompressOutgoing)).IsTrue();
            await Assert.That(client.Algorithms!.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);
            await ExchangeAsync(client, server, 30_000, 9);
        }
    }

    [Test]
    public async Task AReexchangeThatNegotiatesNone_TurnsCompressionOff()
    {
        var (client, server) = await StartAsync(new FakeServerOptions { Compression = ServerOffers, RekeyCompression = ["none"] });
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);
            await ExchangeAsync(client, server, 10_000, 3);
            var sentBefore = server.SentPackets.Count;
            var receivedBefore = server.ReceivedPackets.Count;

            var (clientNext, serverNext) = await RekeyAsync(client, server);
            await Assert.That(client.Algorithms!.CompressionClientToServer).IsEqualTo(SshAlgorithms.CompressionNone);
            await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);

            var up = Message(94, 10_000, 7);
            await client.SendAsync(up, Timeout());
            await Assert.That((await serverNext).AsSpan().SequenceEqual(up)).IsTrue();
            var down = Message(94, 10_000, 8);
            await server.SendAsync(down, Timeout());
            await Assert.That((await clientNext).AsSpan().SequenceEqual(down)).IsTrue();

            // After both NEWKEYS: plain again.
            await Assert.That(server.SentPackets.Skip(sentBefore).SkipWhile(p => p.Type != SshMessage.NewKeys).Skip(1).All(p => !p.Compressed)).IsTrue();
            await Assert.That(server.ReceivedPackets.Skip(receivedBefore).SkipWhile(p => p.Type != SshMessage.NewKeys).Skip(1).All(p => !p.Compressed)).IsTrue();
        }
    }

    [Test]
    public async Task ADecompressionBomb_FailsTheConnectionWithAProtocolError()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);

            // 1 MiB of zeros: a few kilobytes on the wire, far past the 256 KiB a packet may carry once inflated.
            var bomb = new byte[1024 * 1024];
            bomb[0] = 94;
            await server.SendAsync(bomb, Timeout());
            var error = await Assert.That(async () => await client.ReceiveAsync(Timeout())).Throws<SshProtocolException>();
            await Assert.That(error!.Message).Contains("inflates to");
        }
    }

    [Test]
    public async Task MalformedCompressedData_FailsTheConnectionWithAProtocolError()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);

            // The server's first compressed packet: a valid zlib header, then a block of the reserved type.
            await server.SendUncompressedAsync(new byte[] { 0x78, 0x9C, 0x06, 0x00, 0x00 }, Timeout());
            var error = await Assert.That(async () => await client.ReceiveAsync(Timeout())).Throws<SshProtocolException>();
            await Assert.That(error!.Message).Contains("not valid zlib");
        }
    }

    [Test]
    public async Task AnUncompressedPacketAfterTheSuccess_IsNotTakenAsPlainData()
    {
        var (client, server) = await StartAsync();
        await using (client)
        await using (server)
        {
            await AuthenticateAsync(client, server);

            // A server that forgets to compress: its plain packet is inflated as zlib and rejected, never handed on as a message.
            await server.SendUncompressedAsync(Message(94, 100, 1), Timeout());
            await Assert.That(async () => await client.ReceiveAsync(Timeout())).Throws<SshProtocolException>();
        }
    }
}
