using System.Threading.Channels;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class SshTransportRekeyTests
{
    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _milliseconds;

        public override long TimestampFrequency => 1000;

        public override long GetTimestamp() => Interlocked.Read(ref _milliseconds);

        public void Advance(TimeSpan span) => Interlocked.Add(ref _milliseconds, (long)span.TotalMilliseconds);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static SshTransportOptions ClientOptions(long rekeyBytes = long.MaxValue, TimeProvider? time = null, TimeSpan? interval = null, long rekeyPackets = long.MaxValue) => new()
    {
        VerifyHostKey = (_, _) => ValueTask.FromResult(true),
        RekeyBytes = rekeyBytes,
        RekeyPackets = rekeyPackets,
        RekeyInterval = interval ?? TimeSpan.FromHours(1),
        TimeProvider = time ?? TimeProvider.System,
    };

    /// <summary>Everything one side received, in order, collected by a background pump (which also drives re-exchanges).</summary>
    private sealed class Pump
    {
        private readonly Channel<byte[]> _messages = Channel.CreateUnbounded<byte[]>();

        public Pump(Func<CancellationToken, ValueTask<DecodedPacket>> receive)
        {
            Task = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        using var packet = await receive(Stop.Token);
                        _messages.Writer.TryWrite(packet.Payload.ToArray());
                    }
                }
                catch (Exception ex)
                {
                    Error = ex;
                    _messages.Writer.TryComplete();
                }
            });
        }

        public CancellationTokenSource Stop { get; } = new();

        public Task Task { get; }

        public Exception? Error { get; private set; }

        public async Task<byte[]> NextAsync() => await _messages.Reader.ReadAsync(Timeout());

        public async Task StopAsync()
        {
            await Stop.CancelAsync();
            await Task;
        }
    }

    private static async Task<(SshTransport Client, FakeSshServer Server, Pump ClientPump, Pump ServerPump)> StartAsync(FakeServerOptions? server = null, SshTransportOptions? client = null)
    {
        var fake = new FakeSshServer(server);
        var transport = new SshTransport(fake.ClientStream, client ?? ClientOptions());
        var token = Timeout();
        var serverTask = fake.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;
        return (transport, fake, new Pump(ct => transport.ReceiveAsync(ct)), new Pump(ct => fake.ReceiveAsync(ct)));
    }

    private static byte[] Message(byte tag, int index, int size)
    {
        var data = new byte[size];
        data[0] = tag;
        BitConverter.GetBytes(index).CopyTo(data, 1);
        for (var i = 5; i < size; i++)
        {
            data[i] = (byte)(index + i);
        }

        return data;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var token = Timeout();
        while (!condition())
        {
            await Task.Delay(10, token);
        }
    }

    [Test]
    public async Task ByteThreshold_TriggersRekeysAndNoDataIsLost()
    {
        var (client, server, clientPump, serverPump) = await StartAsync(client: ClientOptions(rekeyBytes: 20_000));
        await using (client)
        await using (server)
        {
            var sessionId = Convert.ToHexString(client.SessionId!);
            for (var i = 0; i < 100; i++)
            {
                await client.SendAsync(Message(90, i, 1000), Timeout());
            }

            for (var i = 0; i < 100; i++)
            {
                var received = await serverPump.NextAsync();
                await Assert.That(received.AsSpan().SequenceEqual(Message(90, i, 1000))).IsTrue();
            }

            // Both directions keep working on the newest keys.
            await server.SendAsync(Message(94, 7, 300), Timeout());
            var echoed = await clientPump.NextAsync();
            await Assert.That(echoed.AsSpan().SequenceEqual(Message(94, 7, 300))).IsTrue();

            await WaitUntilAsync(() => client.KeyExchangeCount >= 4 && server.KeyExchangeCount == client.KeyExchangeCount);
            await Assert.That(Convert.ToHexString(client.SessionId!)).IsEqualTo(sessionId);
            await Assert.That(clientPump.Error).IsNull();
            await Assert.That(serverPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task PacketThreshold_TriggersRekeys_EvenWhenFewBytesMove()
    {
        // Tiny packets barely move the byte counter, but sequence numbers (the ChaCha20-Poly1305 nonce) must never wrap under one key.
        var (client, server, clientPump, serverPump) = await StartAsync(client: ClientOptions(rekeyPackets: 25));
        await using (client)
        await using (server)
        {
            for (var i = 0; i < 100; i++)
            {
                await client.SendAsync(Message(90, i, 8), Timeout());
            }

            for (var i = 0; i < 100; i++)
            {
                var received = await serverPump.NextAsync();
                await Assert.That(received.AsSpan().SequenceEqual(Message(90, i, 8))).IsTrue();
            }

            await WaitUntilAsync(() => client.KeyExchangeCount >= 4 && server.KeyExchangeCount == client.KeyExchangeCount);
            await Assert.That(clientPump.Error).IsNull();
            await Assert.That(serverPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task AReceiveOnlyConnectionRekeysOnItsOwn()
    {
        // The client only receives (a big download): the byte threshold counts both directions, so it must start the re-exchange itself.
        var (client, server, clientPump, serverPump) = await StartAsync(client: ClientOptions(rekeyBytes: 20_000));
        await using (client)
        await using (server)
        {
            for (var i = 0; i < 100; i++)
            {
                await server.SendAsync(Message(94, i, 1000), Timeout());
            }

            for (var i = 0; i < 100; i++)
            {
                await Assert.That((await clientPump.NextAsync()).AsSpan().SequenceEqual(Message(94, i, 1000))).IsTrue();
            }

            await WaitUntilAsync(() => client.KeyExchangeCount >= 2 && server.KeyExchangeCount == client.KeyExchangeCount);
            await Assert.That(clientPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task TimeThreshold_TriggersARekey()
    {
        var time = new ManualTimeProvider();
        var (client, server, clientPump, serverPump) = await StartAsync(client: ClientOptions(time: time, interval: TimeSpan.FromHours(1)));
        await using (client)
        await using (server)
        {
            await client.SendAsync(Message(90, 1, 50), Timeout());
            await serverPump.NextAsync();
            await Assert.That(client.KeyExchangeCount).IsEqualTo(1);

            time.Advance(TimeSpan.FromMinutes(59));
            await client.SendAsync(Message(90, 2, 50), Timeout());
            await serverPump.NextAsync();
            await Assert.That(client.KeyExchangeCount).IsEqualTo(1);

            time.Advance(TimeSpan.FromMinutes(2));
            await client.SendAsync(Message(90, 3, 50), Timeout()); // sent, then the re-exchange starts
            await serverPump.NextAsync();
            await client.SendAsync(Message(90, 4, 50), Timeout()); // waits for the re-exchange, then goes out under the new keys
            var after = await serverPump.NextAsync();
            await Assert.That(after.AsSpan().SequenceEqual(Message(90, 4, 50))).IsTrue();
            await Assert.That(client.KeyExchangeCount).IsEqualTo(2);
            await Assert.That(server.KeyExchangeCount).IsEqualTo(2);
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task ServerInitiatedRekey_WithDataInFlightBothWays()
    {
        var (client, server, clientPump, serverPump) = await StartAsync();
        await using (client)
        await using (server)
        {
            const int count = 300;
            var clientSender = Task.Run(async () =>
            {
                for (var i = 0; i < count; i++)
                {
                    await client.SendAsync(Message(90, i, 500), Timeout());
                    if (i == 100)
                    {
                        await Task.Yield();
                    }
                }
            });
            var serverSender = Task.Run(async () =>
            {
                for (var i = 0; i < count; i++)
                {
                    await server.SendAsync(Message(94, i, 500), Timeout());
                    if (i == 100)
                    {
                        await server.RekeyAsync(Timeout());
                    }
                }
            });

            await Task.WhenAll(clientSender, serverSender);
            for (var i = 0; i < count; i++)
            {
                await Assert.That((await serverPump.NextAsync()).AsSpan().SequenceEqual(Message(90, i, 500))).IsTrue();
                await Assert.That((await clientPump.NextAsync()).AsSpan().SequenceEqual(Message(94, i, 500))).IsTrue();
            }

            await WaitUntilAsync(() => client.KeyExchangeCount == 2 && server.KeyExchangeCount == 2);
            await Assert.That(clientPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task ManyRekeysUnderContinuousTraffic()
    {
        var (client, server, clientPump, serverPump) = await StartAsync(client: ClientOptions(rekeyBytes: 40_000));
        await using (client)
        await using (server)
        {
            const int count = 600;
            var senders = new[]
            {
                Task.Run(async () => { for (var i = 0; i < count; i++) { await client.SendAsync(Message(90, i, 800), Timeout()); } }),
                Task.Run(async () => { for (var i = 0; i < count; i++) { await server.SendAsync(Message(94, i, 800), Timeout()); } }),
                Task.Run(async () => { for (var i = 0; i < 8; i++) { await Task.Delay(20); await server.RekeyAsync(Timeout()); } }),
            };
            await Task.WhenAll(senders);

            for (var i = 0; i < count; i++)
            {
                await Assert.That((await serverPump.NextAsync()).AsSpan().SequenceEqual(Message(90, i, 800))).IsTrue();
                await Assert.That((await clientPump.NextAsync()).AsSpan().SequenceEqual(Message(94, i, 800))).IsTrue();
            }

            await WaitUntilAsync(() => client.KeyExchangeCount > 5 && client.KeyExchangeCount == server.KeyExchangeCount);
            await Assert.That(clientPump.Error).IsNull();
            await Assert.That(serverPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    public static IEnumerable<(string From, string To)> CipherChanges() =>
        SshAlgorithms.DefaultCiphers.Select((c, i) => (c, SshAlgorithms.DefaultCiphers[(i + 1) % SshAlgorithms.DefaultCiphers.Count]));

    [Test]
    [MethodDataSource(nameof(CipherChanges))]
    public async Task AlgorithmsMayChangeAcrossARekey(string from, string to)
    {
        var (client, server, clientPump, serverPump) = await StartAsync(new FakeServerOptions { Cipher = from, RekeyCipher = to });
        await using (client)
        await using (server)
        {
            await client.SendAsync(Message(90, 1, 100), Timeout());
            await serverPump.NextAsync();
            await server.RekeyAsync(Timeout());
            await server.SendAsync(Message(94, 2, 100), Timeout()); // gated until the exchange is done, then under the new cipher
            await clientPump.NextAsync();
            await client.SendAsync(Message(90, 3, 100), Timeout());
            await serverPump.NextAsync();

            await Assert.That(client.Algorithms!.CipherClientToServer).IsEqualTo(to);
            await Assert.That(client.Algorithms.StrictKex).IsTrue();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    [Arguments(SshAlgorithms.EcdhNistp256)]
    [Arguments(SshAlgorithms.EcdhNistp521)]
    [Arguments(SshAlgorithms.DhGroup14Sha256)]
    [Arguments(SshAlgorithms.DhGroup16Sha512)]
    public async Task TheKeyExchangeMethodMayChangeAcrossARekey(string rekeyKex)
    {
        var (client, server, clientPump, serverPump) = await StartAsync(new FakeServerOptions { RekeyKex = rekeyKex });
        await using (client)
        await using (server)
        {
            await server.RekeyAsync(Timeout());
            await server.SendAsync(Message(94, 1, 100), Timeout());
            await clientPump.NextAsync();
            await Assert.That(client.Algorithms!.Kex).IsEqualTo(rekeyKex);
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task NonStrictConnectionsRekeyToo_WithoutResettingSequenceNumbers()
    {
        var (client, server, clientPump, serverPump) = await StartAsync(new FakeServerOptions { AdvertiseStrictKex = false });
        await using (client)
        await using (server)
        {
            await Assert.That(client.Algorithms!.StrictKex).IsFalse();
            for (var round = 0; round < 3; round++)
            {
                await server.RekeyAsync(Timeout());
                await server.SendAsync(Message(94, round, 100), Timeout());
                await clientPump.NextAsync();
                await client.SendAsync(Message(90, round, 100), Timeout());
                await serverPump.NextAsync();
            }

            await WaitUntilAsync(() => client.KeyExchangeCount == 4);
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task AChangedHostKeyDuringARekeyIsRejected_AndBlockedSendsFail()
    {
        var (client, server, clientPump, serverPump) = await StartAsync(new FakeServerOptions { RekeyHostKey = FakeHostKey.Ed25519() });
        await using (client)
        await using (server)
        {
            await server.RekeyAsync(Timeout());
            await WaitUntilAsync(() => clientPump.Error is not null);
            var error = (SshException)clientPump.Error!;
            await Assert.That(error.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
            await Assert.That(error.Message).Contains("changed");

            // The connection cannot continue; senders that were waiting for the exchange fail instead of hanging.
            await Assert.That(async () => await client.SendAsync(Message(90, 1, 10), Timeout())).Throws<SshException>();
            await serverPump.StopAsync();
        }
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task IgnoreDuringARekeyIsAccepted_StrictKexOnlyPolicesTheInitialExchange(bool strict)
    {
        // OpenSSH PROTOCOL 1.10: unexpected messages are fatal during the initial KEX only (SshTransportTests covers that case).
        var (client, server, clientPump, serverPump) = await StartAsync(new FakeServerOptions { IgnoreDuringRekey = true, AdvertiseStrictKex = strict });
        await using (client)
        await using (server)
        {
            await server.RekeyAsync(Timeout());
            await server.SendAsync(Message(94, 1, 50), Timeout());
            await clientPump.NextAsync();
            await Assert.That(client.KeyExchangeCount).IsEqualTo(2);
            await Assert.That(clientPump.Error).IsNull();
            await clientPump.StopAsync();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task AGarbledReexchangeEndsTheConnection()
    {
        var (client, server, clientPump, serverPump) = await StartAsync();
        await using (client)
        await using (server)
        {
            await server.SendAsync(new byte[] { SshMessage.KexInit, 1, 2, 3 }); // a KEXINIT that cannot be parsed
            await WaitUntilAsync(() => clientPump.Error is not null);
            await Assert.That(clientPump.Error).IsTypeOf<SshProtocolException>();
            await serverPump.StopAsync();
        }
    }

    [Test]
    public async Task DisposingWhileSendsWaitForARekeyFailsThemCleanly()
    {
        // The server never reads, so the client's own re-exchange can never complete and its application sends queue up behind it.
        var fake = new FakeSshServer();
        var transport = new SshTransport(fake.ClientStream, ClientOptions(rekeyBytes: 100));
        var token = Timeout();
        var serverTask = fake.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;

        await transport.SendAsync(Message(90, 0, 200), Timeout()); // crosses the threshold: our KEXINIT goes out
        var blocked = transport.SendAsync(Message(90, 1, 10), Timeout()).AsTask();
        await Task.Delay(100);
        await Assert.That(blocked.IsCompleted).IsFalse();

        await transport.DisposeAsync();
        await Assert.That(async () => await blocked).Throws<SshException>();
        await fake.DisposeAsync();
    }

    [Test]
    public async Task ASendWaitingForARekeyHonoursCancellation()
    {
        var fake = new FakeSshServer();
        await using var transport = new SshTransport(fake.ClientStream, ClientOptions(rekeyBytes: 100));
        var token = Timeout();
        var serverTask = fake.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;

        await transport.SendAsync(Message(90, 0, 200), Timeout());
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.That(async () => await transport.SendAsync(Message(90, 1, 10), cts.Token)).Throws<OperationCanceledException>();
        await fake.DisposeAsync();
    }
}