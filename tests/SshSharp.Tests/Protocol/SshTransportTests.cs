using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class SshTransportTests
{
    private static readonly FakeHostKey SharedRsa = FakeHostKey.Rsa(2048);

    private static SshTransportOptions Accepting(Action<HostKeyInfo>? seen = null, AlgorithmPreferences? preferences = null) => new()
    {
        Preferences = preferences ?? new AlgorithmPreferences(),
        VerifyHostKey = (info, _) =>
        {
            seen?.Invoke(info);
            return ValueTask.FromResult(true);
        },
    };

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    private static async Task<(SshTransport Transport, FakeSshServer Server)> Connect(FakeServerOptions? serverOptions = null, SshTransportOptions? clientOptions = null)
    {
        var server = new FakeSshServer(serverOptions);
        var transport = new SshTransport(server.ClientStream, clientOptions ?? Accepting());
        var token = Timeout();
        var serverTask = server.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;
        return (transport, server);
    }

    /// <summary>Runs a handshake that is expected to fail on the client and returns the client's exception.</summary>
    private static async Task<Exception> ConnectFails(FakeServerOptions serverOptions, SshTransportOptions? clientOptions = null)
    {
        await using var server = new FakeSshServer(serverOptions);
        await using var transport = new SshTransport(server.ClientStream, clientOptions ?? Accepting());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serverTask = server.StartAsync(cts.Token);
        try
        {
            await transport.ConnectAsync(cts.Token);
        }
        catch (Exception ex)
        {
            await server.CloseAsync();
            try
            {
                await serverTask;
            }
            catch (Exception)
            {
                // The server may fail too once the client has gone; only the client's error matters here.
            }

            return ex;
        }

        throw new InvalidOperationException("The handshake was expected to fail but succeeded.");
    }

    public static IEnumerable<string> Ciphers() => SshAlgorithms.DefaultCiphers;

    // mlkem768x25519-sha256 only where the platform has ML-KEM (.NET 10 with OpenSSL 3.5+ or a recent Windows).
    public static IEnumerable<string> KexMethods() =>
    [
        .. SshAlgorithms.HasMlKem ? [SshAlgorithms.MlKem768X25519Sha256] : Array.Empty<string>(),
        SshAlgorithms.Curve25519Sha256, SshAlgorithms.Curve25519Sha256Libssh, SshAlgorithms.EcdhNistp256, SshAlgorithms.EcdhNistp384,
        SshAlgorithms.EcdhNistp521, SshAlgorithms.DhGroup14Sha256, SshAlgorithms.DhGroup16Sha512,
    ];

    public static IEnumerable<string> HostKeyKinds() => ["ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa-sha2-512", "rsa-sha2-256"];

    private static (FakeHostKey Key, string[] Preferred) HostKeyFor(string kind) => kind switch
    {
        "ed25519" => (FakeHostKey.Ed25519(), [SshAlgorithms.SshEd25519]),
        "ecdsa256" => (FakeHostKey.Ecdsa(256), [SshAlgorithms.EcdsaNistp256]),
        "ecdsa384" => (FakeHostKey.Ecdsa(384), [SshAlgorithms.EcdsaNistp384]),
        "ecdsa521" => (FakeHostKey.Ecdsa(521), [SshAlgorithms.EcdsaNistp521]),
        "rsa-sha2-512" => (SharedRsa, [SshAlgorithms.RsaSha2_512]),
        _ => (SharedRsa, [SshAlgorithms.RsaSha2_256]),
    };

    [Test]
    [MethodDataSource(nameof(Ciphers))]
    public async Task EveryCipher_HandshakesAndCarriesTrafficBothWays(string cipher)
    {
        var (transport, server) = await Connect(new FakeServerOptions { Cipher = cipher }, Accepting(preferences: new AlgorithmPreferences { Ciphers = [cipher] }));
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.Algorithms!.CipherClientToServer).IsEqualTo(cipher);
            var rng = new Random(61);
            var token = Timeout();
            foreach (var size in new[] { 1, 2, 15, 16, 17, 100, 1000, 30000 })
            {
                var upstream = new byte[size];
                rng.NextBytes(upstream);
                upstream[0] = 90;
                await transport.SendAsync(upstream, token);
                using var received = await server.ReceiveAsync(token);
                await Assert.That(Convert.ToHexString(received.Payload.Span)).IsEqualTo(Convert.ToHexString(upstream));

                var downstream = new byte[size];
                rng.NextBytes(downstream);
                downstream[0] = 94;
                await server.SendAsync(downstream, token);
                using var back = await transport.ReceiveAsync(token);
                await Assert.That(Convert.ToHexString(back.Payload.Span)).IsEqualTo(Convert.ToHexString(downstream));
            }
        }
    }

    [Test]
    [MethodDataSource(nameof(KexMethods))]
    public async Task EveryKex_Handshakes(string kex)
    {
        var (transport, server) = await Connect(new FakeServerOptions { Kex = kex }, Accepting(preferences: new AlgorithmPreferences { Kex = [kex] }));
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.Algorithms!.Kex).IsEqualTo(kex);
            await Assert.That(Convert.ToHexString(transport.SessionId!)).IsEqualTo(Convert.ToHexString(server.SessionId!));
        }
    }

    [Test]
    [MethodDataSource(nameof(HostKeyKinds))]
    public async Task EveryHostKeyType_IsVerifiedAndHandedToTheTrustCallback(string kind)
    {
        var (key, preferred) = HostKeyFor(kind);
        HostKeyInfo? seen = null;
        var (transport, server) = await Connect(
            new FakeServerOptions { HostKey = key },
            Accepting(info => seen = info, new AlgorithmPreferences { HostKeys = preferred }));
        await using (transport)
        await using (server)
        {
            await Assert.That(seen).IsNotNull();
            await Assert.That(seen!.Fingerprint).IsEqualTo(key.Fingerprint);
            await Assert.That(seen.KeyType).IsEqualTo(key.KeyType);
            await Assert.That(seen.Algorithm).IsEqualTo(preferred[0]);
            await Assert.That(Convert.ToHexString(seen.Blob.Span)).IsEqualTo(Convert.ToHexString(key.Blob));
            await Assert.That(transport.HostKey).IsEqualTo(seen);
        }
    }

    [Test]
    public async Task StrictKex_IsNegotiated_AndNonStrictServersStillWork()
    {
        var (strict, strictServer) = await Connect();
        await using (strict)
        await using (strictServer)
        {
            await Assert.That(strict.Algorithms!.StrictKex).IsTrue();
            await Assert.That(strict.ServerExtensions.ContainsKey("server-sig-algs")).IsFalse(); // arrives with the first receive
            await strictServer.SendAsync(new byte[] { 99, 1 });
            using var packet = await strict.ReceiveAsync(Timeout());
            await Assert.That(strict.ServerExtensions["server-sig-algs"]).Contains("ssh-ed25519");
        }

        var (plain, plainServer) = await Connect(new FakeServerOptions { AdvertiseStrictKex = false });
        await using (plain)
        await using (plainServer)
        {
            await Assert.That(plain.Algorithms!.StrictKex).IsFalse();
            await plainServer.SendAsync(new byte[] { 99, 7 });
            using var packet = await plain.ReceiveAsync(Timeout());
            await Assert.That(packet.Payload.Span[1]).IsEqualTo((byte)7);
        }
    }

    [Test]
    public async Task StrictKex_RejectsPacketsInjectedBeforeKexInit_ButNonStrictAllowsThem()
    {
        var injected = await ConnectFails(new FakeServerOptions { IgnoresBeforeKexInit = 1 });
        await Assert.That(injected).IsTypeOf<SshProtocolException>();
        await Assert.That(injected.Message).Contains("first packet");

        var (transport, server) = await Connect(new FakeServerOptions { IgnoresBeforeKexInit = 2, AdvertiseStrictKex = false });
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.Algorithms!.StrictKex).IsFalse();
        }
    }

    [Test]
    public async Task StrictKex_RejectsPacketsInsideTheKeyExchange_ButNonStrictAllowsThem()
    {
        var injected = await ConnectFails(new FakeServerOptions { IgnoreDuringKex = true });
        await Assert.That(injected).IsTypeOf<SshProtocolException>();

        var (transport, server) = await Connect(new FakeServerOptions { IgnoreDuringKex = true, AdvertiseStrictKex = false });
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.SessionId).IsNotNull();
        }
    }

    [Test]
    public async Task RejectsABadHostKeySignature()
    {
        var error = await ConnectFails(new FakeServerOptions { CorruptSignature = true });
        await Assert.That(error).IsTypeOf<SshException>();
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(error.Message).Contains("signature");
    }

    [Test]
    public async Task RejectsAHostKeyOfTheWrongTypeForTheNegotiatedAlgorithm()
    {
        var error = await ConnectFails(new FakeServerOptions { HostKey = SharedRsa, HostKeyAlgorithm = SshAlgorithms.SshEd25519 });
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(error.Message).Contains("ssh-rsa");
    }

    [Test]
    public async Task RejectsWeakRsaHostKeys_UnlessThePolicyAllowsThem()
    {
        var weak = FakeHostKey.Rsa(1024);
        var error = await ConnectFails(new FakeServerOptions { HostKey = weak });
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(error.Message).Contains("1024");

        var relaxed = new SshTransportOptions { VerifyHostKey = (_, _) => ValueTask.FromResult(true), MinimumRsaBits = 1024, Preferences = new AlgorithmPreferences { HostKeys = [SshAlgorithms.RsaSha2_512] } };
        var (transport, server) = await Connect(new FakeServerOptions { HostKey = weak }, relaxed);
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.HostKey!.KeySizeBits).IsEqualTo(1024);
        }
    }

    [Test]
    public async Task AnUntrustedHostKeyAbortsTheConnection()
    {
        HostKeyInfo? asked = null;
        var options = new SshTransportOptions
        {
            VerifyHostKey = (info, _) =>
            {
                asked = info;
                return ValueTask.FromResult(false);
            },
        };
        var error = await ConnectFails(new FakeServerOptions(), options);
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(error.Message).Contains(asked!.Fingerprint);
    }

    [Test]
    public async Task ServerDisconnectDuringKex_SurfacesItsDescription()
    {
        var error = await ConnectFails(new FakeServerOptions { DisconnectInsteadOfReply = "go away" });
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        await Assert.That(error.Message).Contains("go away");
    }

    [Test]
    public async Task ServerClosingTheConnection_IsReported()
    {
        var error = await ConnectFails(new FakeServerOptions { CloseAfterKexInit = true });
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
    }

    [Test]
    public async Task BannerLinesBeforeTheIdentificationAreSkipped()
    {
        var (transport, server) = await Connect(new FakeServerOptions { BannerLines = ["Welcome to the test server", "Authorized use only"], Identification = "SSH-2.0-Fake comment" });
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.ServerIdentification!.SoftwareVersion).IsEqualTo("Fake");
            await Assert.That(transport.ServerIdentification.Comments).IsEqualTo("comment");
            await Assert.That(server.ClientIdentification!.Line).StartsWith("SSH-2.0-SshSharp_");
        }
    }

    [Test]
    public async Task AWronglyGuessedFirstPacketIsDiscarded()
    {
        var (transport, server) = await Connect(new FakeServerOptions { WrongGuess = true });
        await using (transport)
        await using (server)
        {
            await Assert.That(transport.Algorithms!.ServerGuessedWrong).IsTrue();
            await Assert.That(transport.Algorithms.Kex).IsEqualTo(SshAlgorithms.Curve25519Sha256);
        }
    }

    [Test]
    public async Task ConnectWaitsForTheServer_AndHonoursCancellation()
    {
        await using var server = new FakeSshServer(new FakeServerOptions { SilentOnConnect = true });
        await using var transport = new SshTransport(server.ClientStream, Accepting());
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.That(async () => await transport.ConnectAsync(cts.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task NoMatchingAlgorithms_FailsWithKeyExchangeFailed()
    {
        var options = Accepting(preferences: new AlgorithmPreferences { Ciphers = ["aes128-ctr"] });
        var error = await ConnectFails(new FakeServerOptions { Cipher = "aes256-ctr" }, options);
        await Assert.That(((SshException)error).Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
    }

    [Test]
    public async Task ReceiveSkipsHousekeepingMessages_AndReturnsApplicationMessages()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            await server.SendAsync(FakeSshServer.IgnorePayload());
            await server.SendAsync(new byte[] { SshMessage.Debug, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            await server.SendAsync(new byte[] { SshMessage.Unimplemented, 0, 0, 0, 5 });
            await server.SendAsync(new byte[] { 94, 1, 2, 3 });

            using var packet = await transport.ReceiveAsync(Timeout());
            await Assert.That(Convert.ToHexString(packet.Payload.Span)).IsEqualTo("5E010203");
            await Assert.That(transport.ServerExtensions.ContainsKey("server-sig-algs")).IsTrue();
        }
    }

    [Test]
    public async Task ReceiveRaisesOnDisconnect_AndOnUnsupportedRekey()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            await server.SendAsync(FakeSshServer.DisconnectPayload("maintenance"));
            var error = await Assert.ThrowsAsync<SshException>(async () => { using var _ = await transport.ReceiveAsync(Timeout()); });
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
            await Assert.That(error.Message).Contains("maintenance");
        }

        var (second, secondServer) = await Connect();
        await using (second)
        await using (secondServer)
        {
            // A malformed DISCONNECT still ends the connection, with a generic message.
            await secondServer.SendAsync(new byte[] { SshMessage.Disconnect, 0 });
            var malformed = await Assert.ThrowsAsync<SshException>(async () => { using var _ = await second.ReceiveAsync(Timeout()); });
            await Assert.That(malformed!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        }

        var (third, thirdServer) = await Connect();
        await using (third)
        await using (thirdServer)
        {
            await thirdServer.SendAsync(new byte[] { SshMessage.KexInit, 0 });
            var rekey = await Assert.ThrowsAsync<SshException>(async () => { using var _ = await third.ReceiveAsync(Timeout()); });
            await Assert.That(rekey!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        }
    }

    [Test]
    public async Task EmptyAndCorruptPacketsAreProtocolErrors()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            await server.SendAsync(ReadOnlyMemory<byte>.Empty);
            await Assert.That(async () => { using var _ = await transport.ReceiveAsync(Timeout()); }).Throws<SshProtocolException>();
        }

        var (second, secondServer) = await Connect();
        await using (second)
        await using (secondServer)
        {
            await secondServer.WriteRawAsync(new byte[64]); // garbage that cannot authenticate
            await Assert.That(async () => { using var _ = await second.ReceiveAsync(Timeout()); }).Throws<SshProtocolException>();
        }
    }

    [Test]
    public async Task ServerHangingUp_EndsReceiveWithConnectionClosed()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            await server.CloseAsync();
            var error = await Assert.ThrowsAsync<SshException>(async () => { using var _ = await transport.ReceiveAsync(Timeout()); });
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        }
    }

    [Test]
    public async Task DisconnectAsync_TellsTheServer()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            await transport.DisconnectAsync(DisconnectReason.ByApplication, "bye", Timeout());
            using var packet = await server.ReceiveAsync(Timeout());
            await Assert.That(packet.Payload.Span[0]).IsEqualTo(SshMessage.Disconnect);
            await Assert.That(System.Text.Encoding.UTF8.GetString(packet.Payload.Span[9..12])).IsEqualTo("bye");
        }
    }

    [Test]
    public async Task ApiMisuseIsReported()
    {
        var (transport, server) = await Connect();
        await using (server)
        {
            await Assert.That(async () => await transport.ConnectAsync(Timeout())).Throws<InvalidOperationException>();
            await transport.DisposeAsync();
            await transport.DisposeAsync(); // idempotent
            await transport.DisconnectAsync(DisconnectReason.ByApplication, "late"); // no-op after dispose
            await Assert.That(async () => await transport.ConnectAsync(Timeout())).Throws<ObjectDisposedException>();
            await Assert.That(async () => await transport.SendAsync(new byte[] { 1 })).Throws<ObjectDisposedException>();
            await Assert.That(async () => { using var _ = await transport.ReceiveAsync(); }).Throws<ObjectDisposedException>();
        }

        await Assert.That(() => new SshTransport(null!, Accepting())).Throws<ArgumentNullException>();
        await Assert.That(() => new SshTransport(Stream.Null, null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task ReceiveHonoursCancellation()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.That(async () => { using var _ = await transport.ReceiveAsync(cts.Token); }).Throws<OperationCanceledException>();
        }
    }

    [Test]
    public async Task ManyMessagesInFlight_KeepTheSequenceInStep()
    {
        var (transport, server) = await Connect();
        await using (transport)
        await using (server)
        {
            var token = Timeout();
            const int count = 300;
            var senders = Enumerable.Range(0, count).Select(async i =>
            {
                await transport.SendAsync(new byte[] { 90, (byte)(i % 251) }, token);
            });
            await Task.WhenAll(senders);

            for (var i = 0; i < count; i++)
            {
                using var packet = await server.ReceiveAsync(token);
                await Assert.That(packet.Payload.Span[0]).IsEqualTo((byte)90);
            }
        }
    }
}