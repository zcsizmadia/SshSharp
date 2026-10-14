using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>mlkem768x25519-sha256: offered first where the platform has ML-KEM, never in FIPS mode, and good for rekeys too.</summary>
public class MlKemKexTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Test]
    public async Task TheHybrid_LeadsTheDefaults_OnlyWherePlatformHasMlKem()
    {
        var defaults = new AlgorithmPreferences().Kex;
        if (SshAlgorithms.HasMlKem)
        {
            await Assert.That(defaults[0]).IsEqualTo(SshAlgorithms.MlKem768X25519Sha256);
        }
        else
        {
            await Assert.That(defaults).DoesNotContain(SshAlgorithms.MlKem768X25519Sha256);
        }

        await Assert.That(SshAlgorithms.FilterFips(defaults, AlgorithmKind.Kex)).DoesNotContain(SshAlgorithms.MlKem768X25519Sha256);
    }

    [Test]
    public async Task TheNistHybrids_FollowIt_AndLeadFipsMode_WherePlatformHasMlKem()
    {
        var defaults = new AlgorithmPreferences().Kex;
        var fips = AlgorithmPreferences.Fips().Kex;
        if (!SshAlgorithms.HasMlKem)
        {
            await Assert.That(defaults).DoesNotContain(SshAlgorithms.MlKem768Nistp256Sha256);
            await Assert.That(fips).DoesNotContain(SshAlgorithms.MlKem1024Nistp384Sha384);
            return;
        }

        await Assert.That(defaults.Take(3)).IsEquivalentTo(new[]
        {
            SshAlgorithms.MlKem768X25519Sha256, SshAlgorithms.MlKem768Nistp256Sha256, SshAlgorithms.MlKem1024Nistp384Sha384,
        });

        // FIPS mode had no post-quantum key exchange before (X25519 is not FIPS-approved); now the NIST hybrids lead it.
        await Assert.That(fips[0]).IsEqualTo(SshAlgorithms.MlKem768Nistp256Sha256);
        await Assert.That(fips[1]).IsEqualTo(SshAlgorithms.MlKem1024Nistp384Sha384);
        await Assert.That(SshAlgorithms.IsPostQuantum(fips[0])).IsTrue();
    }

    [Test]
    [Arguments("mlkem768nistp256-sha256")]
    [Arguments("mlkem1024nistp384-sha384")]
    public async Task TheNistHybrids_Handshake_RunCommands_AndRekey(string kex)
    {
        if (!SshAlgorithms.HasMlKem)
        {
            Skip.Test("This platform has no ML-KEM (it needs .NET 10 with OpenSSL 3.5+ or a recent Windows).");
            return;
        }

        await using var server = new FakeSessionServer(new FakeServerOptions { Kex = kex });
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            AlgorithmPreferences = new AlgorithmPreferences { Kex = [kex] },
            RekeyAfterBytes = 64 * 1024,
        }, leaveOpen: true, Timeout());

        await Assert.That(client.Algorithms.KeyExchange).IsEqualTo(kex);
        await Assert.That(client.Algorithms.IsPostQuantum).IsTrue();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(new byte[96 * 1024]);
            await script.FinishAsync(0);
        };
        for (var round = 0; round < 3; round++)
        {
            var result = await client.RunCommandAsync("cat big", Timeout());
            await Assert.That(result.StandardOutput.Length).IsEqualTo(96 * 1024);
        }

        await Assert.That(server.Raw.KeyExchangeCount).IsGreaterThan(2);
    }

    [Test]
    [Arguments("mlkem768nistp256-sha256", "short")]
    [Arguments("mlkem768nistp256-sha256", "compressed")]
    [Arguments("mlkem768nistp256-sha256", "off-curve")]
    [Arguments("mlkem1024nistp384-sha384", "short")]
    [Arguments("mlkem1024nistp384-sha384", "off-curve")]
    public async Task AMalformedNistHybridReply_IsRefused(string kex, string damage)
    {
        if (!SshAlgorithms.HasMlKem)
        {
            Skip.Test("This platform has no ML-KEM (it needs .NET 10 with OpenSSL 3.5+ or a recent Windows).");
            return;
        }

        var (ciphertextSize, fieldSize) = kex == SshAlgorithms.MlKem768Nistp256Sha256 ? (1088, 32) : (1568, 48);
        var serverReply = new byte[ciphertextSize + 1 + (2 * fieldSize)];
        serverReply[ciphertextSize] = 4;
        serverReply[^1] = 7; // (0, ..., 7) is not a point on either curve
        serverReply = damage switch
        {
            "short" => serverReply[..^1],
            "compressed" => [.. serverReply[..ciphertextSize], 2, .. new byte[fieldSize], .. new byte[fieldSize]],
            _ => serverReply,
        };

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        var writer = new SshWriter(buffer);
        writer.WriteByte(SshMessage.KexEcdhReply);
        writer.WriteString(new byte[] { 0, 0, 0, 1, 0x78 }); // K_S: not looked at before the reply is validated
        writer.WriteString(serverReply);
        writer.WriteString(new byte[] { 0 });

        using var exchange = ClientKeyExchange.Create(kex);
        var context = new KexContext("SSH-2.0-client", "SSH-2.0-server", [20], [20]);
        var error = Assert.Throws<SshException>(() => exchange.ProcessReply(buffer.WrittenSpan, context));
        if (damage == "off-curve")
        {
            await Assert.That(error).IsNotTypeOf<SshProtocolException>();
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        }
        else
        {
            await Assert.That(error).IsTypeOf<SshProtocolException>();
        }
    }

    [Test]
    public async Task TheHybrid_Handshakes_AndRekeys_WithDataInFlight()
    {
        if (!SshAlgorithms.HasMlKem)
        {
            Skip.Test("This platform has no ML-KEM (it needs .NET 10 with OpenSSL 3.5+ or a recent Windows).");
            return;
        }

        var options = new FakeServerOptions { Kex = SshAlgorithms.MlKem768X25519Sha256 };
        await using var server = new FakeSessionServer(options);
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            RekeyAfterBytes = 64 * 1024, // several key re-exchanges over the hybrid during the command
        }, leaveOpen: true, Timeout());

        server.OnExec = async script =>
        {
            for (var i = 0; i < 3; i++)
            {
                await script.StdoutAsync(new byte[32 * 1024]);
            }

            await script.FinishAsync(0);
        };

        // Each command moves more than the 64 KiB limit, so each starts a re-exchange. The next command's channel open waits for that
        // exchange to finish, so the count does not depend on how the data and the re-exchange interleave (which made one long transfer
        // flaky on slower runners).
        for (var round = 0; round < 4; round++)
        {
            var result = await client.RunCommandAsync("cat big", Timeout());
            await Assert.That(result.StandardOutput.Length).IsEqualTo(3 * 32 * 1024);
        }

        await Assert.That(server.Raw.KeyExchangeCount).IsGreaterThan(2);
        await Assert.That(server.Raw.Negotiated!.Kex).IsEqualTo(SshAlgorithms.MlKem768X25519Sha256);
    }
}
