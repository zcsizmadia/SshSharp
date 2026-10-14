using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>sntrup761x25519-sha512: offered on every platform after the ML-KEM hybrids, never in FIPS mode, and good for rekeys.</summary>
public class SntrupKexTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Test]
    public async Task ItIsOfferedEverywhere_AfterMlKem_BeforeTheClassicMethods_ButNotInFipsMode()
    {
        var defaults = new AlgorithmPreferences().Kex.ToList();
        var index = defaults.IndexOf(SshAlgorithms.Sntrup761X25519Sha512);
        await Assert.That(index).IsEqualTo(SshAlgorithms.HasMlKem ? 3 : 0);
        await Assert.That(defaults[index + 1]).IsEqualTo(SshAlgorithms.Sntrup761X25519Sha512OpenSsh);
        await Assert.That(defaults[index + 2]).IsEqualTo(SshAlgorithms.Curve25519Sha256);
        await Assert.That(SshAlgorithms.IsPostQuantum(SshAlgorithms.Sntrup761X25519Sha512)).IsTrue();
        await Assert.That(SshAlgorithms.IsPostQuantum(SshAlgorithms.Sntrup761X25519Sha512OpenSsh)).IsTrue();
        await Assert.That(AlgorithmPreferences.Fips().Kex).DoesNotContain(SshAlgorithms.Sntrup761X25519Sha512);
        await Assert.That(SshAlgorithms.FilterFips(defaults, AlgorithmKind.Kex)).DoesNotContain(SshAlgorithms.Sntrup761X25519Sha512OpenSsh);
    }

    [Test]
    [Arguments("sntrup761x25519-sha512")]
    [Arguments("sntrup761x25519-sha512@openssh.com")]
    public async Task ItHandshakes_RunsCommands_AndRekeys(string kex)
    {
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
    [Arguments("short")]
    [Arguments("long")]
    [Arguments("low-order")]
    public async Task AMalformedReply_IsRefused(string damage)
    {
        var serverReply = new byte[Sntrup761.CiphertextSize + 32]; // an all-zero X25519 share is a low-order point
        serverReply = damage switch
        {
            "short" => serverReply[..^1],
            "long" => [.. serverReply, 0],
            _ => serverReply,
        };

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        var writer = new SshWriter(buffer);
        writer.WriteByte(SshMessage.KexEcdhReply);
        writer.WriteString(new byte[] { 0, 0, 0, 1, 0x78 }); // K_S: not looked at before the reply is validated
        writer.WriteString(serverReply);
        writer.WriteString(new byte[] { 0 });

        using var exchange = ClientKeyExchange.Create(SshAlgorithms.Sntrup761X25519Sha512);
        var context = new KexContext("SSH-2.0-client", "SSH-2.0-server", [20], [20]);
        var error = Assert.Throws<SshException>(() => exchange.ProcessReply(buffer.WrittenSpan, context));
        if (damage == "low-order")
        {
            await Assert.That(error).IsNotTypeOf<SshProtocolException>();
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        }
        else
        {
            await Assert.That(error).IsTypeOf<SshProtocolException>();
        }
    }
}
