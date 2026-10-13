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
