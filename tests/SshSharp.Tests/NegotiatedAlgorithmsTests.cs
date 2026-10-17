using Microsoft.Extensions.Logging;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary><see cref="SshClient.Algorithms"/>: what was negotiated, and whether the key exchange is post-quantum (#96).</summary>
public class NegotiatedAlgorithmsTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, ILogger? logger = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Logger = logger,
        }, leaveOpen: true, Timeout());
    }

    /// <summary>Collects log messages.</summary>
    private sealed class ListLogger : ILogger
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception));
            }
        }
    }

    [Test]
    public async Task AClassicKeyExchange_IsNotPostQuantum_AndSaysSoInTheLog()
    {
        var logger = new ListLogger();
        await using var server = new FakeSessionServer(new FakeServerOptions { Kex = SshAlgorithms.Curve25519Sha256 });
        await using var client = await ConnectAsync(server, logger);

        var algorithms = client.Algorithms;
        await Assert.That(algorithms.KeyExchange).IsEqualTo("curve25519-sha256");
        await Assert.That(algorithms.IsPostQuantum).IsFalse();
        await Assert.That(algorithms.HostKeyAlgorithm).IsEqualTo("ssh-ed25519");
        await Assert.That(algorithms.StrictKeyExchange).IsTrue();
        await Assert.That(logger.Messages.Any(m => m.Contains("is not post-quantum", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task TheMlKemHybrid_IsPostQuantum_AndTheLogStaysQuiet()
    {
        if (!SshAlgorithms.HasMlKem)
        {
            Skip.Test("This platform has no ML-KEM (it needs .NET 10 with OpenSSL 3.5+ or a recent Windows).");
            return;
        }

        var logger = new ListLogger();
        await using var server = new FakeSessionServer(new FakeServerOptions { Kex = SshAlgorithms.MlKem768X25519Sha256 });
        await using var client = await ConnectAsync(server, logger);

        await Assert.That(client.Algorithms.KeyExchange).IsEqualTo("mlkem768x25519-sha256");
        await Assert.That(client.Algorithms.IsPostQuantum).IsTrue();
        await Assert.That(logger.Messages.Any(m => m.Contains("post-quantum", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    [Arguments("chacha20-poly1305@openssh.com", "")]
    [Arguments("aes256-gcm@openssh.com", "")]
    [Arguments("aes256-ctr", "hmac-sha2-256-etm@openssh.com")]
    public async Task AnAeadCipherReportsNoMac_OthersReportTheirs(string cipher, string expectedMac)
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { Cipher = cipher, Mac = "hmac-sha2-256-etm@openssh.com" });
        await using var client = await ConnectAsync(server);
        var algorithms = client.Algorithms;
        await Assert.That(algorithms.EncryptionClientToServer).IsEqualTo(cipher);
        await Assert.That(algorithms.EncryptionServerToClient).IsEqualTo(cipher);
        await Assert.That(algorithms.MacClientToServer).IsEqualTo(expectedMac);
        await Assert.That(algorithms.MacServerToClient).IsEqualTo(expectedMac);
    }

    /// <summary>
    /// A server that offers only a plain (encrypt-and-MAC) HMAC with AES-CTR, as network equipment often does (#268): the client connects
    /// with its defaults, authenticates and runs a command, so many packets in both directions carry the plain MAC.
    /// </summary>
    [Test]
    [Arguments("aes128-ctr", "hmac-sha2-256")]
    [Arguments("aes256-ctr", "hmac-sha2-512")]
    public async Task APlainHmacSha2_ConnectsAndCarriesASession(string cipher, string mac)
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { Cipher = cipher, Mac = mac });
        await using var client = await ConnectAsync(server);
        await Assert.That(client.Algorithms.EncryptionClientToServer).IsEqualTo(cipher);
        await Assert.That(client.Algorithms.MacClientToServer).IsEqualTo(mac);
        await Assert.That(client.Algorithms.MacServerToClient).IsEqualTo(mac);

        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task AKeyReexchange_IsReflected()
    {
        await using var server = new FakeSessionServer(new FakeServerOptions { Cipher = "chacha20-poly1305@openssh.com", RekeyCipher = "aes256-gcm@openssh.com" });
        await using var client = await ConnectAsync(server);
        await Assert.That(client.Algorithms.EncryptionClientToServer).IsEqualTo("chacha20-poly1305@openssh.com");

        // The client takes the server's KEXINIT on its receive loop; wait until the server has counted the finished exchange.
        await server.Raw.RekeyAsync(Timeout());
        var token = Timeout();
        while (server.Raw.KeyExchangeCount < 2)
        {
            await Task.Delay(10, token);
        }

        await Assert.That(client.Algorithms.EncryptionClientToServer).IsEqualTo("aes256-gcm@openssh.com");
    }
}
