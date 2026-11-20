namespace SshSharp.Tests.Integration;

/// <summary>
/// Channel types and global requests a real server does not know (<see cref="SshClient.OpenChannelAsync"/>,
/// <see cref="SshClient.SendGlobalRequestAsync"/>): each server must refuse them and keep the connection, as RFC 4254 requires.
/// </summary>
[Category("Integration")]
public class CustomChannelInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Test]
    public async Task UnknownChannelTypesAndGlobalRequests_AreRefused_AndTheConnectionStaysUp()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR are needed.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());

        var refused = await client.SendGlobalRequestAsync("sshsharp-interop-test@example.com", new byte[] { 0, 0, 0, 1, 42 }, Timeout());
        await Assert.That(refused.Success).IsFalse();

        var error = await Assert.ThrowsAsync<SshException>(() => client.OpenChannelAsync("sshsharp-interop-test@example.com", new byte[] { 0, 0, 0, 0 }, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);

        await client.PingAsync(Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }
}
