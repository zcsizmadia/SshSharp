using System.Net;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Dynamic forwarding with a SOCKS 5 password, through a real server: a second SSH connection goes through the authenticated proxy to
/// the server's own sshd. Needs SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR.
/// </summary>
public class SocksAuthenticationInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>The proxy's credentials, made for the test run: never written in the source.</summary>
    private static readonly NetworkCredential ProxyCredentials = new("socks-" + Guid.NewGuid().ToString("N")[..8], Guid.NewGuid().ToString("N"));

    private static async Task<SshClientOptions?> OptionsAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is null || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadAsync(keyFile) : null;
        return new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
    }

    /// <summary>The port sshd listens on inside the server's own network: 22 in the containers, the published port on the runner.</summary>
    private static int ServerSidePort => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD_INNER_PORT") is { } inner
        ? int.Parse(inner, System.Globalization.CultureInfo.InvariantCulture)
        : RealServer.Endpoint!.Value.Port;

    [Test]
    public async Task ASecondConnection_GoesThroughTheAuthenticatedProxy()
    {
        if (await OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        var (host, port) = RealServer.Endpoint!.Value;
        await using var first = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var socks = await first.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), ProxyCredentials, Timeout());

        // SshSharp's SOCKS 5 client authenticates (RFC 1929); "localhost" is resolved by the server.
        var proxied = new SshClientOptions
        {
            UserName = options.UserName,
            Password = options.Password,
            PrivateKeys = options.PrivateKeys,
            HostKeyVerifier = options.HostKeyVerifier,
            Proxy = SshProxy.Socks5("127.0.0.1", socks.LocalEndPoint.Port, ProxyCredentials),
        };
        await using var second = await SshClient.ConnectAsync("localhost", ServerSidePort, proxied, Timeout());
        await Assert.That(second.IsConnected).IsTrue();
        await Assert.That(second.ServerIdentification).StartsWith("SSH-2.0-");

        // The wrong password is refused before anything reaches the server.
        var wrong = SshProxy.Socks5("127.0.0.1", socks.LocalEndPoint.Port, new NetworkCredential(ProxyCredentials.UserName, "not-" + ProxyCredentials.Password));
        var error = await Assert.ThrowsAsync<SshException>(async () => await wrong.ConnectAsync("localhost", ServerSidePort, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
    }
}
