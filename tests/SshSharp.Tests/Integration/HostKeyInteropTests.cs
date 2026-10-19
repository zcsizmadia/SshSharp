using SshSharp.Config;

namespace SshSharp.Tests.Integration;

/// <summary>
/// known_hosts against the real server's key: a changed key and a revoked one are refused whatever the policy says, and the right one
/// is accepted. Needs SSHSHARP_TEST_SSHD and an account.
/// </summary>
[Category("Integration")]
public sealed class HostKeyInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-hki-" + Guid.NewGuid().ToString("N"));

    public HostKeyInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    [Test]
    public async Task AChangedOrRevokedKey_IsRefused_AndTheRightOneAccepted()
    {
        if (await RealServer.OptionsAsync() is not { } probe)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and an account are needed.");
            return;
        }

        var (host, port) = RealServer.Endpoint!.Value;
        SshHostKey real;
        await using (var first = await SshClient.ConnectAsync(host, port, probe, Timeout()))
        {
            real = first.HostKey;
        }

        var name = KnownHostsEntry.FormatHost(host, port);
        var line = $"{name} {real.KeyType} {Convert.ToBase64String(real.PublicKey.Span)}\n";

        async Task<SshClient> ConnectAsync(StrictHostKeyChecking policy)
        {
            var options = (await RealServer.OptionsAsync(new KnownHostsVerifier([KnownHosts]) { Policy = policy }))!;
            return await SshClient.ConnectAsync(host, port, options, Timeout());
        }

        // The same key type with different bytes: "host key changed", refused under every policy but No.
        var forged = real.PublicKey.ToArray();
        forged[^1] ^= 0xFF;
        await File.WriteAllTextAsync(KnownHosts, $"{name} {real.KeyType} {Convert.ToBase64String(forged)}\n");
        foreach (var policy in new[] { StrictHostKeyChecking.Yes, StrictHostKeyChecking.AcceptNew, StrictHostKeyChecking.Ask })
        {
            var error = await Assert.ThrowsAsync<SshHostKeyException>(() => ConnectAsync(policy));
            await Assert.That(error!.Message).Contains("changed");
            await Assert.That(error.HostKey!.Fingerprint).IsEqualTo(real.Fingerprint);
        }

        // Revoked: refused even under No.
        await File.WriteAllTextAsync(KnownHosts, line + $"@revoked {name} {real.KeyType} {Convert.ToBase64String(real.PublicKey.Span)}\n");
        var revoked = await Assert.ThrowsAsync<SshHostKeyException>(() => ConnectAsync(StrictHostKeyChecking.No));
        await Assert.That(revoked!.Message).Contains("revoked");

        // The real key: accepted under Yes.
        await File.WriteAllTextAsync(KnownHosts, line);
        await using var client = await ConnectAsync(StrictHostKeyChecking.Yes);
        await Assert.That(client.HostKey.Fingerprint).IsEqualTo(real.Fingerprint);
    }
}
