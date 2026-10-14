namespace SshSharp.Tests.Integration;

/// <summary><see cref="SshClient.ScanHostKeysAsync(string, int, SshHostKeyScanOptions?, CancellationToken)"/> against a real server (#116).</summary>
public class HostKeyScanInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    [Test]
    public async Task TheScan_FindsTheKeyAConnectionVerifies_AndEachKeyTypeOnce()
    {
        if (RealServer.Endpoint is not { } endpoint)
        {
            Skip.Test("No real server configured.");
            return;
        }

        var keys = await SshClient.ScanHostKeysAsync(endpoint.Host, endpoint.Port, cancellationToken: Timeout());

        await Assert.That(keys).IsNotEmpty();
        await Assert.That(keys.Select(k => k.KeyType).Distinct().Count()).IsEqualTo(keys.Count);

        // Asking for one type again finds the same key.
        var first = keys[0];
        var again = await SshClient.ScanHostKeysAsync(endpoint.Host, endpoint.Port, new SshHostKeyScanOptions { HostKeyAlgorithms = [first.Algorithm] }, Timeout());
        await Assert.That(again.Single().Fingerprint).IsEqualTo(first.Fingerprint);

        // The key an authenticated connection verifies is among them.
        if (await RealServer.OptionsAsync() is { } options)
        {
            await using var client = await SshClient.ConnectAsync(endpoint.Host, endpoint.Port, options, Timeout());
            await Assert.That(keys.Select(k => k.Fingerprint)).Contains(client.HostKey.Fingerprint);
        }
    }
}
