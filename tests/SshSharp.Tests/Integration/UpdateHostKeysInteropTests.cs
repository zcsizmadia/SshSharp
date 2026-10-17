using SshSharp.Config;

namespace SshSharp.Tests.Integration;

/// <summary>
/// UpdateHostKeys against OpenSSH: accept-new records the key used for the connection, then sshd announces all its host keys and proves
/// the others, which get recorded too. Needs SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR.
/// </summary>
public sealed class UpdateHostKeysInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-uhki-" + Guid.NewGuid().ToString("N"));

    public UpdateHostKeysInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Test]
    public async Task OpenSshProvesItsOtherHostKeys_AndTheyAreRecorded()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and a password or key are needed.");
            return;
        }

        if (!RealServer.IsOpenSsh)
        {
            Skip.Test("hostkeys-00@openssh.com is an OpenSSH extension.");
            return;
        }

        using var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadAsync(keyFile) : null;
        var knownHosts = Path.Combine(_dir, "known_hosts");
        var options = new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = new KnownHostsVerifier([knownHosts]) { Policy = StrictHostKeyChecking.AcceptNew, UpdateHostKeys = true },
        };

        await using var client = await SshClient.ConnectAsync(host, port, options, new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token);
        var types = Array.Empty<string>();
        for (var i = 0; i < 500 && types.Length < 2; i++)
        {
            await Task.Delay(20);
            types = [.. KnownHostsFile.Load(knownHosts).Entries.Select(e => e.KeyType).Distinct()];
        }

        // The connection's own key plus at least one more that sshd proved (CI's sshd has Ed25519, ECDSA and RSA keys).
        await Assert.That(types.Length).IsGreaterThanOrEqualTo(2);
        await Assert.That(types).Contains(client.HostKey.KeyType);
    }
}
