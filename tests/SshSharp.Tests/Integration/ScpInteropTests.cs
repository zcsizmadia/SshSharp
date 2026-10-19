using System.Text;
using SshSharp.Scp;

namespace SshSharp.Tests.Integration;

/// <summary>
/// SCP against the real server's scp program: files, streams and directories up and back down, times kept, and a missing file.
/// Needs SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR; skipped where scp is missing.
/// </summary>
[Category("Integration")]
public sealed class ScpInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-scpi-" + Guid.NewGuid().ToString("N"));

    public ScpInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    private static async Task<SshClient?> ConnectAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadAsync(keyFile) : null;
        return await SshClient.ConnectAsync(host, port, new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, Timeout());
    }

    [Test]
    public async Task FilesStreamsAndDirectories_GoUpAndComeBack()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if ((await client.RunCommandAsync("command -v scp", Timeout())).ExitStatus != 0)
        {
            Skip.Test("The server has no scp program.");
            return;
        }

        var remote = (await client.RunCommandAsync("mktemp -d", Timeout())).StandardOutputText.Trim();
        try
        {
            // A file with a space in its remote name, larger than the channel window, and back.
            var content = new byte[3 * 1024 * 1024 + 7];
            Random.Shared.NextBytes(content);
            var local = Path.Combine(_dir, "big.bin");
            await File.WriteAllBytesAsync(local, content);
            await client.UploadFileAsync(local, $"{remote}/big copy.bin", cancellationToken: Timeout());
            var back = Path.Combine(_dir, "big.back");
            await client.DownloadFileAsync($"{remote}/big copy.bin", back, cancellationToken: Timeout());
            await Assert.That((await File.ReadAllBytesAsync(back)).AsSpan().SequenceEqual(content)).IsTrue();

            // A stream, read back into a stream.
            await client.UploadAsync(new MemoryStream("hello from a stream\n"u8.ToArray()), $"{remote}/note.txt", cancellationToken: Timeout());
            using var memory = new MemoryStream();
            await client.DownloadAsync($"{remote}/note.txt", memory, cancellationToken: Timeout());
            await Assert.That(Encoding.UTF8.GetString(memory.ToArray())).IsEqualTo("hello from a stream\n");

            // A tree, with times kept, round-tripped.
            var tree = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
            await File.WriteAllTextAsync(Path.Combine(tree.FullName, "a.txt"), "A");
            Directory.CreateDirectory(Path.Combine(tree.FullName, "sub"));
            await File.WriteAllTextAsync(Path.Combine(tree.FullName, "sub", "b.txt"), "B");
            var stamp = new DateTime(2023, 3, 4, 5, 6, 7, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(Path.Combine(tree.FullName, "sub", "b.txt"), stamp);
            await client.UploadDirectoryAsync(tree.FullName, $"{remote}/up", new SshScpOptions { Preserve = true }, Timeout());
            await Assert.That((await client.RunCommandAsync($"cat '{remote}/up/sub/b.txt'", Timeout())).StandardOutputText).IsEqualTo("B");

            var down = Path.Combine(_dir, "down");
            await client.DownloadDirectoryAsync($"{remote}/up", down, new SshScpOptions { Preserve = true }, Timeout());
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(down, "a.txt"))).IsEqualTo("A");
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(down, "sub", "b.txt"))).IsEqualTo("B");
            await Assert.That(File.GetLastWriteTimeUtc(Path.Combine(down, "sub", "b.txt"))).IsEqualTo(stamp);

            // A missing file is a transfer error with the server's own words.
            using var nothing = new MemoryStream();
            var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadAsync($"{remote}/missing", nothing, cancellationToken: Timeout()));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.TransferFailed);
        }
        finally
        {
            await client.RunCommandAsync($"rm -rf '{remote}'", Timeout());
        }
    }
}
