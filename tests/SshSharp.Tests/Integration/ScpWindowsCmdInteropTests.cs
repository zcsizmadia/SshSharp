using SshSharp.Scp;

namespace SshSharp.Tests.Integration;

/// <summary>
/// SCP with <see cref="SshScpPathQuoting.DoubleQuote"/> against OpenSSH for Windows whose default shell is <c>cmd.exe</c>: paths with
/// spaces and the characters <c>cmd.exe</c> reads outside quotes go up and come back, and a path that would run a command outside
/// quotes runs nothing. Needs SSHSHARP_TEST_SERVER_SHELL=cmd, which CI sets in the Windows job's last step, after switching the
/// server's default shell from Git Bash to <c>cmd.exe</c>; its own category keeps it out of the other interop runs.
/// </summary>
[Category("Integration")]
[Category("WindowsCmd")]
public sealed class ScpWindowsCmdInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-scpw-" + Guid.NewGuid().ToString("N"));

    public ScpWindowsCmdInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    [Test]
    public async Task DoubleQuotedPaths_GoUpAndComeBack_AndRunNothing()
    {
        if (!RealServer.IsWindowsCmd || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("Needs OpenSSH for Windows with cmd.exe as its default shell (SSHSHARP_TEST_SERVER_SHELL=cmd) and a test account.");
            return;
        }

        var (host, port) = RealServer.Endpoint!.Value;
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        var temp = (await client.RunCommandAsync("echo %TEMP%", Timeout())).StandardOutputText.Trim();
        await Assert.That(temp).DoesNotContain("%"); // cmd.exe expanded it: this is the shell the test is for
        var remote = $@"{temp}\sshsharp scp & co ({Guid.NewGuid():N})";
        await Assert.That((await client.RunCommandAsync($"mkdir \"{remote}\"", Timeout())).ExitStatus).IsEqualTo(0);
        try
        {
            var quoted = new SshScpOptions { PathQuoting = SshScpPathQuoting.DoubleQuote };

            // A file whose name has a space and & ^ ( ) ; ' in it, which cmd.exe reads outside quotes, and back.
            var content = new byte[256 * 1024 + 3];
            Random.Shared.NextBytes(content);
            var local = Path.Combine(_dir, "data.bin");
            await File.WriteAllBytesAsync(local, content);
            var name = "a b&c^d(e);f'g.bin";
            await client.UploadFileAsync(local, $@"{remote}\{name}", quoted, Timeout());
            var back = Path.Combine(_dir, "back.bin");
            await client.DownloadFileAsync($@"{remote}\{name}", back, quoted, Timeout());
            await Assert.That((await File.ReadAllBytesAsync(back)).AsSpan().SequenceEqual(content)).IsTrue();

            // A stream, to a path in forward slashes, read back into a stream.
            await client.UploadAsync(new MemoryStream("from a stream\r\n"u8.ToArray()), remote.Replace('\\', '/') + "/note & more.txt", options: quoted, cancellationToken: Timeout());
            using var memory = new MemoryStream();
            await client.DownloadAsync($@"{remote}\note & more.txt", memory, quoted, Timeout());
            await Assert.That(memory.ToArray().AsSpan().SequenceEqual("from a stream\r\n"u8)).IsTrue();

            // A tree, into a directory that does not exist yet, and back.
            var tree = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
            await File.WriteAllTextAsync(Path.Combine(tree.FullName, "a & b.txt"), "A");
            Directory.CreateDirectory(Path.Combine(tree.FullName, "sub (1)"));
            await File.WriteAllTextAsync(Path.Combine(tree.FullName, "sub (1)", "c.txt"), "C");
            await client.UploadDirectoryAsync(tree.FullName, $@"{remote}\up & in", quoted, Timeout());
            var down = Path.Combine(_dir, "down");
            await client.DownloadDirectoryAsync($@"{remote}\up & in", down, quoted, Timeout());
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(down, "a & b.txt"))).IsEqualTo("A");
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(down, "sub (1)", "c.txt"))).IsEqualTo("C");

            // Outside quotes, this path would run "mkdir ...\injected" on the server. Quoted, it is one path, with a drive colon in
            // the middle, which scp.exe cannot create: the transfer fails, and nothing runs.
            var hostile = $@"{remote}\x & mkdir {remote}\injected";
            try
            {
                await client.UploadAsync(new MemoryStream("x"u8.ToArray()), hostile, options: quoted, cancellationToken: Timeout());
            }
            catch (SshException ex) when (ex.Reason == SshFailureReason.TransferFailed)
            {
                // expected; what matters is below
            }

            var check = await client.RunCommandAsync($"if exist \"{remote}\\injected\" (echo found) else (echo absent)", Timeout());
            await Assert.That(check.StandardOutputText.Trim()).IsEqualTo("absent");
        }
        finally
        {
            await client.RunCommandAsync($"rmdir /s /q \"{remote}\"", Timeout());
        }
    }
}
