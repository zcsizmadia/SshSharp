using System.Security.Cryptography;
using System.Text;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Directory transfers with path safety, and resumed transfers (#7).</summary>
public sealed class SftpDirectoryTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-sftpdir-" + Guid.NewGuid().ToString("N"));

    public SftpDirectoryTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<(FakeSessionServer Ssh, SshClient Client, SftpClient Sftp)> StartAsync(FakeSftpServer files)
    {
        var ssh = new FakeSessionServer();
        files.Install(ssh);
        _ = ssh.StartAsync();
        var client = await SshClient.ConnectAsync(ssh.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
        return (ssh, client, await client.OpenSftpAsync(Timeout()));
    }

    private static async Task StopAsync((FakeSessionServer Ssh, SshClient Client, SftpClient Sftp) rig)
    {
        await rig.Sftp.DisposeAsync();
        await rig.Client.DisposeAsync();
        await rig.Ssh.DisposeAsync();
    }

    [Test]
    public async Task DownloadDirectory_CopiesTheTree_AndSkipsLinks()
    {
        var files = new FakeSftpServer();
        files.AddDirectory(Home + "/tree");
        files.AddFile(Home + "/tree/a.txt", "alpha"u8.ToArray(), modifyTime: 1_600_000_000);
        files.AddDirectory(Home + "/tree/sub");
        files.AddFile(Home + "/tree/sub/b.bin", new byte[70_000]);
        files.AddDirectory(Home + "/tree/sub/deeper");
        files.AddFile(Home + "/tree/sub/deeper/c", "c"u8.ToArray());
        files.AddDirectory(Home + "/tree/empty");
        files.AddLink(Home + "/tree/escape", "/etc");
        var rig = await StartAsync(files);
        try
        {
            var target = Path.Combine(_dir, "down");
            var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target, new SftpTransferOptions { Preserve = true }, Timeout());

            await Assert.That(summary).IsEqualTo(new SftpTransferSummary(3, 3, 5 + 70_000 + 1, 1));
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "a.txt"))).IsEqualTo("alpha");
            await Assert.That(new FileInfo(Path.Combine(target, "sub", "b.bin")).Length).IsEqualTo(70_000L);
            await Assert.That(File.Exists(Path.Combine(target, "sub", "deeper", "c"))).IsTrue();
            await Assert.That(Directory.Exists(Path.Combine(target, "empty"))).IsTrue();
            await Assert.That(Path.Exists(Path.Combine(target, "escape"))).IsFalse();
            await Assert.That(new DateTimeOffset(File.GetLastWriteTimeUtc(Path.Combine(target, "a.txt")))).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000));
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    [Arguments("..\\..\\escaped")]
    [Arguments("c:evil")]
    [Arguments("nul.txt")]
    [Arguments("trailing.")]
    public async Task AHostileName_IsNeverWrittenOutside_AndIsSkippedWhereThisSystemCannotHoldIt(string name)
    {
        var files = new FakeSftpServer();
        files.AddDirectory(Home + "/tree");
        files.AddFile(Home + "/tree/" + name, "pwned"u8.ToArray());
        files.AddFile(Home + "/tree/ok.txt", "fine"u8.ToArray());
        var rig = await StartAsync(files);
        try
        {
            var target = Path.Combine(_dir, "inner", "down");
            var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target, cancellationToken: Timeout());

            // Whatever happens to the name, nothing lands outside the target, and the rest of the tree still downloads.
            var written = Directory.GetFiles(_dir, "*", SearchOption.AllDirectories);
            await Assert.That(written.All(f => f.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.Ordinal))).IsTrue();
            await Assert.That(File.ReadAllText(Path.Combine(target, "ok.txt"))).IsEqualTo("fine");
            if (OperatingSystem.IsWindows())
            {
                // '\', ':', device names and trailing dots cannot be file names here: skipped, not written.
                await Assert.That(summary.Skipped).IsEqualTo(1);
                await Assert.That(summary.Files).IsEqualTo(1);
            }
            else
            {
                // On POSIX they are ordinary characters: the file keeps its name, inside the target.
                await Assert.That(summary.Files).IsEqualTo(2);
                await Assert.That(File.Exists(Path.Combine(target, name))).IsTrue();
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task ATreeDeeperThanTheLimit_IsRefused()
    {
        var files = new FakeSftpServer();
        var path = Home + "/deep";
        files.AddDirectory(path);
        for (var i = 0; i < 70; i++)
        {
            path += "/d";
            files.AddDirectory(path);
        }

        var rig = await StartAsync(files);
        try
        {
            var ex = await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("deep", Path.Combine(_dir, "deep"), cancellationToken: Timeout())).Throws<SshException>();
            await Assert.That(ex!.Message).Contains("deeper");
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task UploadDirectory_CopiesTheTree_IntoAnExistingDirectoryToo()
    {
        var local = Path.Combine(_dir, "up");
        Directory.CreateDirectory(Path.Combine(local, "sub", "deeper"));
        await File.WriteAllTextAsync(Path.Combine(local, "a.txt"), "alpha");
        await File.WriteAllBytesAsync(Path.Combine(local, "sub", "b.bin"), new byte[50_000]);
        await File.WriteAllTextAsync(Path.Combine(local, "sub", "deeper", "c"), "c");
        var files = new FakeSftpServer();
        files.AddDirectory(Home + "/existing");
        var rig = await StartAsync(files);
        try
        {
            var summary = await rig.Sftp.UploadDirectoryAsync(local, "existing", cancellationToken: Timeout());

            await Assert.That(summary).IsEqualTo(new SftpTransferSummary(3, 2, 5 + 50_000 + 1, 0));
            await Assert.That(Encoding.ASCII.GetString(files.FileData(Home + "/existing/a.txt")!)).IsEqualTo("alpha");
            await Assert.That(files.FileData(Home + "/existing/sub/b.bin")!.Length).IsEqualTo(50_000);
            await Assert.That(files.Exists(Home + "/existing/sub/deeper/c")).IsTrue();

            await rig.Sftp.UploadDirectoryAsync(local, "fresh", cancellationToken: Timeout());
            await Assert.That(files.Exists(Home + "/fresh/sub/deeper/c")).IsTrue();
            await Assert.That(async () => await rig.Sftp.UploadDirectoryAsync(Path.Combine(_dir, "missing"), "x", cancellationToken: Timeout())).Throws<DirectoryNotFoundException>();
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task UploadDirectory_SkipsLocalLinks()
    {
        var local = Path.Combine(_dir, "withlink");
        Directory.CreateDirectory(local);
        await File.WriteAllTextAsync(Path.Combine(local, "real"), "r");
        try
        {
            File.CreateSymbolicLink(Path.Combine(local, "link"), Path.GetTempPath());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Skip.Test("Creating a symbolic link needs a privilege this account lacks.");
            return;
        }

        var files = new FakeSftpServer();
        var rig = await StartAsync(files);
        try
        {
            var summary = await rig.Sftp.UploadDirectoryAsync(local, "dest", cancellationToken: Timeout());
            await Assert.That(summary.Files).IsEqualTo(1);
            await Assert.That(summary.Skipped).IsEqualTo(1);
            await Assert.That(files.Exists(Home + "/dest/link")).IsFalse();
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task ResumedTransfers_SendOnlyTheRest()
    {
        var data = RandomNumberGenerator.GetBytes(200_000);
        var files = new FakeSftpServer();
        files.AddFile(Home + "/whole", data);
        files.AddFile(Home + "/half", data[..80_000]);
        var rig = await StartAsync(files);
        try
        {
            // Download: the local file has the first 120000 bytes.
            var local = Path.Combine(_dir, "partial");
            await File.WriteAllBytesAsync(local, data[..120_000]);
            var fetched = await rig.Sftp.DownloadFileAsync("whole", local, new SftpTransferOptions { Resume = true }, Timeout());
            await Assert.That(fetched).IsEqualTo(80_000L);
            await Assert.That((await File.ReadAllBytesAsync(local)).AsSpan().SequenceEqual(data)).IsTrue();

            // Upload: the remote file has the first 80000 bytes.
            var sent = await rig.Sftp.UploadAsync(new MemoryStream(data), "half", new SftpTransferOptions { Resume = true }, Timeout());
            await Assert.That(sent).IsEqualTo(120_000L);
            await Assert.That(files.FileData(Home + "/half").AsSpan().SequenceEqual(data)).IsTrue();

            // Nothing there yet: a resume is a whole transfer.
            await Assert.That(await rig.Sftp.UploadAsync(new MemoryStream(data), "new", new SftpTransferOptions { Resume = true }, Timeout())).IsEqualTo(200_000L);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task AResume_FromALargerDestination_IsRefused()
    {
        var files = new FakeSftpServer();
        files.AddFile(Home + "/small", new byte[10]);
        files.AddFile(Home + "/big", new byte[100]);
        var rig = await StartAsync(files);
        try
        {
            var local = Path.Combine(_dir, "bigger");
            await File.WriteAllBytesAsync(local, new byte[50]);
            await Assert.That(async () => await rig.Sftp.DownloadFileAsync("small", local, new SftpTransferOptions { Resume = true }, Timeout())).Throws<IOException>();
            await Assert.That(new FileInfo(local).Length).IsEqualTo(50L); // untouched

            await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(new byte[20]), "big", new SftpTransferOptions { Resume = true }, Timeout())).Throws<IOException>();
            await Assert.That(async () => await rig.Sftp.UploadAsync(new NonSeekable(new byte[20]), "big", new SftpTransferOptions { Resume = true }, Timeout())).Throws<IOException>();
            await Assert.That(files.FileData(Home + "/big")!.Length).IsEqualTo(100);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task AResumedUpload_FromANonSeekableSource_SkipsByReading()
    {
        var data = RandomNumberGenerator.GetBytes(100_000);
        var files = new FakeSftpServer();
        files.AddFile(Home + "/part", data[..30_000]);
        var rig = await StartAsync(files);
        try
        {
            var sent = await rig.Sftp.UploadAsync(new NonSeekable(data), "part", new SftpTransferOptions { Resume = true }, Timeout());
            await Assert.That(sent).IsEqualTo(70_000L);
            await Assert.That(files.FileData(Home + "/part").AsSpan().SequenceEqual(data)).IsTrue();
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    /// <summary>A stream that can only be read forward, like a network or pipe source.</summary>
    private sealed class NonSeekable(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _inner.ReadAsync(buffer, cancellationToken);

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
