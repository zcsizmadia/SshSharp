using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Downloading one file in parallel ranges over several SFTP sessions (<see cref="SftpTransferOptions.Segments"/>).</summary>
public sealed class SftpSegmentedDownloadTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-segments-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null)
        {
            var rig = new Rig();
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = TestSecrets.Password,
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            }, leaveOpen: true, Timeout());
            rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    /// <summary>Collects progress reports synchronously (Progress&lt;T&gt; would post them later).</summary>
    private sealed class Recorder : IProgress<SftpTransferProgress>
    {
        public List<long> Values { get; } = [];

        public void Report(SftpTransferProgress value)
        {
            lock (Values)
            {
                Values.Add(value.BytesTransferred);
            }
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        while (!condition())
        {
            if (deadline.Elapsed > TimeSpan.FromSeconds(30))
            {
                throw new TimeoutException("The condition did not become true.");
            }

            await Task.Delay(10);
        }
    }

    [Test]
    public async Task AConnectionThatRefusesNewSessions_DownloadsOverTheOpenSession()
    {
        var data = RandomNumberGenerator.GetBytes((5 * 1024 * 1024) + 7);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", data));
        await rig.Client.PreventNewSessionsAsync(Timeout()); // opening a session now throws InvalidOperationException
        var local = Path.Combine(_dir, "big.bin");

        var total = await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4 }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That((await File.ReadAllBytesAsync(local)).SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task FourSegments_FetchEveryQuarter_OverFourSessions_IntoTheRightPlaces()
    {
        var data = RandomNumberGenerator.GetBytes((5 * 1024 * 1024) + 12345);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", data));
        var local = Path.Combine(_dir, "big.bin");
        var progress = new Recorder();

        var total = await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4, Progress = progress }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That((await File.ReadAllBytesAsync(local)).SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(4); // the first session and three more
        await Assert.That(rig.Files.MaxConcurrentSessions).IsGreaterThanOrEqualTo(2);
        var quarter = data.Length / 4;
        for (var i = 0; i < 4; i++)
        {
            await Assert.That(rig.Files.ReadOffsets.Contains(i * (long)quarter)).IsTrue().Because($"the range from {i * quarter} is read");
        }

        await Assert.That(progress.Values[^1]).IsEqualTo(data.Length);
        await Assert.That(progress.Values.Zip(progress.Values.Skip(1)).All(p => p.First < p.Second)).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task ASmallFile_UsesFewerSegments_AndResumeUsesOne()
    {
        var small = RandomNumberGenerator.GetBytes((3 * 1024 * 1024) / 2);
        var large = RandomNumberGenerator.GetBytes(3 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/small.bin", small);
            f.AddFile(Home + "/large.bin", large);
        });

        // 1.5 MiB: one segment of at least 1 MiB, so no other session.
        await rig.Sftp.DownloadFileAsync("small.bin", Path.Combine(_dir, "small.bin"), new SftpTransferOptions { Segments = 8 }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);

        // Resume needs a sequential download: segments are ignored.
        var partial = Path.Combine(_dir, "large.bin");
        await File.WriteAllBytesAsync(partial, large[..1000]);
        await rig.Sftp.DownloadFileAsync("large.bin", partial, new SftpTransferOptions { Segments = 4, Resume = true }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
        await Assert.That((await File.ReadAllBytesAsync(partial)).SequenceEqual(large)).IsTrue();

        // 3 MiB with 8 asked: three segments.
        await rig.Sftp.DownloadFileAsync("large.bin", Path.Combine(_dir, "large2.bin"), new SftpTransferOptions { Segments = 8 }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(3);
        await Assert.That((await File.ReadAllBytesAsync(Path.Combine(_dir, "large2.bin"))).SequenceEqual(large)).IsTrue();
    }

    [Test]
    public async Task AServerThatOpensNoMoreSessions_GetsTheWholeFileOverOne()
    {
        var data = RandomNumberGenerator.GetBytes(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", data));
        rig.Ssh.Subsystems.Remove("sftp"); // as sshd past MaxSessions: further subsystem requests are refused

        var local = Path.Combine(_dir, "big.bin");
        await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4 }, Timeout());

        await Assert.That((await File.ReadAllBytesAsync(local)).SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task AFailingRange_StopsTheOthers_AndLeavesNoFile()
    {
        var data = RandomNumberGenerator.GetBytes(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.FailReadAt = offset => offset == 2 * 1024 * 1024 + (64 * 1024 * 3); // inside the third range
        });
        var local = Path.Combine(_dir, "big.bin");

        var error = await Assert.That(async () =>
            await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4 }, Timeout())).Throws<SftpException>();

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(File.Exists(local)).IsFalse();

        // Every handle is closed: the ranges close theirs, and an OPEN the failure cancelled is closed with its session, which the server
        // may finish ending a moment after the download has returned (seen on macos-latest).
        for (var i = 0; i < 1000 && rig.Files.OpenHandles != 0; i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);

        // The session is still usable.
        rig.Files.FailReadAt = null;
        await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4 }, Timeout());
        await Assert.That((await File.ReadAllBytesAsync(local)).SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task Cancelling_StopsEverySegment_AndLeavesNoFile()
    {
        // Each session holds its first READ unanswered (and everything after it), so every segment is waiting on its first two reads
        // (a range starts with two in flight) when the download is cancelled: no wall-clock race decides where the cancellation lands.
        // Once released, the server answers what was sent; a segment that missed the cancellation would read on through its 1 MiB.
        var data = RandomNumberGenerator.GetBytes(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (32 * 1024, 32 * 1024);
            f.AddFile(Home + "/big.bin", data);
            f.Hold = packet => packet[0] == 5;
        });
        var local = Path.Combine(_dir, "big.bin");
        using var cancel = new CancellationTokenSource();

        var download = rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4 }, cancel.Token);
        await WaitUntilAsync(() => rig.Files.Held == 4 || download.IsCompleted); // every segment has its reads out
        await Assert.That(rig.Files.Held).IsEqualTo(4);
        await cancel.CancelAsync();
        rig.Files.Released.SetResult();

        await Assert.That(async () => await download).Throws<OperationCanceledException>();
        await Assert.That(File.Exists(local)).IsFalse();
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0);
        // Every handle closed: each session's CLOSE was answered after the reads queued before it.
        await Assert.That(rig.Files.ReadOffsets.Count).IsLessThanOrEqualTo(4 * 2).Because("only the two reads each segment had sent are answered: every segment stopped");
    }

    [Test]
    public async Task Times_ArePreserved_AfterASegmentedDownload()
    {
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", data, modifyTime: 1_600_000_000));
        var local = Path.Combine(_dir, "big.bin");

        await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 2, Preserve = true }, Timeout());

        await Assert.That(new DateTimeOffset(File.GetLastWriteTimeUtc(local)).ToUnixTimeSeconds()).IsEqualTo(1_600_000_000);
        await Assert.That(rig.Files.Sessions).IsEqualTo(2);
    }
}
