using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Uploading one file in parallel ranges over several SFTP sessions (<see cref="SftpTransferOptions.Segments"/>).</summary>
public sealed class SftpSegmentedUploadTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-upload-segments-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, TimeProvider? time = null)
        {
            var rig = new Rig();
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = "secret",
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
                TimeProvider = time ?? TimeProvider.System,
            }, leaveOpen: true, Timeout());
            rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            Files.Released.TrySetResult(); // a held session answers, and can end
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    /// <summary>Collects progress reports synchronously (Progress&lt;T&gt; would post them later).</summary>
    private sealed class Recorder : IProgress<SftpTransferProgress>
    {
        public List<SftpTransferProgress> Values { get; } = [];

        public void Report(SftpTransferProgress value)
        {
            lock (Values)
            {
                Values.Add(value);
            }
        }
    }

    private async Task<(string Path, byte[] Data)> LocalFileAsync(int length)
    {
        var data = RandomNumberGenerator.GetBytes(length);
        var path = Path.Combine(_dir, "big.bin");
        await File.WriteAllBytesAsync(path, data);
        return (path, data);
    }

    /// <summary>Whether the remote file holds an unbroken start of <paramref name="data"/>, and nothing else.</summary>
    private static bool IsPrefixOf(byte[]? remote, byte[] data) =>
        remote is not null && remote.Length <= data.Length && remote.AsSpan().SequenceEqual(data.AsSpan(0, remote.Length));

    [Test]
    public async Task FourSegments_WriteEveryQuarter_OverFourSessions_IntoTheRightPlaces()
    {
        var (local, data) = await LocalFileAsync((5 * 1024 * 1024) + 12345);
        await using var rig = await Rig.StartAsync();
        var progress = new Recorder();

        var total = await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4, Progress = progress }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(4); // the first session and three more
        await Assert.That(rig.Files.MaxConcurrentSessions).IsGreaterThanOrEqualTo(2);
        var quarter = data.Length / 4;
        for (var i = 0; i < 4; i++)
        {
            await Assert.That(rig.Files.WriteOffsets.Contains(i * (long)quarter)).IsTrue().Because($"the range from {i * quarter} is written");
        }

        var reported = progress.Values.Select(p => p.BytesTransferred).ToList();
        await Assert.That(reported[^1]).IsEqualTo(data.Length);
        await Assert.That(reported.Zip(reported.Skip(1)).All(p => p.First < p.Second)).IsTrue();
        await Assert.That(progress.Values.All(p => p.TotalBytes == data.Length && p.Path == "big.bin")).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task ASmallFile_UsesOneSession_AndSoDoesResume()
    {
        var (local, data) = await LocalFileAsync((3 * 1024 * 1024) / 2);
        await using var rig = await Rig.StartAsync();

        // 1.5 MiB: one segment of at least 1 MiB, so no other session.
        await rig.Sftp.UploadFileAsync(local, "small.bin", new SftpTransferOptions { Segments = 8 }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
        await Assert.That(rig.Files.FileData(Home + "/small.bin")!.SequenceEqual(data)).IsTrue();

        // Resume needs a sequential upload: segments are ignored.
        var large = RandomNumberGenerator.GetBytes(3 * 1024 * 1024);
        await File.WriteAllBytesAsync(local, large);
        rig.Files.AddFile(Home + "/large.bin", large[..1000]);
        await rig.Sftp.UploadFileAsync(local, "large.bin", new SftpTransferOptions { Segments = 4, Resume = true }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
        await Assert.That(rig.Files.FileData(Home + "/large.bin")!.SequenceEqual(large)).IsTrue();

        // 3 MiB with 8 asked: three segments.
        await rig.Sftp.UploadFileAsync(local, "large2.bin", new SftpTransferOptions { Segments = 8 }, Timeout());
        await Assert.That(rig.Files.Sessions).IsEqualTo(3);
        await Assert.That(rig.Files.FileData(Home + "/large2.bin")!.SequenceEqual(large)).IsTrue();
    }

    [Test]
    public async Task AServerThatOpensNoMoreSessions_GetsTheWholeFileOverOne()
    {
        var (local, data) = await LocalFileAsync(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync();
        rig.Ssh.Subsystems.Remove("sftp"); // as sshd past MaxSessions: further subsystem requests are refused

        await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout());

        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task AConnectionThatRefusesNewSessions_UploadsOverTheOpenSession()
    {
        var (local, data) = await LocalFileAsync((4 * 1024 * 1024) + 3);
        await using var rig = await Rig.StartAsync();
        await rig.Client.PreventNewSessionsAsync(Timeout());

        var total = await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task AServerWithOneWriterPerFile_GetsTheFileOverOneSession()
    {
        var (local, data) = await LocalFileAsync((4 * 1024 * 1024) + 99);
        await using var rig = await Rig.StartAsync(f => f.RefuseSecondWriter = true);

        var total = await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(2); // one more was opened, could not open the file, and was closed at once
        await Assert.That(rig.Files.WriteOffsets.SequenceEqual(rig.Files.WriteOffsets.Order())).IsTrue().Because("one session wrote it, in order");
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task AServerThatTakesWritesInOrderOnly_GetsTheRestInOrderOverTheFirstSession()
    {
        var (local, data) = await LocalFileAsync((5 * 1024 * 1024) + 777);
        await using var rig = await Rig.StartAsync(f => f.WritesInOrderOnly = true);
        var progress = new Recorder();

        var total = await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4, Progress = progress }, Timeout());

        await Assert.That(total).IsEqualTo(data.Length);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        var reported = progress.Values.Select(p => p.BytesTransferred).ToList();
        await Assert.That(reported[^1]).IsEqualTo(data.Length);
        await Assert.That(reported.Zip(reported.Skip(1)).All(p => p.First < p.Second)).IsTrue().Because("progress never goes back for the fallback");
        await Assert.That(rig.Files.Sessions).IsEqualTo(4).Because("the ranges were tried before the server refused one out of order");
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task AFailingWrite_StopsTheOthers_CutsTheFileToItsUnbrokenStart_AndResumeCompletesIt()
    {
        var (local, data) = await LocalFileAsync(4 * 1024 * 1024);
        var failAt = (2 * 1024 * 1024) + (64 * 1024 * 3); // inside the third range, after its first writes
        await using var rig = await Rig.StartAsync(f => f.FailWriteAt = offset => offset == failAt);

        var error = await Assert.That(async () =>
            await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout())).Throws<SftpException>();

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(error.Data.Contains(SftpClient.UploadCleanupIncompleteKey)).IsFalse().Because("the cleanup finished");
        var remote = rig.Files.FileData(Home + "/big.bin");
        await Assert.That(IsPrefixOf(remote, data)).IsTrue().Because("the file keeps only the start the server holds without a gap");
        await Assert.That(remote!.Length).IsLessThanOrEqualTo(failAt);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);

        // A resumed upload continues from there, over one session.
        rig.Files.FailWriteAt = null;
        var rest = await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Resume = true, Segments = 4 }, Timeout());
        await Assert.That(rest).IsEqualTo(data.Length - remote.Length);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task AFailedUpload_ToAServerThatCannotCutAFile_DeletesIt()
    {
        var (local, _) = await LocalFileAsync(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.FailWriteAt = offset => offset == (3 * 1024 * 1024) + (64 * 1024 * 2);
            f.RefuseSetSize = true;
        });

        await Assert.That(async () =>
            await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout())).Throws<SftpException>();

        await Assert.That(rig.Files.Exists(Home + "/big.bin")).IsFalse();
    }

    [Test]
    public async Task Cancelling_StopsEverySegment_AndLeavesAnUnbrokenStart()
    {
        var (local, data) = await LocalFileAsync(4 * 1024 * 1024);
        var firstWrites = new TaskCompletionSource();
        await using var rig = await Rig.StartAsync();

        // Every write waits until the test has cancelled, so the upload is surely in the middle of its ranges when it is cancelled.
        rig.Files.HoldWrites = firstWrites;
        using var cancel = new CancellationTokenSource();
        // A small window, so each range still has writes to send once the held ones are answered.
        var upload = rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4, MaxRequestsInFlight = 4 }, cancel.Token);
        while (rig.Files.Sessions < 4 || rig.Files.OpenHandles < 4)
        {
            await Task.Delay(5);
        }

        await cancel.CancelAsync();
        firstWrites.SetResult();

        var cancelled = await Assert.That(async () => await upload).Throws<OperationCanceledException>();
        await Assert.That(cancelled!.Data.Contains(SftpClient.UploadCleanupIncompleteKey)).IsFalse().Because("every answer came, and the file was cut");
        await Assert.That(IsPrefixOf(rig.Files.FileData(Home + "/big.bin"), data)).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    /// <summary>Moves the fake clock a second at a time until <paramref name="upload"/> ends (at most a minute of fake time).</summary>
    private static async Task AdvanceUntilDoneAsync(FakeTimeProvider time, Task upload)
    {
        for (var i = 0; i < 60 && !upload.IsCompleted; i++)
        {
            time.Advance(TimeSpan.FromSeconds(1));
            for (var j = 0; j < 50 && !upload.IsCompleted; j++)
            {
                await Task.Delay(10); // what the clock released is on its way
            }
        }
    }

    [Test]
    public async Task ACancelledUpload_WhoseWritesGoUnanswered_GivesUpAfterTheBound_AndSaysTheCleanupDidNotFinish()
    {
        var (local, _) = await LocalFileAsync(4 * 1024 * 1024);
        var time = new FakeTimeProvider();

        // The fourth range's session stops answering at its first write: those writes may still land later, after any cut.
        await using var rig = await Rig.StartAsync(f => f.Hold = packet => FakeSftpServer.WriteOffset(packet) == 3 * 1024 * 1024, time);
        using var cancel = new CancellationTokenSource();
        var upload = rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, cancel.Token);
        while (rig.Files.Held == 0)
        {
            await Task.Delay(5);
        }

        await cancel.CancelAsync();

        // Without the clock moving, the answers are still awaited: the upload cannot have ended.
        await Task.Delay(200);
        await Assert.That(upload.IsCompleted).IsFalse();
        time.Advance(TimeSpan.FromSeconds(4));
        await Task.Delay(200);
        await Assert.That(upload.IsCompleted).IsFalse().Because("the bound is 5 s when OperationTimeout is not set");

        await AdvanceUntilDoneAsync(time, upload);

        var error = await Assert.That(async () => await upload).Throws<OperationCanceledException>();
        await Assert.That(error!.Data[SftpClient.UploadCleanupIncompleteKey] is true).IsTrue();
    }

    [Test]
    public async Task AFailedUpload_WhoseCutGoesUnanswered_ThrowsItsOwnFailure_AndSaysTheCleanupDidNotFinish()
    {
        var (local, _) = await LocalFileAsync(4 * 1024 * 1024);
        var time = new FakeTimeProvider();
        await using var rig = await Rig.StartAsync(f =>
        {
            f.FailWriteAt = offset => offset == (2 * 1024 * 1024) + (64 * 1024 * 2);
            f.Hold = packet => packet[0] == 10; // FSETSTAT: the cut is never answered
        }, time);

        var upload = rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, Timeout());
        while (rig.Files.Held == 0)
        {
            await Task.Delay(5);
        }

        await AdvanceUntilDoneAsync(time, upload);

        var error = await Assert.That(async () => await upload).Throws<SftpException>();
        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(error.Data[SftpClient.UploadCleanupIncompleteKey] is true).IsTrue();
    }

    [Test]
    public async Task TheCleanupBound_IsTheOperationTimeout_WhenItIsSet()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(rig.Sftp.CleanupWait).IsEqualTo(TimeSpan.FromSeconds(5));
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(2);
        await Assert.That(rig.Sftp.CleanupWait).IsEqualTo(TimeSpan.FromSeconds(2));
        rig.Sftp.OperationTimeout = TimeSpan.FromMinutes(3);
        await Assert.That(rig.Sftp.CleanupWait).IsEqualTo(TimeSpan.FromMinutes(3));
    }

    [Test]
    public async Task WithoutOverwrite_AnExistingFile_FailsBeforeAnyOtherSession()
    {
        var (local, _) = await LocalFileAsync(4 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", [1, 2, 3]));

        await Assert.That(async () =>
            await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4, Overwrite = false }, Timeout())).Throws<SftpException>();

        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task Times_ArePreserved_AfterASegmentedUpload()
    {
        var (local, data) = await LocalFileAsync(2 * 1024 * 1024);
        File.SetLastWriteTimeUtc(local, DateTime.UnixEpoch.AddSeconds(1_600_000_000));
        await using var rig = await Rig.StartAsync();

        await rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 2, Preserve = true }, Timeout());

        await Assert.That(rig.Files.ModifyTime(Home + "/big.bin")).IsEqualTo(1_600_000_000u);
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(2);
    }

    [Test]
    public async Task ADirectoryUpload_SplitsItsLargeFiles()
    {
        var tree = Path.Combine(_dir, "tree");
        Directory.CreateDirectory(tree);
        var large = RandomNumberGenerator.GetBytes(3 * 1024 * 1024);
        var small = RandomNumberGenerator.GetBytes(1000);
        await File.WriteAllBytesAsync(Path.Combine(tree, "large.bin"), large);
        await File.WriteAllBytesAsync(Path.Combine(tree, "small.bin"), small);
        await using var rig = await Rig.StartAsync();

        var summary = await rig.Sftp.UploadDirectoryAsync(tree, "tree", new SftpTransferOptions { Segments = 3, MaxConcurrentFiles = 2 }, Timeout());

        await Assert.That(summary.Files).IsEqualTo(2);
        await Assert.That(rig.Files.FileData(Home + "/tree/large.bin")!.SequenceEqual(large)).IsTrue();
        await Assert.That(rig.Files.FileData(Home + "/tree/small.bin")!.SequenceEqual(small)).IsTrue();
        await Assert.That(rig.Files.Sessions).IsEqualTo(3);
    }
}
