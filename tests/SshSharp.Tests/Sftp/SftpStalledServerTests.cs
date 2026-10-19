using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// An <c>sftp-server</c> that stops reading while sshd goes on: the channel's window fills and a request cannot be sent.
/// <see cref="SftpClient.OperationTimeout"/> bounds that too, and the cleanups that wait for writes in flight stay bounded. Also what a
/// failed sequential upload leaves for <see cref="SftpTransferOptions.Resume"/>. All on a fake clock.
/// </summary>
public sealed class SftpStalledServerTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-stalled-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; private init; } = null!;

        public FakeSftpServer Files { get; } = new();

        public FakeTimeProvider Time { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        /// <summary>A server whose channels take <paramref name="window"/> bytes before the client must wait for the server to read.</summary>
        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, uint window = 256 * 1024)
        {
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var rig = new Rig { Ssh = new FakeSessionServer { Password = password, ServerWindow = window } };
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = password,
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
                TimeProvider = rig.Time,
            }, leaveOpen: true, Timeout());
            rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            return rig;
        }

        /// <summary>Waits until the server has stopped reading a session.</summary>
        public async Task StoppedAsync()
        {
            var token = Timeout();
            while (Files.StoppedReading == 0)
            {
                await Task.Delay(5, token);
            }
        }

        /// <summary>Moves the clock a second at a time until <paramref name="work"/> ends (at most a minute of fake time).</summary>
        public Task AdvanceUntilDoneAsync(Task work) => AdvanceUntilAsync(() => work.IsCompleted);

        /// <summary>Moves the clock a second at a time until <paramref name="done"/> holds (at most a minute of fake time).</summary>
        public async Task AdvanceUntilAsync(Func<bool> done)
        {
            for (var i = 0; i < 60 && !done(); i++)
            {
                Time.Advance(TimeSpan.FromSeconds(1));
                for (var j = 0; j < 50 && !done(); j++)
                {
                    await Task.Delay(10); // what the clock released is on its way
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            Files.ReadingResumed.TrySetResult(); // a stopped session reads again, and can end
            Files.Released.TrySetResult(); // and a held one answers
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
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

    // ---- a request that cannot be sent ----

    [Test]
    public async Task AnUpload_ToAServerThatStopsReading_FailsWithinTheOperationTimeout_AndClosesTheSession()
    {
        // The server stops reading at the second write: the window fills with the writes behind it, and a send waits for the window
        // with nothing coming back.
        await using var rig = await Rig.StartAsync(f => f.StopReading = packet => FakeSftpServer.WriteOffset(packet) == 64 * 1024);
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(10);
        using var source = new MemoryStream(RandomNumberGenerator.GetBytes(4 * 1024 * 1024));

        var upload = rig.Sftp.UploadAsync(source, "big.bin", cancellationToken: Timeout());
        await rig.StoppedAsync();
        await Task.Delay(100);
        await Assert.That(upload.IsCompleted).IsFalse();

        await rig.AdvanceUntilDoneAsync(upload);

        await Assert.That(upload.IsCompleted).IsTrue().Because("a send the server takes nothing of is bounded by OperationTimeout");
        var error = await Assert.That(async () => await upload).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(rig.Sftp.IsConnected).IsFalse().Because("part of a request may have gone out: nothing can follow it");
        await Assert.That(async () => await rig.Sftp.GetAttributesAsync("big.bin", cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(rig.Client.IsConnected).IsTrue(); // only the SFTP session is gone
    }

    [Test]
    public async Task AWriteStream_ToAServerThatStopsReading_IsDisposedWithinTheOperationTimeout()
    {
        await using var rig = await Rig.StartAsync(f => f.StopReading = packet => FakeSftpServer.WriteOffset(packet) == 0);
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(10);
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);

        var written = Task.Run(async () =>
        {
            var stream = await rig.Sftp.OpenWriteAsync("big.bin", Timeout());
            try
            {
                await stream.WriteAsync(data, Timeout());
            }
            finally
            {
                await stream.DisposeAsync();
            }
        });
        await rig.StoppedAsync();
        await rig.AdvanceUntilDoneAsync(written);

        await Assert.That(written.IsCompleted).IsTrue().Because("the writes in flight are bounded by OperationTimeout when the stream is disposed");
        await Assert.That(async () => await written).Throws<SshException>();
        await Assert.That(rig.Sftp.IsConnected).IsFalse();
    }

    [Test]
    public async Task ACancelledUpload_ToAServerThatStopsReading_EndsWithoutAnOperationTimeout()
    {
        // No OperationTimeout: the send in progress cannot end, but the caller stops waiting for it once cancelled.
        await using var rig = await Rig.StartAsync(f => f.StopReading = packet => FakeSftpServer.WriteOffset(packet) == 0);
        using var source = new MemoryStream(RandomNumberGenerator.GetBytes(4 * 1024 * 1024));
        using var cancel = new CancellationTokenSource();

        var started = rig.Time.GetUtcNow();
        var upload = rig.Sftp.UploadAsync(source, "big.bin", cancellationToken: cancel.Token);
        await rig.StoppedAsync();
        await cancel.CancelAsync();

        // The answers to the writes sent are waited for 5 s, then given up; closing the file, whose CLOSE waits behind the write that
        // cannot be sent, waits 5 s more (not the 30 s a close otherwise gets).
        await rig.AdvanceUntilDoneAsync(upload);

        await Assert.That(upload.IsCompleted).IsTrue();
        await Assert.That(async () => await upload).Throws<OperationCanceledException>();
        await Assert.That(rig.Time.GetUtcNow() - started).IsLessThanOrEqualTo(TimeSpan.FromSeconds(11));
    }

    [Test]
    public async Task ACancelledRequest_WhoseSendIsStuck_StillClosesTheSessionAfterTheOperationTimeout()
    {
        // The server answers one request, then stops reading. A request too large for the channel's window cannot be sent; its caller
        // cancels, and the send goes on in the background, holding the session's send lock: the timeout still bounds it.
        await using var rig = await Rig.StartAsync(f => f.StopReading = packet => packet[0] == 17 && Encoding.UTF8.GetString(packet).Contains("stop-here", StringComparison.Ordinal));
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(10);
        await Assert.That(async () => await rig.Sftp.GetAttributesAsync("stop-here", cancellationToken: Timeout())).Throws<SftpException>();
        await rig.StoppedAsync();
        var silent = rig.Time.GetUtcNow(); // the server's last reply

        using var cancel = new CancellationTokenSource();
        var stuck = rig.Sftp.GetAttributesAsync(new string('a', 600_000), cancellationToken: cancel.Token);
        rig.Time.Advance(TimeSpan.FromSeconds(2));
        await cancel.CancelAsync();
        await Assert.That(async () => await stuck).Throws<OperationCanceledException>();
        await Assert.That(rig.Sftp.IsConnected).IsTrue(); // the server has been silent for 2 s only

        await rig.AdvanceUntilAsync(() => !rig.Sftp.IsConnected);

        await Assert.That(rig.Sftp.IsConnected).IsFalse().Because("nobody waits for the send any more, but it is still bounded");
        await Assert.That(rig.Time.GetUtcNow() - silent).IsLessThanOrEqualTo(TimeSpan.FromSeconds(11));
        var error = await Assert.That(async () => await rig.Sftp.GetAttributesAsync("x", cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(rig.Client.IsConnected).IsTrue(); // only the SFTP session is gone
    }

    [Test]
    public async Task ACancelledSegmentedUpload_WhoseSessionStopsReading_GivesUpAfterTheBound_AndSaysTheCleanupDidNotFinish()
    {
        var (local, _) = await LocalFileAsync(4 * 1024 * 1024);

        // The fourth range's session stops reading at its first write: the writes behind it cannot even be sent.
        await using var rig = await Rig.StartAsync(f => f.StopReading = packet => FakeSftpServer.WriteOffset(packet) == 3 * 1024 * 1024);
        using var cancel = new CancellationTokenSource();
        var upload = rig.Sftp.UploadFileAsync(local, "big.bin", new SftpTransferOptions { Segments = 4 }, cancel.Token);
        await rig.StoppedAsync();

        await cancel.CancelAsync();
        await rig.AdvanceUntilDoneAsync(upload);

        await Assert.That(upload.IsCompleted).IsTrue().Because("the cleanup's waits are bounded (5 s each without OperationTimeout)");
        var error = await Assert.That(async () => await upload).Throws<OperationCanceledException>();
        await Assert.That(error!.Data[SftpClient.UploadCleanupIncompleteKey] is true).IsTrue();
    }

    // ---- what a failed sequential upload leaves ----

    [Test]
    public async Task AFailedUpload_WhoseLaterWritesLanded_IsCutToItsUnbrokenStart_SoResumeKeepsNoGap()
    {
        // A write in the middle fails while the writes in flight after it land: the file would reach its full size with a gap.
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f => f.FailWriteAt = offset => offset == 1024 * 1024, window: 2 * 1024 * 1024);

        var error = await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(data), "big.bin", cancellationToken: Timeout()))
            .Throws<SftpException>();

        await Assert.That(error!.Data.Contains(SftpClient.UploadCleanupIncompleteKey)).IsFalse();
        var remote = rig.Files.FileData(Home + "/big.bin");
        await Assert.That(remote!.Length).IsEqualTo(1024 * 1024);
        await Assert.That(IsPrefixOf(remote, data)).IsTrue();
        await Assert.That(rig.Files.WriteOffsets.Max()).IsGreaterThan(1024 * 1024).Because("writes after the failed one were in flight");

        // Resume continues from the unbroken start.
        rig.Files.FailWriteAt = null;
        await rig.Sftp.UploadAsync(new MemoryStream(data), "big.bin", new SftpTransferOptions { Resume = true }, Timeout());
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.AsSpan().SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task AFailedUpload_WhoseLaterWritesGoUnanswered_SaysTheCleanupDidNotFinish()
    {
        // A write in the middle is refused, and the server answers nothing after it: the writes in flight behind the refused one may
        // still land, past the gap it left.
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.FailWriteAt = offset => offset == 1024 * 1024;
            f.Hold = packet => FakeSftpServer.WriteOffset(packet) > 1024 * 1024;
        }, window: 2 * 1024 * 1024);
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(10);

        var upload = rig.Sftp.UploadAsync(new MemoryStream(data), "big.bin", cancellationToken: Timeout());
        await rig.AdvanceUntilDoneAsync(upload);

        await Assert.That(upload.IsCompleted).IsTrue();
        var error = await Assert.That(async () => await upload).Throws<SftpException>();
        await Assert.That(error!.Data[SftpClient.UploadCleanupIncompleteKey] is true).IsTrue().Because("a write past the refused one may land yet");
        await Assert.That(rig.Files.Held).IsGreaterThan(0).Because("writes after the refused one were in flight");
    }

    [Test]
    public async Task AFailedUpload_WhoseFileCannotBeCut_SaysTheCleanupDidNotFinish()
    {
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.FailWriteAt = offset => offset == 1024 * 1024;
            f.RefuseSetSize = true;
        }, window: 2 * 1024 * 1024);

        var error = await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(data), "big.bin", cancellationToken: Timeout()))
            .Throws<SftpException>();

        await Assert.That(error!.Data[SftpClient.UploadCleanupIncompleteKey] is true).IsTrue();
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.Length).IsEqualTo(data.Length); // kept, gap and all: the key says so
    }

    [Test]
    public async Task AFailedUpload_WithNothingPastTheFailure_KeepsWhatWasWritten_WithoutACut()
    {
        // The last write fails: nothing landed after it, so there is no gap and nothing to cut.
        var data = RandomNumberGenerator.GetBytes(256 * 1024);
        await using var rig = await Rig.StartAsync(f => f.FailWriteAt = offset => offset == (256 - 64) * 1024, window: 2 * 1024 * 1024);

        var error = await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(data), "big.bin", cancellationToken: Timeout()))
            .Throws<SftpException>();

        await Assert.That(error!.Data.Contains(SftpClient.UploadCleanupIncompleteKey)).IsFalse();
        await Assert.That(rig.Files.Requests.Contains(10)).IsFalse(); // no FSETSTAT
        await Assert.That(rig.Files.FileData(Home + "/big.bin")!.Length).IsEqualTo((256 - 64) * 1024);
    }
}
