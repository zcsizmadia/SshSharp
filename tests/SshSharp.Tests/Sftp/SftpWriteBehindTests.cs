using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// The write-behind of <see cref="SftpFileStream"/> (#293): writes in flight together, bounded; a failed write never lost; flush,
/// dispose, seek, <see cref="Stream.SetLength"/> and reads consistent with the writes before them; cancellation.
/// </summary>
public sealed class SftpWriteBehindTests
{
    private const string Home = FakeSftpServer.Home;
    private const int Chunk = 8 * 1024;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; private init; } = null!;

        public FakeSftpServer Files { get; } = new() { Limits = (Chunk, Chunk) };

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null)
        {
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var rig = new Rig { Ssh = new FakeSessionServer { Password = password } };
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = password,
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

        /// <summary>Waits until the server has no handle open: a synchronous dispose sends the close in the background.</summary>
        public async Task HandlesClosedAsync()
        {
            var token = Timeout();
            while (Files.OpenHandles != 0)
            {
                await Task.Delay(10, token);
            }
        }
    }

    [Test]
    public async Task ManySmallAndLargeWrites_ArriveIntact_ThroughOneReusedBuffer()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(5));
        var expected = new MemoryStream();
        var buffer = new byte[5 * Chunk + 123];
        var random = new Random(293);

        await using (var stream = await rig.Sftp.OpenWriteAsync("mixed", Timeout()))
        {
            for (var i = 0; i < 200; i++)
            {
                // Sizes from one byte to several requests; the buffer is overwritten as soon as each call returns.
                var size = i % 3 == 0 ? random.Next(1, 100) : random.Next(1, buffer.Length + 1);
                random.NextBytes(buffer.AsSpan(0, size));
                await stream.WriteAsync(buffer.AsMemory(0, size), Timeout());
                expected.Write(buffer, 0, size);
                await Assert.That(stream.Length).IsEqualTo(expected.Length); // counts the writes in flight
            }
        }

        await Assert.That(rig.Files.FileData(Home + "/mixed").AsSpan().SequenceEqual(expected.ToArray())).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
        await Assert.That(rig.Files.MaxDataRequestsInFlight).IsLessThanOrEqualTo(SftpFileStream.MaxWriteBehind);
    }

    [Test]
    public async Task CopyToAsync_KeepsSixteenWritesInFlight_AndNoMore()
    {
        // The writes are held until the window is full, so the peak is reached whatever the timing, and the seventeenth cannot be sent
        // before the first is answered.
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f => f.HoldWrites = hold);
        var data = RandomNumberGenerator.GetBytes(40 * Chunk + 17);

        await using (var stream = await rig.Sftp.OpenWriteAsync("copy", Timeout()))
        {
            var copying = new PlainStream(data).CopyToAsync(stream, Timeout());
            var token = Timeout();
            while (rig.Files.MaxDataRequestsInFlight < SftpFileStream.MaxWriteBehind)
            {
                await Task.Delay(10, token);
            }

            await Assert.That(copying.IsCompleted).IsFalse(); // waiting for room
            hold.SetResult();
            await copying;
            await stream.FlushAsync(Timeout());
        }

        await Assert.That(rig.Files.FileData(Home + "/copy").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.MaxDataRequestsInFlight).IsEqualTo(SftpFileStream.MaxWriteBehind);
        await Assert.That(rig.Files.WriteOffsets.SequenceEqual(Enumerable.Range(0, 41).Select(i => (long)i * Chunk))).IsTrue(); // in offset order
    }

    [Test]
    public async Task CopyToAsync_OverLatency_Measure()
    {
        // A measurement, not a check: with SSHSHARP_MEASURE=1, prints how long 4 MiB takes over 25 ms of reply latency (in requests of
        // 32 KiB), copied into OpenWriteAsync and with UploadAsync. Nothing here asserts a time.
        if (Environment.GetEnvironmentVariable("SSHSHARP_MEASURE") != "1")
        {
            Skip.Test("Set SSHSHARP_MEASURE=1 to measure.");
            return;
        }

        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (32 * 1024, 32 * 1024);
            f.Latency = TimeSpan.FromMilliseconds(25);
        });
        var data = RandomNumberGenerator.GetBytes(4 * 1024 * 1024);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        await rig.Sftp.UploadAsync(new MemoryStream(data), "uploaded", cancellationToken: Timeout());
        var upload = clock.Elapsed;

        clock.Restart();
        await using (var stream = await rig.Sftp.OpenWriteAsync("copied", Timeout()))
        {
            await new PlainStream(data).CopyToAsync(stream, Timeout());
        }

        var copy = clock.Elapsed;
        Console.WriteLine($"4 MiB, 25 ms latency: UploadAsync {upload.TotalSeconds:F2} s, CopyToAsync into OpenWriteAsync {copy.TotalSeconds:F2} s");
        await Assert.That(rig.Files.FileData(Home + "/copied").AsSpan().SequenceEqual(data)).IsTrue();
    }

    /// <summary>A memory stream copied the way any stream is (<see cref="MemoryStream"/> writes itself in one call).</summary>
    private sealed class PlainStream(byte[] data) : MemoryStream(data);

    [Test]
    public async Task FlushAsync_WaitsForEveryWrite()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f => f.HoldWrites = hold);
        var data = RandomNumberGenerator.GetBytes(10 * Chunk);
        await using var stream = await rig.Sftp.OpenWriteAsync("flushed", Timeout());

        await stream.WriteAsync(data, Timeout()); // returns with the writes in flight
        var flushing = stream.FlushAsync(Timeout());
        await Assert.That(flushing.IsCompleted).IsFalse();
        hold.SetResult();
        await flushing;

        await Assert.That(rig.Files.FileData(Home + "/flushed").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.Fsyncs).IsEqualTo(1);
    }

    [Test]
    [Arguments("flush")]
    [Arguments("dispose")]
    [Arguments("sync dispose")]
    [Arguments("read")]
    [Arguments("set length")]
    [Arguments("length")]
    [Arguments("write")]
    [Arguments("seek")]
    public async Task AFailedWrite_SurfacesOnALaterCall_AndTheHandleIsClosed(string call)
    {
        await using var rig = await Rig.StartAsync(f => f.FailWriteAt = offset => offset == 2 * Chunk);
        var stream = (SftpFileStream)await rig.Sftp.OpenAsync("failing", FileMode.Create, FileAccess.ReadWrite, Timeout());
        var sevens = Enumerable.Repeat((byte)7, 5 * Chunk).ToArray();
        await stream.WriteAsync(sevens, Timeout()); // five requests in flight: this call does not wait for them

        SftpException? error;
        switch (call)
        {
            case "flush":
                error = await Assert.ThrowsAsync<SftpException>(async () => await stream.FlushAsync(Timeout()));
                break;
            case "dispose":
                error = await Assert.ThrowsAsync<SftpException>(async () => await stream.DisposeAsync());
                break;
            case "sync dispose":
                error = Assert.Throws<SftpException>(stream.Dispose);
                break;
            case "read":
                error = await Assert.ThrowsAsync<SftpException>(async () => await stream.ReadExactlyAsync(new byte[1], Timeout()));
                break;
            case "set length":
                error = Assert.Throws<SftpException>(() => stream.SetLength(1));
                break;
            case "length":
                error = await Assert.ThrowsAsync<SftpException>(async () => await stream.GetLengthAsync(Timeout()));
                break;
            case "write":
                // A write that fills the window waits for the oldest writes, and so meets the failed one.
                error = await Assert.ThrowsAsync<SftpException>(async () => await stream.WriteAsync(new byte[20 * Chunk], Timeout()));
                break;
            default:
                // A seek does not wait, but throws once the failure is in: it is tried until then.
                error = null;
                var token = Timeout();
                while (error is null)
                {
                    try
                    {
                        stream.Seek(0, SeekOrigin.Current);
                        await Task.Delay(10, token);
                    }
                    catch (SftpException ex)
                    {
                        error = ex;
                    }
                }

                break;
        }

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(error.Message).Contains("No space left on device");

        if (!call.Contains("dispose", StringComparison.Ordinal))
        {
            // Faulted: every later call throws the same failure; disposing then does not throw it again, and closes the handle.
            await Assert.That(async () => await stream.WriteAsync(new byte[1], Timeout())).Throws<SftpException>();
            await Assert.That(async () => await stream.FlushAsync(Timeout())).Throws<SftpException>();
            await Assert.That(() => stream.Position = 0).Throws<SftpException>();
            await stream.DisposeAsync();
        }

        stream.Dispose(); // once disposed, again is a no-op
        await rig.HandlesClosedAsync();
        var written = rig.Files.FileData(Home + "/failing")!;
        await Assert.That(written[2 * Chunk]).IsEqualTo((byte)0); // the server wrote nothing there, and the stream said so
        await Assert.That(written[3 * Chunk]).IsEqualTo((byte)7);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Disposing_WaitsForTheWritesInFlight(bool synchronously)
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(20));
        var data = RandomNumberGenerator.GetBytes(12 * Chunk + 5);

        var stream = await rig.Sftp.OpenWriteAsync("disposed", Timeout());
        await stream.WriteAsync(data, Timeout());
        if (synchronously)
        {
            stream.Dispose();
        }
        else
        {
            await stream.DisposeAsync();
        }

        // Every write was acknowledged before disposing returned; the close may still be on its way after a synchronous dispose.
        await Assert.That(rig.Files.FileData(Home + "/disposed").AsSpan().SequenceEqual(data)).IsTrue();
        await rig.HandlesClosedAsync();
    }

    [Test]
    public async Task SeeksReadsAndSetLength_AfterWrites_SeeTheWrittenData()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(5));
        var expected = RandomNumberGenerator.GetBytes(10 * Chunk);
        await using var stream = await rig.Sftp.OpenAsync("rw", FileMode.Create, FileAccess.ReadWrite, Timeout());

        await stream.WriteAsync(expected, Timeout());

        // Back over bytes still in flight: the later write wins.
        var patch = RandomNumberGenerator.GetBytes(3 * Chunk);
        stream.Seek(Chunk / 2, SeekOrigin.Begin);
        await stream.WriteAsync(patch, Timeout());
        patch.CopyTo(expected, Chunk / 2);

        // A read sees every write before it.
        stream.Position = 0;
        var read = new byte[expected.Length];
        await stream.ReadExactlyAsync(read, Timeout());
        await Assert.That(read.AsSpan().SequenceEqual(expected)).IsTrue();

        // SetLength comes after the writes in flight, so none of them lands past the new end.
        stream.Position = 8 * Chunk;
        await stream.WriteAsync(new byte[Chunk], Timeout());
        stream.SetLength(4 * Chunk);
        await Assert.That(stream.Length).IsEqualTo(4L * Chunk);
        await Assert.That(rig.Files.FileData(Home + "/rw").AsSpan().SequenceEqual(expected.AsSpan(0, 4 * Chunk))).IsTrue();
        await Assert.That(await ((SftpFileStream)stream).GetLengthAsync(Timeout())).IsEqualTo(4L * Chunk);
    }

    [Test]
    public async Task CancellingAWriteInFlight_FaultsTheStream_AndDisposingClosesTheHandle()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f => f.HoldWrites = hold);
        var stream = await rig.Sftp.OpenWriteAsync("cancelled", Timeout());
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();

        // Already cancelled: nothing is sent, and the stream goes on.
        await Assert.That(async () => await stream.WriteAsync(new byte[1], cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(rig.Files.MaxDataRequestsInFlight).IsEqualTo(0);

        using var cancelMidway = new CancellationTokenSource();
        var writing = stream.WriteAsync(new byte[40 * Chunk], cancelMidway.Token); // sends 16, then waits for room
        await Assert.That(writing.IsCompleted).IsFalse();
        await cancelMidway.CancelAsync();
        await Assert.That(async () => await writing).Throws<OperationCanceledException>();

        // Part of that write went out: the stream is faulted.
        await Assert.That(async () => await stream.WriteAsync(new byte[1], Timeout())).Throws<OperationCanceledException>();
        hold.SetResult();
        await stream.DisposeAsync(); // reported already: not thrown again
        await rig.HandlesClosedAsync();
        await Assert.That(rig.Files.WriteOffsets.Count).IsEqualTo(SftpFileStream.MaxWriteBehind);
    }

    [Test]
    public async Task CancellingAFlush_LeavesTheWritesInFlight_AndTheStreamUsable()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f => f.HoldWrites = hold);
        var data = RandomNumberGenerator.GetBytes(4 * Chunk);
        await using var stream = await rig.Sftp.OpenWriteAsync("flush-cancelled", Timeout());
        await stream.WriteAsync(data, Timeout());

        using var cancel = new CancellationTokenSource();
        var flushing = stream.FlushAsync(cancel.Token);
        await cancel.CancelAsync();
        await Assert.That(async () => await flushing).Throws<OperationCanceledException>();

        hold.SetResult();
        await stream.WriteAsync(data, Timeout());
        await stream.FlushAsync(Timeout());
        await Assert.That(rig.Files.FileData(Home + "/flush-cancelled").AsSpan().SequenceEqual([.. data, .. data])).IsTrue();
    }
}
