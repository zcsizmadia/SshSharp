using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// SFTP requests built in pooled buffers (<see cref="SftpRequestFrame"/>) and DATA replies read into pooled buffers
/// (<see cref="SftpResponse"/>): content intact around chunk boundaries, through failures, cancellation, the streams' read-ahead and
/// write-behind, and transfers sharing one session. In the instrumented build (<c>-p:SshSharpInstrument=true</c>) a buffer returned twice
/// or changed while out is reported, and a returned reply's buffer is overwritten, so a slice used after its return shows up as wrong
/// content here.
/// </summary>
public sealed class SftpBufferPoolingTests
{
    private const string Home = FakeSftpServer.Home;
    private const int Chunk = 8 * 1024;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        private readonly int _reportsBefore = Instrumentation.Reports;

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

        /// <summary>No double return or buffer changed while out was reported meanwhile (always true in a build without the checks).</summary>
        public async Task NothingReportedAsync() => await Assert.That(Instrumentation.Reports).IsEqualTo(_reportsBefore);

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    private static byte[] Data(int size, int seed)
    {
        var data = new byte[size];
        new Random(seed).NextBytes(data);
        return data;
    }

    private static async Task<byte[]> DownloadAsync(SftpClient sftp, string path)
    {
        var received = new MemoryStream();
        await sftp.DownloadAsync(path, received, cancellationToken: Timeout());
        return received.ToArray();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(Chunk - 1)]
    [Arguments(Chunk)]
    [Arguments(Chunk + 1)]
    [Arguments(5 * Chunk)]
    [Arguments((5 * Chunk) + 3)]
    public async Task UploadAndDownload_AroundChunkBoundaries_KeepEveryByte(int size)
    {
        await using var rig = await Rig.StartAsync();
        var data = Data(size, size);

        await Assert.That(await rig.Sftp.UploadAsync(new MemoryStream(data), "up", cancellationToken: Timeout())).IsEqualTo(size);
        await Assert.That(rig.Files.FileData(Home + "/up").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That((await DownloadAsync(rig.Sftp, "up")).AsSpan().SequenceEqual(data)).IsTrue();

        // The same through the streams: write-behind in one write and in odd pieces, read-ahead with a buffer that never lines up.
        await using (var stream = await rig.Sftp.OpenWriteAsync("whole", Timeout()))
        {
            await stream.WriteAsync(data, Timeout());
        }

        await using (var stream = await rig.Sftp.OpenWriteAsync("pieces", Timeout()))
        {
            for (var offset = 0; offset < size; offset += 1000)
            {
                await stream.WriteAsync(data.AsMemory(offset, Math.Min(1000, size - offset)), Timeout());
            }
        }

        await Assert.That(rig.Files.FileData(Home + "/whole").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.FileData(Home + "/pieces").AsSpan().SequenceEqual(data)).IsTrue();

        var read = new MemoryStream();
        await using (var stream = await rig.Sftp.OpenReadAsync("up", Timeout()))
        {
            var buffer = new byte[1000];
            while (await stream.ReadAsync(buffer, Timeout()) is var n and > 0)
            {
                read.Write(buffer, 0, n);
            }
        }

        await Assert.That(read.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task OpenSshSizedChunks_RoundTrip()
    {
        // OpenSSH's 255 KiB reads and writes: frames and replies a few bytes over 255 KiB, still within the pool's 256 KiB arrays.
        await using var rig = await Rig.StartAsync(f => f.Limits = (SftpProtocol.MaxChunk, SftpProtocol.MaxChunk));
        var data = Data((3 * SftpProtocol.MaxChunk) + 11, 255);

        await rig.Sftp.UploadAsync(new MemoryStream(data), "big", cancellationToken: Timeout());
        await Assert.That(rig.Files.FileData(Home + "/big").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That((await DownloadAsync(rig.Sftp, "big")).AsSpan().SequenceEqual(data)).IsTrue();

        var read = new MemoryStream();
        await using (var stream = await rig.Sftp.OpenReadAsync("big", Timeout()))
        {
            await stream.CopyToAsync(read, Timeout());
        }

        await Assert.That(read.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task DownloadFailingMidway_LeavesTheNextTransfersIntact()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(2));
        var data = Data(20 * Chunk, 1);
        rig.Files.AddFile(Home + "/f", data);
        rig.Files.FailReadAt = offset => offset == 6 * Chunk;

        // Replies in flight behind the failure are awaited and their buffers returned; the read-ahead drops its own.
        await Assert.That(async () => await DownloadAsync(rig.Sftp, "f")).Throws<SftpException>();
        await Assert.That(async () =>
        {
            await using var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
            await stream.CopyToAsync(Stream.Null, Timeout());
        }).Throws<SftpException>();

        rig.Files.FailReadAt = null;
        await Assert.That((await DownloadAsync(rig.Sftp, "f")).AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task MalformedDataReply_FailsTheRead_AndReturnsItsBuffer()
    {
        // A DATA reply longer than the read asked for: rejected after it was read into a pooled buffer, which goes back.
        await using var rig = await Rig.StartAsync();
        rig.Files.AddFile(Home + "/f", Data(4 * Chunk, 2));
        rig.Files.RawFrame = packet =>
        {
            if (packet[0] != SftpProtocol.Read)
            {
                return null;
            }

            var id = packet.AsSpan(1, 4).ToArray();
            byte[] body = [SftpProtocol.Data, .. id, 0, 0, 0x40, 0, .. new byte[0x4000]]; // 16 KiB of data for an 8 KiB read
            return [0, 0, (byte)(body.Length >> 8), (byte)body.Length, .. body];
        };

        await Assert.That(async () => await DownloadAsync(rig.Sftp, "f")).Throws<SshException>();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task UploadFailingMidway_LeavesTheNextTransfersIntact()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(2));
        var data = Data(20 * Chunk, 3);
        rig.Files.FailWriteAt = offset => offset == 6 * Chunk;

        await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(data), "f", cancellationToken: Timeout())).Throws<SftpException>();
        await Assert.That(async () =>
        {
            await using var stream = await rig.Sftp.OpenWriteAsync("g", Timeout());
            await stream.WriteAsync(data, Timeout());
        }).Throws<SftpException>();

        rig.Files.FailWriteAt = null;
        await rig.Sftp.UploadAsync(new MemoryStream(data), "f", cancellationToken: Timeout());
        await Assert.That(rig.Files.FileData(Home + "/f").AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task CancelledTransfers_LeaveTheNextOnesIntact()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(5));
        var data = Data(40 * Chunk, 4);
        rig.Files.AddFile(Home + "/f", data);

        // Cancelled once the first data has arrived or been acknowledged; a window of two keeps the transfer from finishing first.
        using (var cancel = new CancellationTokenSource())
        {
            var options = new SftpTransferOptions { MaxRequestsInFlight = 2, Progress = new SynchronousProgress<SftpTransferProgress>(_ => cancel.Cancel()) };
            await Assert.That(async () => await rig.Sftp.DownloadAsync("f", Stream.Null, options, cancel.Token)).Throws<OperationCanceledException>();
        }

        using (var cancel = new CancellationTokenSource())
        {
            var options = new SftpTransferOptions { MaxRequestsInFlight = 2, Progress = new SynchronousProgress<SftpTransferProgress>(_ => cancel.Cancel()) };
            await Assert.That(async () => await rig.Sftp.UploadAsync(new MemoryStream(data), "g", options, cancel.Token)).Throws<OperationCanceledException>();
        }

        await Assert.That((await DownloadAsync(rig.Sftp, "f")).AsSpan().SequenceEqual(data)).IsTrue();
        await rig.Sftp.UploadAsync(new MemoryStream(data), "g", cancellationToken: Timeout());
        await Assert.That(rig.Files.FileData(Home + "/g").AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task ReadAhead_SeeksAndShortReads_ReturnTheRightBytes()
    {
        await using var rig = await Rig.StartAsync(f => f.ShortReads = true);
        var data = Data((10 * Chunk) + 5, 5);
        rig.Files.AddFile(Home + "/f", data);

        await using var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
        foreach (var (at, count) in new[] { (0, 100), (Chunk - 10, 20), (5 * Chunk, 3 * Chunk), (3, 1), ((10 * Chunk) - 2, 7), (Chunk, Chunk) })
        {
            stream.Position = at;
            var buffer = new byte[count];
            var total = await stream.ReadAtLeastAsync(buffer, count, throwOnEndOfStream: false, Timeout());
            await Assert.That(buffer.AsSpan(0, total).SequenceEqual(data.AsSpan(at, Math.Min(count, data.Length - at)))).IsTrue();
        }

        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task ReadAhead_DisposedDuringARead_ReleasesItsBuffersOnce()
    {
        // The reply the read waits for arrives after the stream is disposed: the read in progress keeps it until it ends.
        await using var rig = await Rig.StartAsync(f => f.ReplyDelay = (request, _) => request == SftpProtocol.Read ? TimeSpan.FromMilliseconds(200) : TimeSpan.Zero);
        var data = Data(8 * Chunk, 6);
        rig.Files.AddFile(Home + "/f", data);

        for (var i = 0; i < 3; i++)
        {
            var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
            var buffer = new byte[Chunk];
            var reading = stream.ReadAsync(buffer, Timeout()).AsTask();
            await stream.DisposeAsync();
            try
            {
                var n = await reading;
                await Assert.That(buffer.AsSpan(0, n).SequenceEqual(data.AsSpan(0, n))).IsTrue();
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SshException)
            {
                // Disposed first, or the close won the race to the server.
            }
        }

        await Assert.That((await DownloadAsync(rig.Sftp, "f")).AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task ReadAhead_CancelledWait_LeavesTheReplyToTheNextRead()
    {
        // The reply the cancelled read waited for stays with the read-ahead; the next read takes it, and the bytes are right. The server
        // holds the reads back on a fake clock, so the reply cannot come before the cancellation, however loaded the machine.
        var time = new FakeTimeProvider();
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Time = time;
            f.ReplyDelay = (request, _) => request == SftpProtocol.Read ? TimeSpan.FromMilliseconds(200) : TimeSpan.Zero;
        });
        var data = Data((6 * Chunk) + 1, 9);
        rig.Files.AddFile(Home + "/f", data);

        await using var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
        using (var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(20)))
        {
            await Assert.That(async () => await stream.ReadAsync(new byte[Chunk], cancel.Token)).Throws<OperationCanceledException>();
        }

        rig.Files.ReplyDelay = null; // the rest come at once, and the clock lets out the one held back
        var read = new MemoryStream();
        var copy = stream.CopyToAsync(read, Timeout());
        await FakeClock.AdvanceUntilAsync(time, TimeSpan.FromMilliseconds(200), () => copy.IsCompleted);
        await copy;
        await Assert.That(read.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task ConcurrentReadAhead_IsRefused()
    {
        // The server holds the reads back on a fake clock, so the first read is still waiting when the second comes, on any machine.
        var time = new FakeTimeProvider();
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Time = time;
            f.ReplyDelay = (request, _) => request == SftpProtocol.Read ? TimeSpan.FromMilliseconds(200) : TimeSpan.Zero;
        });
        rig.Files.AddFile(Home + "/f", Data(4 * Chunk, 7));

        await using var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
        var first = stream.ReadAsync(new byte[10], Timeout()).AsTask();
        await Assert.That(async () => await stream.ReadAsync(new byte[10], Timeout())).Throws<InvalidOperationException>();
        rig.Files.ReplyDelay = null;
        await FakeClock.AdvanceUntilAsync(time, TimeSpan.FromMilliseconds(200), () => first.IsCompleted);
        await Assert.That(await first).IsEqualTo(10);
    }

    [Test]
    public async Task WriteBehind_FailureAmongManyInFlight_LeavesTheNextStreamIntact()
    {
        await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(2));
        var data = Data(40 * Chunk, 8);
        rig.Files.FailWriteAt = offset => offset == 20 * Chunk;

        await Assert.That(async () =>
        {
            await using var stream = await rig.Sftp.OpenWriteAsync("f", Timeout());
            await new MemoryStream(data).CopyToAsync(stream, Timeout());
            await stream.FlushAsync(Timeout());
        }).Throws<SftpException>();

        rig.Files.FailWriteAt = null;
        await using (var stream = await rig.Sftp.OpenWriteAsync("f", Timeout()))
        {
            await new MemoryStream(data).CopyToAsync(stream, Timeout());
        }

        await Assert.That(rig.Files.FileData(Home + "/f").AsSpan().SequenceEqual(data)).IsTrue();
        await rig.NothingReportedAsync();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConcurrentTransfers_OnOneSession_AreIntact(bool shortReads)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Latency = TimeSpan.FromMilliseconds(1);
            f.ShortReads = shortReads;
        });
        var files = Enumerable.Range(0, 8).Select(i => Data((i * 3 * Chunk) + (i * 37), 100 + i)).ToArray();
        for (var i = 0; i < files.Length; i++)
        {
            rig.Files.AddFile($"{Home}/down{i}", files[i]);
        }

        // Downloads, uploads and streams at once, all matched to their replies by id over one channel.
        var downloads = files.Select((_, i) => DownloadAsync(rig.Sftp, $"down{i}")).ToArray();
        var uploads = files.Select((data, i) => rig.Sftp.UploadAsync(new MemoryStream(data), $"up{i}", cancellationToken: Timeout())).ToArray();
        var streams = files.Select(async (data, i) =>
        {
            await using var stream = await rig.Sftp.OpenWriteAsync($"stream{i}", Timeout());
            await new MemoryStream(data).CopyToAsync(stream, 3000, Timeout());
        }).ToArray();
        await Task.WhenAll(downloads);
        await Task.WhenAll(uploads);
        await Task.WhenAll(streams);

        for (var i = 0; i < files.Length; i++)
        {
            await Assert.That(downloads[i].Result.AsSpan().SequenceEqual(files[i])).IsTrue();
            await Assert.That(rig.Files.FileData($"{Home}/up{i}").AsSpan().SequenceEqual(files[i])).IsTrue();
            await Assert.That(rig.Files.FileData($"{Home}/stream{i}").AsSpan().SequenceEqual(files[i])).IsTrue();
        }

        await rig.NothingReportedAsync();
    }

    [Test]
    public async Task DirectoryTransfers_WithManyFilesAtOnce_AreIntact()
    {
        var local = Path.Combine(Path.GetTempPath(), "sshsharp-sftppool-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(local, "up", "sub"));
            var sizes = new[] { 0, 1, Chunk - 1, Chunk, Chunk + 1, 7 * Chunk, (7 * Chunk) + 9, 100, 3 * Chunk, 20_000 };
            var files = new Dictionary<string, byte[]>();
            for (var i = 0; i < sizes.Length; i++)
            {
                var name = (i % 2 == 0 ? "sub/" : string.Empty) + $"f{i}";
                files[name] = Data(sizes[i], 200 + i);
                await File.WriteAllBytesAsync(Path.Combine(local, "up", name), files[name], Timeout());
            }

            await using var rig = await Rig.StartAsync(f => f.Latency = TimeSpan.FromMilliseconds(1));
            var options = new SftpTransferOptions { MaxConcurrentFiles = 8, MaxRequestsInFlight = 16 };
            await rig.Sftp.UploadDirectoryAsync(Path.Combine(local, "up"), "tree", options, Timeout());
            await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(local, "down"), options, Timeout());

            foreach (var (name, data) in files)
            {
                await Assert.That(rig.Files.FileData($"{Home}/tree/{name}").AsSpan().SequenceEqual(data)).IsTrue();
                await Assert.That((await File.ReadAllBytesAsync(Path.Combine(local, "down", name), Timeout())).AsSpan().SequenceEqual(data)).IsTrue();
            }

            await rig.NothingReportedAsync();
        }
        finally
        {
            Directory.Delete(local, recursive: true);
        }
    }

    [Test]
    public async Task RequestFrame_GrowsKeepingWhatWasWritten_AndFillsInLengthAndId()
    {
        using var frame = SftpRequestFrame.Start(SftpProtocol.Stat);
        var name = new string('x', 1000); // more than the first buffer
        frame.Writer.WriteString(name);
        var sent = frame.Complete(0x01020304).ToArray();

        await Assert.That(sent.Length).IsEqualTo(SftpRequestFrame.HeaderLength + 4 + 1000);
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sent)).IsEqualTo((uint)(sent.Length - 4));
        await Assert.That(sent[4]).IsEqualTo(SftpProtocol.Stat);
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(5))).IsEqualTo(0x01020304u);
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(9))).IsEqualTo(1000u);
        await Assert.That(sent.AsSpan(13).IndexOfAnyExcept((byte)'x')).IsEqualTo(-1);
    }

    [Test]
    public async Task RequestFrame_PatchesOnlyWhatWasWritten_AndDisposesOnce()
    {
        var frame = SftpRequestFrame.Start(SftpProtocol.Write);
        frame.Writer.WriteUInt32(0);
        frame.PatchUInt32(SftpRequestFrame.HeaderLength, 42);
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(frame.Complete(1).Span[9..])).IsEqualTo(42u);
        await Assert.That(() => frame.PatchUInt32(SftpRequestFrame.HeaderLength + 1, 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => frame.PatchUInt32(4, 0)).Throws<ArgumentOutOfRangeException>(); // the header is the channel's

        frame.Dispose();
        frame.Dispose(); // once only: a second return would hand one buffer to two renters
        await Assert.That(() => frame.Complete(2)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task PooledResponse_ReturnsOnce_AndRefusesUseAfterwards()
    {
        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(64);
        Instrumentation.Rented(buffer, nameof(PooledResponse_ReturnsOnce_AndRefusesUseAfterwards));
        buffer[0] = SftpProtocol.Data;
        var reply = SftpResponse.Pooled(buffer, 20);
        await Assert.That(reply.Packet.Length).IsEqualTo(20);
        await Assert.That(reply.Type).IsEqualTo(SftpProtocol.Data);

        reply.Dispose();
        reply.Dispose();
        await Assert.That(() => reply.Packet).Throws<ObjectDisposedException>();

        var plain = new SftpResponse(SftpProtocol.Status, new byte[9]);
        plain.Dispose(); // nothing to return: still readable
        await Assert.That(plain.Packet.Length).IsEqualTo(9);
    }

    [Test]
    public async Task WriteFrame_OfOpenSshSize_AllocatesNoLargeArray()
    {
        if (Instrumentation.Enabled)
        {
            return; // the checks allocate
        }

        var data = new byte[SftpProtocol.MaxChunk];
        var lowest = double.MaxValue;
        for (var round = 0; round < 5; round++)
        {
            const int iterations = 50;
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < iterations; i++)
            {
                using var frame = SftpRequestFrame.Start(SftpProtocol.Write, SftpRequestFrame.HeaderLength + 4 + 16 + 8 + 4 + data.Length);
                frame.Writer.WriteString(data.AsSpan(0, 16)); // a handle
                frame.Writer.WriteUInt64(0);
                frame.Writer.WriteString(data);
                _ = frame.Complete(1);
            }

            lowest = Math.Min(lowest, (GC.GetAllocatedBytesForCurrentThread() - before) / (double)iterations);
        }

        // The frame object only; the 255 KiB buffer comes from the pool (before, each write cost three large arrays).
        await Assert.That(lowest).IsLessThan(256);
    }

    private sealed class SynchronousProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
