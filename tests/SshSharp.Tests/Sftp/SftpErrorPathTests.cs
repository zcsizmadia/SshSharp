using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Replies a well-behaved server rarely sends, and the cleanup each failure needs: status without text, unexpected reply types, failed writes and stats.</summary>
public sealed class SftpErrorPathTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;
    private const byte Open = 3;
    private const byte Read = 5;
    private const byte Write = 6;
    private const byte FStat = 8;
    private const byte MkDir = 14;
    private const byte RealPath = 16;
    private const byte Stat = 17;
    private const byte Extended = 200;

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-sftp-err-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, bool open = true)
        {
            var rig = new Rig();
            rig.Files.AddFile(Home + "/f", [1, 2, 3]);
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = "secret",
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            }, leaveOpen: true, Timeout());
            if (open)
            {
                rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            }

            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            if (Sftp is not null)
            {
                await Sftp.DisposeAsync();
            }

            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    /// <summary>A framed reply to <paramref name="request"/> (same request id): its type and the body after the id.</summary>
    private static byte[] Reply(byte[] request, byte type, Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new SshWriter(buffer);
        writer.WriteByte(type);
        writer.WriteUInt32(BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(1)));
        body(writer);
        var frame = new byte[4 + buffer.WrittenCount];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(frame.AsSpan(4));
        return frame;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition() && deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    [Test]
    [Arguments(SftpStatusCode.NoSuchFile, "No such file")]
    [Arguments(SftpStatusCode.PermissionDenied, "Permission denied")]
    [Arguments(SftpStatusCode.OperationUnsupported, "Operation unsupported")]
    [Arguments(SftpStatusCode.EndOfFile, "End of file")]
    [Arguments(SftpStatusCode.BadMessage, "Failure")]
    public async Task AStatusWithoutText_IsDescribedByItsCode(SftpStatusCode code, string described)
    {
        // Some servers send only the code (the message is optional in their replies): the error still says what happened.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == Stat ? Reply(request, 101, w => w.WriteUInt32((uint)code)) : null);

        var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.GetAttributesAsync("f", cancellationToken: Timeout()));

        await Assert.That(error!.Status).IsEqualTo(code);
        await Assert.That(error.Message).Contains(described);
        await Assert.That(error.Path).IsEqualTo("f");
    }

    [Test]
    public async Task AReplyOfTheWrongType_WhereNamesWereExpected_IsAProtocolError()
    {
        // REALPATH answered with ATTRS (105): neither the names it asked for nor a status.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == RealPath ? Reply(request, 105, w => w.WriteUInt32(0)) : null);

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Sftp.GetFullPathAsync(".", Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("message 105");
    }

    [Test]
    public async Task OpeningAFileWhoseSizeCannotBeRead_ClosesTheHandle()
    {
        // OpenAsync reads the size once (FSTAT); when that fails, the handle it already holds is closed, not leaked.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == FStat ? Reply(request, 101, w => { w.WriteUInt32(4); w.WriteString("disk on fire"); w.WriteString("en"); }) : null);

        await Assert.That(async () => await rig.Sftp.OpenReadAsync("f", Timeout())).Throws<SftpException>().WithMessageContaining("disk on fire");
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task TruncateAndOpenOrCreate_OpenAsFileStreamDoes_AndUnknownModesAreRejected()
    {
        await using var rig = await Rig.StartAsync();

        await using (var created = await rig.Sftp.OpenAsync("new", FileMode.OpenOrCreate, FileAccess.Write, Timeout()))
        {
            await created.WriteAsync(new byte[] { 9, 9 });
        }

        await using (var truncated = await rig.Sftp.OpenAsync("f", FileMode.Truncate, FileAccess.Write, Timeout()))
        {
            await Assert.That(truncated.Length).IsEqualTo(0);
        }

        await Assert.That(rig.Files.FileData(Home + "/new")).IsEquivalentTo(new byte[] { 9, 9 });
        await Assert.That(rig.Files.FileData(Home + "/f")).IsEmpty();
        await Assert.That(async () => await rig.Sftp.OpenAsync("f", (FileMode)99, FileAccess.Read, Timeout())).Throws<ArgumentOutOfRangeException>();
        await Assert.That(async () => await rig.Sftp.OpenAsync("f", FileMode.Open, (FileAccess)99, Timeout())).Throws<ArgumentOutOfRangeException>();
        await Assert.That(async () => await rig.Sftp.OpenAsync("f", FileMode.Truncate, FileAccess.Read, Timeout())).Throws<ArgumentException>();
    }

    [Test]
    public async Task AnUploadWithOneRequestInFlight_WaitsForEachWrite()
    {
        await using var rig = await Rig.StartAsync(f => f.Limits = (32 * 1024, 32 * 1024));
        var data = new byte[200 * 1024];
        Random.Shared.NextBytes(data);

        var written = await rig.Sftp.UploadAsync(new MemoryStream(data), "up.bin", new SftpTransferOptions { MaxRequestsInFlight = 1 }, Timeout());

        await Assert.That(written).IsEqualTo(data.Length);
        await Assert.That(rig.Files.MaxOutstanding).IsEqualTo(1);
        await Assert.That(rig.Files.FileData(Home + "/up.bin")!.SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task AWriteTheServerFails_StopsTheUpload_AfterTheOtherWritesAreAnswered()
    {
        // The third WRITE fails (a full disk, say); the writes already sent are still answered before the upload reports the failure,
        // so none of their replies arrive after the handle is closed.
        var writes = 0;
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (32 * 1024, 32 * 1024);
            f.RawFrame = request => request[0] == Write && Interlocked.Increment(ref writes) == 3
                ? Reply(request, 101, w => { w.WriteUInt32(4); w.WriteString("No space left on device"); w.WriteString("en"); })
                : null;
        });

        var error = await Assert.ThrowsAsync<SftpException>(async () =>
            await rig.Sftp.UploadAsync(new MemoryStream(new byte[1024 * 1024]), "up.bin", new SftpTransferOptions { MaxRequestsInFlight = 8 }, Timeout()));

        await Assert.That(error!.Message).Contains("No space left on device");
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
        await Assert.That(await rig.Sftp.ExistsAsync("f", Timeout())).IsTrue(); // the session is fine
    }

    [Test]
    public async Task AFreshDownloadThatFails_LeavesNoLocalFile()
    {
        var data = new byte[256 * 1024];
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.FailReadAt = offset => offset >= 64 * 1024;
        });
        var local = Path.Combine(_dir, "big.bin");

        await Assert.That(async () => await rig.Sftp.DownloadFileAsync("big.bin", local, cancellationToken: Timeout())).Throws<SftpException>();

        await Assert.That(File.Exists(local)).IsFalse();
    }

    [Test]
    public async Task ACancelledOpenThatFailsAnyway_LeavesNothingToClose()
    {
        // The open the caller gave up on is refused by the server (no such file): there is no handle, and nothing is closed.
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f => f.HoldOpens = hold);

        using var cancel = new CancellationTokenSource();
        var opening = rig.Sftp.OpenReadAsync("missing", cancel.Token);
        await WaitUntilAsync(() => rig.Files.HeldOpens == 1);
        await cancel.CancelAsync();
        await Assert.That(async () => await opening).Throws<OperationCanceledException>();
        hold.SetResult();

        // The session goes on; no CLOSE was sent for the refused open.
        await Assert.That(await rig.Sftp.ExistsAsync("f", Timeout())).IsTrue();
        await Assert.That(rig.Files.Requests.Count(r => r == 4)).IsEqualTo(0);
    }

    [Test]
    public async Task ACancelledOpenAnsweredWithAMalformedHandle_IsDropped()
    {
        // The late reply to an abandoned OPEN claims a 1000-byte handle and holds none: nothing can be closed, and the session goes on.
        using var entered = new SemaphoreSlim(0);
        using var release = new SemaphoreSlim(0);
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
        {
            if (request[0] != Open)
            {
                return null;
            }

            entered.Release();
            release.Wait(TimeSpan.FromSeconds(30));
            return Reply(request, 102, w => w.WriteUInt32(1000));
        });

        using var cancel = new CancellationTokenSource();
        var opening = rig.Sftp.OpenReadAsync("f", cancel.Token);
        await entered.WaitAsync(Timeout());
        await cancel.CancelAsync();
        await Assert.That(async () => await opening).Throws<OperationCanceledException>();
        release.Release();

        await Assert.That(await rig.Sftp.ExistsAsync("f", Timeout())).IsTrue();
        await Assert.That(rig.Files.Requests.Count(r => r == 4)).IsEqualTo(0);
    }

    [Test]
    public async Task AMalformedLimitsReply_FailsOpening_AndClosesTheSession()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == Extended && PathOf(request) == "limits@openssh.com" ? Reply(request, 201, w => w.WriteUInt32(5)) : null, open: false);

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Client.OpenSftpAsync(Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(rig.Files.Sessions).IsEqualTo(1);
        await WaitUntilAsync(() => rig.Files.OpenSessions == 0); // the session was closed, not left open on the server
    }

    [Test]
    public async Task ASessionEndingMidUpload_FailsItAsAProtocolError()
    {
        // The second WRITE is answered with a broken frame, which ends the session: the writes still in flight fail with it, and the
        // upload reports that failure, not a status of its own.
        var writes = 0;
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (32 * 1024, 32 * 1024);
            f.RawFrame = request => request[0] == Write && Interlocked.Increment(ref writes) == 2 ? [0, 0, 0, 0] : null;
        });

        var error = await Assert.ThrowsAsync<SshException>(async () =>
            await rig.Sftp.UploadAsync(new MemoryStream(new byte[1024 * 1024]), "up.bin", new SftpTransferOptions { MaxRequestsInFlight = 8 }, Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error).IsNotTypeOf<SftpException>();
    }

    [Test]
    public async Task ASegmentThatFails_StopsTheDownload_AndRemovesTheLocalFile()
    {
        var data = new byte[4 * 1024 * 1024];
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.FailReadAt = offset => offset >= 3 * 1024 * 1024; // in the second half
        });
        var local = Path.Combine(_dir, "big.bin");

        var error = await Assert.ThrowsAsync<SftpException>(async () =>
            await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 2 }, Timeout()));

        await Assert.That(error!.Message).DoesNotContain("cancel");
        await Assert.That(File.Exists(local)).IsFalse();
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0);
    }

    [Test]
    public async Task AFileThatShrinksDuringASegmentedDownload_FailsIt()
    {
        // The first half reaches the end of the file at 1 MiB (it was cut short meanwhile): the download fails rather than leave a gap.
        var data = new byte[4 * 1024 * 1024];
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.RawFrame = request => request[0] == Read && ReadOffsetOf(request) is >= 1024 * 1024 and < 2 * 1024 * 1024
                ? Reply(request, 101, w => { w.WriteUInt32(1); w.WriteString("EOF"); w.WriteString("en"); })
                : null;
        });
        var local = Path.Combine(_dir, "big.bin");

        var error = await Assert.ThrowsAsync<IOException>(async () =>
            await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 2 }, Timeout()));

        await Assert.That(error!.Message).Contains("became shorter");
        await Assert.That(File.Exists(local)).IsFalse();
    }

    [Test]
    public async Task AStreamOverAFileWithoutASize_ReadsButCannotSayItsLength()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == FStat ? Reply(request, 105, w => w.WriteUInt32(0)) : null);

        await using var stream = (SftpFileStream)await rig.Sftp.OpenReadAsync("f", Timeout());

        // Not seekable, so callers do not ask for the length (CopyToAsync did, and failed, when the stream said it could seek).
        await Assert.That(stream.CanSeek).IsFalse();
        await Assert.That(() => stream.Length).Throws<NotSupportedException>();
        await Assert.That(() => stream.Seek(0, SeekOrigin.End)).Throws<NotSupportedException>();
        await Assert.That(async () => await stream.GetLengthAsync(Timeout())).Throws<NotSupportedException>();
        var copy = new MemoryStream();
        await stream.CopyToAsync(copy);
        await Assert.That(copy.ToArray()).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task ASegmentedDownload_OverAnExistingFile_FailsBeforeOpeningSessions()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", new byte[4 * 1024 * 1024]));
        var opened = 0;
        var open = rig.Sftp.OpenSibling!;
        rig.Sftp.OpenSibling = ct =>
        {
            Interlocked.Increment(ref opened);
            return open(ct);
        };
        var local = Path.Combine(_dir, "big.bin");
        await File.WriteAllTextAsync(local, "keep me");

        await Assert.That(async () => await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 4, Overwrite = false }, Timeout()))
            .Throws<IOException>().WithMessageContaining("already exists");

        await Assert.That(opened).IsEqualTo(0);
        await Assert.That(await File.ReadAllTextAsync(local)).IsEqualTo("keep me");
    }

    [Test]
    public async Task ASegmentedDownload_OfAFileReplacedMeanwhile_Fails()
    {
        // The first FSTAT (on the first handle) sees the file as it was; the later ones, on the handles the other sessions open by
        // path, see another file there.
        var data = new byte[4 * 1024 * 1024];
        var fstats = 0;
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.RawFrame = request => request[0] == FStat && Interlocked.Increment(ref fstats) > 1
                ? Reply(request, 105, w => { w.WriteUInt32(1); w.WriteUInt64((ulong)data.Length + 1); })
                : null;
        });
        var local = Path.Combine(_dir, "big.bin");

        var error = await Assert.ThrowsAsync<IOException>(async () =>
            await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 2 }, Timeout()));

        await Assert.That(error!.Message).Contains("changed during the download");
        await Assert.That(File.Exists(local)).IsFalse();
    }

    [Test]
    public async Task TheFileSystemStreamOverAFileWithoutASize_StillSeeks()
    {
        // The open handle's FSTAT has no size; the path's STAT has it.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == FStat ? Reply(request, 105, w => w.WriteUInt32(0)) : null);
        var fs = new SshSharp.IO.Abstractions.SftpFileSystem(rig.Sftp);

        await using var stream = fs.FileStream.New("f", FileMode.Open, FileAccess.Read);

        await Assert.That(stream.CanSeek).IsTrue();
        stream.Position = 1;
        await Assert.That(stream.ReadByte()).IsEqualTo(2);
        await Assert.That(stream.Seek(-1, SeekOrigin.End)).IsEqualTo(2);
        await Assert.That(stream.ReadByte()).IsEqualTo(3);
        await Assert.That(stream.Length).IsEqualTo(3);
        stream.Position = 0;
        var copy = new MemoryStream();
        await stream.CopyToAsync(copy);
        await Assert.That(copy.ToArray()).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task GetLengthAsync_SeesAnotherWritersChange()
    {
        await using var rig = await Rig.StartAsync();
        await using var stream = (SftpFileStream)await rig.Sftp.OpenReadAsync("f", Timeout());
        await Assert.That(stream.Length).IsEqualTo(3);

        rig.Files.AddFile(Home + "/f", new byte[10]); // written by someone else

        await Assert.That(stream.Length).IsEqualTo(3); // as known when opened
        await Assert.That(await stream.GetLengthAsync(Timeout())).IsEqualTo(10);
        await Assert.That(stream.Length).IsEqualTo(10);
    }

    [Test]
    public async Task AFileStream_RefusesWhatItWasNotOpenedFor()
    {
        await using var rig = await Rig.StartAsync();
        await using var reading = await rig.Sftp.OpenReadAsync("f", Timeout());
        await using var writing = await rig.Sftp.OpenWriteAsync("w", Timeout());

        await Assert.That(async () => await writing.ReadAsync(new byte[1])).Throws<NotSupportedException>();
        await Assert.That(async () => await reading.WriteAsync(new byte[1])).Throws<NotSupportedException>();
        await Assert.That(() => reading.SetLength(0)).Throws<NotSupportedException>();
        await Assert.That(() => reading.Seek(0, (SeekOrigin)9)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => reading.Read(new byte[1], 0, 1)).Throws<NotSupportedException>();
        await Assert.That(() => writing.Write(new byte[1], 0, 1)).Throws<NotSupportedException>();

        // An empty read asks the server nothing.
        var before = rig.Files.Requests.Count;
        await Assert.That(await reading.ReadAsync(Memory<byte>.Empty)).IsEqualTo(0);
        await Assert.That(rig.Files.Requests.Count).IsEqualTo(before);
        await Assert.That(rig.Files.FileData(Home + "/f")).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task AFileStream_ReadsAndWritesThroughTheArrayOverloads()
    {
        await using var rig = await Rig.StartAsync();
        await using var stream = await rig.Sftp.OpenAsync("f", FileMode.Open, FileAccess.ReadWrite, Timeout());

        stream.Seek(1, SeekOrigin.Begin);
#pragma warning disable CA1835 // the array overloads are what is tested
        await stream.WriteAsync(new byte[] { 0, 7, 8, 0 }, 1, 2, Timeout());
        stream.Flush(); // does not wait for the write in flight; the read below does
        stream.Position = 0;
        var buffer = new byte[8];
        var read = await stream.ReadAsync(buffer, 2, 6, Timeout());
#pragma warning restore CA1835

        await Assert.That(read).IsEqualTo(3);
        await Assert.That(buffer[2..5]).IsEquivalentTo(new byte[] { 1, 7, 8 });
    }

    [Test]
    public async Task UploadingATreeOntoARemoteFile_Fails_WithTheServersError()
    {
        await using var rig = await Rig.StartAsync();
        var local = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
        await File.WriteAllBytesAsync(Path.Combine(local.FullName, "a"), [1]);

        var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.UploadDirectoryAsync(local.FullName, "f", cancellationToken: Timeout()));

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(rig.Files.FileData(Home + "/f")).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task ARemoteDirectoryThatCannotBeCreatedOrRead_ReportsTheCreateError()
    {
        // MKDIR is denied, and the STAT that would show the directory is there already fails too: the denial is what the caller sees.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request => request[0] switch
        {
            MkDir => Reply(request, 101, w => { w.WriteUInt32(3); w.WriteString("denied"); w.WriteString("en"); }),
            Stat => Reply(request, 101, w => { w.WriteUInt32(2); w.WriteString("gone"); w.WriteString("en"); }),
            _ => null,
        });
        var local = Directory.CreateDirectory(Path.Combine(_dir, "tree"));

        var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.UploadDirectoryAsync(local.FullName, "up", cancellationToken: Timeout()));

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
        await Assert.That(error.Message).Contains("denied");
    }

    [Test]
    public async Task Preserve_AppliesToUploadedDirectoriesToo()
    {
        await using var rig = await Rig.StartAsync();
        var local = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
        var sub = local.CreateSubdirectory("sub");
        await File.WriteAllBytesAsync(Path.Combine(sub.FullName, "a"), [1]);
        var stamp = new DateTime(2020, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        sub.LastWriteTimeUtc = stamp;

        await rig.Sftp.UploadDirectoryAsync(local.FullName, "up", new SftpTransferOptions { Preserve = true }, Timeout());

        await Assert.That(rig.Files.ModifyTime(Home + "/up/sub")).IsEqualTo((uint)new DateTimeOffset(stamp).ToUnixTimeSeconds());
    }

    [Test]
    public async Task FileSystemInfo_TheServerRefuses_IsAnSftpError()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == Extended && PathOf(request) == "statvfs@openssh.com"
                ? Reply(request, 101, w => { w.WriteUInt32(2); w.WriteString(""); w.WriteString(""); })
                : null);

        var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.GetFileSystemInfoAsync("nowhere", Timeout()));

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
        await Assert.That(error.Path).IsEqualTo("nowhere");
    }

    [Test]
    public async Task ACopyToADestinationTheServerCannotResolve_StillCopies()
    {
        // Newer OpenSSH refuses REALPATH for a path that does not exist: the destination is then simply not the source.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == RealPath && PathOf(request) == "copy" ? Reply(request, 101, w => { w.WriteUInt32(2); w.WriteString("No such file"); w.WriteString(""); }) : null);

        await rig.Sftp.CopyFileAsync("f", "copy", cancellationToken: Timeout());

        await Assert.That(rig.Files.FileData(Home + "/copy")).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task ACopyFromASourceTheServerCannotResolve_ReportsTheMissingSource()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == RealPath && PathOf(request) == "missing" ? Reply(request, 101, w => { w.WriteUInt32(2); w.WriteString("No such file"); w.WriteString(""); }) : null);

        var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.CopyFileAsync("missing", "copy", cancellationToken: Timeout()));

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
        await Assert.That(rig.Files.Exists(Home + "/copy")).IsFalse();
    }

    [Test]
    public async Task OverwritingByCopy_WhenTheSourceSizeIsUnknown_EmptiesTheDestinationFirst()
    {
        // Without the source's size the destination cannot be cut to it afterwards: it is emptied before the copy, so no old tail remains.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/long", [9, 9, 9, 9, 9, 9]);
            f.RawFrame = request => request[0] == FStat ? Reply(request, 105, w => w.WriteUInt32(0)) : null;
        });

        await rig.Sftp.CopyFileAsync("f", "long", overwrite: true, Timeout());

        await Assert.That(rig.Files.FileData(Home + "/long")).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task ExtendedAttributes_RoundTrip()
    {
        var attributes = new SftpFileAttributes
        {
            Size = 5,
            Extended = new Dictionary<string, byte[]> { ["acl@example.com"] = [1, 2], ["empty@example.com"] = [] },
        };
        var buffer = new ArrayBufferWriter<byte>();
        attributes.Write(new SshWriter(buffer));
        var reader = new SshReader(buffer.WrittenSpan);

        var read = SftpFileAttributes.Read(ref reader);

        await Assert.That(read.Size).IsEqualTo(5L);
        await Assert.That(read.Extended.Count).IsEqualTo(2);
        await Assert.That(read.Extended["acl@example.com"]).IsEquivalentTo(new byte[] { 1, 2 });
        await Assert.That(read.Extended["empty@example.com"]).IsEmpty();
    }

    [Test]
    public async Task DisposingAfterTheConnectionIsGone_DoesNotThrow_AndRequestsFailAsClosed()
    {
        await using var rig = await Rig.StartAsync();
        await rig.Client.DisposeAsync();

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Sftp.ExistsAsync("f", Timeout()));
        await Assert.That(error!.Reason).IsNotEqualTo(SshFailureReason.SftpFailed);
        await Assert.That(async () => await rig.Sftp.DisposeAsync()).ThrowsNothing();
    }

    [Test]
    public async Task UploadingATreeDeeperThanTheLimit_Fails_BeforeGoingThatDeep()
    {
        await using var rig = await Rig.StartAsync();
        var path = Path.Combine(_dir, "deep");
        for (var i = 0; i <= SftpClient.MaxDepth + 1; i++)
        {
            path = Path.Combine(path, "d");
        }

        Directory.CreateDirectory(path);

        var error = await Assert.ThrowsAsync<IOException>(async () => await rig.Sftp.UploadDirectoryAsync(Path.Combine(_dir, "deep"), "up", cancellationToken: Timeout()));

        await Assert.That(error!.Message).Contains($"{SftpClient.MaxDepth} levels");
    }

    [Test]
    public async Task UploadingATree_SkipsLocalSymbolicLinks()
    {
        // A link could lead anywhere on this machine (out of the tree, or round in a loop): it is skipped, not followed.
        await using var rig = await Rig.StartAsync();
        var local = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
        await File.WriteAllBytesAsync(Path.Combine(local.FullName, "real"), [1]);
        try
        {
            File.CreateSymbolicLink(Path.Combine(local.FullName, "link"), Path.Combine(local.FullName, "real"));
            Directory.CreateSymbolicLink(Path.Combine(local.FullName, "loop"), local.FullName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Skip.Test("Creating symbolic links needs a privilege this account lacks (Windows without developer mode).");
        }

        var summary = await rig.Sftp.UploadDirectoryAsync(local.FullName, "up", cancellationToken: Timeout());

        await Assert.That(summary.Files).IsEqualTo(1);
        await Assert.That(summary.Skipped).IsEqualTo(2);
        await Assert.That(rig.Files.Exists(Home + "/up/link")).IsFalse();
        await Assert.That(rig.Files.Exists(Home + "/up/loop")).IsFalse();
    }

    [Test]
    public async Task FileSystemSpace_ClampsWhatALongCannotHold_AndCountsInBlocksWithoutAFragmentSize()
    {
        // statvfs counts in fragments, or in blocks when the fragment size is 0; a count times its unit past long.MaxValue is clamped,
        // not wrapped negative.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == Extended && PathOf(request) == "statvfs@openssh.com"
                ? Reply(request, 201, w =>
                {
                    foreach (var value in new ulong[] { 512, 0, ulong.MaxValue / 2, 10, 0, ulong.MaxValue, 7, 7, 1, 0, ulong.MaxValue })
                    {
                        w.WriteUInt64(value);
                    }
                })
                : null);

        var info = await rig.Sftp.GetFileSystemInfoAsync(".", Timeout());

        await Assert.That(info.TotalBytes).IsEqualTo(long.MaxValue);
        await Assert.That(info.FreeBytes).IsEqualTo(5120L);
        await Assert.That(info.AvailableBytes).IsEqualTo(0L);
        await Assert.That(info.TotalFiles).IsEqualTo(long.MaxValue);
        await Assert.That(info.FreeFiles).IsEqualTo(7L);
        await Assert.That(info.MaxNameLength).IsEqualTo(int.MaxValue);
        await Assert.That(info.IsReadOnly).IsFalse();
    }

    [Test]
    public async Task ARealPathAnsweredWithTwoNames_IsAProtocolError()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request =>
            request[0] == RealPath ? Reply(request, 104, w =>
            {
                w.WriteUInt32(2);
                for (var i = 0; i < 2; i++)
                {
                    w.WriteString("/x");
                    w.WriteString("/x");
                    w.WriteUInt32(0);
                }
            }) : null);

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Sftp.GetFullPathAsync(".", Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("2 names");
    }

    [Test]
    public async Task PathsWithATrailingSeparator_JoinTheirNamesWithOne()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/dir");
            f.AddFile(Home + "/dir/a", [1]);
        });
        var local = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
        await File.WriteAllBytesAsync(Path.Combine(local.FullName, "b"), [2]);

        var listed = new List<string>();
        await foreach (var entry in rig.Sftp.ListDirectoryAsync("dir/", Timeout()))
        {
            listed.Add(entry.FullPath);
        }

        await rig.Sftp.UploadDirectoryAsync(local.FullName, "up/", cancellationToken: Timeout());

        await Assert.That(listed).Contains("dir/a");
        await Assert.That(rig.Files.FileData(Home + "/up/b")).IsEquivalentTo(new byte[] { 2 });
    }

    [Test]
    public async Task ASegmentedDownloadWithoutOverwrite_LeavesAnExistingLocalFileAlone()
    {
        // CreateNew fails on the existing file: the download stops, and the file it did not create is not the one it removes.
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big.bin", new byte[4 * 1024 * 1024]));
        var local = Path.Combine(_dir, "big.bin");
        await File.WriteAllBytesAsync(local, [7, 7, 7]);

        await Assert.That(async () => await rig.Sftp.DownloadFileAsync("big.bin", local, new SftpTransferOptions { Segments = 2, Overwrite = false }, Timeout()))
            .Throws<IOException>();

        await Assert.That(await File.ReadAllBytesAsync(local)).IsEquivalentTo(new byte[] { 7, 7, 7 });
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0);
    }

    [Test]
    public async Task SettingOnlyTheAccessTime_SendsItForBoth()
    {
        // SFTP v3 sets the two times together: with only one given, the other gets the same value rather than garbage.
        var when = new DateTimeOffset(2022, 3, 4, 5, 6, 7, TimeSpan.Zero);
        var attributes = new SftpFileAttributes { LastAccessTime = when };
        var buffer = new ArrayBufferWriter<byte>();
        attributes.Write(new SshWriter(buffer));
        var reader = new SshReader(buffer.WrittenSpan);

        var read = SftpFileAttributes.Read(ref reader);

        await Assert.That(read.LastAccessTime).IsEqualTo(when);
        await Assert.That(read.LastWriteTime).IsEqualTo(when);
    }

    [Test]
    public async Task ALocalRootWithATrailingSeparator_StillContainsItsFiles()
    {
        var root = _dir + Path.DirectorySeparatorChar;

        await Assert.That(SftpClient.LocalPathFor(_dir, "a.txt", root)).IsEqualTo(Path.Combine(_dir, "a.txt"));
        await Assert.That(SftpClient.LocalPathFor(_dir, "..", root)).IsNull();
    }

    [Test]
    public async Task ADisposedStream_CannotSeek()
    {
        await using var rig = await Rig.StartAsync();
        var stream = await rig.Sftp.OpenReadAsync("f", Timeout());
        await Assert.That(stream.CanSeek).IsTrue();

        await stream.DisposeAsync();

        await Assert.That(stream.CanSeek).IsFalse();
        await Assert.That(stream.CanRead).IsFalse();
    }

    /// <summary>The first string of a request's body: the path, or an extended request's name.</summary>
    private static string PathOf(byte[] request)
    {
        var reader = new SshReader(request.AsSpan(5));
        return reader.ReadUtf8String();
    }

    /// <summary>A READ request's offset (after its handle).</summary>
    private static long ReadOffsetOf(byte[] request)
    {
        var reader = new SshReader(request.AsSpan(5));
        reader.ReadString();
        return (long)reader.ReadUInt64();
    }
}
