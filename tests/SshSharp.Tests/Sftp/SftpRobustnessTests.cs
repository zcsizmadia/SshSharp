using System.Diagnostics;
using System.Text;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>SFTP against servers that log, stall, loop, or send names and data this client must not choke on (the pre-0.5.0 review).</summary>
public sealed class SftpRobustnessTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-sftp-rb-" + Guid.NewGuid().ToString("N"));

    public SftpRobustnessTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout(int seconds = 60) => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

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

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Stopwatch.StartNew();
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
    public async Task AServerThatLogsToStderr_NeverStallsTheSession()
    {
        // 8 KiB of stderr per reply: 600 requests make 4.8 MB, more than twice the 2 MiB channel window. Unread, it would stop the replies.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.StderrPerReply = 8192;
            f.AddFile(Home + "/f", Encoding.ASCII.GetBytes("data"));
        });

        for (var i = 0; i < 600; i++)
        {
            await Assert.That((await rig.Sftp.GetAttributesAsync("f", cancellationToken: Timeout(30))).Size).IsEqualTo(4L);
        }
    }

    [Test]
    public async Task CopyingAFileOntoItself_IsRefused_AndKeepsItsData()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/a.txt", "keep me"u8.ToArray()));

        foreach (var same in new[] { "a.txt", "./a.txt", Home + "/a.txt", "x/../a.txt" })
        {
            var ex = await Assert.That(async () => await rig.Sftp.CopyFileAsync("a.txt", same, overwrite: true, Timeout())).Throws<SftpException>();
            await Assert.That(ex!.Status).IsEqualTo(SftpStatusCode.Failure);
        }

        await Assert.That(rig.Files.FileData(Home + "/a.txt")).IsEquivalentTo("keep me"u8.ToArray());
    }

    [Test]
    public async Task CopyingOverALongerFile_LeavesExactlyTheSource()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/short.txt", "abc"u8.ToArray());
            f.AddFile(Home + "/long.txt", "0123456789"u8.ToArray());
        });

        await rig.Sftp.CopyFileAsync("short.txt", "long.txt", overwrite: true, Timeout());
        await Assert.That(Encoding.ASCII.GetString(rig.Files.FileData(Home + "/long.txt")!)).IsEqualTo("abc");
        await Assert.That(async () => await rig.Sftp.CopyFileAsync("short.txt", "long.txt", overwrite: false, Timeout())).Throws<SftpException>();
    }

    [Test]
    public async Task ANameInALegacyEncoding_IsListedLossily_AndSkippedByADownload()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/ok.txt", "fine"u8.ToArray());
            f.RawListingName = [0x63, 0x61, 0x66, 0xE9, 0x2E, 0x74, 0x78, 0x74]; // "café.txt" in Latin-1
        });

        var names = new List<string>();
        await foreach (var entry in rig.Sftp.ListDirectoryAsync("tree", Timeout()))
        {
            names.Add(entry.Name);
        }

        await Assert.That(names).Contains("caf�.txt");
        await Assert.That(names).Contains("ok.txt");

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"), cancellationToken: Timeout());
        await Assert.That(summary.Files).IsEqualTo(1);
        await Assert.That(summary.Skipped).IsEqualTo(1);
        await Assert.That(File.ReadAllText(Path.Combine(_dir, "down", "ok.txt"))).IsEqualTo("fine");
    }

    [Test]
    public async Task Length_NeedsNoRoundTrip_FollowsWrites_AndCopyToAsyncWorks()
    {
        var content = Enumerable.Range(0, 300_000).Select(i => (byte)i).ToArray();
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/big", content));

        await using (var read = await rig.Sftp.OpenReadAsync("big", Timeout()))
        {
            var fstats = rig.Files.Requests.Count(t => t == 8);
            await Assert.That(read.Length).IsEqualTo(300_000L);
            await Assert.That(read.Seek(-10, SeekOrigin.End)).IsEqualTo(299_990L);
            read.Position = 0;
            using var copy = new MemoryStream();
            await read.CopyToAsync(copy, Timeout());
            await Assert.That(copy.ToArray().SequenceEqual(content)).IsTrue();
            await Assert.That(rig.Files.Requests.Count(t => t == 8)).IsEqualTo(fstats); // no FSTAT for Length
        }

        await using var write = await rig.Sftp.OpenAsync("new", FileMode.Create, FileAccess.ReadWrite, Timeout());
        await Assert.That(write.Length).IsEqualTo(0L);
        await write.WriteAsync(new byte[1000], Timeout());
        await Assert.That(write.Length).IsEqualTo(1000L);
        write.SetLength(10);
        await Assert.That(write.Length).IsEqualTo(10L);
    }

    [Test]
    [Arguments("open")]
    [Arguments("opendir")]
    public async Task CancellingAnOpen_ClosesTheHandleTheServerOpensAnyway(string what)
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            f.AddFile(Home + "/f", "x"u8.ToArray());
            f.HoldOpens = hold;
        });

        using var cancel = new CancellationTokenSource();
        var opening = what == "open"
            ? (Task)rig.Sftp.OpenReadAsync("f", cancel.Token)
            : Task.Run(async () =>
            {
                await foreach (var _ in rig.Sftp.ListDirectoryAsync("d", cancel.Token))
                {
                }
            });
        await WaitUntilAsync(() => rig.Files.HeldOpens == 1);
        await cancel.CancelAsync();
        await Assert.That(async () => await opening).Throws<OperationCanceledException>();

        // The server opens the handle after all; the client closes it when the reply comes.
        hold.SetResult();
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0 && rig.Files.Requests.Contains(4));
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task UploadingATreeWithAFifo_SkipsIt_InsteadOfWaitingForAWriter()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("Windows has no FIFOs in a directory tree.");
            return;
        }

        var tree = Path.Combine(_dir, "up");
        Directory.CreateDirectory(tree);
        await File.WriteAllTextAsync(Path.Combine(tree, "regular.txt"), "data");
        using (var mkfifo = Process.Start(new ProcessStartInfo("mkfifo", [Path.Combine(tree, "pipe")]))!)
        {
            await mkfifo.WaitForExitAsync();
            await Assert.That(mkfifo.ExitCode).IsEqualTo(0);
        }

        await using var rig = await Rig.StartAsync();
        var summary = await rig.Sftp.UploadDirectoryAsync(tree, "up", cancellationToken: Timeout(30));
        await Assert.That(summary.Files).IsEqualTo(1);
        await Assert.That(summary.Skipped).IsEqualTo(1);
        await Assert.That(rig.Files.Exists(Home + "/up/pipe")).IsFalse();
        await Assert.That(LocalFileType.IsRegularFile(Path.Combine(tree, "regular.txt"))).IsTrue();
        await Assert.That(LocalFileType.IsRegularFile(Path.Combine(tree, "pipe"))).IsFalse();
    }

    [Test]
    public async Task BinaryExtensionData_DoesNotFailTheSession()
    {
        await using var rig = await Rig.StartAsync(f => f.RawExtensions.Add(("vendor-id@example.com", [0xFF, 0xFE, 0x00, 0x01, 0x80])));
        await Assert.That(rig.Sftp.Extensions.ContainsKey("vendor-id@example.com")).IsTrue();
        await Assert.That(await rig.Sftp.GetFullPathAsync(".", Timeout())).IsEqualTo(Home);
    }

    [Test]
    public async Task AListingThatNeverEnds_IsStopped()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/loop");
            f.EndlessListing = true;
        });

        var ex = await Assert.That(async () =>
        {
            await foreach (var _ in rig.Sftp.ListDirectoryAsync("loop", Timeout()))
            {
            }
        }).Throws<SshException>();
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0); // closed on the way out
    }

    [Test]
    public async Task AnOkWhereAHandleWasExpected_IsAProtocolError_AndAppendIsWriteOnly()
    {
        await using var rig = await Rig.StartAsync(f => f.OpenAnswersOk = true);

        var ex = await Assert.That(async () => await rig.Sftp.OpenReadAsync("f", Timeout())).Throws<SshException>();
        await Assert.That(ex).IsNotTypeOf<SftpException>();
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ProtocolError);

        await Assert.That(async () => await rig.Sftp.OpenAsync("f", FileMode.Append, FileAccess.ReadWrite, Timeout())).Throws<ArgumentException>();
    }

    [Test]
    public async Task OwnerIds_AboveIntMaxValue_RoundTrip()
    {
        var attributes = new SftpFileAttributes { UserId = 4_294_967_294, GroupId = 4_000_000_000 };
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        attributes.Write(new global::SshSharp.Protocol.SshWriter(buffer));
        var reader = new global::SshSharp.Protocol.SshReader(buffer.WrittenSpan);
        var read = SftpFileAttributes.Read(ref reader);
        await Assert.That(read.UserId).IsEqualTo(4_294_967_294u);
        await Assert.That(read.GroupId).IsEqualTo(4_000_000_000u);
    }

    [Test]
    [Arguments("backup-12:00.tar", false, true)]
    [Arguments("back\\slash", false, true)]
    [Arguments("backup-12:00.tar", true, false)]
    [Arguments("con.txt", true, false)]
    [Arguments("con.txt", false, true)]
    [Arguments("..", false, false)]
    [Arguments("a\u0001b", false, false)]
    [Arguments("caf�", false, false)]
    public async Task DownloadNames_FollowTheLocalSystemsRules(string name, bool windows, bool acceptable) =>
        await Assert.That(SftpClient.IsAcceptableName(name, windows)).IsEqualTo(acceptable);
}
