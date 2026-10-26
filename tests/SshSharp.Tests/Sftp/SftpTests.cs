using System.Security.Cryptography;
using System.Text;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>The SFTP client (#7) against the in-memory fake SFTP server.</summary>
public sealed class SftpTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-sftp-" + Guid.NewGuid().ToString("N"));

    public SftpTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; private init; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, string? identification = null)
        {
            var rig = identification is null ? new Rig() : new Rig { Ssh = new FakeSessionServer(new FakeServerOptions { Identification = identification }) };
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

    private const string Home = FakeSftpServer.Home;

    // ---- session ----

    [Test]
    public async Task TheSession_ReportsTheVersionExtensionsAndLimits()
    {
        await using var rig = await Rig.StartAsync(f => f.Limits = (100_000, 50_000));

        await Assert.That(rig.Sftp.ProtocolVersion).IsEqualTo(3);
        await Assert.That(rig.Sftp.Extensions.ContainsKey("posix-rename@openssh.com")).IsTrue();
        await Assert.That(rig.Sftp.Limits.MaxReadLength).IsEqualTo(100_000);
        await Assert.That(rig.Sftp.Limits.MaxWriteLength).IsEqualTo(50_000);
        await Assert.That(rig.Sftp.Limits.MaxOpenHandles).IsEqualTo(1024);
    }

    [Test]
    public async Task WithoutLimits_ThirtyTwoKibibyteChunksAreUsed_AndHugeLimitsAreCapped()
    {
        await using (var plain = await Rig.StartAsync(f => f.Extensions.Remove("limits@openssh.com")))
        {
            await Assert.That(plain.Sftp.Limits).IsEqualTo(new SftpLimits(32 * 1024, 32 * 1024, null));
        }

        await using var huge = await Rig.StartAsync(f => f.Limits = (100_000_000, 0));
        await Assert.That(huge.Sftp.Limits.MaxReadLength).IsEqualTo(255 * 1024);
        await Assert.That(huge.Sftp.Limits.MaxWriteLength).IsEqualTo(32 * 1024); // 0: unknown
    }

    [Test]
    public async Task AnOldProtocolVersion_IsRefused()
    {
        var ex = await Assert.That(async () => await Rig.StartAsync(f => f.Version = 2)).Throws<SshException>();
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task AServerWithoutSftp_IsAChannelError()
    {
        await using var ssh = new FakeSessionServer();
        _ = ssh.StartAsync();
        await using var client = await SshClient.ConnectAsync(ssh.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());

        var ex = await Assert.That(async () => await client.OpenSftpAsync(Timeout())).Throws<SshException>();
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
    }

    // ---- attributes, directories, names ----

    [Test]
    public async Task Attributes_DescribeFilesDirectoriesAndLinks()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/a.txt", "hello"u8.ToArray(), modifyTime: 1_600_000_000);
            f.AddLink(Home + "/link", "a.txt");
        });

        var file = await rig.Sftp.GetAttributesAsync("a.txt", cancellationToken: Timeout());
        await Assert.That(file.IsRegularFile).IsTrue();
        await Assert.That(file.Size).IsEqualTo(5L);
        await Assert.That(file.Permissions).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        await Assert.That(file.LastWriteTime).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000));
        await Assert.That(file.UserId).IsEqualTo(1000u);

        await Assert.That((await rig.Sftp.GetAttributesAsync(Home, cancellationToken: Timeout())).IsDirectory).IsTrue();
        await Assert.That((await rig.Sftp.GetAttributesAsync("link", followSymbolicLinks: false, Timeout())).IsSymbolicLink).IsTrue();
        await Assert.That((await rig.Sftp.GetAttributesAsync("link", cancellationToken: Timeout())).IsRegularFile).IsTrue();
        await Assert.That(await rig.Sftp.ExistsAsync("a.txt", Timeout())).IsTrue();
        await Assert.That(await rig.Sftp.ExistsAsync("missing", Timeout())).IsFalse();
    }

    [Test]
    public async Task AMissingFile_IsAnSftpExceptionWithItsStatusAndPath()
    {
        await using var rig = await Rig.StartAsync();

        var ex = await Assert.That(async () => await rig.Sftp.GetAttributesAsync("/nope", cancellationToken: Timeout())).Throws<SftpException>();

        await Assert.That(ex!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
        await Assert.That(ex.Path).IsEqualTo("/nope");
        await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.SftpFailed);
        await Assert.That(ex.Message).Contains("No such file");
    }

    [Test]
    public async Task SetAttributes_ChangesOnlyWhatIsSet()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", new byte[10]));

        await rig.Sftp.SetAttributesAsync("f", new SftpFileAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite }, Timeout());
        await rig.Sftp.SetAttributesAsync("f", new SftpFileAttributes { LastWriteTime = DateTimeOffset.FromUnixTimeSeconds(1_234_567_890) }, Timeout());
        await rig.Sftp.SetAttributesAsync("f", new SftpFileAttributes { Size = 4 }, Timeout());

        await Assert.That(rig.Files.Mode(Home + "/f")).IsEqualTo(0x180u);
        await Assert.That(rig.Files.ModifyTime(Home + "/f")).IsEqualTo(1_234_567_890u);
        await Assert.That(rig.Files.FileData(Home + "/f")!.Length).IsEqualTo(4);
        await Assert.That(() => new SftpFileAttributes { UserId = 1 }.Write(new global::SshSharp.Protocol.SshWriter(new System.Buffers.ArrayBufferWriter<byte>()))).Throws<ArgumentException>();
    }

    [Test]
    public async Task ListDirectory_ReadsEveryBatch_WithoutDotAndDotDot()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingBatch = 2;
            f.AddDirectory(Home + "/d");
            for (var i = 0; i < 7; i++)
            {
                f.AddFile($"{Home}/d/file{i}", new byte[i]);
            }

            f.AddDirectory(Home + "/d/sub");
        });

        var entries = new List<SftpFileInfo>();
        await foreach (var entry in rig.Sftp.ListDirectoryAsync("d", Timeout()))
        {
            entries.Add(entry);
        }

        await Assert.That(entries.Select(e => e.Name)).IsEquivalentTo(Enumerable.Range(0, 7).Select(i => $"file{i}").Append("sub"));
        await Assert.That(entries.Single(e => e.Name == "file3").Attributes.Size).IsEqualTo(3L);
        await Assert.That(entries.Single(e => e.Name == "file3").FullPath).IsEqualTo("d/file3");
        await Assert.That(entries.Single(e => e.Name == "sub").Attributes.IsDirectory).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0); // the directory handle was closed
    }

    [Test]
    public async Task StoppingAListingEarly_ClosesItsHandle()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            for (var i = 0; i < 10; i++)
            {
                f.AddFile($"{Home}/d/f{i}", []);
            }
        });

        await foreach (var _ in rig.Sftp.ListDirectoryAsync("d", Timeout()))
        {
            break;
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task Directories_AreCreatedAndDeleted()
    {
        await using var rig = await Rig.StartAsync();

        await rig.Sftp.CreateDirectoryAsync("new", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, Timeout());
        await Assert.That(rig.Files.Mode(Home + "/new")).IsEqualTo(0x1C0u);
        await Assert.That((await Assert.That(async () => await rig.Sftp.CreateDirectoryAsync("new", cancellationToken: Timeout())).Throws<SftpException>())!.Status)
            .IsEqualTo(SftpStatusCode.Failure);

        await rig.Sftp.UploadAsync(new MemoryStream("x"u8.ToArray()), "new/f", cancellationToken: Timeout());
        await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("new", Timeout())).Throws<SftpException>(); // not empty
        await rig.Sftp.DeleteFileAsync("new/f", Timeout());
        await rig.Sftp.DeleteDirectoryAsync("new", Timeout());
        await Assert.That(rig.Files.Exists(Home + "/new")).IsFalse();
    }

    [Test]
    public async Task Rename_RefusesAnExistingTarget_UnlessOverwriting()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/a", "a"u8.ToArray());
            f.AddFile(Home + "/b", "b"u8.ToArray());
        });

        await Assert.That(async () => await rig.Sftp.RenameAsync("a", "b", cancellationToken: Timeout())).Throws<SftpException>();
        await rig.Sftp.RenameAsync("a", "b", overwrite: true, Timeout());
        await Assert.That(rig.Files.FileData(Home + "/b").AsSpan().SequenceEqual("a"u8.ToArray())).IsTrue();
        await rig.Sftp.RenameAsync("b", "c", cancellationToken: Timeout());
        await Assert.That(rig.Files.Exists(Home + "/c")).IsTrue();
    }

    [Test]
    public async Task WithoutTheExtensions_OverwritingRenamesAndHardLinksAreNotSupported()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Extensions.Clear();
            f.AddFile(Home + "/a", []);
        });

        await Assert.That(async () => await rig.Sftp.RenameAsync("a", "b", overwrite: true, Timeout())).Throws<NotSupportedException>();
        await Assert.That(async () => await rig.Sftp.CreateHardLinkAsync("b", "a", Timeout())).Throws<NotSupportedException>();
        await Assert.That(await rig.Sftp.GetHomeDirectoryAsync(Timeout())).IsEqualTo(Home); // from realpath "."
    }

    [Test]
    public async Task AHomeDirectoryExtensionThatFails_FallsBackToTheLoginDirectory()
    {
        // OpenSSH 9.x announces home-directory but answers Failure for the empty name PROTOCOL defines as the session's user.
        await using var rig = await Rig.StartAsync(f => f.HomeDirectoryFailsForEmptyUser = true);

        await Assert.That(await rig.Sftp.GetHomeDirectoryAsync(Timeout())).IsEqualTo(Home);
    }

    [Test]
    public async Task Paths_Links_AndTheHomeDirectory()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/target", "t"u8.ToArray()));

        await Assert.That(await rig.Sftp.GetFullPathAsync("x/../target", Timeout())).IsEqualTo(Home + "/target");
        await Assert.That(await rig.Sftp.GetHomeDirectoryAsync(Timeout())).IsEqualTo(Home);

        await rig.Sftp.CreateSymbolicLinkAsync("soft", "target", Timeout());
        await Assert.That(await rig.Sftp.ReadSymbolicLinkAsync("soft", Timeout())).IsEqualTo("target");

        await rig.Sftp.CreateHardLinkAsync("hard", "target", Timeout());
        await Assert.That(rig.Files.FileData(Home + "/hard").AsSpan().SequenceEqual("t"u8.ToArray())).IsTrue();
    }

    [Test]
    [Arguments("SSH-2.0-AsyncSSH_2.21.0", true)]
    [Arguments("SSH-2.0-Erlang/5.3.3", true)]
    [Arguments("SSH-2.0-OpenSSH_9.9", false)]
    [Arguments("SSH-2.0-dropbear_2025.88", false)]
    [Arguments("SSH-2.0-Go", false)]
    [Arguments("SSH-2.0-APACHE-SSHD-2.20.0", false)]
    public async Task SymbolicLinks_UseTheArgumentOrderTheServerExpects(string identification, bool draftOrder)
    {
        // OpenSSH reverses SSH_FXP_SYMLINK's arguments and most servers follow it; AsyncSSH keeps the draft's order with this client,
        // and Erlang/OTP's ssh_sftpd always does.
        // Sent the other way round, the link would be created at the target's path.
        await using var rig = await Rig.StartAsync(files => files.SymlinkInDraftOrder = draftOrder, identification);
        await rig.Sftp.CreateSymbolicLinkAsync("soft", "target", Timeout());

        await Assert.That(await rig.Sftp.ReadSymbolicLinkAsync("soft", Timeout())).IsEqualTo("target");
    }

    [Test]
    public async Task ExpandPath_ExpandsTildes_AndResolvesThePath()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(await rig.Sftp.ExpandPathAsync("~", Timeout())).IsEqualTo(Home);
        await Assert.That(await rig.Sftp.ExpandPathAsync("~/a/../b", Timeout())).IsEqualTo(Home + "/b");
        await Assert.That(await rig.Sftp.ExpandPathAsync("~other/x", Timeout())).IsEqualTo("/home/other/x");
        await Assert.That(await rig.Sftp.ExpandPathAsync("c", Timeout())).IsEqualTo(Home + "/c");
    }

    [Test]
    public async Task ExpandPath_WithoutTheExtension_ExpandsOnlyTheOwnHome()
    {
        await using var rig = await Rig.StartAsync(f => f.Extensions.Remove("expand-path@openssh.com"));

        // The home directory (home-directory, or "."), then the rest resolved as REALPATH resolves it.
        await Assert.That(await rig.Sftp.ExpandPathAsync("~", Timeout())).IsEqualTo(Home);
        await Assert.That(await rig.Sftp.ExpandPathAsync("~/a/../b", Timeout())).IsEqualTo(Home + "/b");
        await Assert.That(await rig.Sftp.ExpandPathAsync("c", Timeout())).IsEqualTo(Home + "/c");
        await Assert.That(async () => await rig.Sftp.ExpandPathAsync("~other/x", Timeout())).Throws<NotSupportedException>();
    }

    [Test]
    public async Task SetAttributes_NotFollowingLinks_ChangesTheLinkItself()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/target", "t"u8.ToArray());
            f.AddLink(Home + "/link", "target");
        });
        var readOnly = new SftpFileAttributes { Permissions = UnixFileMode.UserRead };

        await rig.Sftp.SetAttributesAsync("link", readOnly, followSymbolicLinks: false, Timeout());
        await Assert.That(rig.Files.Mode(Home + "/link")).IsEqualTo(0x100u);
        await Assert.That(rig.Files.Mode(Home + "/target")).IsEqualTo(0x1A4u); // untouched

        await rig.Sftp.SetAttributesAsync("link", readOnly, followSymbolicLinks: true, Timeout());
        await Assert.That(rig.Files.Mode(Home + "/target")).IsEqualTo(0x100u);
    }

    [Test]
    public async Task SetAttributes_NotFollowingLinks_NeedsLSetStat()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Extensions.Remove("lsetstat@openssh.com");
            f.AddFile(Home + "/target", "t"u8.ToArray());
        });

        await Assert.That(async () => await rig.Sftp.SetAttributesAsync("target", new SftpFileAttributes(), followSymbolicLinks: false, Timeout()))
            .Throws<NotSupportedException>();
    }

    [Test]
    public async Task OwnerNames_AreLookedUpById_AndUnknownIdsAreLeftOut()
    {
        await using var rig = await Rig.StartAsync(f => f.UserNames[0] = "root");

        var (users, groups) = await rig.Sftp.GetOwnerNamesAsync([1000, 0, 1000, 4242], [1000, 77], Timeout());
        await Assert.That(users).IsEquivalentTo(new Dictionary<uint, string> { [1000] = "tester", [0] = "root" });
        await Assert.That(groups).IsEquivalentTo(new Dictionary<uint, string> { [1000] = "testers" });

        var (none, onlyGroups) = await rig.Sftp.GetOwnerNamesAsync([], [1000], Timeout());
        await Assert.That(none).IsEmpty();
        await Assert.That(onlyGroups[1000]).IsEqualTo("testers");
    }

    [Test]
    public async Task OwnerNames_NeedTheExtension()
    {
        await using var rig = await Rig.StartAsync(f => f.Extensions.Remove("users-groups-by-id@openssh.com"));
        await Assert.That(async () => await rig.Sftp.GetOwnerNamesAsync([1000], [1000], Timeout())).Throws<NotSupportedException>();
    }

    // ---- streams ----

    [Test]
    public async Task AFileStream_ReadsWritesSeeksAndTruncates()
    {
        await using var rig = await Rig.StartAsync();

        await using (var stream = await rig.Sftp.OpenAsync("s", FileMode.CreateNew, FileAccess.ReadWrite, Timeout()))
        {
            await stream.WriteAsync("hello world"u8.ToArray(), Timeout());
            await Assert.That(stream.Position).IsEqualTo(11L);
            await Assert.That(stream.Length).IsEqualTo(11L);
            stream.Seek(6, SeekOrigin.Begin);
            var buffer = new byte[5];
            await stream.ReadExactlyAsync(buffer, Timeout());
            await Assert.That(Encoding.ASCII.GetString(buffer)).IsEqualTo("world");
            await Assert.That(await stream.ReadAsync(buffer, Timeout())).IsEqualTo(0); // end of file
            stream.SetLength(5);
        }

        await Assert.That(rig.Files.FileData(Home + "/s").AsSpan().SequenceEqual("hello"u8.ToArray())).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);

        await using (var append = await rig.Sftp.OpenAsync("s", FileMode.Append, FileAccess.Write, Timeout()))
        {
            await Assert.That(append.Position).IsEqualTo(5L);
            await append.WriteAsync("!"u8.ToArray(), Timeout());
        }

        await Assert.That(rig.Files.FileData(Home + "/s").AsSpan().SequenceEqual("hello!"u8.ToArray())).IsTrue();
        await Assert.That(async () => await rig.Sftp.OpenAsync("s", FileMode.CreateNew, FileAccess.Write, Timeout())).Throws<SftpException>();
        await Assert.That(async () => await rig.Sftp.OpenAsync("s", FileMode.Create, FileAccess.Read, Timeout())).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AReadOnlyStream_ReadsAhead_AndStaysCorrectAcrossSeeksShortReadsAndReordering(bool misbehave)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (8 * 1024, 8 * 1024);
            f.ShortReads = misbehave;
            f.ReorderReplies = misbehave;
            f.PipelineGate = 2; // the first read is answered once a second one is in flight: no race with the client's next send
        });
        var data = RandomNumberGenerator.GetBytes(400_003);
        rig.Files.AddFile(Home + "/ahead", data);

        await using var stream = await rig.Sftp.OpenReadAsync("ahead", Timeout());

        // Sequential reads in odd sizes, smaller and larger than a request.
        var copy = new MemoryStream();
        var buffer = new byte[3000];
        int read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(0, copy.Length % 2 == 0 ? 3000 : 1001), Timeout())) > 0)
        {
            copy.Write(buffer, 0, read);
        }

        await Assert.That(copy.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.MaxOutstanding).IsGreaterThan(1); // reads were in flight together

        // Seeks back and forward, then reads: the bytes at each new position.
        foreach (var at in new long[] { 12_345, 300_000, 5, 399_999 })
        {
            stream.Seek(at, SeekOrigin.Begin);
            var piece = new byte[Math.Min(5000, data.Length - (int)at)];
            await stream.ReadExactlyAsync(piece, Timeout());
            await Assert.That(piece.AsSpan().SequenceEqual(data.AsSpan((int)at, piece.Length))).IsTrue();
        }

        await Assert.That(await stream.ReadAsync(buffer, Timeout())).IsEqualTo(0);
    }

    [Test]
    public async Task AReadOnlyStream_RefusesWrites_AndSyncCallsAreNotSupported()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/r", "data"u8.ToArray()));
        await using var stream = await rig.Sftp.OpenReadAsync("r", Timeout());

        await Assert.That(stream.CanWrite).IsFalse();
        await Assert.That(async () => await stream.WriteAsync(new byte[1], Timeout())).Throws<NotSupportedException>();
        await Assert.That(() => stream.Read(new byte[1], 0, 1)).Throws<NotSupportedException>();
    }

    // ---- transfers ----

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(64 * 1024)]
    [Arguments(1_000_003)]
    public async Task UploadThenDownload_RoundTripsAnySize_WithPipelining(int size)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (16 * 1024, 16 * 1024);
            f.PipelineGate = size > 200_000 ? 2 : 0; // the first write is answered once a second one is in flight (checked below)
        });
        var data = RandomNumberGenerator.GetBytes(size);
        var progress = new List<long>();

        var uploaded = await rig.Sftp.UploadAsync(new MemoryStream(data), "big", new SftpTransferOptions { Progress = new SyncProgress(progress) }, Timeout());
        await Assert.That(uploaded).IsEqualTo((long)size);
        await Assert.That(rig.Files.FileData(Home + "/big").AsSpan().SequenceEqual(data)).IsTrue();
        if (size > 0)
        {
            await Assert.That(progress[^1]).IsEqualTo((long)size);
        }

        var copy = new MemoryStream();
        var downloaded = await rig.Sftp.DownloadAsync("big", copy, cancellationToken: Timeout());
        await Assert.That(downloaded).IsEqualTo((long)size);
        await Assert.That(copy.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
        if (size > 200_000)
        {
            await Assert.That(rig.Files.MaxOutstanding).IsGreaterThan(1); // several reads or writes were in flight
        }
    }

    [Test]
    public async Task ShortReads_AndRepliesOutOfOrder_StillGiveTheRightBytes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (8 * 1024, 8 * 1024);
            f.ShortReads = true;
            f.ReorderReplies = true;
            f.PipelineGate = 2; // a second read is waiting when the first is answered, so the two are swapped
        });
        var data = RandomNumberGenerator.GetBytes(300_001);
        rig.Files.AddFile(Home + "/odd", data);

        var copy = new MemoryStream();
        await rig.Sftp.DownloadAsync("odd", copy, new SftpTransferOptions { MaxRequestsInFlight = 16 }, Timeout());

        await Assert.That(copy.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.ReorderedPairs).IsGreaterThan(0);

        await rig.Sftp.UploadAsync(new MemoryStream(data), "back", cancellationToken: Timeout());
        await Assert.That(rig.Files.FileData(Home + "/back").AsSpan().SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task FileTransfers_KeepTimes_AndRespectOverwrite()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/remote", "remote data"u8.ToArray(), modifyTime: 1_500_000_000));
        var local = Path.Combine(_dir, "local");

        await rig.Sftp.DownloadFileAsync("remote", local, new SftpTransferOptions { Preserve = true }, Timeout());
        await Assert.That(await File.ReadAllTextAsync(local)).IsEqualTo("remote data");
        await Assert.That(new DateTimeOffset(File.GetLastWriteTimeUtc(local))).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_500_000_000));

        await Assert.That(async () => await rig.Sftp.DownloadFileAsync("remote", local, new SftpTransferOptions { Overwrite = false }, Timeout())).Throws<IOException>();
        await Assert.That(await File.ReadAllTextAsync(local)).IsEqualTo("remote data");

        File.SetLastWriteTimeUtc(local, new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc));
        await rig.Sftp.UploadFileAsync(local, "uploaded", new SftpTransferOptions { Preserve = true }, Timeout());
        await Assert.That(rig.Files.ModifyTime(Home + "/uploaded")).IsEqualTo((uint)new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero).ToUnixTimeSeconds());
        await Assert.That(async () => await rig.Sftp.UploadFileAsync(local, "uploaded", new SftpTransferOptions { Overwrite = false }, Timeout())).Throws<SftpException>();
    }

    [Test]
    public async Task Preserve_CopiesThePermissionBits_ButNeverSetuid()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/tool", "#!/bin/sh"u8.ToArray()));
        rig.Files.SetMode(Home + "/tool", 0xDED); // 06755: setuid and setgid, rwxr-xr-x
        var local = Path.Combine(_dir, "tool");

        await rig.Sftp.DownloadFileAsync("tool", local, new SftpTransferOptions { Preserve = true }, Timeout());
        await rig.Sftp.UploadFileAsync(local, "copy", new SftpTransferOptions { Preserve = true }, Timeout());

        if (OperatingSystem.IsWindows())
        {
            // No Unix modes here: the times are copied, the permissions are not sent, and the server keeps its default.
            await Assert.That(rig.Files.Mode(Home + "/copy")).IsEqualTo(0x1A4u);
            return;
        }

        // The rwx bits arrive; setuid and setgid do not, whichever way they would travel.
        await Assert.That(File.GetUnixFileMode(local)).IsEqualTo((UnixFileMode)0x1ED);
        await Assert.That(rig.Files.Mode(Home + "/copy")).IsEqualTo(0x1EDu);

        File.SetUnixFileMode(local, (UnixFileMode)0x9A0); // 04640: setuid, rw-r-----
        await rig.Sftp.UploadFileAsync(local, "copy", new SftpTransferOptions { Preserve = true }, Timeout());
        await Assert.That(rig.Files.Mode(Home + "/copy")).IsEqualTo(0x1A0u);
    }

    [Test]
    public async Task Progress_NamesTheFile_AndItsSize_WhenKnown()
    {
        var data = RandomNumberGenerator.GetBytes(300 * 1024);
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/data.bin", data));
        var reports = new List<SftpTransferProgress>();
        var progress = new SyncReports(reports);

        await rig.Sftp.DownloadAsync("data.bin", new MemoryStream(), new SftpTransferOptions { Progress = progress }, Timeout());
        await Assert.That(reports[^1]).IsEqualTo(new SftpTransferProgress("data.bin", data.Length, data.Length));

        // An upload knows the size when the source can tell it, and not otherwise.
        reports.Clear();
        await rig.Sftp.UploadAsync(new MemoryStream(data), "up.bin", new SftpTransferOptions { Progress = progress }, Timeout());
        await Assert.That(reports[^1]).IsEqualTo(new SftpTransferProgress("up.bin", data.Length, data.Length));

        reports.Clear();
        await rig.Sftp.UploadAsync(new UnseekableStream(data), "up2.bin", new SftpTransferOptions { Progress = progress }, Timeout());
        await Assert.That(reports[^1]).IsEqualTo(new SftpTransferProgress("up2.bin", data.Length, null));
    }

    [Test]
    public async Task AFailedDownload_LeavesNoPartialFile()
    {
        await using var rig = await Rig.StartAsync();
        var local = Path.Combine(_dir, "never");

        await Assert.That(async () => await rig.Sftp.DownloadFileAsync("missing", local, cancellationToken: Timeout())).Throws<SftpException>();

        await Assert.That(File.Exists(local)).IsFalse();
    }

    [Test]
    public async Task ConcurrentCallers_ShareOneSession()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            for (var i = 0; i < 20; i++)
            {
                f.AddFile($"{Home}/c{i}", Encoding.ASCII.GetBytes($"content {i}"));
            }
        });

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(async i =>
        {
            var copy = new MemoryStream();
            await rig.Sftp.DownloadAsync($"c{i}", copy, cancellationToken: Timeout());
            return Encoding.ASCII.GetString(copy.ToArray());
        }));

        await Assert.That(results).IsEquivalentTo(Enumerable.Range(0, 20).Select(i => $"content {i}"));
    }

    [Test]
    public async Task AfterDispose_RequestsFail_AndTheConnectionStaysUp()
    {
        await using var rig = await Rig.StartAsync();
        await rig.Sftp.DisposeAsync();

        await Assert.That(async () => await rig.Sftp.GetAttributesAsync(".", cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(rig.Client.IsConnected).IsTrue();
        await using var again = await rig.Client.OpenSftpAsync(Timeout());
        await Assert.That(await again.ExistsAsync(".", Timeout())).IsTrue();
    }

    [Test]
    public async Task ARequestWhoseSendFails_ClosesTheSession_BeforeItThrows()
    {
        // The session's input is shut under the SFTP client while the server goes on (its replies would still be read): the send fails,
        // and nothing else would tell the client that the session is unusable.
        await using var rig = await Rig.StartAsync();
        await using var session = await rig.Client.StartSubsystemAsync("sftp", cancellationToken: Timeout());
        await using var sftp = await SftpClient.StartAsync(session, serverSoftware: null, Timeout());
        await Assert.That(await sftp.ExistsAsync(".", Timeout())).IsTrue();

        await session.CloseInputAsync(Timeout());

        var error = await Assert.That(async () => await sftp.GetAttributesAsync(".", cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(sftp.IsConnected).IsFalse();
        await Assert.That(rig.Client.IsConnected).IsTrue();
    }

    [Test]
    public async Task ARequestOnADroppedConnection_FindsTheSessionClosed_WhenItFails()
    {
        // What the adapters rely on to replace a session: once a request has failed because the connection dropped, IsConnected is
        // false already, not only once the session's read loop has noticed the end too.
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var server = new FakeSessionServer { Password = password };
        new FakeSftpServer().Install(server);
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        await Assert.That(await sftp.ExistsAsync(".", Timeout())).IsTrue();

        await server.DisposeAsync();
        for (var i = 0; i < 500 && client.IsConnected; i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(async () => await sftp.GetAttributesAsync(".", cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(sftp.IsConnected).IsFalse();
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(async () => await rig.Sftp.GetAttributesAsync("", cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.GetAttributesAsync("a\0b", cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(() => new SftpTransferOptions { MaxRequestsInFlight = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpFileAttributes { LastWriteTime = new DateTimeOffset(1960, 1, 1, 0, 0, 0, TimeSpan.Zero) }
            .Write(new global::SshSharp.Protocol.SshWriter(new System.Buffers.ArrayBufferWriter<byte>()))).Throws<ArgumentOutOfRangeException>();
    }

    /// <summary>Records progress on the reporting thread (Progress&lt;T&gt; posts to the thread pool, which would race the assertions).</summary>
    private sealed class SyncReports(List<SftpTransferProgress> reports) : IProgress<SftpTransferProgress>
    {
        public void Report(SftpTransferProgress value)
        {
            lock (reports)
            {
                reports.Add(value);
            }
        }
    }

    /// <summary>A source that cannot tell its length, as a network stream cannot.</summary>
    private sealed class UnseekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }

    private sealed class SyncProgress(List<long> values) : IProgress<SftpTransferProgress>
    {
        public void Report(SftpTransferProgress value)
        {
            lock (values)
            {
                values.Add(value.BytesTransferred);
            }
        }
    }
}
