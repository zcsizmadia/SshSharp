using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// Directory transfers with <see cref="SftpTransferOptions.Filter"/> and <see cref="SftpTransferOptions.SkipUnchanged"/> (#266), its
/// <see cref="SftpTransferOptions.TimeTolerance"/>, and <see cref="SftpTransferOptions.SkipUnreadableDirectories"/> (#379).
/// </summary>
public sealed class SftpTransferFilterTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-sftpfilter-" + Guid.NewGuid().ToString("N"));

    public SftpTransferFilterTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; private init; } = null!;

        public FakeSftpServer Files { get; } = new();

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
    }

    /// <summary>The filter's view of what it was asked about, safe to record from a concurrent transfer.</summary>
    private sealed class Recorder
    {
        private readonly List<SftpTransferEntry> _seen = [];

        public Func<SftpTransferEntry, bool> Wrap(Func<SftpTransferEntry, bool> filter) => entry =>
        {
            lock (_seen)
            {
                _seen.Add(entry);
            }

            return filter(entry);
        };

        public SftpTransferEntry this[string path]
        {
            get
            {
                lock (_seen)
                {
                    return _seen.Single(e => e.RelativePath == path);
                }
            }
        }

        public List<string> Paths
        {
            get
            {
                lock (_seen)
                {
                    return [.. _seen.Select(e => e.RelativePath).Order(StringComparer.Ordinal)];
                }
            }
        }
    }

    /// <summary>Leaves out *.tmp files and the directory "cache".</summary>
    private static bool NoTempsOrCache(SftpTransferEntry entry) => !entry.Name.EndsWith(".tmp", StringComparison.Ordinal) && entry.RelativePath != "cache";

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task DownloadDirectory_Filter_LeavesOutFilesAndWholeDirectories(int concurrentFiles)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", "alpha"u8.ToArray());
            f.AddFile(Home + "/tree/b.tmp", [1]);
            f.AddDirectory(Home + "/tree/cache");
            f.AddFile(Home + "/tree/cache/c.txt", [2]);
            f.AddDirectory(Home + "/tree/sub");
            f.AddFile(Home + "/tree/sub/d.txt", [3, 3]);
            f.AddFile(Home + "/tree/sub/e.tmp", [4]);
            f.AddLink(Home + "/tree/link", "a.txt");
        });
        var recorder = new Recorder();
        var target = Path.Combine(_dir, "down");

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target,
            new SftpTransferOptions { Filter = recorder.Wrap(NoTempsOrCache), MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(2, 1, 5 + 2, 1) { Excluded = 3 });
        await Assert.That(File.Exists(Path.Combine(target, "a.txt"))).IsTrue();
        await Assert.That(File.Exists(Path.Combine(target, "sub", "d.txt"))).IsTrue();
        await Assert.That(Path.Exists(Path.Combine(target, "b.tmp"))).IsFalse();
        await Assert.That(Path.Exists(Path.Combine(target, "cache"))).IsFalse(); // neither created nor entered
        await Assert.That(Path.Exists(Path.Combine(target, "sub", "e.tmp"))).IsFalse();

        // Files and directories only (not the link), with paths relative to the top, '/'-separated; nothing below a left-out directory.
        await Assert.That(string.Join(",", recorder.Paths)).IsEqualTo("a.txt,b.tmp,cache,sub,sub/d.txt,sub/e.tmp");
        await Assert.That(recorder["a.txt"].Attributes.Size).IsEqualTo(5L);
        await Assert.That(recorder["a.txt"].Attributes.IsRegularFile).IsTrue();
        await Assert.That(recorder["sub"].Attributes.IsDirectory).IsTrue();
        await Assert.That(recorder["sub/d.txt"].Name).IsEqualTo("d.txt");
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task UploadDirectory_Filter_LeavesOutFilesAndWholeDirectories(int concurrentFiles)
    {
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(Path.Combine(source, "cache"));
        Directory.CreateDirectory(Path.Combine(source, "sub"));
        await File.WriteAllTextAsync(Path.Combine(source, "a.txt"), "alpha");
        await File.WriteAllTextAsync(Path.Combine(source, "b.tmp"), "b");
        await File.WriteAllTextAsync(Path.Combine(source, "cache", "c.txt"), "c");
        await File.WriteAllTextAsync(Path.Combine(source, "sub", "d.txt"), "dd");
        await File.WriteAllTextAsync(Path.Combine(source, "sub", "e.tmp"), "e");
        File.SetLastWriteTimeUtc(Path.Combine(source, "a.txt"), new DateTime(2024, 5, 6, 7, 8, 9, 500, DateTimeKind.Utc));
        await using var rig = await Rig.StartAsync();
        var recorder = new Recorder();

        var summary = await rig.Sftp.UploadDirectoryAsync(source, "up",
            new SftpTransferOptions { Filter = recorder.Wrap(NoTempsOrCache), MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(2, 1, 5 + 2, 0) { Excluded = 3 });
        await Assert.That(string.Join(",", rig.Files.FilesUnder(Home + "/up"))).IsEqualTo($"{Home}/up/a.txt,{Home}/up/sub/d.txt");
        await Assert.That(rig.Files.Exists(Home + "/up/cache")).IsFalse();
        await Assert.That(string.Join(",", recorder.Paths)).IsEqualTo("a.txt,b.tmp,cache,sub,sub/d.txt,sub/e.tmp");

        // The local attributes, as SFTP would carry them: whole seconds.
        var a = recorder["a.txt"].Attributes;
        await Assert.That(a.Size).IsEqualTo(5L);
        await Assert.That(a.FileType).IsEqualTo(SftpFileType.RegularFile);
        await Assert.That(a.LastWriteTime).IsEqualTo(new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero));
        await Assert.That(recorder["sub"].Attributes.FileType).IsEqualTo(SftpFileType.Directory);
        await Assert.That(recorder["sub"].Attributes.Size).IsNull();
    }

    [Test]
    public async Task Filter_ThatThrows_FailsTheTransfer()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", [1]);
        });

        await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"),
            new SftpTransferOptions { Filter = _ => throw new InvalidOperationException("no") }, Timeout())).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task DownloadDirectory_SkipUnchanged_LeavesFilesOfTheSameSizeAndTime(int concurrentFiles)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/same.txt", "same"u8.ToArray(), modifyTime: 1_600_000_000);
            f.AddFile(Home + "/tree/newer.txt", "old"u8.ToArray(), modifyTime: 1_600_000_000);
            f.AddFile(Home + "/tree/longer.txt", "short"u8.ToArray(), modifyTime: 1_600_000_000);
            f.AddFile(Home + "/tree/sneaky.txt", "abc"u8.ToArray(), modifyTime: 1_600_000_000);
            f.AddDirectory(Home + "/tree/sub");
            f.AddFile(Home + "/tree/sub/kept.txt", "kept"u8.ToArray(), modifyTime: 1_600_000_000);
        });
        var target = Path.Combine(_dir, "down");
        var options = new SftpTransferOptions { Preserve = true, SkipUnchanged = true, MaxConcurrentFiles = concurrentFiles };
        await Assert.That((await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout())).Files).IsEqualTo(5);

        // Changed on the server: a newer time (same size), a new size (same time), and new contents with size and time kept as they
        // were, which the quick check cannot see. One more file appears.
        rig.Files.AddFile(Home + "/tree/newer.txt", "new"u8.ToArray(), modifyTime: 1_600_000_100);
        rig.Files.AddFile(Home + "/tree/longer.txt", "longer"u8.ToArray(), modifyTime: 1_600_000_000);
        rig.Files.AddFile(Home + "/tree/sneaky.txt", "xyz"u8.ToArray(), modifyTime: 1_600_000_000);
        rig.Files.AddFile(Home + "/tree/sub/added.txt", "added"u8.ToArray());

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(3, 1, 3 + 6 + 5, 0) { Unchanged = 3 });
        await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "newer.txt"))).IsEqualTo("new");
        await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "longer.txt"))).IsEqualTo("longer");
        await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "sneaky.txt"))).IsEqualTo("abc"); // not a content check
        await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "sub", "added.txt"))).IsEqualTo("added");
    }

    [Test]
    public async Task DownloadDirectory_SkipUnchanged_WithoutPreserve_TransfersEverythingAgain()
    {
        // Without Preserve the local files carry the time they were written, which never matches the server's: as rsync without -t.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", "a"u8.ToArray(), modifyTime: 1_600_000_000);
        });
        var target = Path.Combine(_dir, "down");
        var options = new SftpTransferOptions { SkipUnchanged = true };
        await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(1, 0, 1, 0));
    }

    [Test]
    public async Task DownloadDirectory_SkipUnchanged_ComparesToTheSecond_AndOverridesOverwrite()
    {
        // The local time's fraction is dropped: 1_600_000_000.9 is the server's 1_600_000_000. An unchanged file is left even with
        // Overwrite off, where a changed one would be an error.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", "a"u8.ToArray(), modifyTime: 1_600_000_000);
        });
        var target = Path.Combine(_dir, "down");
        Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "a.txt"), "a");
        File.SetLastWriteTimeUtc(Path.Combine(target, "a.txt"), DateTime.UnixEpoch.AddSeconds(1_600_000_000.9));

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target,
            new SftpTransferOptions { SkipUnchanged = true, Overwrite = false }, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(0, 0, 0, 0) { Unchanged = 1 });
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task UploadDirectory_SkipUnchanged_LeavesRemoteFilesOfTheSameSizeAndTime(int concurrentFiles)
    {
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(Path.Combine(source, "sub"));
        var time = new DateTime(2024, 5, 6, 7, 8, 9, 250, DateTimeKind.Utc);
        foreach (var (name, text) in new[] { ("same.txt", "same"), ("newer.txt", "old"), ("longer.txt", "short"), (Path.Combine("sub", "kept.txt"), "kept") })
        {
            await File.WriteAllTextAsync(Path.Combine(source, name), text);
            File.SetLastWriteTimeUtc(Path.Combine(source, name), time);
        }

        await using var rig = await Rig.StartAsync();
        var options = new SftpTransferOptions { Preserve = true, SkipUnchanged = true, MaxConcurrentFiles = concurrentFiles };
        await Assert.That((await rig.Sftp.UploadDirectoryAsync(source, "up", options, Timeout())).Files).IsEqualTo(4);

        // Every remote directory was created by that upload: there was nothing to compare with, so nothing was listed.
        await Assert.That(rig.Files.Requests.Contains(12)).IsFalse();

        await File.WriteAllTextAsync(Path.Combine(source, "newer.txt"), "new");
        File.SetLastWriteTimeUtc(Path.Combine(source, "newer.txt"), time.AddSeconds(5));
        await File.WriteAllTextAsync(Path.Combine(source, "longer.txt"), "longer");
        File.SetLastWriteTimeUtc(Path.Combine(source, "longer.txt"), time);
        Directory.CreateDirectory(Path.Combine(source, "fresh"));
        await File.WriteAllTextAsync(Path.Combine(source, "fresh", "added.txt"), "added");

        var summary = await rig.Sftp.UploadDirectoryAsync(source, "up", options, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(3, 2, 3 + 6 + 5, 0) { Unchanged = 2 });
        await Assert.That(System.Text.Encoding.UTF8.GetString(rig.Files.FileData(Home + "/up/newer.txt")!)).IsEqualTo("new");
        await Assert.That(System.Text.Encoding.UTF8.GetString(rig.Files.FileData(Home + "/up/longer.txt")!)).IsEqualTo("longer");
        await Assert.That(System.Text.Encoding.UTF8.GetString(rig.Files.FileData(Home + "/up/fresh/added.txt")!)).IsEqualTo("added");
    }

    [Test]
    [Arguments(4u, "File exists", 1)] // OpenSSH
    [Arguments(11u, "File/Directory already exists", 1)] // Apache MINA SSHD: SSH_FX_FILE_ALREADY_EXISTS, a later draft's code
    [Arguments(11u, "", 4)] // the same without a message
    [Arguments(3u, "Permission denied", 4)]
    public async Task UploadDirectory_IntoExistingDirectories_WhateverStatusMkdirAnswers(uint code, string message, int concurrentFiles)
    {
        // A second upload of a tree finds every remote directory there already. Servers say so differently; the upload looks at what
        // is at the path rather than trusting the status, and goes on into a directory.
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(Path.Combine(source, "sub"));
        await File.WriteAllTextAsync(Path.Combine(source, "a.txt"), "a");
        await File.WriteAllTextAsync(Path.Combine(source, "sub", "b.txt"), "bb");
        await using var rig = await Rig.StartAsync(f => f.MkdirExistingStatus = (code, message));
        var options = new SftpTransferOptions { Preserve = true, MaxConcurrentFiles = concurrentFiles };
        await rig.Sftp.UploadDirectoryAsync(source, "up", options, Timeout());

        var again = await rig.Sftp.UploadDirectoryAsync(source, "up", options, Timeout());
        var unchanged = await rig.Sftp.UploadDirectoryAsync(source, "up", new SftpTransferOptions { Preserve = true, SkipUnchanged = true, MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(again).IsEqualTo(new SftpTransferSummary(2, 1, 3, 0));
        await Assert.That(unchanged).IsEqualTo(new SftpTransferSummary(0, 1, 0, 0) { Unchanged = 2 });
    }

    [Test]
    public async Task UploadDirectory_OntoAFile_StillFailsWithTheServersError()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.MkdirExistingStatus = (11, "File/Directory already exists");
            f.AddFile(Home + "/up", [1]);
        });
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(source);
        await File.WriteAllTextAsync(Path.Combine(source, "a.txt"), "a");

        var thrown = await Assert.That(async () => await rig.Sftp.UploadDirectoryAsync(source, "up", cancellationToken: Timeout())).Throws<SftpException>();
        await Assert.That((uint)thrown!.Status).IsEqualTo(11u);
    }

    [Test]
    [Arguments(1600000000L, 1600000000L, 10L, 10L, true)]
    [Arguments(1600000000L, 1600000001L, 10L, 10L, false)]
    [Arguments(1600000000L, 1600000000L, 10L, 11L, false)]
    public async Task IsUnchanged_NeedsTheSameSizeAndSecond(long sourceSeconds, long destinationSeconds, long sourceSize, long destinationSize, bool expected) =>
        await Assert.That(SftpClient.IsUnchanged(sourceSize, DateTimeOffset.FromUnixTimeSeconds(sourceSeconds).AddMilliseconds(999), destinationSize,
            DateTimeOffset.FromUnixTimeSeconds(destinationSeconds))).IsEqualTo(expected);

    [Test]
    public async Task IsUnchanged_MissingSizeOrTime_IsAChange()
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000);
        await Assert.That(SftpClient.IsUnchanged(null, time, 1, time)).IsFalse();
        await Assert.That(SftpClient.IsUnchanged(1, time, null, time)).IsFalse();
        await Assert.That(SftpClient.IsUnchanged(1, null, 1, time)).IsFalse();
        await Assert.That(SftpClient.IsUnchanged(1, time, 1, null)).IsFalse();
    }

    // ---- TimeTolerance (#379) ----

    [Test]
    [Arguments(0, 0L, true)]
    [Arguments(0, 1L, false)]
    [Arguments(999, 1L, false)] // whole seconds: below a second is none
    [Arguments(1000, 1L, true)]
    [Arguments(1000, -1L, true)] // either side may be the later one
    [Arguments(2000, 2L, true)]
    [Arguments(2000, -2L, true)]
    [Arguments(2000, 3L, false)]
    [Arguments(2500, 3L, false)] // a fraction above whole seconds is dropped
    [Arguments(3000, 3L, true)]
    public async Task IsUnchanged_WithATolerance_TakesTimesThatMuchApart(int toleranceMilliseconds, long apartSeconds, bool expected)
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000);
        await Assert.That(SftpClient.IsUnchanged(10, time.AddMilliseconds(999), 10, time.AddSeconds(apartSeconds), TimeSpan.FromMilliseconds(toleranceMilliseconds)))
            .IsEqualTo(expected);
    }

    [Test]
    public async Task IsUnchanged_WithATolerance_StillNeedsTheSameSize()
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000);
        await Assert.That(SftpClient.IsUnchanged(10, time, 11, time, TimeSpan.FromHours(1))).IsFalse();
        await Assert.That(SftpClient.IsUnchanged(10, time, 10, time.AddYears(100), TimeSpan.MaxValue)).IsTrue();
    }

    [Test]
    public async Task TimeTolerance_IsZeroByDefault_AndCannotBeNegative()
    {
        await Assert.That(new SftpTransferOptions().TimeTolerance).IsEqualTo(TimeSpan.Zero);
        await Assert.That(new SftpTransferOptions { TimeTolerance = TimeSpan.FromSeconds(2) }.TimeTolerance).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(() => new SftpTransferOptions { TimeTolerance = TimeSpan.FromTicks(-1) }).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task DownloadDirectory_TimeTolerance_LeavesFilesWhoseTimesDifferByNoMore(int concurrentFiles)
    {
        // The local copies are on a file system that rounded their times (FAT keeps even seconds): one second, two, and three off.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/one.txt", "1"u8.ToArray(), modifyTime: 1_600_000_001);
            f.AddFile(Home + "/tree/two.txt", "2"u8.ToArray(), modifyTime: 1_600_000_003);
            f.AddFile(Home + "/tree/three.txt", "3"u8.ToArray(), modifyTime: 1_600_000_003);
        });
        var target = Path.Combine(_dir, "down");
        Directory.CreateDirectory(target);
        foreach (var (name, text, seconds) in new[] { ("one.txt", "1", 1_600_000_002), ("two.txt", "2", 1_600_000_001), ("three.txt", "3", 1_600_000_006) })
        {
            await File.WriteAllTextAsync(Path.Combine(target, name), text);
            File.SetLastWriteTimeUtc(Path.Combine(target, name), DateTime.UnixEpoch.AddSeconds(seconds));
        }

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target,
            new SftpTransferOptions { SkipUnchanged = true, TimeTolerance = TimeSpan.FromSeconds(2), MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(1, 0, 1, 0) { Unchanged = 2 });
        await Assert.That(File.GetLastWriteTimeUtc(Path.Combine(target, "one.txt"))).IsEqualTo(DateTime.UnixEpoch.AddSeconds(1_600_000_002)); // left alone
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task UploadDirectory_TimeTolerance_LeavesRemoteFilesWhoseTimesDifferByNoMore(int concurrentFiles)
    {
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(source);
        await File.WriteAllTextAsync(Path.Combine(source, "near.txt"), "near");
        File.SetLastWriteTimeUtc(Path.Combine(source, "near.txt"), DateTime.UnixEpoch.AddSeconds(1_600_000_001.5));
        await File.WriteAllTextAsync(Path.Combine(source, "far.txt"), "far");
        File.SetLastWriteTimeUtc(Path.Combine(source, "far.txt"), DateTime.UnixEpoch.AddSeconds(1_600_000_005));
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/up");
            f.AddFile(Home + "/up/near.txt", "near"u8.ToArray(), modifyTime: 1_600_000_000); // a share that kept even seconds
            f.AddFile(Home + "/up/far.txt", "old"u8.ToArray(), modifyTime: 1_600_000_000);
        });

        var summary = await rig.Sftp.UploadDirectoryAsync(source, "up",
            new SftpTransferOptions { SkipUnchanged = true, TimeTolerance = TimeSpan.FromSeconds(1), MaxConcurrentFiles = concurrentFiles }, Timeout());
        var exact = await rig.Sftp.UploadDirectoryAsync(source, "up",
            new SftpTransferOptions { SkipUnchanged = true, MaxConcurrentFiles = concurrentFiles, Filter = e => e.Name == "near.txt" }, Timeout());

        await Assert.That(summary).IsEqualTo(new SftpTransferSummary(1, 0, 3, 0) { Unchanged = 1 });
        await Assert.That(System.Text.Encoding.UTF8.GetString(rig.Files.FileData(Home + "/up/far.txt")!)).IsEqualTo("far");
        await Assert.That(exact.Files).IsEqualTo(1).Because("a second apart is a change without a tolerance");
    }

    // ---- SkipUnreadableDirectories (#379) ----

    /// <summary>tree/a.txt, tree/locked/ (b.txt, inner/c.txt), tree/open/d.txt, tree/z.txt.</summary>
    private static void AddLockedTree(FakeSftpServer files)
    {
        files.AddDirectory(Home + "/tree");
        files.AddFile(Home + "/tree/a.txt", "a"u8.ToArray());
        files.AddDirectory(Home + "/tree/locked");
        files.AddFile(Home + "/tree/locked/b.txt", "b"u8.ToArray());
        files.AddDirectory(Home + "/tree/locked/inner");
        files.AddFile(Home + "/tree/locked/inner/c.txt", "c"u8.ToArray());
        files.AddDirectory(Home + "/tree/open");
        files.AddFile(Home + "/tree/open/d.txt", "d"u8.ToArray());
        files.AddDirectory(Home + "/tree/open/private");
        files.AddFile(Home + "/tree/z.txt", "z"u8.ToArray());
        files.DenyOpenDir = path => path is Home + "/tree/locked" or Home + "/tree/open/private";
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task DownloadDirectory_SkipUnreadableDirectories_LeavesThemOut_AndReportsThem(int concurrentFiles)
    {
        await using var rig = await Rig.StartAsync(AddLockedTree);
        var target = Path.Combine(_dir, "down");

        var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target,
            new SftpTransferOptions { SkipUnreadableDirectories = true, MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(summary with { UnreadableDirectories = [] }).IsEqualTo(new SftpTransferSummary(3, 1, 3, 0));
        await Assert.That(string.Join(",", summary.UnreadableDirectories)).IsEqualTo("locked,open/private");
        await Assert.That(File.Exists(Path.Combine(target, "z.txt"))).IsTrue(); // the transfer went on after them
        await Assert.That(File.Exists(Path.Combine(target, "open", "d.txt"))).IsTrue();
        await Assert.That(Path.Exists(Path.Combine(target, "locked"))).IsFalse(); // not created
        await Assert.That(Path.Exists(Path.Combine(target, "open", "private"))).IsFalse();
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task DownloadDirectory_AnUnreadableDirectory_FailsTheTransferByDefault(int concurrentFiles)
    {
        await using var rig = await Rig.StartAsync(AddLockedTree);

        var thrown = await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"),
            new SftpTransferOptions { MaxConcurrentFiles = concurrentFiles }, Timeout())).Throws<SftpException>();

        await Assert.That(thrown!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
    }

    [Test]
    [Arguments(2u, "No such file")] // deleted meanwhile
    [Arguments(4u, "Failure")]
    public async Task DownloadDirectory_SkipUnreadableDirectories_StillFailsOnOtherErrors(uint code, string message)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddLockedTree(f);
            f.DenyOpenDirStatus = (code, message);
        });

        var thrown = await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"),
            new SftpTransferOptions { SkipUnreadableDirectories = true }, Timeout())).Throws<SftpException>();

        await Assert.That((uint)thrown!.Status).IsEqualTo(code);
    }

    [Test]
    public async Task DownloadDirectory_SkipUnreadableDirectories_TheTopDirectoryStillFails()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddLockedTree(f);
            f.DenyOpenDir = path => path == Home + "/tree";
        });

        var thrown = await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"),
            new SftpTransferOptions { SkipUnreadableDirectories = true }, Timeout())).Throws<SftpException>();

        await Assert.That(thrown!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task UploadDirectory_SkipUnreadableDirectories_LeavesLocalOnesOut_AndReportsThem(int concurrentFiles)
    {
        var source = Path.Combine(_dir, "up");
        Directory.CreateDirectory(Path.Combine(source, "locked", "inner"));
        Directory.CreateDirectory(Path.Combine(source, "open"));
        await File.WriteAllTextAsync(Path.Combine(source, "a.txt"), "a");
        await File.WriteAllTextAsync(Path.Combine(source, "locked", "b.txt"), "b");
        await File.WriteAllTextAsync(Path.Combine(source, "open", "d.txt"), "d");
        await File.WriteAllTextAsync(Path.Combine(source, "z.txt"), "z");
        using var denied = LocalDenial.Deny(Path.Combine(source, "locked"));
        await using var rig = await Rig.StartAsync();

        var thrown = await Assert.That(async () => await rig.Sftp.UploadDirectoryAsync(source, "failed",
            new SftpTransferOptions { MaxConcurrentFiles = concurrentFiles }, Timeout())).Throws<UnauthorizedAccessException>();
        var summary = await rig.Sftp.UploadDirectoryAsync(source, "up",
            new SftpTransferOptions { SkipUnreadableDirectories = true, MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(thrown).IsNotNull(); // by default
        await Assert.That(summary with { UnreadableDirectories = [] }).IsEqualTo(new SftpTransferSummary(3, 1, 3, 0));
        await Assert.That(string.Join(",", summary.UnreadableDirectories)).IsEqualTo("locked");
        await Assert.That(string.Join(",", rig.Files.FilesUnder(Home + "/up"))).IsEqualTo($"{Home}/up/a.txt,{Home}/up/open/d.txt,{Home}/up/z.txt");
        await Assert.That(rig.Files.Exists(Home + "/up/locked")).IsFalse(); // not created
    }

    /// <summary>
    /// Makes a local directory unreadable for this account (a deny ACE for listing it on Windows, mode 000 elsewhere) until disposed,
    /// so the temporary tree can be deleted again.
    /// </summary>
    private sealed class LocalDenial : IDisposable
    {
        private readonly string _path;
        private readonly System.Security.AccessControl.FileSystemAccessRule? _rule;
        private readonly UnixFileMode _mode;

        private LocalDenial(string path)
        {
            _path = path;
            if (OperatingSystem.IsWindows())
            {
                _rule = new System.Security.AccessControl.FileSystemAccessRule(System.Security.Principal.WindowsIdentity.GetCurrent().User!,
                    System.Security.AccessControl.FileSystemRights.ListDirectory, System.Security.AccessControl.AccessControlType.Deny);
                var info = new DirectoryInfo(path);
                var security = info.GetAccessControl();
                security.AddAccessRule(_rule);
                info.SetAccessControl(security);
            }
            else
            {
                _mode = File.GetUnixFileMode(path);
                File.SetUnixFileMode(path, UnixFileMode.None);
            }
        }

        public static LocalDenial Deny(string path)
        {
            var denial = new LocalDenial(path);
            try
            {
                _ = Directory.EnumerateFileSystemEntries(path).Any();
            }
            catch (UnauthorizedAccessException)
            {
                return denial;
            }

            denial.Dispose();
            Skip.Test("This account reads every directory (root), so none can be made unreadable to it.");
            return denial;
        }

        public void Dispose()
        {
            if (OperatingSystem.IsWindows())
            {
                var info = new DirectoryInfo(_path);
                var security = info.GetAccessControl();
                security.RemoveAccessRule(_rule!);
                info.SetAccessControl(security);
            }
            else
            {
                File.SetUnixFileMode(_path, _mode);
            }
        }
    }
}
