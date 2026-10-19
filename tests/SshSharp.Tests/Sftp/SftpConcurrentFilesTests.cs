using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Directory transfers with several files at once (<see cref="SftpTransferOptions.MaxConcurrentFiles"/>, #278).</summary>
public sealed class SftpConcurrentFilesTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-sftpconc-" + Guid.NewGuid().ToString("N"));

    public SftpConcurrentFilesTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows())
        {
            // A preserved read-only directory would keep the test's directory from being removed.
            foreach (var directory in Directory.EnumerateDirectories(_dir, "*", SearchOption.AllDirectories))
            {
                File.SetUnixFileMode(directory, (UnixFileMode)0x1ED);
            }
        }

        Directory.Delete(_dir, recursive: true);
    }

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

    /// <summary>
    /// A tree of many small files and some larger ones, nested four levels deep, with an empty directory: the relative paths (with
    /// <c>/</c>) and their contents.
    /// </summary>
    private static Dictionary<string, byte[]> Tree(int seed = 278)
    {
        var random = new Random(seed);
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        int[] sizes = [0, 1, 17, 1000, 4096, 70_000, 200_000];
        string[] directories = ["", "a", "a/b", "a/b/c", "a/b/c/d", "e", "e/f"];
        var n = 0;
        foreach (var directory in directories)
        {
            for (var i = 0; i < 9; i++, n++)
            {
                var data = new byte[sizes[n % sizes.Length] + (n % 3)];
                random.NextBytes(data);
                files[(directory.Length == 0 ? "" : directory + "/") + $"file{n:D2}.bin"] = data;
            }
        }

        return files;
    }

    private static readonly string[] TreeDirectories = ["a", "a/b", "a/b/c", "a/b/c/d", "e", "e/f", "empty"];

    private static void AddRemoteTree(FakeSftpServer server, string root, Dictionary<string, byte[]> tree)
    {
        server.AddDirectory(root);
        foreach (var directory in TreeDirectories)
        {
            server.AddDirectory(root + "/" + directory);
        }

        foreach (var (path, data) in tree)
        {
            server.AddFile(root + "/" + path, data);
        }
    }

    private static string WriteLocalTree(string root, Dictionary<string, byte[]> tree)
    {
        foreach (var directory in TreeDirectories)
        {
            Directory.CreateDirectory(Path.Combine(root, directory));
        }

        foreach (var (path, data) in tree)
        {
            File.WriteAllBytes(Path.Combine(root, path), data);
        }

        return root;
    }

    private static SftpTransferSummary Expected(Dictionary<string, byte[]> tree) =>
        new(tree.Count, TreeDirectories.Length, tree.Values.Sum(d => (long)d.Length), 0);

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    [Arguments(16)]
    public async Task ATree_DownloadsAndUploadsTheSame_WithAnyNumberOfFilesAtOnce(int files)
    {
        var tree = Tree();
        var server = new FakeSftpServer();
        AddRemoteTree(server, Home + "/tree", tree);
        var rig = await StartAsync(server);
        try
        {
            var options = new SftpTransferOptions { MaxConcurrentFiles = files };
            var target = Path.Combine(_dir, "down");
            var down = await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());

            await Assert.That(down).IsEqualTo(Expected(tree));
            await Assert.That(Directory.Exists(Path.Combine(target, "empty"))).IsTrue();
            foreach (var (path, data) in tree)
            {
                await Assert.That((await File.ReadAllBytesAsync(Path.Combine(target, path))).AsSpan().SequenceEqual(data)).IsTrue();
            }

            var up = await rig.Sftp.UploadDirectoryAsync(target, "up", options, Timeout());

            await Assert.That(up).IsEqualTo(Expected(tree));
            await Assert.That(server.Exists(Home + "/up/empty")).IsTrue();
            await Assert.That(server.FilesUnder(Home + "/up").Count).IsEqualTo(tree.Count);
            foreach (var (path, data) in tree)
            {
                await Assert.That(server.FileData(Home + "/up/" + path)!.AsSpan().SequenceEqual(data)).IsTrue();
            }

            await Assert.That(server.MissingParents).IsEqualTo(0);
            await Assert.That(server.OpenHandles).IsEqualTo(0);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    [Arguments(16)]
    public async Task TheNumberOfFilesOpenAtOnce_NeverExceedsTheLimit(int files)
    {
        // The latency keeps every file open for a few round trips, so the transfers overlap as much as the limit lets them.
        var tree = Tree();
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(5) };
        AddRemoteTree(server, Home + "/tree", tree);
        var rig = await StartAsync(server);
        try
        {
            var options = new SftpTransferOptions { MaxConcurrentFiles = files };
            await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"), options, Timeout());
            var downloading = server.MaxOpenFileHandles;
            await rig.Sftp.UploadDirectoryAsync(Path.Combine(_dir, "down"), "up", options, Timeout());

            await Assert.That(downloading).IsLessThanOrEqualTo(files);
            await Assert.That(server.MaxOpenFileHandles).IsLessThanOrEqualTo(files);
            if (files == 1)
            {
                await Assert.That(server.MaxOpenFileHandles).IsEqualTo(1);
            }
            else
            {
                await Assert.That(downloading).IsGreaterThan(1); // they did overlap
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task TheFiles_ShareMaxRequestsInFlight_RatherThanTakeThatManyEach()
    {
        // Eight larger files at once, each of which alone would fill a window of 8: together they still keep at most 8 reads, or 8
        // writes, in flight (and so in memory), not 64.
        var data = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(5), Limits = (16 * 1024, 16 * 1024) };
        server.AddDirectory(Home + "/big");
        for (var i = 0; i < 8; i++)
        {
            var bytes = new byte[300_000];
            new Random(i).NextBytes(bytes);
            data[$"f{i}"] = bytes;
            server.AddFile(Home + "/big/f" + i, bytes);
        }

        var rig = await StartAsync(server);
        try
        {
            var options = new SftpTransferOptions { MaxConcurrentFiles = 8, MaxRequestsInFlight = 8 };
            var target = Path.Combine(_dir, "big");
            await rig.Sftp.DownloadDirectoryAsync("big", target, options, Timeout());
            await Assert.That(server.MaxDataRequestsInFlight).IsLessThanOrEqualTo(8);
            await Assert.That(server.MaxOpenFileHandles).IsGreaterThan(1);

            await rig.Sftp.UploadDirectoryAsync(target, "up", options, Timeout());
            await Assert.That(server.MaxDataRequestsInFlight).IsLessThanOrEqualTo(8);
            foreach (var (name, bytes) in data)
            {
                await Assert.That((await File.ReadAllBytesAsync(Path.Combine(target, name))).AsSpan().SequenceEqual(bytes)).IsTrue();
                await Assert.That(server.FileData(Home + "/up/" + name)!.AsSpan().SequenceEqual(bytes)).IsTrue();
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task NoFileOrDirectory_IsCreatedBeforeItsParentExists()
    {
        // A deep, wide tree: directories are created several at a time and files start as soon as theirs exists. The fake server, as
        // a real one, refuses a MKDIR or an OPEN whose parent is missing, and counts every one.
        var local = Path.Combine(_dir, "deep");
        var expected = new List<string>();
        for (var branch = 0; branch < 6; branch++)
        {
            var path = local;
            var relative = "";
            for (var depth = 0; depth < 6; depth++)
            {
                path = Path.Combine(path, $"d{branch}{depth}");
                relative += $"/d{branch}{depth}";
                Directory.CreateDirectory(path);
                for (var i = 0; i < 3; i++)
                {
                    await File.WriteAllTextAsync(Path.Combine(path, $"f{i}"), relative);
                    expected.Add(Home + "/up" + relative + $"/f{i}");
                }
            }
        }

        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(2) };
        var rig = await StartAsync(server);
        try
        {
            var summary = await rig.Sftp.UploadDirectoryAsync(local, "up", new SftpTransferOptions { MaxConcurrentFiles = 16 }, Timeout());

            await Assert.That(summary.Files).IsEqualTo(expected.Count);
            await Assert.That(summary.Directories).IsEqualTo(36);
            await Assert.That(server.MissingParents).IsEqualTo(0);
            await Assert.That(server.FilesUnder(Home + "/up")).IsEquivalentTo(expected.Order(StringComparer.Ordinal));
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task TheFirstFailure_StopsTheRest_AndIsTheExceptionThrown()
    {
        var tree = Tree();
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(2) };
        AddRemoteTree(server, Home + "/tree", tree);
        // The listing is in name order and directories come before files ("a" < "file"), so a/b/c/d holds the first files fetched.
        server.FailOpen = path => path.EndsWith("/a/b/c/d/file37.bin", StringComparison.Ordinal);
        var rig = await StartAsync(server);
        try
        {
            var options = new SftpTransferOptions { MaxConcurrentFiles = 4 };
            var target = Path.Combine(_dir, "down");
            var error = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout()));

            // Not wrapped, and not the cancellations it caused in the other files.
            await Assert.That(error!.Path).IsEqualTo("tree/a/b/c/d/file37.bin");
            await Assert.That(error.Status).IsEqualTo(SftpStatusCode.Failure);

            // The walk stopped: of the 63 files, only those started before the failure (a few slots' worth) were fetched, and each file
            // left behind is complete (a cancelled download removes what it wrote, as a single-file download does).
            var written = Directory.GetFiles(target, "*", SearchOption.AllDirectories);
            await Assert.That(written.Length).IsLessThan(tree.Count / 2);
            foreach (var file in written)
            {
                var relative = Path.GetRelativePath(target, file).Replace('\\', '/');
                await Assert.That((await File.ReadAllBytesAsync(file)).AsSpan().SequenceEqual(tree[relative])).IsTrue();
            }

            // The same on the way up: the failing file's open is the error, not a cancellation.
            server.FailOpen = path => path.EndsWith("/a/b/file22.bin", StringComparison.Ordinal);
            var source = WriteLocalTree(Path.Combine(_dir, "source"), tree);
            var upError = await Assert.ThrowsAsync<SftpException>(async () => await rig.Sftp.UploadDirectoryAsync(source, "up", options, Timeout()));
            await Assert.That(upError!.Path).IsEqualTo("up/a/b/file22.bin");
            await Assert.That(server.FilesUnder(Home + "/up").Count).IsLessThan(tree.Count);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task AFailedDirectory_StopsTheUpload_AndIsTheExceptionThrown()
    {
        var tree = Tree();
        var source = WriteLocalTree(Path.Combine(_dir, "source"), tree);
        var server = new FakeSftpServer();
        server.AddDirectory(Home + "/up");
        server.AddFile(Home + "/up/e", "a file where a directory goes"u8.ToArray());
        var rig = await StartAsync(server);
        try
        {
            var error = await Assert.ThrowsAsync<SftpException>(async () =>
                await rig.Sftp.UploadDirectoryAsync(source, "up", new SftpTransferOptions { MaxConcurrentFiles = 8 }, Timeout()));

            await Assert.That(error!.Path).IsEqualTo("up/e");
            await Assert.That(server.Exists(Home + "/up/e/file45.bin")).IsFalse();
            await Assert.That(server.MissingParents).IsEqualTo(0);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task Cancelling_StopsEveryFile()
    {
        var tree = Tree();
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(2) };
        AddRemoteTree(server, Home + "/tree", tree);
        var rig = await StartAsync(server);
        try
        {
            // Cancelled from the progress callback once some data has arrived, while several files are in flight.
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(Timeout());
            var reports = 0;
            var options = new SftpTransferOptions
            {
                MaxConcurrentFiles = 8,
                Progress = new Callback(_ =>
                {
                    if (++reports == 10)
                    {
                        cancel.Cancel();
                    }
                }),
            };
            var target = Path.Combine(_dir, "down");
            await Assert.That(async () => await rig.Sftp.DownloadDirectoryAsync("tree", target, options, cancel.Token)).Throws<OperationCanceledException>();

            var written = Directory.GetFiles(target, "*", SearchOption.AllDirectories);
            await Assert.That(written.Length).IsLessThan(tree.Count);
            foreach (var file in written)
            {
                var relative = Path.GetRelativePath(target, file).Replace('\\', '/');
                await Assert.That((await File.ReadAllBytesAsync(file)).AsSpan().SequenceEqual(tree[relative])).IsTrue(); // no partial file
            }

            // And on the way up.
            using var cancelUp = CancellationTokenSource.CreateLinkedTokenSource(Timeout());
            var upReports = 0;
            var upOptions = new SftpTransferOptions
            {
                MaxConcurrentFiles = 8,
                Progress = new Callback(_ =>
                {
                    if (++upReports == 10)
                    {
                        cancelUp.Cancel();
                    }
                }),
            };
            var source = WriteLocalTree(Path.Combine(_dir, "source"), tree);
            await Assert.That(async () => await rig.Sftp.UploadDirectoryAsync(source, "up", upOptions, cancelUp.Token)).Throws<OperationCanceledException>();
            await Assert.That(server.FilesUnder(Home + "/up").Count).IsLessThan(tree.Count);

            // The session is still usable after both.
            await Assert.That(await rig.Sftp.ExistsAsync("tree/file00.bin", Timeout())).IsTrue();
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task Progress_ReportsEveryFileToItsSize_OneReportAtATime()
    {
        var tree = Tree();
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(1) };
        AddRemoteTree(server, Home + "/tree", tree);
        var rig = await StartAsync(server);
        try
        {
            foreach (var upload in new[] { false, true })
            {
                var last = new Dictionary<string, SftpTransferProgress>(StringComparer.Ordinal);
                var inside = 0;
                var overlapped = false;
                var options = new SftpTransferOptions
                {
                    MaxConcurrentFiles = 8,
                    Progress = new Callback(report =>
                    {
                        if (Interlocked.Increment(ref inside) > 1)
                        {
                            overlapped = true;
                        }

                        Thread.SpinWait(200); // a callback that takes a moment: a second report arriving meanwhile would overlap it
                        last[report.Path] = report; // a plain dictionary: reports made at the same time would corrupt it
                        Interlocked.Decrement(ref inside);
                    }),
                };

                var summary = upload
                    ? await rig.Sftp.UploadDirectoryAsync(Path.Combine(_dir, "down"), "up", options, Timeout())
                    : await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"), options, Timeout());

                await Assert.That(overlapped).IsFalse();
                var nonEmpty = tree.Where(f => f.Value.Length > 0).ToList(); // an empty file has nothing to report
                await Assert.That(last.Count).IsEqualTo(nonEmpty.Count);
                foreach (var (path, data) in nonEmpty)
                {
                    var report = last[(upload ? "up/" : "tree/") + path];
                    await Assert.That(report.BytesTransferred).IsEqualTo((long)data.Length);
                    await Assert.That(report.TotalBytes).IsEqualTo((long)data.Length);
                }

                await Assert.That(last.Values.Sum(r => r.BytesTransferred)).IsEqualTo(summary.Bytes);
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task Preserve_SetsDirectoryTimes_AfterEveryFileIsIn()
    {
        var server = new FakeSftpServer();
        server.AddDirectory(Home + "/tree");
        server.AddDirectory(Home + "/tree/sub");
        server.AddDirectory(Home + "/tree/sub/deeper");
        for (var i = 0; i < 12; i++)
        {
            server.AddFile(Home + $"/tree/sub/deeper/f{i}", new byte[5000 + i], modifyTime: 1_600_000_000);
            server.AddFile(Home + $"/tree/sub/g{i}", new byte[i], modifyTime: 1_600_000_000);
        }

        var rig = await StartAsync(server);
        try
        {
            // The fake gives directories a default time; give these their own, so each can be told apart.
            await rig.Sftp.SetAttributesAsync("tree/sub", Times(1_500_000_000), Timeout());
            await rig.Sftp.SetAttributesAsync("tree/sub/deeper", Times(1_400_000_000), Timeout());

            var target = Path.Combine(_dir, "down");
            var options = new SftpTransferOptions { MaxConcurrentFiles = 8, Preserve = true };
            await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());

            await Assert.That(new DateTimeOffset(Directory.GetLastWriteTimeUtc(Path.Combine(target, "sub")))).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_500_000_000));
            await Assert.That(new DateTimeOffset(Directory.GetLastWriteTimeUtc(Path.Combine(target, "sub", "deeper")))).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_400_000_000));
            await Assert.That(new DateTimeOffset(File.GetLastWriteTimeUtc(Path.Combine(target, "sub", "deeper", "f3")))).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000));

            await rig.Sftp.UploadDirectoryAsync(target, "up", options, Timeout());

            await Assert.That(server.ModifyTime(Home + "/up/sub")).IsEqualTo(1_500_000_000u);
            await Assert.That(server.ModifyTime(Home + "/up/sub/deeper")).IsEqualTo(1_400_000_000u);
            await Assert.That(server.ModifyTime(Home + "/up/sub/deeper/f3")).IsEqualTo(1_600_000_000u);
        }
        finally
        {
            await StopAsync(rig);
        }

        static SftpFileAttributes Times(long seconds) => new()
        {
            LastWriteTime = DateTimeOffset.FromUnixTimeSeconds(seconds),
            LastAccessTime = DateTimeOffset.FromUnixTimeSeconds(seconds),
        };
    }

    [Test]
    public async Task NamesThatDifferOnlyInCase_AreFetchedOneAfterTheOther()
    {
        // On Windows (and macOS by default) they are one local file: fetched at once they would collide; one after the other, the last
        // listed replaces the first, as with one file at a time.
        var server = new FakeSftpServer();
        server.AddDirectory(Home + "/tree");
        server.AddFile(Home + "/tree/README", new byte[100_000]);
        server.AddFile(Home + "/tree/readme", "lower"u8.ToArray());
        for (var i = 0; i < 6; i++)
        {
            server.AddFile(Home + $"/tree/other{i}", [(byte)i]);
        }

        var rig = await StartAsync(server);
        try
        {
            var target = Path.Combine(_dir, "down");
            var summary = await rig.Sftp.DownloadDirectoryAsync("tree", target, new SftpTransferOptions { MaxConcurrentFiles = 8 }, Timeout());

            await Assert.That(summary.Files).IsEqualTo(8);
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(target, "readme"))).IsEqualTo("lower");
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task TheServersOpenHandleLimit_CapsTheFilesAtOnce()
    {
        var tree = Tree();
        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(2), MaxHandles = 4 };
        AddRemoteTree(server, Home + "/tree", tree);
        var rig = await StartAsync(server);
        try
        {
            await Assert.That(rig.Sftp.Limits.MaxOpenHandles).IsEqualTo(4);
            await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"), new SftpTransferOptions { MaxConcurrentFiles = 16 }, Timeout());

            await Assert.That(server.MaxOpenFileHandles).IsLessThanOrEqualTo(3); // one handle kept for the listing
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task SegmentsAndSeveralFiles_Combine()
    {
        var server = new FakeSftpServer();
        server.AddDirectory(Home + "/big");
        var data = new byte[3][];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = new byte[2_500_000 + i];
            new Random(i).NextBytes(data[i]);
            server.AddFile(Home + $"/big/f{i}", data[i]);
        }

        var rig = await StartAsync(server);
        try
        {
            var target = Path.Combine(_dir, "big");
            var options = new SftpTransferOptions { MaxConcurrentFiles = 3, Segments = 2, MaxRequestsInFlight = 16 };
            await rig.Sftp.DownloadDirectoryAsync("big", target, options, Timeout());

            await Assert.That(server.Sessions).IsGreaterThan(1); // the files' segments used sessions of their own
            await Assert.That(server.MaxDataRequestsInFlight).IsLessThanOrEqualTo(16); // shared across those sessions too
            for (var i = 0; i < data.Length; i++)
            {
                await Assert.That((await File.ReadAllBytesAsync(Path.Combine(target, $"f{i}"))).AsSpan().SequenceEqual(data[i])).IsTrue();
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task MaxConcurrentFiles_IsOneByDefault_AndBounded()
    {
        await Assert.That(new SftpTransferOptions().MaxConcurrentFiles).IsEqualTo(1);
        await Assert.That(new SftpTransferOptions { MaxConcurrentFiles = 64 }.MaxConcurrentFiles).IsEqualTo(64);
        await Assert.That(() => new SftpTransferOptions { MaxConcurrentFiles = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpTransferOptions { MaxConcurrentFiles = 65 }).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Category("Measure")] // opt-in with SSHSHARP_MEASURE=1; CI leaves it out
    public async Task OverLatency_SeveralFilesAtOnce_Measure()
    {
        // A measurement, not a check: run with SSHSHARP_MEASURE=1 to print how long a tree of small files takes over 25 ms of latency,
        // one file at a time and several. Nothing here asserts a time.
        if (Environment.GetEnvironmentVariable("SSHSHARP_MEASURE") != "1")
        {
            Skip.Test("Set SSHSHARP_MEASURE=1 to measure.");
            return;
        }

        var tree = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        for (var i = 0; i < 100; i++)
        {
            tree[$"d{i % 4}/f{i:D3}"] = new byte[2000 + i];
        }

        var server = new FakeSftpServer { Latency = TimeSpan.FromMilliseconds(25) };
        server.AddDirectory(Home + "/tree");
        for (var d = 0; d < 4; d++)
        {
            server.AddDirectory(Home + $"/tree/d{d}");
        }

        foreach (var (path, data) in tree)
        {
            server.AddFile(Home + "/tree/" + path, data);
        }

        var rig = await StartAsync(server);
        try
        {
            foreach (var files in new[] { 1, 4, 8, 16 })
            {
                var options = new SftpTransferOptions { MaxConcurrentFiles = files };
                var target = Path.Combine(_dir, "down" + files);
                var clock = System.Diagnostics.Stopwatch.StartNew();
                await rig.Sftp.DownloadDirectoryAsync("tree", target, options, Timeout());
                var down = clock.Elapsed;
                clock.Restart();
                await rig.Sftp.UploadDirectoryAsync(target, "up" + files, options, Timeout());
                var up = clock.Elapsed;
                Console.WriteLine($"100 files, 25 ms latency, MaxConcurrentFiles={files}: download {down.TotalSeconds:F2} s, upload {up.TotalSeconds:F2} s");
            }
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    /// <summary>A synchronous progress callback: <see cref="Progress{T}"/> would post each report to the thread pool instead.</summary>
    private sealed class Callback(Action<SftpTransferProgress> report) : IProgress<SftpTransferProgress>
    {
        public void Report(SftpTransferProgress value) => report(value);
    }
}
