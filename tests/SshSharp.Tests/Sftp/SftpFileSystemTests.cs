// The interfaces mark Unix modes as Unix-only and encryption as Windows-only (true of local files); over SFTP they work, or fail
// with NotSupportedException, from any client OS.
#pragma warning disable CA1416

using System.IO.Abstractions;
using System.Security.Cryptography;
using System.Text;
using SshSharp.IO.Abstractions;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary><see cref="SftpFileSystem"/> (#134): System.IO.Abstractions over SFTP, against the in-memory server.</summary>
public class SftpFileSystemTests
{
    private const string Home = FakeSftpServer.Home;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public SftpFileSystem Fs { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, SftpFileSystemOptions? options = null)
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
            }, leaveOpen: true, Timeout());
            rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            rig.Fs = new SftpFileSystem(rig.Sftp, options);
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    // ---- Path ----

    [Test]
    public async Task Path_HasPosixSemantics_OnEveryClientOs()
    {
        await using var rig = await Rig.StartAsync();
        var path = rig.Fs.Path;

        await Assert.That(path.DirectorySeparatorChar).IsEqualTo('/');
        await Assert.That(path.PathSeparator).IsEqualTo(':');
        await Assert.That(path.Combine("a", "b", "c.txt")).IsEqualTo("a/b/c.txt");
        await Assert.That(path.Combine("a", "/root", "x")).IsEqualTo("/root/x");
        await Assert.That(path.Join("a/", "/b")).IsEqualTo("a//b");
        await Assert.That(path.Join("a", "b")).IsEqualTo("a/b");
        await Assert.That(path.GetDirectoryName("/a/b/c.txt")).IsEqualTo("/a/b");
        await Assert.That(path.GetDirectoryName("/a")).IsEqualTo("/");
        await Assert.That(path.GetDirectoryName("/")).IsNull();
        await Assert.That(path.GetDirectoryName("a")).IsEqualTo(string.Empty);
        await Assert.That(path.GetFileName("/a/b/c.tar.gz")).IsEqualTo("c.tar.gz");
        await Assert.That(path.GetExtension("/a/b/c.tar.gz")).IsEqualTo(".gz");
        // A name that starts with its only dot is all extension, as System.IO.Path has it.
        await Assert.That(path.GetExtension("/a/.bashrc")).IsEqualTo(System.IO.Path.GetExtension("/a/.bashrc")).And.IsEqualTo(".bashrc");
        await Assert.That(path.GetFileNameWithoutExtension("/a/.bashrc")).IsEqualTo(System.IO.Path.GetFileNameWithoutExtension("/a/.bashrc")).And.IsEmpty();
        await Assert.That(path.HasExtension(".bashrc")).IsTrue();
        await Assert.That(path.GetExtension("/a/file.")).IsEqualTo(string.Empty);
        await Assert.That(path.GetFileNameWithoutExtension("/a/file.")).IsEqualTo("file");
        await Assert.That(rig.Fs.FileInfo.New("/a/.profile").Extension).IsEqualTo(".profile");
        await Assert.That(path.GetFileNameWithoutExtension("dir.d/file.txt")).IsEqualTo("file");
        await Assert.That(path.ChangeExtension("a/b.txt", "md")).IsEqualTo("a/b.md");
        await Assert.That(path.ChangeExtension("a/b.txt", null)).IsEqualTo("a/b");
        await Assert.That(path.HasExtension("a.b/c")).IsFalse();
        await Assert.That(path.IsPathRooted("/x")).IsTrue();
        await Assert.That(path.IsPathRooted("C:\\x")).IsFalse(); // not a POSIX root
        await Assert.That(path.GetPathRoot("/x/y")).IsEqualTo("/");
        await Assert.That(path.GetFullPath("docs/../x.txt")).IsEqualTo(Home + "/x.txt");
        await Assert.That(path.GetFullPath("y", "/base")).IsEqualTo("/base/y");
        await Assert.That(path.GetRelativePath("/a/b", "/a/c/d")).IsEqualTo("../c/d");
        await Assert.That(path.TrimEndingDirectorySeparator("/a/b/")).IsEqualTo("/a/b");
        await Assert.That(path.TrimEndingDirectorySeparator("/")).IsEqualTo("/");
        await Assert.That(path.GetInvalidFileNameChars()).IsEquivalentTo(new[] { '\0', '/' });
        await Assert.That(path.GetTempPath()).IsEqualTo("/tmp/");
        var destination = new char[16];
        await Assert.That(path.TryJoin("ab", "cd", destination, out var written)).IsTrue();
        await Assert.That(new string(destination, 0, written)).IsEqualTo("ab/cd");
        await Assert.That(path.TryJoin("ab", "cd", new char[2], out _)).IsFalse();
    }

    // ---- File ----

    [Test]
    public async Task Text_RoundTrips_WithEncodingsAndByteOrderMarks()
    {
        await using var rig = await Rig.StartAsync();
        var file = rig.Fs.File;

        file.WriteAllText("plain.txt", "héllo");
        await Assert.That(rig.Files.FileData(Home + "/plain.txt")).IsEquivalentTo(Encoding.UTF8.GetBytes("héllo")); // UTF-8 without BOM
        await Assert.That(file.ReadAllText("plain.txt")).IsEqualTo("héllo");

        file.WriteAllText("utf16.txt", "wide", Encoding.Unicode);
        await Assert.That(rig.Files.FileData(Home + "/utf16.txt")!.Take(2)).IsEquivalentTo(new byte[] { 0xFF, 0xFE });
        await Assert.That(file.ReadAllText("utf16.txt")).IsEqualTo("wide"); // the BOM decides

        file.WriteAllLines("lines.txt", ["one", "two"]);
        file.AppendAllLines("lines.txt", ["three"]);
        file.AppendAllText("lines.txt", "four");
        await Assert.That(file.ReadAllLines("lines.txt")).IsEquivalentTo(["one", "two", "three", "four"]);
        await Assert.That(file.ReadLines("lines.txt").First()).IsEqualTo("one");

        await file.WriteAllTextAsync("async.txt", "async text", Timeout());
        await file.AppendAllTextAsync("async.txt", "!", Timeout());
        await Assert.That(await file.ReadAllTextAsync("async.txt", Timeout())).IsEqualTo("async text!");
        var lines = new List<string>();
        await foreach (var line in file.ReadLinesAsync("lines.txt", Timeout()))
        {
            lines.Add(line);
        }

        await Assert.That(lines.Count).IsEqualTo(4);
    }

    [Test]
    public async Task Bytes_RoundTrip_ThroughTheStreams_WithManySmallWrites()
    {
        await using var rig = await Rig.StartAsync();
        var data = RandomNumberGenerator.GetBytes(500_000);

        rig.Fs.File.WriteAllBytes("blob", data);
        await Assert.That(rig.Fs.File.ReadAllBytes("blob").AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That((await rig.Fs.File.ReadAllBytesAsync("blob", Timeout())).AsSpan().SequenceEqual(data)).IsTrue();

        // A StreamWriter's small writes, synchronously, then read back with a StreamReader.
        using (var writer = rig.Fs.File.CreateText("log.txt"))
        {
            for (var i = 0; i < 2000; i++)
            {
                writer.WriteLine($"line {i}");
            }
        }

        var requests = rig.Files.Requests.Count(t => t == 6); // SSH_FXP_WRITE
        await Assert.That(requests).IsLessThan(10); // buffered into few large writes
        using (var reader = rig.Fs.File.OpenText("log.txt"))
        {
            await Assert.That(reader.ReadLine()).IsEqualTo("line 0");
        }

        await Assert.That(rig.Fs.File.ReadAllLines("log.txt").Length).IsEqualTo(2000);

        using (var stream = rig.Fs.File.Open("blob", FileMode.Open, FileAccess.ReadWrite))
        {
            await Assert.That(stream.Length).IsEqualTo(500_000L);
            stream.Seek(-4, SeekOrigin.End);
            stream.Write("tail"u8);
            stream.Position = 0;
            var first = new byte[4];
            stream.ReadExactly(first);
            await Assert.That(first.AsSpan().SequenceEqual(data.AsSpan(0, 4))).IsTrue();
            await Assert.That(stream.Name).IsEqualTo(Home + "/blob");
        }

        await Assert.That(rig.Files.FileData(Home + "/blob")![^4..]).IsEquivalentTo("tail"u8.ToArray());
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task MissingFilesAndDirectories_AreTheUsualExceptions()
    {
        await using var rig = await Rig.StartAsync(f => f.AddDirectory(Home + "/dir"));
        var file = rig.Fs.File;

        await Assert.That(() => file.ReadAllText("nope.txt")).Throws<FileNotFoundException>();
        await Assert.That(() => file.OpenRead("nope.txt")).Throws<FileNotFoundException>();
        await Assert.That(() => file.WriteAllText("no/such/dir/x.txt", "x")).Throws<DirectoryNotFoundException>();
        await Assert.That(() => file.Create("no/such/dir/x.txt")).Throws<DirectoryNotFoundException>();
        await Assert.That(async () => await file.ReadAllTextAsync("nope.txt", Timeout())).Throws<FileNotFoundException>();
        await Assert.That(() => file.ReadLines("nope.txt")).Throws<FileNotFoundException>(); // when called, not when enumerated
        await Assert.That(() => file.GetAttributes("nope")).Throws<FileNotFoundException>();
        await Assert.That(file.GetLastWriteTimeUtc("nope")).IsEqualTo(DateTime.FromFileTimeUtc(0));

        file.Delete("nope.txt"); // a missing file is not an error
        await Assert.That(() => file.Delete("no/such/dir/x")).Throws<DirectoryNotFoundException>();
        await Assert.That(() => file.ReadAllText("")).Throws<ArgumentException>();
    }

    [Test]
    public async Task Exists_CopyMoveAndDelete()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/a.txt", "a"u8.ToArray());
            f.AddDirectory(Home + "/dir");
        });
        var file = rig.Fs.File;

        await Assert.That(file.Exists("a.txt")).IsTrue();
        await Assert.That(file.Exists("dir")).IsFalse(); // a directory is not a file
        await Assert.That(file.Exists(null)).IsFalse();
        await Assert.That(file.Exists("")).IsFalse();

        file.Copy("a.txt", "b.txt");
        await Assert.That(rig.Files.Requests.Count(t => t is 5)).IsEqualTo(0); // copied on the server (copy-data): no reads
        await Assert.That(file.ReadAllText("b.txt")).IsEqualTo("a");
        await Assert.That(rig.Files.Requests.Count(t => t is 5)).IsLessThanOrEqualTo(3); // a 1-byte file costs a few reads, not a full window
        await Assert.That(() => file.Copy("a.txt", "b.txt")).Throws<IOException>();
        file.WriteAllText("a.txt", "newer");
        file.Copy("a.txt", "b.txt", overwrite: true);
        await Assert.That(file.ReadAllText("b.txt")).IsEqualTo("newer");
        await Assert.That(() => file.Copy("missing", "c.txt")).Throws<FileNotFoundException>();

        await Assert.That(() => file.Move("a.txt", "b.txt")).Throws<IOException>();
        file.Move("a.txt", "dir/a.txt");
        await Assert.That(file.Exists("a.txt")).IsFalse();
        await Assert.That(file.Exists("dir/a.txt")).IsTrue();
        file.Move("b.txt", "dir/a.txt", overwrite: true);
        await Assert.That(file.ReadAllText("dir/a.txt")).IsEqualTo("newer");

        file.Delete("dir/a.txt");
        await Assert.That(file.Exists("dir/a.txt")).IsFalse();
    }

    [Test]
    public async Task WithoutCopyData_CopyGoesThroughTheClient()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Extensions.Remove("copy-data");
            f.AddFile(Home + "/a.bin", RandomNumberGenerator.GetBytes(100_000));
        });

        rig.Fs.File.Copy("a.bin", "b.bin");

        await Assert.That(rig.Files.FileData(Home + "/b.bin").AsSpan().SequenceEqual(rig.Files.FileData(Home + "/a.bin"))).IsTrue();
    }

    [Test]
    public async Task AttributesTimesAndModes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/f", [1], modifyTime: 1_600_000_000);
            f.AddFile(Home + "/.hidden", [1]);
        });
        var file = rig.Fs.File;

        await Assert.That(file.GetAttributes("f")).IsEqualTo(FileAttributes.Normal);
        await Assert.That(file.GetAttributes(".hidden")).IsEqualTo(FileAttributes.Hidden);
        await Assert.That(file.GetLastWriteTimeUtc("f")).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000).UtcDateTime);
        await Assert.That(file.GetCreationTimeUtc("f")).IsEqualTo(file.GetLastWriteTimeUtc("f")); // no creation times in SFTP

        var when = new DateTime(2021, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        file.SetLastWriteTimeUtc("f", when);
        await Assert.That(file.GetLastWriteTimeUtc("f")).IsEqualTo(when);
        file.SetCreationTimeUtc("f", when); // does nothing, without failing

        file.SetAttributes("f", FileAttributes.ReadOnly);
        await Assert.That(file.GetAttributes("f")).IsEqualTo(FileAttributes.ReadOnly);
        await Assert.That(rig.Fs.FileInfo.New("f").IsReadOnly).IsTrue();
        file.SetAttributes("f", FileAttributes.Normal);
        await Assert.That(file.GetAttributes("f")).IsEqualTo(FileAttributes.Normal);

        file.SetUnixFileMode("f", UnixFileMode.UserRead | UnixFileMode.UserExecute);
        await Assert.That(file.GetUnixFileMode("f")).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserExecute);
    }

    [Test]
    public async Task SymbolicLinks_AreCreatedAndResolved()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/target.txt", "t"u8.ToArray());
            f.AddDirectory(Home + "/realdir");
        });

        var link = rig.Fs.File.CreateSymbolicLink("link.txt", "target.txt");
        await Assert.That(link.LinkTarget).IsEqualTo("target.txt");
        await Assert.That(rig.Fs.File.ResolveLinkTarget("link.txt", returnFinalTarget: false)!.FullName).IsEqualTo(Home + "/target.txt");
        await Assert.That(rig.Fs.File.ResolveLinkTarget("target.txt", returnFinalTarget: false)).IsNull(); // not a link
        await Assert.That((rig.Fs.File.GetAttributes("link.txt") & FileAttributes.ReparsePoint) != 0).IsTrue();

        rig.Fs.Directory.CreateSymbolicLink("dirlink", "realdir");
        await Assert.That(rig.Fs.Directory.ResolveLinkTarget("dirlink", false)).IsAssignableTo<IDirectoryInfo>();
    }

    [Test]
    public async Task UnsupportedFeatures_SayTheyAreNotSupported()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", [1]));
        var fs = rig.Fs;

        await Assert.That(() => fs.FileSystemWatcher.New()).Throws<NotSupportedException>();
        await Assert.That(() => fs.DriveInfo.GetDrives()).Throws<NotSupportedException>();
        await Assert.That(() => fs.FileVersionInfo.GetVersionInfo("f")).Throws<NotSupportedException>();
        await Assert.That(() => fs.File.Encrypt("f")).Throws<NotSupportedException>();
        await Assert.That(() => fs.File.Replace("f", "g", null)).Throws<NotSupportedException>();
        await Assert.That(() => fs.File.OpenHandle("f")).Throws<NotSupportedException>();
        await Assert.That(() => fs.RandomAccess.GetLength(null!)).Throws<NotSupportedException>();
        await Assert.That(() => fs.FileInfo.Wrap(new FileInfo("local"))).Throws<NotSupportedException>();
    }

    // ---- Directory ----

    [Test]
    public async Task Directories_AreCreatedWithParents_AndDeleted()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/file", [1]));
        var directory = rig.Fs.Directory;

        var info = directory.CreateDirectory("a/b/c");
        await Assert.That(info.Exists).IsTrue();
        await Assert.That(info.FullName).IsEqualTo(Home + "/a/b/c");
        directory.CreateDirectory("a/b/c"); // already there: fine
        await Assert.That(() => directory.CreateDirectory("file/sub")).Throws<IOException>();
        await Assert.That(directory.Exists("a/b")).IsTrue();
        await Assert.That(directory.Exists("file")).IsFalse();

        rig.Fs.File.WriteAllText("a/b/c/x.txt", "x");
        await Assert.That(() => directory.Delete("a")).Throws<IOException>(); // not empty
        directory.Delete("a", recursive: true);
        await Assert.That(directory.Exists("a")).IsFalse();
        await Assert.That(() => directory.Delete("a")).Throws<DirectoryNotFoundException>();
    }

    [Test]
    public async Task Enumeration_MatchesPatterns_Recurses_AndSkipsHiddenOnlyWithEnumerationOptions()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", []);
            f.AddFile(Home + "/tree/b.log", []);
            f.AddFile(Home + "/tree/abc", []);
            f.AddFile(Home + "/tree/.hidden.txt", []);
            f.AddDirectory(Home + "/tree/sub");
            f.AddFile(Home + "/tree/sub/c.txt", []);
            f.AddFile(Home + "/tree/sub/C.TXT", []);
        });
        var directory = rig.Fs.Directory;

        await Assert.That(directory.GetFiles("tree")).IsEquivalentTo(["tree/.hidden.txt", "tree/a.txt", "tree/abc", "tree/b.log"]);
        await Assert.That(directory.GetFiles("tree", "*.txt")).IsEquivalentTo(["tree/.hidden.txt", "tree/a.txt"]);
        await Assert.That(directory.GetFiles("tree", "a?c")).IsEquivalentTo(["tree/abc"]);
        await Assert.That(directory.GetFiles("tree", "*.txt", SearchOption.AllDirectories))
            .IsEquivalentTo(["tree/.hidden.txt", "tree/a.txt", "tree/sub/c.txt"]); // case-sensitive: not C.TXT
        await Assert.That(directory.GetFiles("tree", "*.txt", new EnumerationOptions { RecurseSubdirectories = true, MatchCasing = MatchCasing.CaseInsensitive }))
            .IsEquivalentTo(["tree/a.txt", "tree/sub/C.TXT", "tree/sub/c.txt"]); // hidden skipped by default with EnumerationOptions
        await Assert.That(directory.GetDirectories("tree")).IsEquivalentTo(["tree/sub"]);
        await Assert.That(directory.GetFileSystemEntries("tree", "s*")).IsEquivalentTo(["tree/sub"]);
        await Assert.That(directory.GetDirectories("tree", "*", new EnumerationOptions { ReturnSpecialDirectories = true }))
            .IsEquivalentTo(["tree/.", "tree/..", "tree/sub"]);
        await Assert.That(() => directory.GetFiles("missing")).Throws<DirectoryNotFoundException>();
        await Assert.That(() => directory.EnumerateFiles("missing")).Throws<DirectoryNotFoundException>();
    }

    [Test]
    public async Task TheCurrentDirectory_ResolvesRelativePaths()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/work");
            f.AddFile(Home + "/work/in.txt", "inside"u8.ToArray());
        });
        var fs = rig.Fs;

        await Assert.That(fs.Directory.GetCurrentDirectory()).IsEqualTo(Home);
        fs.Directory.SetCurrentDirectory("work");
        await Assert.That(fs.Directory.GetCurrentDirectory()).IsEqualTo(Home + "/work");
        await Assert.That(fs.File.ReadAllText("in.txt")).IsEqualTo("inside");
        await Assert.That(fs.Path.GetFullPath("in.txt")).IsEqualTo(Home + "/work/in.txt");
        await Assert.That(() => fs.Directory.SetCurrentDirectory("missing")).Throws<DirectoryNotFoundException>();
        await Assert.That(fs.Directory.GetParent("work/in.txt")!.FullName).IsEqualTo(Home + "/work/work");
        await Assert.That(fs.Directory.GetParent("/")).IsNull();
        await Assert.That(fs.Directory.GetDirectoryRoot("x")).IsEqualTo("/");
        await Assert.That(fs.Directory.GetLogicalDrives()).IsEquivalentTo(["/"]);
    }

    [Test]
    public async Task InAChroot_RelativePathsStartWhereTheServerResolvesThem_NotAtThePasswdHome()
    {
        // OpenSSH's home-directory answers /home/<user> even with ChrootDirectory, where that path does not exist.
        await using var rig = await Rig.StartAsync(f => f.HomeDirectoryAnswer = "/outside/the/chroot");
        var fs = rig.Fs;

        await Assert.That(fs.Directory.GetCurrentDirectory()).IsEqualTo(Home);
        fs.Directory.CreateDirectory("upload/a/b");
        await Assert.That(fs.Directory.Exists(Home + "/upload/a/b")).IsTrue();
    }

    [Test]
    public async Task Directory_MoveAndTimes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/from");
            f.AddFile(Home + "/from/x", [1]);
            f.AddDirectory(Home + "/taken");
        });
        var directory = rig.Fs.Directory;

        await Assert.That(() => directory.Move("from", "taken")).Throws<IOException>();
        directory.Move("from", "to");
        await Assert.That(rig.Fs.File.Exists("to/x")).IsTrue();
        await Assert.That(() => directory.Move("from", "elsewhere")).Throws<DirectoryNotFoundException>();

        var when = new DateTime(2022, 6, 7, 8, 9, 10, DateTimeKind.Utc);
        directory.SetLastWriteTimeUtc("to", when);
        await Assert.That(directory.GetLastWriteTimeUtc("to")).IsEqualTo(when);
    }

    // ---- FileInfo and DirectoryInfo ----

    [Test]
    public async Task Infos_DescribeAndChangeFiles_AsFileInfoDoes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/docs");
            f.AddFile(Home + "/docs/readme.md", "hello"u8.ToArray());
        });
        var info = rig.Fs.FileInfo.New("docs/readme.md");

        await Assert.That(info.Exists).IsTrue();
        await Assert.That(info.Length).IsEqualTo(5L);
        await Assert.That(info.Name).IsEqualTo("readme.md");
        await Assert.That(info.Extension).IsEqualTo(".md");
        await Assert.That(info.DirectoryName).IsEqualTo(Home + "/docs");
        await Assert.That(info.Directory!.Name).IsEqualTo("docs");
        await Assert.That(info.ToString()).IsEqualTo("docs/readme.md");

        // Cached until Refresh, as FileInfo is.
        rig.Fs.File.WriteAllText("docs/readme.md", "much longer");
        await Assert.That(info.Length).IsEqualTo(5L);
        info.Refresh();
        await Assert.That(info.Length).IsEqualTo(11L);

        var copy = info.CopyTo("docs/copy.md");
        await Assert.That(copy.Exists).IsTrue();
        info.MoveTo("docs/moved.md");
        await Assert.That(info.FullName).IsEqualTo(Home + "/docs/moved.md");
        await Assert.That(info.Exists).IsTrue();

        var missing = rig.Fs.FileInfo.New("nope");
        await Assert.That(missing.Exists).IsFalse();
        await Assert.That(() => missing.Length).Throws<FileNotFoundException>();
        await Assert.That((int)missing.Attributes).IsEqualTo(-1);
    }

    [Test]
    public async Task DirectoryInfo_EnumeratesWithTheListingsAttributes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            for (var i = 0; i < 5; i++)
            {
                f.AddFile($"{Home}/d/f{i}.txt", new byte[i]);
            }

            f.AddDirectory(Home + "/d/sub");
        });
        var directory = rig.Fs.DirectoryInfo.New("d");

        var files = directory.GetFiles("*.txt");
        var before = rig.Files.Requests.Count;
        var total = files.Sum(f => f.Length); // known from the listing: no request per file
        await Assert.That(rig.Files.Requests.Count).IsEqualTo(before);
        await Assert.That(total).IsEqualTo(10L);

        await Assert.That(directory.GetDirectories().Single().Name).IsEqualTo("sub");
        await Assert.That(directory.GetFileSystemInfos().Length).IsEqualTo(6);
        await Assert.That(directory.Parent!.FullName).IsEqualTo(Home);
        await Assert.That(directory.Root.FullName).IsEqualTo("/");

        var created = directory.CreateSubdirectory("x/y");
        await Assert.That(created.Exists).IsTrue();
        await Assert.That(() => directory.CreateSubdirectory("../escape")).Throws<ArgumentException>();
        await Assert.That(() => directory.CreateSubdirectory("/abs")).Throws<ArgumentException>();
    }

    // ---- sessions ----

    [Test]
    public async Task ABrokenSession_IsAnIOException()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", [1]));
        await rig.Sftp.DisposeAsync();

        await Assert.That(() => rig.Fs.File.ReadAllBytes("/home/tester/f")).Throws<IOException>();
    }

    [Test]
    public async Task ManyThreads_ShareOneFileSystem()
    {
        await using var rig = await Rig.StartAsync();
        var fs = rig.Fs;

        await Task.WhenAll(Enumerable.Range(0, 16).Select(i => Task.Run(() =>
        {
            fs.File.WriteAllText($"/home/tester/t{i}.txt", $"value {i}");
            return fs.File.ReadAllText($"/home/tester/t{i}.txt");
        })));

        await Assert.That(fs.Directory.GetFiles("/home/tester", "t*.txt").Length).IsEqualTo(16);
    }

    // ---- found in the pre-0.5.0 review ----

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CopyingAFileOntoItself_IsRefused_AndKeepsTheData(bool serverSideCopy)
    {
        var data = RandomNumberGenerator.GetBytes(5000);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/a.bin", data);
            f.AddLink(Home + "/alias.bin", "a.bin");
            if (!serverSideCopy)
            {
                f.Extensions.Remove("copy-data");
            }
        });
        var fs = rig.Fs;

        // The same path, the same path spelled differently, and the same file through a link: all refused before anything is opened.
        await Assert.That(() => fs.File.Copy("a.bin", "a.bin", overwrite: true)).Throws<IOException>();
        await Assert.That(() => fs.File.Copy("a.bin", "./sub/../a.bin", overwrite: true)).Throws<IOException>();
        await Assert.That(() => fs.File.Copy("a.bin", "alias.bin", overwrite: true)).Throws<IOException>();
        await Assert.That(() => fs.FileInfo.New(Home + "/a.bin").CopyTo("a.bin", overwrite: true)).Throws<IOException>();
        await Assert.That(rig.Files.FileData(Home + "/a.bin")!.SequenceEqual(data)).IsTrue();

        // A real copy still works.
        fs.File.Copy("a.bin", "b.bin");
        await Assert.That(rig.Files.FileData(Home + "/b.bin")!.SequenceEqual(data)).IsTrue();
    }

    [Test]
    public async Task Exists_NeverThrows_EvenWhenTheServerDeniesOrTheSessionIsGone()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/locked");
            f.AddFile(Home + "/locked/x", [1]);
            f.DenyStat = path => path.StartsWith(Home + "/locked", StringComparison.Ordinal);
        });
        var fs = rig.Fs;

        await Assert.That(fs.File.Exists("locked/x")).IsFalse();
        await Assert.That(fs.Directory.Exists("locked")).IsFalse();
        await Assert.That(fs.Path.Exists("locked/x")).IsFalse();
        var info = fs.FileInfo.New("locked/x");
        await Assert.That(info.Exists).IsFalse();
        await Assert.That(() => info.Length).Throws<UnauthorizedAccessException>(); // the other members report the error, as FileInfo does
        await Assert.That(() => fs.File.GetAttributes("locked/x")).Throws<UnauthorizedAccessException>();

        await rig.Sftp.DisposeAsync();
        await Assert.That(fs.File.Exists(Home + "/anything")).IsFalse();
        await Assert.That(fs.Directory.Exists(Home)).IsFalse();
        await Assert.That(fs.FileInfo.New(Home + "/anything").Exists).IsFalse();
    }

    [Test]
    public async Task WholeFileTransfers_AreTimedOnlyWithoutProgress_ButASilentServerStillTimesOut()
    {
        // Every answer with data (and to every WRITE) takes 100 ms and they come one after another, so a whole-file transfer takes longer
        // than the 6 s timeout: it must still succeed, as each answer comes well within it. A macOS runner running the whole suite (a
        // starved thread pool, as the synchronous API blocks a thread) has stalled for 1.35 s, and in a later stress run for over 3 s
        // (when the timeout was 3 s), so the margin is now nearly 6 s.
        var data = RandomNumberGenerator.GetBytes(4 * 1024 * 1024); // 64 READs of 64 KiB, so about 6.4 s in all
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/big.bin", data);
            f.ReplyDelay = (request, reply) => (request, reply) is (5, 103) or (6, _) ? TimeSpan.FromMilliseconds(100) : TimeSpan.Zero;
        }, new SftpFileSystemOptions { OperationTimeout = TimeSpan.FromSeconds(6) });
        var fs = rig.Fs;

        var started = System.Diagnostics.Stopwatch.StartNew();
        await Assert.That(TestBytes.Compare(fs.File.ReadAllBytes("big.bin"), data)).IsEqualTo("equal");
        await Assert.That(started.Elapsed).IsGreaterThan(TimeSpan.FromSeconds(6));
        await Assert.That(TestBytes.Compare(await fs.File.ReadAllBytesAsync("big.bin", Timeout()), data)).IsEqualTo("equal");
        fs.File.WriteAllBytes("copy.bin", data);
        await Assert.That(TestBytes.Compare(rig.Files.FileData(Home + "/copy.bin")!, data)).IsEqualTo("equal");
        fs.File.AppendAllText("copy.bin", "tail");
        await Assert.That(rig.Files.FileData(Home + "/copy.bin")!.Length).IsEqualTo(data.Length + 4);

        // A request the server sits on is still a timeout.
        rig.Files.ReplyDelay = (request, _) => request is 7 or 17 ? TimeSpan.FromSeconds(10) : TimeSpan.Zero;
        await Assert.That(() => fs.File.GetAttributes("big.bin")).Throws<IOException>().WithMessageContaining("did not answer in time");
    }

    [Test]
    public async Task Timeouts_CanBeInfinite_ButNotTooLarge()
    {
        await Assert.That(new SftpFileSystemOptions { OperationTimeout = System.Threading.Timeout.InfiniteTimeSpan }.OperationTimeout)
            .IsEqualTo(System.Threading.Timeout.InfiniteTimeSpan);
        await Assert.That(() => new SftpFileSystemOptions { OperationTimeout = TimeSpan.MaxValue }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpFileSystemOptions { OperationTimeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();

        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", [1, 2, 3]),
            new SftpFileSystemOptions { OperationTimeout = System.Threading.Timeout.InfiniteTimeSpan });
        await Assert.That(rig.Fs.File.ReadAllBytes("f")).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task AsynchronousStreamErrors_AreSystemIOExceptions()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f.txt", Encoding.UTF8.GetBytes("one\ntwo\n")));
        var fs = rig.Fs;

        await Assert.That(async () =>
        {
            await foreach (var _ in fs.File.ReadLinesAsync("missing.txt", Timeout()))
            {
            }
        }).Throws<FileNotFoundException>();

        await using var stream = fs.File.OpenRead("f.txt");
        var reader = fs.File.OpenRead("f.txt");
        await rig.Sftp.DisposeAsync(); // the session goes away under open streams
        await Assert.That(async () => await stream.ReadAsync(new byte[16], Timeout())).Throws<IOException>();
        await Assert.That(async () =>
        {
            await foreach (var _ in fs.File.ReadLinesAsync("f.txt", Timeout()))
            {
            }
        }).Throws<IOException>();
        await Assert.That(async () => await reader.DisposeAsync()).ThrowsNothing();
    }

    [Test]
    public async Task Move_RenamesFilesOnly_AndNeedsPosixRenameOnlyToReplace()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/dir");
            f.AddFile(Home + "/a.txt", [1]);
            f.AddFile(Home + "/b.txt", [2]);
            f.Extensions.Remove("posix-rename@openssh.com");
        });
        var fs = rig.Fs;

        await Assert.That(() => fs.File.Move("dir", "dir2")).Throws<FileNotFoundException>();
        await Assert.That(fs.Directory.Exists("dir")).IsTrue();

        fs.File.Move("a.txt", "c.txt", overwrite: true); // nothing to replace: a plain rename
        await Assert.That(rig.Files.FileData(Home + "/c.txt")).IsEquivalentTo(new byte[] { 1 });
        await Assert.That(() => fs.File.Move("b.txt", "c.txt", overwrite: true)).Throws<NotSupportedException>(); // replacing needs posix-rename
    }

    [Test]
    public async Task EnumeratedLinks_DescribeTheLink_AsGetAttributesDoes()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            f.AddFile(Home + "/d/target.txt", [1, 2, 3]);
            f.AddLink(Home + "/d/link.txt", "target.txt");
        });
        var fs = rig.Fs;

        var link = fs.DirectoryInfo.New("d").GetFiles().Single(f => f.Name == "link.txt");
        await Assert.That(link.Attributes).IsEqualTo(fs.File.GetAttributes("d/link.txt"));
        await Assert.That(link.Attributes.HasFlag(FileAttributes.ReparsePoint)).IsTrue();
        await Assert.That(link.LinkTarget).IsEqualTo("target.txt");
        await Assert.That(link.Length).IsEqualTo(3); // the size is the target's, as FileInfo reports it
        var plain = fs.DirectoryInfo.New("d").GetFiles().Single(f => f.Name == "target.txt");
        await Assert.That(plain.LinkTarget).IsNull();
        await Assert.That(plain.Attributes.HasFlag(FileAttributes.ReparsePoint)).IsFalse();
    }
}
