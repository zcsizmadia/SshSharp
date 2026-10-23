// The interfaces mark Unix modes as Unix-only and encryption as Windows-only (true of local files); over SFTP they work, or fail
// with NotSupportedException, from any client OS.
#pragma warning disable CA1416

using System.IO.Abstractions;
using System.Text;
using SshSharp.IO.Abstractions;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// Every overload of <see cref="SftpFileSystem"/>'s members does what its System.IO counterpart does: the same bytes written, the same
/// text read, the same entries listed. Where there is no counterpart over SFTP, the member says so (<see cref="NotSupportedException"/>).
/// </summary>
public sealed class SftpFileSystemSurfaceTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;
    private static readonly byte[] Bytes = [1, 2, 3, 250];
    private static readonly string Text = "héllo\nwörld";
    private static readonly string[] Lines = ["α", "β", ""];

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-surface-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public SftpFileSystem Fs { get; private set; } = null!;

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
            rig.Fs = new SftpFileSystem(rig.Sftp);
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    private static Func<string, Task> Sync(Action<string> action) => path =>
    {
        action(path);
        return Task.CompletedTask;
    };

    private static Func<IFile, string, Task> Sync(Action<IFile, string> action) => (file, path) =>
    {
        action(file, path);
        return Task.CompletedTask;
    };

    /// <summary>Each write (or write, then append) as System.IO does it locally and as the file system does it remotely.</summary>
    private static IEnumerable<(string Name, Func<string, Task> Local, Func<IFile, string, Task> Remote)> WriteCases()
    {
        var unicode = Encoding.Unicode;
        var utf8Bom = Encoding.UTF8;
        yield return ("WriteAllBytes", Sync(p => File.WriteAllBytes(p, Bytes)), Sync((f, p) => f.WriteAllBytes(p, Bytes)));
        yield return ("WriteAllBytesAsync", p => File.WriteAllBytesAsync(p, Bytes), (f, p) => f.WriteAllBytesAsync(p, Bytes));
        yield return ("WriteAllText", Sync(p => File.WriteAllText(p, Text)), Sync((f, p) => f.WriteAllText(p, Text)));
        yield return ("WriteAllText+UTF-16", Sync(p => File.WriteAllText(p, Text, unicode)), Sync((f, p) => f.WriteAllText(p, Text, unicode)));
        yield return ("WriteAllText+UTF-8 BOM", Sync(p => File.WriteAllText(p, Text, utf8Bom)), Sync((f, p) => f.WriteAllText(p, Text, utf8Bom)));
        yield return ("WriteAllText(null)", Sync(p => File.WriteAllText(p, null)), Sync((f, p) => f.WriteAllText(p, null)));
        yield return ("WriteAllTextAsync", p => File.WriteAllTextAsync(p, Text), (f, p) => f.WriteAllTextAsync(p, Text));
        yield return ("WriteAllTextAsync+UTF-16", p => File.WriteAllTextAsync(p, Text, unicode), (f, p) => f.WriteAllTextAsync(p, Text, unicode));
        yield return ("WriteAllLines(array)", Sync(p => File.WriteAllLines(p, Lines)), Sync((f, p) => f.WriteAllLines(p, Lines)));
        yield return ("WriteAllLines(sequence)", Sync(p => File.WriteAllLines(p, Lines.AsEnumerable())), Sync((f, p) => f.WriteAllLines(p, Lines.AsEnumerable())));
        yield return ("WriteAllLines(array)+UTF-16", Sync(p => File.WriteAllLines(p, Lines, unicode)), Sync((f, p) => f.WriteAllLines(p, Lines, unicode)));
        yield return ("WriteAllLines(sequence)+UTF-16", Sync(p => File.WriteAllLines(p, Lines.AsEnumerable(), unicode)), Sync((f, p) => f.WriteAllLines(p, Lines.AsEnumerable(), unicode)));
        yield return ("WriteAllLinesAsync", p => File.WriteAllLinesAsync(p, Lines), (f, p) => f.WriteAllLinesAsync(p, Lines));
        yield return ("WriteAllLinesAsync+UTF-16", p => File.WriteAllLinesAsync(p, Lines, unicode), (f, p) => f.WriteAllLinesAsync(p, Lines, unicode));

        // Appending to a new file, then to the same file again: the byte order mark comes once, at the start.
        yield return ("AppendAllText x2", Sync(p => { File.AppendAllText(p, Text); File.AppendAllText(p, "!"); }), Sync((f, p) => { f.AppendAllText(p, Text); f.AppendAllText(p, "!"); }));
        yield return ("AppendAllText+UTF-16 x2", Sync(p => { File.AppendAllText(p, Text, unicode); File.AppendAllText(p, "!", unicode); }),
            Sync((f, p) => { f.AppendAllText(p, Text, unicode); f.AppendAllText(p, "!", unicode); }));
        yield return ("AppendAllTextAsync x2", async p => { await File.AppendAllTextAsync(p, Text); await File.AppendAllTextAsync(p, "!"); },
            async (f, p) => { await f.AppendAllTextAsync(p, Text); await f.AppendAllTextAsync(p, "!"); });
        yield return ("AppendAllTextAsync+UTF-16 x2", async p => { await File.AppendAllTextAsync(p, Text, unicode); await File.AppendAllTextAsync(p, "!", unicode); },
            async (f, p) => { await f.AppendAllTextAsync(p, Text, unicode); await f.AppendAllTextAsync(p, "!", unicode); });
        yield return ("AppendAllLines x2", Sync(p => { File.AppendAllLines(p, Lines); File.AppendAllLines(p, Lines); }), Sync((f, p) => { f.AppendAllLines(p, Lines); f.AppendAllLines(p, Lines); }));
        yield return ("AppendAllLines+UTF-16 x2", Sync(p => { File.AppendAllLines(p, Lines, unicode); File.AppendAllLines(p, Lines, unicode); }),
            Sync((f, p) => { f.AppendAllLines(p, Lines, unicode); f.AppendAllLines(p, Lines, unicode); }));
        yield return ("AppendAllLinesAsync x2", async p => { await File.AppendAllLinesAsync(p, Lines); await File.AppendAllLinesAsync(p, Lines); },
            async (f, p) => { await f.AppendAllLinesAsync(p, Lines); await f.AppendAllLinesAsync(p, Lines); });
        yield return ("AppendAllLinesAsync+UTF-16 x2", async p => { await File.AppendAllLinesAsync(p, Lines, unicode); await File.AppendAllLinesAsync(p, Lines, unicode); },
            async (f, p) => { await f.AppendAllLinesAsync(p, Lines, unicode); await f.AppendAllLinesAsync(p, Lines, unicode); });

#if NET9_0_OR_GREATER
        yield return ("AppendAllBytes x2", Sync(p => { File.AppendAllBytes(p, Bytes); File.AppendAllBytes(p, Bytes); }), Sync((f, p) => { f.AppendAllBytes(p, Bytes); f.AppendAllBytes(p, Bytes); }));
        yield return ("AppendAllBytes(span) x2", Sync(p => { File.AppendAllBytes(p, Bytes.AsSpan()); File.AppendAllBytes(p, Bytes.AsSpan()); }),
            Sync((f, p) => { f.AppendAllBytes(p, Bytes.AsSpan()); f.AppendAllBytes(p, Bytes.AsSpan()); }));
        yield return ("AppendAllBytesAsync x2", async p => { await File.AppendAllBytesAsync(p, Bytes); await File.AppendAllBytesAsync(p, Bytes); },
            async (f, p) => { await f.AppendAllBytesAsync(p, Bytes); await f.AppendAllBytesAsync(p, Bytes); });
        yield return ("AppendAllBytesAsync(memory) x2", async p => { await File.AppendAllBytesAsync(p, Bytes.AsMemory()); await File.AppendAllBytesAsync(p, Bytes.AsMemory()); },
            async (f, p) => { await f.AppendAllBytesAsync(p, Bytes.AsMemory()); await f.AppendAllBytesAsync(p, Bytes.AsMemory()); });
        yield return ("AppendAllText(span) x2", Sync(p => { File.AppendAllText(p, Text.AsSpan()); File.AppendAllText(p, "!".AsSpan()); }),
            Sync((f, p) => { f.AppendAllText(p, Text.AsSpan()); f.AppendAllText(p, "!".AsSpan()); }));
        yield return ("AppendAllText(span)+UTF-16 x2", Sync(p => { File.AppendAllText(p, Text.AsSpan(), unicode); File.AppendAllText(p, "!".AsSpan(), unicode); }),
            Sync((f, p) => { f.AppendAllText(p, Text.AsSpan(), unicode); f.AppendAllText(p, "!".AsSpan(), unicode); }));
        yield return ("AppendAllTextAsync(memory) x2", async p => { await File.AppendAllTextAsync(p, Text.AsMemory()); await File.AppendAllTextAsync(p, "!".AsMemory()); },
            async (f, p) => { await f.AppendAllTextAsync(p, Text.AsMemory()); await f.AppendAllTextAsync(p, "!".AsMemory()); });
        yield return ("AppendAllTextAsync(memory)+UTF-16 x2", async p => { await File.AppendAllTextAsync(p, Text.AsMemory(), unicode); await File.AppendAllTextAsync(p, "!".AsMemory(), unicode); },
            async (f, p) => { await f.AppendAllTextAsync(p, Text.AsMemory(), unicode); await f.AppendAllTextAsync(p, "!".AsMemory(), unicode); });
        yield return ("WriteAllBytes(span)", Sync(p => File.WriteAllBytes(p, Bytes.AsSpan())), Sync((f, p) => f.WriteAllBytes(p, Bytes.AsSpan())));
        yield return ("WriteAllBytesAsync(memory)", p => File.WriteAllBytesAsync(p, Bytes.AsMemory()), (f, p) => f.WriteAllBytesAsync(p, Bytes.AsMemory()));
        yield return ("WriteAllText(span)", Sync(p => File.WriteAllText(p, Text.AsSpan())), Sync((f, p) => f.WriteAllText(p, Text.AsSpan())));
        yield return ("WriteAllText(span)+UTF-16", Sync(p => File.WriteAllText(p, Text.AsSpan(), unicode)), Sync((f, p) => f.WriteAllText(p, Text.AsSpan(), unicode)));
        yield return ("WriteAllTextAsync(memory)", p => File.WriteAllTextAsync(p, Text.AsMemory()), (f, p) => f.WriteAllTextAsync(p, Text.AsMemory()));
        yield return ("WriteAllTextAsync(memory)+UTF-16", p => File.WriteAllTextAsync(p, Text.AsMemory(), unicode), (f, p) => f.WriteAllTextAsync(p, Text.AsMemory(), unicode));
#endif
    }

    [Test]
    public async Task EveryWriteAndAppendOverload_WritesTheBytesSystemIOWrites()
    {
        await using var rig = await Rig.StartAsync();
        var mismatches = new List<string>();
        var i = 0;
        foreach (var (name, local, remote) in WriteCases())
        {
            var localPath = Path.Combine(_dir, $"w{i}");
            var remotePath = $"w{i}";
            i++;
            await local(localPath);
            await remote(rig.Fs.File, remotePath);
            var expected = await File.ReadAllBytesAsync(localPath);
            var actual = rig.Files.FileData($"{Home}/{remotePath}");
            if (actual is null || !actual.AsSpan().SequenceEqual(expected))
            {
                mismatches.Add($"{name}: expected {Convert.ToHexString(expected)}, got {(actual is null ? "no file" : Convert.ToHexString(actual))}");
            }
        }

        await Assert.That(mismatches).IsEmpty();
        await Assert.That(i).IsGreaterThan(20);
    }

    [Test]
    public async Task EveryReadOverload_ReadsWhatSystemIOReads_AndAByteOrderMarkWins()
    {
        // UTF-16 with its byte order mark, read with a different encoding named: the mark decides, as File.ReadAll* has it.
        var data = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("one\r\ntwo\nthree")).ToArray();
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/t.txt", data));
        var local = Path.Combine(_dir, "t.txt");
        await File.WriteAllBytesAsync(local, data);
        var file = rig.Fs.File;
        var latin1 = Encoding.Latin1;

        await Assert.That(file.ReadAllText("t.txt", latin1)).IsEqualTo(File.ReadAllText(local, latin1));
        await Assert.That(await file.ReadAllTextAsync("t.txt", latin1, Timeout())).IsEqualTo(File.ReadAllText(local, latin1));
        await Assert.That(file.ReadAllLines("t.txt", latin1)).IsEquivalentTo(File.ReadAllLines(local, latin1));
        await Assert.That(await file.ReadAllLinesAsync("t.txt", Timeout())).IsEquivalentTo(File.ReadAllLines(local));
        await Assert.That(await file.ReadAllLinesAsync("t.txt", latin1, Timeout())).IsEquivalentTo(File.ReadAllLines(local, latin1));
        await Assert.That(file.ReadLines("t.txt", latin1).ToArray()).IsEquivalentTo(File.ReadLines(local, latin1).ToArray());
        var lines = new List<string>();
        await foreach (var line in file.ReadLinesAsync("t.txt", latin1, Timeout()))
        {
            lines.Add(line);
        }

        await Assert.That(lines).IsEquivalentTo(File.ReadAllLines(local));
        await Assert.That(() => file.ReadAllText("t.txt", null!)).Throws<ArgumentNullException>();
        await Assert.That(() => file.ReadLines("t.txt", null!)).Throws<ArgumentNullException>();
        await Assert.That(() => file.WriteAllBytes("x", null!)).Throws<ArgumentNullException>();
        await Assert.That(() => file.WriteAllBytesAsync("x", null!)).Throws<ArgumentNullException>();
        await Assert.That(() => file.WriteAllLines("x", (IEnumerable<string>)null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task FileStreams_OpenedEveryWay_ReadAndWriteTheFile()
    {
        await using var rig = await Rig.StartAsync();
        var fs = rig.Fs;
        var file = fs.File;

        using (var created = file.Create("a", 1024, FileOptions.None))
        {
            created.Write(Bytes);
        }

        using (var appending = file.Open("a", FileMode.Append))
        {
            await Assert.That(appending.CanRead).IsFalse(); // Append is write-only, as with FileStream
            appending.Write([9]);
        }

        using (var shared = file.Open("a", FileMode.Open, FileAccess.Read, FileShare.None))
        {
            await Assert.That(shared.Length).IsEqualTo(5L);
        }

        using (var writer = file.AppendText("a"))
        {
            writer.Write("z");
        }

        await Assert.That(rig.Files.FileData(Home + "/a")).IsEquivalentTo(new byte[] { 1, 2, 3, 250, 9, (byte)'z' });

        // Every factory overload opens the same way.
        var factory = fs.FileStream;
        await Assert.That(factory.FileSystem).IsSameReferenceAs(fs);
        FileSystemStream[] streams =
        [
            factory.New("a", FileMode.Open),
            factory.New("a", FileMode.Open, FileAccess.Read),
            factory.New("a", FileMode.Open, FileAccess.Read, FileShare.Read),
            factory.New("a", FileMode.Open, FileAccess.Read, FileShare.Read, 512),
            factory.New("a", FileMode.Open, FileAccess.Read, FileShare.Read, 512, useAsync: true),
            factory.New("a", FileMode.Open, FileAccess.Read, FileShare.Read, 512, FileOptions.Asynchronous),
            factory.New("a", new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read }),
        ];
        foreach (var stream in streams)
        {
            await using (stream)
            {
                var first = new byte[3];
                await stream.ReadExactlyAsync(first, Timeout());
                await Assert.That(first).IsEquivalentTo(new byte[] { 1, 2, 3 });
            }
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task OpeningWithFileStreamOptions_AppliesTheUnixCreateMode_OnlyToANewFile()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip.Test("FileStreamOptions.UnixCreateMode cannot be set on Windows (PlatformNotSupportedException), so a Windows client never gets here.");
        }

        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/old", [1]));
        var file = rig.Fs.File;
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using (file.Open("new", new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = mode }))
        {
        }

        using (file.Open("old", new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.Write, UnixCreateMode = mode }))
        {
        }

        await Assert.That(rig.Files.Mode(Home + "/new")).IsEqualTo(0x180u); // 0600
        await Assert.That(rig.Files.Mode(Home + "/old")).IsEqualTo(0x1A4u); // still 0644: it existed
        await Assert.That(() => file.Open("x", (FileStreamOptions)null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task TheStream_ReadsWritesSeeksAndSyncs_BothWays()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/s", [0, 0, 0, 0, 0, 0]));
        await using var stream = rig.Fs.File.Open("s", FileMode.Open, FileAccess.ReadWrite);

#pragma warning disable CA1835 // the array overloads are what is tested
        await stream.WriteAsync(new byte[] { 7, 8, 9 }, 1, 2, Timeout());
        await stream.FlushAsync(Timeout());
        stream.Seek(-1, SeekOrigin.End);
        stream.WriteByte(5);
        stream.Flush(); // the buffer, then fsync on the server
        stream.SetLength(7);
        stream.Position = 0;
        var buffer = new byte[10];
        var read = await stream.ReadAsync(buffer, 0, 10, Timeout());
#pragma warning restore CA1835

        await Assert.That(buffer[..read]).IsEquivalentTo(new byte[] { 8, 9, 0, 0, 0, 5, 0 });
        await Assert.That(stream.Length).IsEqualTo(7L);
        await Assert.That(rig.Files.Fsyncs).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task AsynchronousWritesAndFlushes_OnABrokenSession_AreIOExceptions()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/s", [1]));
        var stream = rig.Fs.File.Open("s", FileMode.Open, FileAccess.ReadWrite);
        await rig.Sftp.DisposeAsync();

        // With nothing buffered, a flush still asks the server to sync, synchronously or not; then reads, which the buffer cannot answer.
        await Assert.That(async () => await stream.FlushAsync(Timeout())).Throws<IOException>();
        await Assert.That(() => stream.Flush()).Throws<IOException>();
        await Assert.That(() => stream.ReadByte()).Throws<IOException>();

        // The buffer takes the write; the flush that sends it is where the failure shows.
        await stream.WriteAsync(new byte[] { 2 }, Timeout());
        await Assert.That(async () => await stream.FlushAsync(Timeout())).Throws<IOException>();
        await Assert.That(async () => await stream.WriteAsync(new byte[200_000], Timeout())).Throws<IOException>();
    }

    [Test]
    public async Task FileInfo_EveryMember_ActsOnItsFile()
    {
        await using var rig = await Rig.StartAsync();
        var fs = rig.Fs;
        var info = fs.FileInfo.New("i.txt");
        await Assert.That(fs.FileInfo.FileSystem).IsSameReferenceAs(fs);
        await Assert.That(info.FileSystem).IsSameReferenceAs(fs);

        using (var writer = info.CreateText())
        {
            writer.Write("one");
        }

        using (var writer = info.AppendText())
        {
            writer.Write("two");
        }

        using (var reader = info.OpenText())
        {
            await Assert.That(reader.ReadToEnd()).IsEqualTo("onetwo");
        }

        using (var stream = info.Create())
        {
            stream.Write(Bytes);
        }

        using (var stream = info.Open(FileMode.Append, FileAccess.Write))
        {
            stream.Write([4]);
        }

        using (var stream = info.Open(FileMode.Open))
        {
            await Assert.That(stream.Length).IsEqualTo(5L);
        }

        using (var stream = info.Open(FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await Assert.That(stream.ReadByte()).IsEqualTo(1);
        }

        using (var stream = info.Open(new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read }))
        {
            await Assert.That(stream.CanWrite).IsFalse();
        }

        using (var stream = info.OpenWrite())
        {
            stream.Write([6]);
        }

        using (var stream = info.OpenRead())
        {
            await Assert.That(stream.ReadByte()).IsEqualTo(6);
        }

        info.Refresh();
        await Assert.That(info.IsReadOnly).IsFalse();
        info.IsReadOnly = true;
        await Assert.That(info.IsReadOnly).IsTrue();
        await Assert.That(rig.Files.Mode(Home + "/i.txt")! & 0x92u).IsEqualTo(0u); // no write bits
        info.IsReadOnly = false;
        await Assert.That(info.IsReadOnly).IsFalse();

        info.UnixFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        await Assert.That(info.UnixFileMode).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var when = new DateTime(2021, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        info.LastWriteTime = when.ToLocalTime();
        info.LastAccessTime = when.AddDays(1).ToLocalTime();
        await Assert.That(info.LastWriteTimeUtc).IsEqualTo(when);
        await Assert.That(info.LastAccessTimeUtc).IsEqualTo(when.AddDays(1));
        await Assert.That(info.LastAccessTime).IsEqualTo(when.AddDays(1).ToLocalTime());
        info.LastAccessTimeUtc = when;
        await Assert.That(info.LastAccessTimeUtc).IsEqualTo(when);
        info.CreationTime = DateTime.Now; // no creation times in SFTP: ignored
        info.CreationTimeUtc = DateTime.UtcNow;
        await Assert.That(info.CreationTimeUtc).IsEqualTo(when);
        await Assert.That(info.CreationTime).IsEqualTo(when.ToLocalTime());

        var copy = info.CopyTo("c.txt");
        await Assert.That(copy.Length).IsEqualTo(5L);
        await Assert.That(() => info.CopyTo("c.txt")).Throws<IOException>();
        info.MoveTo("m.txt");
        await Assert.That(info.Name).IsEqualTo("m.txt");
        await Assert.That(() => info.MoveTo("c.txt")).Throws<IOException>();

        var link = fs.FileInfo.New("ln");
        link.CreateAsSymbolicLink("m.txt");
        await Assert.That(link.Exists).IsTrue();
        await Assert.That(link.LinkTarget).IsEqualTo("m.txt");
        await Assert.That(link.ResolveLinkTarget(returnFinalTarget: true)!.FullName).IsEqualTo(Home + "/m.txt");
        await Assert.That(info.ResolveLinkTarget(returnFinalTarget: false)).IsNull();
        await Assert.That(fs.FileInfo.New("missing").LinkTarget).IsNull();

        info.Delete();
        await Assert.That(info.Exists).IsFalse();
        await Assert.That(rig.Files.Exists(Home + "/m.txt")).IsFalse();

        await Assert.That(() => copy.Replace("x", null)).Throws<NotSupportedException>();
        await Assert.That(() => copy.Replace("x", null, ignoreMetadataErrors: true)).Throws<NotSupportedException>();
        await Assert.That(() => copy.Encrypt()).Throws<NotSupportedException>();
        await Assert.That(() => copy.Decrypt()).Throws<NotSupportedException>();
    }

    [Test]
    public async Task DirectoryInfo_EveryOverload_ListsWhatItsPrimaryFormLists()
    {
        await using var rig = await Rig.StartAsync();
        var fs = rig.Fs;
        var d = fs.DirectoryInfo.New("d");
        await Assert.That(fs.DirectoryInfo.FileSystem).IsSameReferenceAs(fs);
        d.Create();
        await Assert.That(d.Exists).IsTrue();
        d.CreateSubdirectory("sub");
        fs.File.WriteAllText("d/a.txt", "a");
        fs.File.WriteAllText("d/b.log", "b");
        fs.File.WriteAllText("d/sub/c.txt", "c");
        var recurse = new EnumerationOptions { RecurseSubdirectories = true };

        static string[] Names(IEnumerable<IFileSystemInfo> infos) => [.. infos.Select(i => i.FullName).Order(StringComparer.Ordinal)];

        string[] all = [Home + "/d/a.txt", Home + "/d/b.log", Home + "/d/sub"];
        string[] txt = [Home + "/d/a.txt"];
        string[] txtDeep = [Home + "/d/a.txt", Home + "/d/sub/c.txt"];
        string[] sub = [Home + "/d/sub"];
        (string Name, string[] Actual, string[] Expected)[] cases =
        [
            ("GetFiles()", Names(d.GetFiles()), [Home + "/d/a.txt", Home + "/d/b.log"]),
            ("GetFiles(p)", Names(d.GetFiles("*.txt")), txt),
            ("GetFiles(p, all)", Names(d.GetFiles("*.txt", SearchOption.AllDirectories)), txtDeep),
            ("GetFiles(p, options)", Names(d.GetFiles("*.txt", recurse)), txtDeep),
            ("EnumerateFiles()", Names(d.EnumerateFiles()), [Home + "/d/a.txt", Home + "/d/b.log"]),
            ("EnumerateFiles(p)", Names(d.EnumerateFiles("*.txt")), txt),
            ("EnumerateFiles(p, all)", Names(d.EnumerateFiles("*.txt", SearchOption.AllDirectories)), txtDeep),
            ("EnumerateFiles(p, options)", Names(d.EnumerateFiles("*.txt", recurse)), txtDeep),
            ("GetDirectories()", Names(d.GetDirectories()), sub),
            ("GetDirectories(p)", Names(d.GetDirectories("s*")), sub),
            ("GetDirectories(p, all)", Names(d.GetDirectories("*", SearchOption.AllDirectories)), sub),
            ("GetDirectories(p, options)", Names(d.GetDirectories("*", recurse)), sub),
            ("EnumerateDirectories()", Names(d.EnumerateDirectories()), sub),
            ("EnumerateDirectories(p)", Names(d.EnumerateDirectories("s*")), sub),
            ("EnumerateDirectories(p, all)", Names(d.EnumerateDirectories("*", SearchOption.AllDirectories)), sub),
            ("EnumerateDirectories(p, options)", Names(d.EnumerateDirectories("*", recurse)), sub),
            ("GetFileSystemInfos()", Names(d.GetFileSystemInfos()), all),
            ("GetFileSystemInfos(p)", Names(d.GetFileSystemInfos("*.txt")), txt),
            ("GetFileSystemInfos(p, all)", Names(d.GetFileSystemInfos("*", SearchOption.AllDirectories)), [.. all, Home + "/d/sub/c.txt"]),
            ("GetFileSystemInfos(p, options)", Names(d.GetFileSystemInfos("*", recurse)), [.. all, Home + "/d/sub/c.txt"]),
            ("EnumerateFileSystemInfos()", Names(d.EnumerateFileSystemInfos()), all),
            ("EnumerateFileSystemInfos(p)", Names(d.EnumerateFileSystemInfos("*.txt")), txt),
            ("EnumerateFileSystemInfos(p, all)", Names(d.EnumerateFileSystemInfos("*", SearchOption.AllDirectories)), [.. all, Home + "/d/sub/c.txt"]),
            ("EnumerateFileSystemInfos(p, options)", Names(d.EnumerateFileSystemInfos("*", recurse)), [.. all, Home + "/d/sub/c.txt"]),
        ];

        var wrong = cases.Where(c => !c.Actual.SequenceEqual(c.Expected.Order(StringComparer.Ordinal))).Select(c => $"{c.Name}: {string.Join(", ", c.Actual)}").ToList();
        await Assert.That(wrong).IsEmpty();
    }

    [Test]
    public async Task DirectoryInfo_MovesLinksAndDeletes()
    {
        await using var rig = await Rig.StartAsync();
        var fs = rig.Fs;
        var d = fs.DirectoryInfo.New("d");
        d.Create();
        fs.File.WriteAllText("d/x", "x");

        d.MoveTo("e");
        await Assert.That(d.FullName).IsEqualTo(Home + "/e");
        await Assert.That(d.Exists).IsTrue();
        await Assert.That(fs.File.Exists("e/x")).IsTrue();

        var link = fs.DirectoryInfo.New("l");
        link.CreateAsSymbolicLink("e");
        await Assert.That(link.Exists).IsTrue();
        await Assert.That(link.LinkTarget).IsEqualTo("e");
        await Assert.That(link.ResolveLinkTarget(returnFinalTarget: false)!.FullName).IsEqualTo(Home + "/e");

        await Assert.That(() => d.Delete()).Throws<IOException>(); // not empty
        d.Delete(recursive: true);
        await Assert.That(d.Exists).IsFalse();
        var empty = fs.DirectoryInfo.New("empty");
        empty.Create();
        empty.Delete();
        await Assert.That(empty.Exists).IsFalse();
    }

    [Test]
    public async Task Directory_EveryOverload_ListsWhatItsPrimaryFormLists()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            f.AddFile(Home + "/d/a.txt", [1]);
            f.AddFile(Home + "/d/b.log", [1]);
            f.AddDirectory(Home + "/d/sub");
            f.AddFile(Home + "/d/sub/c.txt", [1]);
        });
        var directory = rig.Fs.Directory;
        await Assert.That(directory.FileSystem).IsSameReferenceAs(rig.Fs);
        var recurse = new EnumerationOptions { RecurseSubdirectories = true };

        static string[] Sorted(IEnumerable<string> paths) => [.. paths.Order(StringComparer.Ordinal)];

        (string Name, string[] Actual, string[] Expected)[] cases =
        [
            ("EnumerateFiles(d)", Sorted(directory.EnumerateFiles("d")), ["d/a.txt", "d/b.log"]),
            ("EnumerateFiles(d, p)", Sorted(directory.EnumerateFiles("d", "*.txt")), ["d/a.txt"]),
            ("EnumerateFiles(d, trailing stars)", Sorted(directory.EnumerateFiles("d", "a.txt**")), ["d/a.txt"]),
            ("EnumerateFiles(d, p, all)", Sorted(directory.EnumerateFiles("d", "*.txt", SearchOption.AllDirectories)), ["d/a.txt", "d/sub/c.txt"]),
            ("EnumerateFiles(d, p, options)", Sorted(directory.EnumerateFiles("d", "*.txt", recurse)), ["d/a.txt", "d/sub/c.txt"]),
            ("EnumerateDirectories(d)", Sorted(directory.EnumerateDirectories("d")), ["d/sub"]),
            ("EnumerateDirectories(d, p)", Sorted(directory.EnumerateDirectories("d", "s*")), ["d/sub"]),
            ("EnumerateDirectories(d, p, all)", Sorted(directory.EnumerateDirectories("d", "*", SearchOption.AllDirectories)), ["d/sub"]),
            ("EnumerateDirectories(d, p, options)", Sorted(directory.EnumerateDirectories("d", "*", recurse)), ["d/sub"]),
            ("GetDirectories(d, p)", Sorted(directory.GetDirectories("d", "s*")), ["d/sub"]),
            ("GetDirectories(d, p, all)", Sorted(directory.GetDirectories("d", "*", SearchOption.AllDirectories)), ["d/sub"]),
            ("EnumerateFileSystemEntries(d)", Sorted(directory.EnumerateFileSystemEntries("d")), ["d/a.txt", "d/b.log", "d/sub"]),
            ("EnumerateFileSystemEntries(d, p)", Sorted(directory.EnumerateFileSystemEntries("d", "*.log")), ["d/b.log"]),
            ("EnumerateFileSystemEntries(d, p, all)", Sorted(directory.EnumerateFileSystemEntries("d", "*.txt", SearchOption.AllDirectories)), ["d/a.txt", "d/sub/c.txt"]),
            ("EnumerateFileSystemEntries(d, p, options)", Sorted(directory.EnumerateFileSystemEntries("d", "*.txt", recurse)), ["d/a.txt", "d/sub/c.txt"]),
            ("GetFileSystemEntries(d)", Sorted(directory.GetFileSystemEntries("d")), ["d/a.txt", "d/b.log", "d/sub"]),
            ("GetFileSystemEntries(d, p, all)", Sorted(directory.GetFileSystemEntries("d", "*.txt", SearchOption.AllDirectories)), ["d/a.txt", "d/sub/c.txt"]),
            ("GetFileSystemEntries(d, p, options)", Sorted(directory.GetFileSystemEntries("d", "*.txt", recurse)), ["d/a.txt", "d/sub/c.txt"]),
        ];

        var wrong = cases.Where(c => !c.Actual.SequenceEqual(c.Expected)).Select(c => $"{c.Name}: {string.Join(", ", c.Actual)}").ToList();
        await Assert.That(wrong).IsEmpty();
    }

    [Test]
    public async Task Directory_CreatesWithAMode_MakesTempDirectories_AndKeepsTimes()
    {
        await using var rig = await Rig.StartAsync(f => f.AddDirectory("/tmp"));
        var directory = rig.Fs.Directory;

        directory.CreateDirectory("private/inner", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        await Assert.That(rig.Files.Mode(Home + "/private/inner")).IsEqualTo(0x1C0u); // 0700

        var temp = directory.CreateTempSubdirectory("job-");
        await Assert.That(temp.FullName).StartsWith("/tmp/job-");
        await Assert.That(temp.Exists).IsTrue();
        await Assert.That(rig.Files.Mode(temp.FullName)).IsEqualTo(0x1C0u);
        await Assert.That(directory.CreateTempSubdirectory().FullName).StartsWith("/tmp/");

        var when = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        directory.SetLastWriteTime("private", when.ToLocalTime());
        directory.SetLastAccessTime("private", when.AddHours(1).ToLocalTime());
        await Assert.That(directory.GetLastWriteTimeUtc("private")).IsEqualTo(when);
        await Assert.That(directory.GetLastWriteTime("private")).IsEqualTo(when.ToLocalTime());
        await Assert.That(directory.GetLastAccessTime("private")).IsEqualTo(when.AddHours(1).ToLocalTime());
        directory.SetLastAccessTimeUtc("private", when);
        await Assert.That(directory.GetLastAccessTimeUtc("private")).IsEqualTo(when);
        directory.SetCreationTime("private", DateTime.Now); // no creation times in SFTP: ignored
        directory.SetCreationTimeUtc("private", DateTime.UtcNow);
        await Assert.That(directory.GetCreationTimeUtc("private")).IsEqualTo(when);
        await Assert.That(directory.GetCreationTime("private")).IsEqualTo(when.ToLocalTime());

        await Assert.That(() => directory.ResolveLinkTarget("missing", false)).Throws<DirectoryNotFoundException>();
        await Assert.That(() => rig.Fs.File.ResolveLinkTarget("missing", false)).Throws<FileNotFoundException>();
        await Assert.That(() => directory.CreateSymbolicLink("l", "")).Throws<ArgumentException>();
    }

    [Test]
    public async Task File_TimesInLocalTime_AreTheUtcTimesConverted()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", [1]));
        var file = rig.Fs.File;
        var when = new DateTime(2019, 8, 7, 6, 5, 4, DateTimeKind.Utc);

        file.SetLastWriteTime("f", when.ToLocalTime());
        file.SetLastAccessTime("f", when.AddMinutes(1).ToLocalTime());
        await Assert.That(file.GetLastWriteTime("f")).IsEqualTo(when.ToLocalTime());
        await Assert.That(file.GetLastAccessTimeUtc("f")).IsEqualTo(when.AddMinutes(1));
        await Assert.That(file.GetLastAccessTime("f")).IsEqualTo(when.AddMinutes(1).ToLocalTime());
        file.SetLastAccessTimeUtc("f", when);
        await Assert.That(file.GetLastAccessTimeUtc("f")).IsEqualTo(when);
        file.SetCreationTime("f", DateTime.Now);
        await Assert.That(file.GetCreationTime("f")).IsEqualTo(when.ToLocalTime());
        await Assert.That(() => file.GetUnixFileMode("missing")).Throws<FileNotFoundException>();
    }

    [Test]
    public async Task ARecursiveListing_SkipsADeniedSubdirectory_UnlessToldNotTo()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/a.txt", [1]);
            f.AddDirectory(Home + "/tree/locked");
            f.AddFile(Home + "/tree/locked/b.txt", [1]);
            f.RawFrame = request =>
            {
                if (request[0] != 11)
                {
                    return null;
                }

                var reader = new SshSharp.Protocol.SshReader(request.AsSpan(5));
                return reader.ReadUtf8String().EndsWith("/locked", StringComparison.Ordinal) ? DeniedReply(request) : null;
            };
        });
        var directory = rig.Fs.Directory;

        // EnumerationOptions skips what it cannot read by default; SearchOption (the legacy form) does not, as with Directory.GetFiles.
        await Assert.That(directory.GetFiles("tree", "*", new EnumerationOptions { RecurseSubdirectories = true })).IsEquivalentTo(["tree/a.txt"]);
        await Assert.That(() => directory.GetFiles("tree", "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = false }))
            .Throws<UnauthorizedAccessException>();
        await Assert.That(() => directory.GetFiles("tree", "*", SearchOption.AllDirectories)).Throws<UnauthorizedAccessException>();
    }

    [Test]
    public async Task ADirectoryCreatedBySomeoneElse_BetweenTheCheckAndTheCreate_IsAccepted()
    {
        // The MKDIR loses a race: another client made the directory first, so it fails, and the directory is there all the same.
        FakeSftpServer files = null!;
        await using var rig = await Rig.StartAsync(f =>
        {
            files = f;
            f.RawFrame = request =>
            {
                if (request[0] != 14)
                {
                    return null;
                }

                files.AddDirectory(PathOf(request));
                return StatusReply(request, 4, "Failure");
            };
        });

        var created = rig.Fs.Directory.CreateDirectory(Home + "/raced");

        await Assert.That(created.Exists).IsTrue();
        await Assert.That(() => rig.Fs.Directory.CreateDirectory(Home + "/raced/f/x")).ThrowsNothing();
    }

    [Test]
    public async Task ACopyOntoAnExistingFile_TheServerCannotResolve_GoesAhead()
    {
        // Comparing the two paths needs REALPATH; when the server cannot answer it for one of them, they are not taken as the same file.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/a", [1, 2]);
            f.AddFile(Home + "/b", [9]);
            f.RawFrame = request => request[0] == 16 && PathOf(request) == Home + "/b" ? StatusReply(request, 4, "Failure") : null;
        });

        rig.Fs.File.Copy("a", "b", overwrite: true);

        await Assert.That(rig.Files.FileData(Home + "/b")).IsEquivalentTo(new byte[] { 1, 2 });
        await Assert.That(() => rig.Fs.File.Exists("bad\0path")).ThrowsNothing();
        await Assert.That(() => rig.Fs.File.ReadAllBytes("bad\0path")).Throws<ArgumentException>();
    }

    [Test]
    public async Task MissingDeniedAndRootPaths_ReadAsSystemIOReadsThem()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/locked");
            f.AddFile(Home + "/locked/x", [1]);
            f.AddFile(Home + "/target", [1]);
            f.AddLink(Home + "/absolute", Home + "/target");
            f.DenyStat = path => path.StartsWith(Home + "/locked", StringComparison.Ordinal);
        });
        var fs = rig.Fs;
        var never = DateTime.FromFileTimeUtc(0);

        // A missing path, as FileInfo and File report one: times of 1601, a mode of -1, no link; changing it is FileNotFound.
        var missing = fs.FileInfo.New("nope");
        await Assert.That(missing.LastWriteTimeUtc).IsEqualTo(never);
        await Assert.That(missing.LastAccessTimeUtc).IsEqualTo(never);
        await Assert.That(missing.UnixFileMode).IsEqualTo((UnixFileMode)(-1));
        await Assert.That(missing.LinkTarget).IsNull();
        await Assert.That(fs.File.GetLastAccessTimeUtc("nope")).IsEqualTo(never);
        await Assert.That(() => fs.File.SetAttributes("nope", FileAttributes.ReadOnly)).Throws<FileNotFoundException>();
        await Assert.That(() => fs.File.SetLastWriteTimeUtc("nope", DateTime.UtcNow)).Throws<FileNotFoundException>();

        // A path the server will not describe: Exists is false, the other members report the denial.
        var denied = fs.FileInfo.New("locked/x");
        await Assert.That(denied.Exists).IsFalse();
        await Assert.That(() => denied.Attributes).Throws<UnauthorizedAccessException>();
        await Assert.That(() => denied.LinkTarget).Throws<UnauthorizedAccessException>();

        // The root.
        await Assert.That(fs.DirectoryInfo.New("/").Name).IsEqualTo("/");
        await Assert.That(fs.FileInfo.New("/").Directory).IsNull();
        await Assert.That(fs.DirectoryInfo.New("/").CreateSubdirectory("top").FullName).IsEqualTo("/top");
        await Assert.That(fs.Path.GetRelativePath("/a", "/a")).IsEqualTo(".");
        await Assert.That(fs.Path.IsPathRooted(string.Empty)).IsFalse();

        // A link stored with an absolute target resolves to it as it is.
        await Assert.That(fs.File.ResolveLinkTarget("absolute", returnFinalTarget: false)!.FullName).IsEqualTo(Home + "/target");
    }

    [Test]
    public async Task SearchPatterns_EmptyMatchesAll_AndStarDotStarNeedsADotUnlessWin32()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/d");
            f.AddFile(Home + "/d/plain", [1]);
            f.AddFile(Home + "/d/dotted.txt", [1]);
        });
        var directory = rig.Fs.Directory;

        await Assert.That(directory.GetFiles("d", string.Empty).Order(StringComparer.Ordinal)).IsEquivalentTo(["d/dotted.txt", "d/plain"]);
        await Assert.That(directory.GetFiles("d", "*.*").Order(StringComparer.Ordinal)).IsEquivalentTo(["d/dotted.txt", "d/plain"]); // Win32 matching, as Directory.GetFiles
        await Assert.That(directory.GetFiles("d", "*.*", new EnumerationOptions { MatchType = MatchType.Simple })).IsEquivalentTo(["d/dotted.txt"]);
    }

    private static string PathOf(byte[] request)
    {
        var reader = new SshSharp.Protocol.SshReader(request.AsSpan(5));
        return reader.ReadUtf8String();
    }

    private static byte[] DeniedReply(byte[] request) => StatusReply(request, 3, "Permission denied");

    private static byte[] StatusReply(byte[] request, uint status, string message)
    {
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        var writer = new SshSharp.Protocol.SshWriter(buffer);
        writer.WriteByte(101);
        writer.WriteUInt32(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(1))); // the request id
        writer.WriteUInt32(status);
        writer.WriteString(message);
        writer.WriteString("en");
        var frame = new byte[4 + buffer.WrittenCount];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(frame.AsSpan(4));
        return frame;
    }

    [Test]
    [Arguments("dir/file.txt")]
    [Arguments("file")]
    [Arguments(".bashrc")]
    [Arguments("a.b/c")]
    [Arguments("archive.tar.gz")]
    [Arguments("trailing.")]
    [Arguments("dir/")]
    [Arguments("")]
    public async Task NamesAndExtensions_MatchSystemIOPath(string path)
    {
        // These do not depend on the separator (both take '/'), so System.IO.Path on any OS is the reference.
        await using var rig = await Rig.StartAsync();
        var p = rig.Fs.Path;

        await Assert.That(p.GetFileName(path)).IsEqualTo(Path.GetFileName(path));
        await Assert.That(p.GetFileName(path.AsSpan()).ToString()).IsEqualTo(Path.GetFileName(path));
        await Assert.That(p.GetExtension(path)).IsEqualTo(Path.GetExtension(path));
        await Assert.That(p.GetExtension(path.AsSpan()).ToString()).IsEqualTo(Path.GetExtension(path));
        await Assert.That(p.GetFileNameWithoutExtension(path)).IsEqualTo(Path.GetFileNameWithoutExtension(path));
        await Assert.That(p.GetFileNameWithoutExtension(path.AsSpan()).ToString()).IsEqualTo(Path.GetFileNameWithoutExtension(path));
        await Assert.That(p.HasExtension(path)).IsEqualTo(Path.HasExtension(path));
        await Assert.That(p.HasExtension(path.AsSpan())).IsEqualTo(Path.HasExtension(path));
        await Assert.That(p.ChangeExtension(path, "md")).IsEqualTo(Path.ChangeExtension(path, "md"));
        await Assert.That(p.ChangeExtension(path, ".md")).IsEqualTo(Path.ChangeExtension(path, ".md"));
        await Assert.That(p.ChangeExtension(path, "")).IsEqualTo(Path.ChangeExtension(path, ""));
        await Assert.That(p.ChangeExtension(path, null)).IsEqualTo(Path.ChangeExtension(path, null));
        await Assert.That(p.EndsInDirectorySeparator(path)).IsEqualTo(path.EndsWith('/'));
    }

    [Test]
    public async Task Path_EveryOverload_AgreesWithItsOtherForms()
    {
        await using var rig = await Rig.StartAsync(f => f.AddDirectory("/tmp"));
        var p = rig.Fs.Path;

        await Assert.That(p.FileSystem).IsSameReferenceAs(rig.Fs);
        await Assert.That(p.AltDirectorySeparatorChar).IsEqualTo('/');
        await Assert.That(p.VolumeSeparatorChar).IsEqualTo('/');
        await Assert.That(p.Combine("a", "b", "c")).IsEqualTo("a/b/c");
        await Assert.That(p.Combine("a", "b", "c", "d")).IsEqualTo("a/b/c/d");
        await Assert.That(p.Combine("a", "b")).IsEqualTo("a/b");
        await Assert.That(p.Combine(new[] { "a", "/b", "c" })).IsEqualTo("/b/c");
        await Assert.That(() => p.Combine((string[])null!)).Throws<ArgumentNullException>();
        await Assert.That(p.Join("a", "b", "c")).IsEqualTo("a/b/c");
        await Assert.That(p.Join("a", "b", "c", "d")).IsEqualTo("a/b/c/d");
        await Assert.That(p.Join("a".AsSpan(), "b".AsSpan(), "c".AsSpan())).IsEqualTo("a/b/c");
        await Assert.That(p.Join("a".AsSpan(), "b".AsSpan(), "c".AsSpan(), "d".AsSpan())).IsEqualTo("a/b/c/d");
        await Assert.That(p.Join(["a", null, "b/", "c"])).IsEqualTo("a/b/c");
        await Assert.That(() => p.Join((string?[])null!)).Throws<ArgumentNullException>();
#if NET9_0_OR_GREATER
        await Assert.That(p.Combine(new ReadOnlySpan<string>(["x", "y"]))).IsEqualTo("x/y");
        await Assert.That(p.Join(new ReadOnlySpan<string?>(["x", "y"]))).IsEqualTo("x/y");
#endif
        var destination = new char[8];
        await Assert.That(p.TryJoin("a", "b", "c", destination, out var written)).IsTrue();
        await Assert.That(new string(destination, 0, written)).IsEqualTo("a/b/c");
        await Assert.That(p.TryJoin("a", "b", "c", new char[2], out written)).IsFalse();
        await Assert.That(written).IsEqualTo(0);

        await Assert.That(p.EndsInDirectorySeparator("a/".AsSpan())).IsTrue();
        await Assert.That(p.EndsInDirectorySeparator(ReadOnlySpan<char>.Empty)).IsFalse();
        await Assert.That(p.GetDirectoryName("/a/b".AsSpan()).ToString()).IsEqualTo("/a");
        await Assert.That(p.GetDirectoryName("/a/b//")).IsEqualTo("/a/b"); // a trailing separator names the directory itself
        await Assert.That(p.GetDirectoryName("")).IsNull();
        await Assert.That(p.GetDirectoryName((string?)null)).IsNull();
        await Assert.That(p.GetFileName((string?)null)).IsNull();
        await Assert.That(p.GetExtension((string?)null)).IsNull();
        await Assert.That(p.GetFileNameWithoutExtension((string?)null)).IsNull();
        await Assert.That(p.ChangeExtension(null, "x")).IsNull();
        await Assert.That(p.HasExtension((string?)null)).IsFalse();
        await Assert.That(p.GetPathRoot((string?)null)).IsNull();
        await Assert.That(p.GetPathRoot("a/b")).IsEqualTo(string.Empty);
        await Assert.That(p.GetPathRoot("/a".AsSpan()).ToString()).IsEqualTo("/");
        await Assert.That(p.IsPathRooted((string?)null)).IsFalse();
        await Assert.That(p.IsPathRooted("/a".AsSpan())).IsTrue();
        await Assert.That(p.IsPathFullyQualified("/a")).IsTrue();
        await Assert.That(p.IsPathFullyQualified("a".AsSpan())).IsFalse();
        await Assert.That(() => p.IsPathFullyQualified((string)null!)).Throws<ArgumentNullException>();
        await Assert.That(p.TrimEndingDirectorySeparator("a/".AsSpan()).ToString()).IsEqualTo("a");
        await Assert.That(p.GetInvalidPathChars()).IsEquivalentTo(new[] { '\0' });
        await Assert.That(() => p.GetFullPath("x", "relative")).Throws<ArgumentException>();
        await Assert.That(p.GetFullPath("/abs", "/base")).IsEqualTo("/abs");
        await Assert.That(p.GetRandomFileName()).Matches("^[a-z0-9]{8}\\.[a-z0-9]{3}$");

#pragma warning disable CS0618 // implemented over SFTP, so tested
        var temp = p.GetTempFileName();
        await Assert.That(temp).StartsWith("/tmp/tmp").And.EndsWith(".tmp");
        await Assert.That(rig.Files.FileData(temp)).IsEmpty();
        await Assert.That(p.GetTempFileName()).IsNotEqualTo(temp);
#pragma warning restore CS0618
        await Assert.That(p.Exists(temp)).IsTrue();
    }

    [Test]
    public async Task WhatSftpCannotDo_SaysSo_ForEveryMember()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/f", [1]));
        var fs = rig.Fs;
        var file = fs.File;
        var handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(IntPtr.Zero, ownsHandle: false);
        var random = fs.RandomAccess;
        var when = DateTime.UtcNow;

        (string Name, Action Call)[] calls =
        [
            ("FileInfo.Wrap", () => fs.FileInfo.Wrap(new FileInfo("x"))),
            ("DirectoryInfo.Wrap", () => fs.DirectoryInfo.Wrap(new DirectoryInfo("x"))),
            ("FileStream.Wrap", () => fs.FileStream.Wrap(null!)),
            ("FileStream.New(handle)", () => fs.FileStream.New(handle, FileAccess.Read)),
            ("FileStream.New(handle, size)", () => fs.FileStream.New(handle, FileAccess.Read, 1)),
            ("FileStream.New(handle, size, async)", () => fs.FileStream.New(handle, FileAccess.Read, 1, true)),
            ("DriveInfo.GetDrives", () => fs.DriveInfo.GetDrives()),
            ("DriveInfo.New", () => fs.DriveInfo.New("/")),
            ("DriveInfo.Wrap", () => fs.DriveInfo.Wrap(null)),
            ("FileSystemWatcher.New()", () => fs.FileSystemWatcher.New()),
            ("FileSystemWatcher.New(path)", () => fs.FileSystemWatcher.New("/")),
            ("FileSystemWatcher.New(path, filter)", () => fs.FileSystemWatcher.New("/", "*")),
            ("FileSystemWatcher.Wrap", () => fs.FileSystemWatcher.Wrap(null)),
            ("FileVersionInfo", () => fs.FileVersionInfo.GetVersionInfo("f")),
            ("RandomAccess.FlushToDisk", () => random.FlushToDisk(handle)),
            ("RandomAccess.GetLength", () => random.GetLength(handle)),
            ("RandomAccess.Read", () => random.Read(handle, new byte[1], 0)),
            ("RandomAccess.Read(buffers)", () => random.Read(handle, [new byte[1]], 0)),
            ("RandomAccess.ReadAsync", () => random.ReadAsync(handle, new byte[1], 0).AsTask()),
            ("RandomAccess.ReadAsync(buffers)", () => random.ReadAsync(handle, [new byte[1]], 0).AsTask()),
            ("RandomAccess.SetLength", () => random.SetLength(handle, 0)),
            ("RandomAccess.Write", () => random.Write(handle, new byte[1], 0)),
            ("RandomAccess.Write(buffers)", () => random.Write(handle, [new ReadOnlyMemory<byte>(new byte[1])], 0)),
            ("RandomAccess.WriteAsync", () => random.WriteAsync(handle, new byte[1], 0).AsTask()),
            ("RandomAccess.WriteAsync(buffers)", () => random.WriteAsync(handle, [new ReadOnlyMemory<byte>(new byte[1])], 0).AsTask()),
            ("File.Decrypt", () => file.Decrypt("f")),
            ("File.Replace(4)", () => file.Replace("f", "g", null, true)),
            ("File.GetAttributes(handle)", () => file.GetAttributes(handle)),
            ("File.GetCreationTime(handle)", () => file.GetCreationTime(handle)),
            ("File.GetCreationTimeUtc(handle)", () => file.GetCreationTimeUtc(handle)),
            ("File.GetLastAccessTime(handle)", () => file.GetLastAccessTime(handle)),
            ("File.GetLastAccessTimeUtc(handle)", () => file.GetLastAccessTimeUtc(handle)),
            ("File.GetLastWriteTime(handle)", () => file.GetLastWriteTime(handle)),
            ("File.GetLastWriteTimeUtc(handle)", () => file.GetLastWriteTimeUtc(handle)),
            ("File.GetUnixFileMode(handle)", () => file.GetUnixFileMode(handle)),
            ("File.SetAttributes(handle)", () => file.SetAttributes(handle, FileAttributes.Normal)),
            ("File.SetCreationTime(handle)", () => file.SetCreationTime(handle, when)),
            ("File.SetCreationTimeUtc(handle)", () => file.SetCreationTimeUtc(handle, when)),
            ("File.SetLastAccessTime(handle)", () => file.SetLastAccessTime(handle, when)),
            ("File.SetLastAccessTimeUtc(handle)", () => file.SetLastAccessTimeUtc(handle, when)),
            ("File.SetLastWriteTime(handle)", () => file.SetLastWriteTime(handle, when)),
            ("File.SetLastWriteTimeUtc(handle)", () => file.SetLastWriteTimeUtc(handle, when)),
            ("File.SetUnixFileMode(handle)", () => file.SetUnixFileMode(handle, UnixFileMode.None)),
        ];

        var wrong = new List<string>();
        foreach (var (name, call) in calls)
        {
            try
            {
                call();
                wrong.Add($"{name}: no exception");
            }
            catch (NotSupportedException ex) when (ex.Message.Length > 0)
            {
            }
            catch (Exception ex)
            {
                wrong.Add($"{name}: {ex.GetType().Name}");
            }
        }

        await Assert.That(wrong).IsEmpty();
        await Assert.That(fs.DriveInfo.FileSystem).IsSameReferenceAs(fs);
        await Assert.That(fs.FileSystemWatcher.FileSystem).IsSameReferenceAs(fs);
        await Assert.That(fs.FileVersionInfo.FileSystem).IsSameReferenceAs(fs);
        await Assert.That(random.FileSystem).IsSameReferenceAs(fs);
        await Assert.That(file.FileSystem).IsSameReferenceAs(fs);
    }
}
