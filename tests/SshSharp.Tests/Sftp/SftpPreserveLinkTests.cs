using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// <see cref="SftpTransferOptions.Preserve"/> on upload never sets attributes through a path another user could have turned into a
/// symbolic link: files get theirs through the open handle, directories theirs with <c>lsetstat@openssh.com</c>.
/// </summary>
public sealed class SftpPreserveLinkTests : IDisposable
{
    private const string Home = FakeSftpServer.Home;
    private const uint VictimTime = 1_600_000_000;

    private static readonly DateTime LocalTime = new(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-preserve-link-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer> setup)
        {
            var rig = new Rig();
            setup(rig.Files);
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

    /// <summary>A local file (or directory) with a mode and time other than the victim's, so either would show if it reached it.</summary>
    private static void Stamp(string path, bool directory = false)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, (UnixFileMode)0x1ED); // 0755
        }

        if (directory)
        {
            Directory.SetLastWriteTimeUtc(path, LocalTime);
        }
        else
        {
            File.SetLastWriteTimeUtc(path, LocalTime);
        }
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task AnUploadedFile_ReplacedByALinkAsItCloses_LeavesTheLinksTargetAlone(int segments)
    {
        // Another user swaps the new file for a link to a file this user owns just as the upload closes it. The times and mode were set
        // on the handle before the close, so they never reach the target (a path setstat after the close would have followed the link).
        var local = Path.Combine(_dir, "file.bin");
        await File.WriteAllBytesAsync(local, RandomNumberGenerator.GetBytes(segments > 1 ? 3 * 1024 * 1024 : 1000));
        Stamp(local);
        await using var rig = await Rig.StartAsync(files =>
        {
            files.AddFile(Home + "/victim", "secret"u8.ToArray(), modifyTime: VictimTime);
            files.SetMode(Home + "/victim", 0x180); // 0600
            files.OnClosed = path =>
            {
                if (path == Home + "/copy")
                {
                    files.ReplaceWithLink(Home + "/copy", Home + "/victim");
                }
            };
        });

        await rig.Sftp.UploadFileAsync(local, "copy", new SftpTransferOptions { Preserve = true, Segments = segments }, Timeout());

        await Assert.That(rig.Files.Mode(Home + "/victim")).IsEqualTo(0x180u);
        await Assert.That(rig.Files.ModifyTime(Home + "/victim")).IsEqualTo(VictimTime);
        await Assert.That(rig.Files.Requests).DoesNotContain((byte)9); // no path SETSTAT
        await Assert.That(rig.Files.Requests).Contains((byte)10); // FSETSTAT
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task AnUploadedDirectory_ReplacedByALinkBeforeItsAttributesAreSet_LeavesTheLinksTargetAlone(int concurrentFiles)
    {
        // The directory's times and mode are set once its contents are in, which leaves time to swap it for a link to a directory this
        // user owns. lsetstat sets them on the link itself.
        var tree = Path.Combine(_dir, "tree");
        var sub = Directory.CreateDirectory(Path.Combine(tree, "sub")).FullName;
        await File.WriteAllTextAsync(Path.Combine(sub, "f"), "data");
        Stamp(sub, directory: true);
        await using var rig = await Rig.StartAsync(files =>
        {
            files.AddDirectory(Home + "/victim");
            files.SetMode(Home + "/victim", 0x1C0); // 0700
            files.OnClosed = path =>
            {
                if (path == Home + "/up/sub/f")
                {
                    files.ReplaceWithLink(Home + "/up/sub", Home + "/victim");
                }
            };
        });

        await rig.Sftp.UploadDirectoryAsync(tree, "up", new SftpTransferOptions { Preserve = true, MaxConcurrentFiles = concurrentFiles }, Timeout());

        await Assert.That(rig.Files.Mode(Home + "/victim")).IsEqualTo(0x1C0u);
        await Assert.That(rig.Files.ModifyTime(Home + "/victim")).IsNotEqualTo((uint)new DateTimeOffset(LocalTime).ToUnixTimeSeconds());
        await Assert.That(rig.Files.Requests).DoesNotContain((byte)9); // no path SETSTAT
    }

    [Test]
    public async Task AServerWithoutLsetstat_GetsAPlainSetstatForDirectories()
    {
        var tree = Path.Combine(_dir, "tree");
        var sub = Directory.CreateDirectory(Path.Combine(tree, "sub")).FullName;
        await File.WriteAllTextAsync(Path.Combine(sub, "f"), "data");
        Stamp(sub, directory: true);
        await using var rig = await Rig.StartAsync(files => files.Extensions.Remove("lsetstat@openssh.com"));

        await rig.Sftp.UploadDirectoryAsync(tree, "up", new SftpTransferOptions { Preserve = true }, Timeout());

        await Assert.That(rig.Files.Requests).Contains((byte)9);
        await Assert.That(rig.Files.ModifyTime(Home + "/up/sub")).IsEqualTo((uint)new DateTimeOffset(LocalTime).ToUnixTimeSeconds());
    }
}
