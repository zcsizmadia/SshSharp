using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// The conveniences of #266: recursive delete, creating a directory with its parents, whole-file reads and writes, and
/// <see cref="SftpClient.OperationTimeout"/>.
/// </summary>
public sealed class SftpConveniencesTests
{
    private const string Home = FakeSftpServer.Home;

    private const byte Mkdir = 14;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; private init; } = null!;

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        /// <summary>A rig whose client and SFTP server (its <see cref="FakeSftpServer.ReplyDelay"/>) run on <paramref name="time"/>.</summary>
        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null, TimeProvider? time = null)
        {
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var rig = new Rig { Ssh = new FakeSessionServer { Password = password } };
            rig.Files.Time = time ?? TimeProvider.System;
            setup?.Invoke(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = password,
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
                TimeProvider = time ?? TimeProvider.System,
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

    // ---- recursive delete ----

    [Test]
    public async Task DeleteRecursive_DeletesTheTree_AndLinksThemselves_NeverWhatTheyPointTo()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/keep");
            f.AddFile(Home + "/keep/precious", "do not touch"u8.ToArray());
            f.AddDirectory(Home + "/tree");
            f.AddDirectory(Home + "/tree/empty");
            f.AddDirectory(Home + "/tree/a");
            f.AddDirectory(Home + "/tree/a/b");
            f.AddLink(Home + "/tree/a/to-keep", "../../keep");
            f.AddLink(Home + "/tree/dangling", "nowhere");
            for (var i = 0; i < 40; i++)
            {
                f.AddFile($"{Home}/tree/file{i}", [(byte)i]);
                f.AddFile($"{Home}/tree/a/b/deep{i}", [(byte)i]);
            }

            // The first REMOVE is answered once a second one is in flight: "pipelined" does not race the server's reply.
            f.PipelineGate = 2;
            f.PipelineGateFor = static packet => packet[0] == 13;
        });

        await rig.Sftp.DeleteDirectoryAsync("tree", recursive: true, Timeout());

        await Assert.That(rig.Files.Exists(Home + "/tree")).IsFalse();
        await Assert.That(rig.Files.FilesUnder(Home + "/tree")).IsEmpty();
        await Assert.That(rig.Files.FileData(Home + "/keep/precious")).IsNotNull();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
        await Assert.That(rig.Files.MaxOutstanding).IsGreaterThan(1); // the removals were pipelined
    }

    [Test]
    public async Task DeleteRecursive_NeverFollowsALink_EvenWhenTheListingDescribesItAsADirectory()
    {
        // A server whose listing stats rather than lstats: the link to a directory outside looks like a directory.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingFollowsLinks = true;
            f.AddDirectory(Home + "/keep");
            f.AddFile(Home + "/keep/precious", [1]);
            f.AddDirectory(Home + "/tree");
            f.AddLink(Home + "/tree/to-keep", Home + "/keep");
        });

        await rig.Sftp.DeleteDirectoryAsync("tree", recursive: true, Timeout());

        await Assert.That(rig.Files.Exists(Home + "/tree")).IsFalse();
        await Assert.That(rig.Files.FileData(Home + "/keep/precious")).IsNotNull();
    }

    [Test]
    public async Task DeleteRecursive_AWideTree_UsesSeveralWalkers_AndLeavesNothing()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/wide");
            for (var d = 0; d < 20; d++)
            {
                f.AddDirectory($"{Home}/wide/d{d}");
                f.AddDirectory($"{Home}/wide/d{d}/inner");
                for (var i = 0; i < 10; i++)
                {
                    f.AddFile($"{Home}/wide/d{d}/f{i}", [1]);
                    f.AddFile($"{Home}/wide/d{d}/inner/g{i}", [2]);
                }
            }
        });

        await rig.Sftp.DeleteDirectoryAsync(Home + "/wide", recursive: true, Timeout());

        await Assert.That(rig.Files.Exists(Home + "/wide")).IsFalse();
        await Assert.That(rig.Files.Exists(Home)).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task DeleteRecursive_StopsAtTheFirstFailure_ThrowsIt_AndLeavesWhatItCouldNotDelete()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddDirectory(Home + "/tree/locked");
            f.AddFile(Home + "/tree/locked/stuck", [1]);
            for (var i = 0; i < 10; i++)
            {
                f.AddFile($"{Home}/tree/f{i}", [1]);
            }

            f.DenyRemove = path => path.EndsWith("/stuck", StringComparison.Ordinal);
        });

        var failure = await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("tree", recursive: true, Timeout())).Throws<SftpException>();

        await Assert.That(failure!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
        await Assert.That(failure.Path).IsEqualTo("tree/locked/stuck");
        await Assert.That(rig.Files.Exists(Home + "/tree/locked/stuck")).IsTrue();
        await Assert.That(rig.Files.Exists(Home + "/tree/locked")).IsTrue();
        await Assert.That(rig.Files.Exists(Home + "/tree")).IsTrue();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);

        // Once the cause is gone, calling again finishes the job.
        rig.Files.DenyRemove = null;
        await rig.Sftp.DeleteDirectoryAsync("tree", recursive: true, Timeout());
        await Assert.That(rig.Files.Exists(Home + "/tree")).IsFalse();
    }

    [Test]
    public async Task DeleteRecursive_OfALink_DeletesTheLinkOnly()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/real");
            f.AddFile(Home + "/real/file", [1]);
            f.AddLink(Home + "/link", "real");
        });

        await rig.Sftp.DeleteDirectoryAsync("link", recursive: true, Timeout());

        await Assert.That(rig.Files.Exists(Home + "/link")).IsFalse();
        await Assert.That(rig.Files.FileData(Home + "/real/file")).IsNotNull();
    }

    [Test]
    public async Task DeleteRecursive_OfAMissingPathOrAFile_FailsAsDeletingOneDirectoryDoes()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/file", [1]));

        var missing = await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("missing", recursive: true, Timeout())).Throws<SftpException>();
        await Assert.That(missing!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);

        await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("file", recursive: true, Timeout())).Throws<SftpException>();
        await Assert.That(rig.Files.Exists(Home + "/file")).IsTrue();
    }

    [Test]
    public async Task DeleteNotRecursive_RefusesADirectoryThatIsNotEmpty()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/full");
            f.AddFile(Home + "/full/x", [1]);
        });

        await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("full", recursive: false, Timeout())).Throws<SftpException>();
        await Assert.That(rig.Files.FileData(Home + "/full/x")).IsNotNull();
    }

    [Test]
    public async Task DeleteRecursive_OfATreeDeeperThan64Levels_Stops()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            var path = Home + "/deep";
            for (var i = 0; i < 70; i++)
            {
                f.AddDirectory(path);
                path += "/d";
            }
        });

        var error = await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("deep", recursive: true, Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.TransferFailed);
        await Assert.That(rig.Files.Exists(Home + "/deep")).IsTrue();
    }

    [Test]
    public async Task DeleteRecursive_Cancelled_ThrowsOperationCanceled()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/tree");
            f.AddFile(Home + "/tree/x", [1]);
        });

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.That(async () => await rig.Sftp.DeleteDirectoryAsync("tree", recursive: true, cancelled.Token)).Throws<OperationCanceledException>();
        await Assert.That(rig.Files.Exists(Home + "/tree/x")).IsTrue();
    }

    // ---- create with parents ----

    [Test]
    public async Task CreateWithParents_CreatesTheMissingDirectories_PermissionsOnTheLastOnly()
    {
        await using var rig = await Rig.StartAsync(f => f.AddDirectory(Home + "/a"));

        await rig.Sftp.CreateDirectoryAsync("a/b/c/d", createParents: true, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, Timeout());

        await Assert.That(rig.Files.Exists(Home + "/a/b/c/d")).IsTrue();
        await Assert.That(rig.Files.Mode(Home + "/a/b/c/d")).IsEqualTo(0x1C0u); // 0700
        await Assert.That(rig.Files.Mode(Home + "/a/b")).IsEqualTo(0x1EDu); // the server's default
        await Assert.That(rig.Files.Mode(Home + "/a/b/c")).IsEqualTo(0x1EDu);
    }

    [Test]
    public async Task CreateWithParents_OfAnExistingDirectory_Succeeds_WithOneCreateRequest()
    {
        await using var rig = await Rig.StartAsync(f => f.AddDirectory(Home + "/there"));
        var before = rig.Files.Requests.Count(r => r == Mkdir);

        await rig.Sftp.CreateDirectoryAsync(Home + "/there", createParents: true, cancellationToken: Timeout());
        await rig.Sftp.CreateDirectoryAsync("there/", createParents: true, cancellationToken: Timeout());

        await Assert.That(rig.Files.Requests.Count(r => r == Mkdir) - before).IsEqualTo(2);
    }

    [Test]
    public async Task CreateWithParents_FailsWhenAPartOfThePathIsAFile()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/file", [1]));

        var below = await Assert.That(async () => await rig.Sftp.CreateDirectoryAsync("file/sub/deeper", createParents: true, cancellationToken: Timeout()))
            .Throws<SftpException>();
        await Assert.That(below!.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(below.Path).IsEqualTo("file");

        var itself = await Assert.That(async () => await rig.Sftp.CreateDirectoryAsync("file", createParents: true, cancellationToken: Timeout()))
            .Throws<SftpException>();
        await Assert.That(itself!.Path).IsEqualTo("file");
        await Assert.That(rig.Files.FileData(Home + "/file")).IsNotNull();
    }

    [Test]
    public async Task CreateWithoutParents_StillFailsForAMissingParent()
    {
        await using var rig = await Rig.StartAsync();

        var error = await Assert.That(async () => await rig.Sftp.CreateDirectoryAsync("x/y", createParents: false, cancellationToken: Timeout())).Throws<SftpException>();
        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
        await Assert.That(rig.Files.Exists(Home + "/x")).IsFalse();
    }

    [Test]
    [Arguments("a/b", "a")]
    [Arguments("a/b/", "a")]
    [Arguments("/a//b", "/a")]
    [Arguments("/srv/www/site", "/srv/www")]
    [Arguments("a", null)]
    [Arguments("/a", null)]
    [Arguments("/", null)]
    public async Task ParentOf_IsTheDirectoryAbove_OrNullAtTheTop(string path, string? parent) =>
        await Assert.That(SftpClient.ParentOf(path)).IsEqualTo(parent);

    // ---- whole files ----

    [Test]
    public async Task WriteAllBytes_ThenReadAllBytes_RoundTrips_AndReplacesTheFile()
    {
        await using var rig = await Rig.StartAsync();
        var data = RandomNumberGenerator.GetBytes(300_000); // several requests both ways

        await rig.Sftp.WriteAllBytesAsync("blob", data, Timeout());
        await Assert.That((await rig.Sftp.ReadAllBytesAsync("blob", Timeout())).AsSpan().SequenceEqual(data)).IsTrue();

        // Shorter contents replace the file rather than overwrite its start; a slice of an array writes just that slice.
        await rig.Sftp.WriteAllBytesAsync("blob", data.AsMemory(10, 5), Timeout());
        await Assert.That(rig.Files.FileData(Home + "/blob")).IsEquivalentTo(data[10..15]);

        await rig.Sftp.WriteAllBytesAsync("empty", ReadOnlyMemory<byte>.Empty, Timeout());
        await Assert.That(await rig.Sftp.ReadAllBytesAsync("empty", Timeout())).IsEmpty();
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task ReadAllBytes_OfAMissingFile_ThrowsNoSuchFile()
    {
        await using var rig = await Rig.StartAsync();

        var error = await Assert.That(async () => await rig.Sftp.ReadAllBytesAsync("missing", Timeout())).Throws<SftpException>();
        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
    }

    [Test]
    public async Task WriteAllText_IsUtf8WithoutABom_ByDefault_AndAGivenEncodingWritesItsPreamble()
    {
        await using var rig = await Rig.StartAsync();

        await rig.Sftp.WriteAllTextAsync("plain.txt", "héllo", cancellationToken: Timeout());
        await Assert.That(rig.Files.FileData(Home + "/plain.txt")).IsEquivalentTo(Encoding.UTF8.GetBytes("héllo"));
        await Assert.That(await rig.Sftp.ReadAllTextAsync("plain.txt", cancellationToken: Timeout())).IsEqualTo("héllo");

        await rig.Sftp.WriteAllTextAsync("wide.txt", "wide", Encoding.Unicode, Timeout());
        await Assert.That(rig.Files.FileData(Home + "/wide.txt")).IsEquivalentTo([.. Encoding.Unicode.Preamble, .. Encoding.Unicode.GetBytes("wide")]);

        // The byte order mark decides when there is one, as File.ReadAllText does.
        await Assert.That(await rig.Sftp.ReadAllTextAsync("wide.txt", cancellationToken: Timeout())).IsEqualTo("wide");
    }

    [Test]
    public async Task ReadAllText_UsesTheGivenEncoding_WithoutABom_AndDropsAUtf8Bom()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/latin1.txt", Encoding.Latin1.GetBytes("café"));
            f.AddFile(Home + "/bom.txt", [0xEF, 0xBB, 0xBF, (byte)'o', (byte)'k']);
        });

        await Assert.That(await rig.Sftp.ReadAllTextAsync("latin1.txt", Encoding.Latin1, Timeout())).IsEqualTo("café");
        await Assert.That(await rig.Sftp.ReadAllTextAsync("bom.txt", cancellationToken: Timeout())).IsEqualTo("ok");
    }

    // ---- OperationTimeout ----

    [Test]
    public async Task OperationTimeout_IsOffByDefault_AndRejectsNonsense()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(rig.Sftp.OperationTimeout).IsEqualTo(System.Threading.Timeout.InfiniteTimeSpan);
        await Assert.That(() => rig.Sftp.OperationTimeout = TimeSpan.Zero).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(-2)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => rig.Sftp.OperationTimeout = TimeSpan.FromDays(30)).Throws<ArgumentOutOfRangeException>();

        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(5);
        await Assert.That(rig.Sftp.OperationTimeout).IsEqualTo(TimeSpan.FromSeconds(5));
        rig.Sftp.OperationTimeout = System.Threading.Timeout.InfiniteTimeSpan;
        await Assert.That(rig.Sftp.OperationTimeout).IsEqualTo(System.Threading.Timeout.InfiniteTimeSpan);
    }

    [Test]
    public async Task OperationTimeout_FailsARequestTheServerDoesNotAnswer_AndTheSessionStaysUsable()
    {
        // The server holds the first STAT's reply until released, and the client's timeout runs on a fake clock, moved on by the test:
        // the timeout comes first, and not before its time, however loaded the machine.
        var time = new FakeTimeProvider();
        var held = 0;
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/f", [1, 2, 3]);
            f.Hold = packet => packet[0] == 17 && Interlocked.Increment(ref held) == 1;
        }, time);
        rig.Sftp.OperationTimeout = TimeSpan.FromMilliseconds(300);
        var started = time.GetTimestamp();

        var stat = rig.Sftp.GetAttributesAsync("f", cancellationToken: Timeout());
        await FakeClock.AdvanceUntilAsync(time, TimeSpan.FromMilliseconds(50), () => stat.IsCompleted);
        var error = await Assert.That(async () => await stat).Throws<SshException>();

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(error.InnerException).IsTypeOf<TimeoutException>();
        await Assert.That(time.GetElapsedTime(started)).IsGreaterThanOrEqualTo(TimeSpan.FromMilliseconds(300)); // never before the timeout
        await Assert.That(rig.Files.Held).IsEqualTo(1);

        // The late reply is dropped; the next request (answered once the server gets to it) works.
        rig.Sftp.OperationTimeout = TimeSpan.FromSeconds(30);
        rig.Files.Released.SetResult();
        await Assert.That((await rig.Sftp.GetAttributesAsync("f", cancellationToken: Timeout())).Size).IsEqualTo(3L);
    }

    [Test]
    public async Task OperationTimeout_DoesNotCutOffATransfer_WhileTheServerKeepsAnswering()
    {
        // Each read is answered 75 ms after the one before, with up to 64 in flight: the later reads of a window wait seconds for their
        // replies, several times the timeout, but the server is never silent for more than 75 ms. The server's delays and the client's
        // timeout run on one fake clock, moved on only once the client has taken every reply sent so far and the server holds the next
        // one back, so a loaded machine (whose stalls once stretched a 75 ms gap past a 1.5 s timeout on the wall clock) changes nothing.
        var time = new FakeTimeProvider();
        var data = RandomNumberGenerator.GetBytes(64 * 32 * 1024);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.Limits = (32 * 1024, 32 * 1024);
            f.AddFile(Home + "/big", data);
            f.ReplyDelay = (request, _) => request == 5 ? TimeSpan.FromMilliseconds(75) : TimeSpan.Zero;
        }, time);
        rig.Sftp.OperationTimeout = TimeSpan.FromMilliseconds(1500);
        var started = time.GetTimestamp();

        var read = rig.Sftp.ReadAllBytesAsync("big", Timeout());
        await FakeClock.AnswerEachInTurnAsync(time, rig.Files, rig.Sftp, TimeSpan.FromMilliseconds(75), read);

        await Assert.That((await read).AsSpan().SequenceEqual(data)).IsTrue();
        await Assert.That(rig.Files.MaxDataRequestsInFlight).IsGreaterThan(20); // 20 × 75 ms: enough in flight that the last waited past the timeout
        await Assert.That(time.GetElapsedTime(started)).IsGreaterThan(TimeSpan.FromSeconds(3)); // the transfer took twice the timeout and more
    }

    [Test]
    public async Task OperationTimeout_OnAnOpen_ClosesTheHandleWhenTheLateReplyComes()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/f", [1]);
            f.HoldOpens = hold;
        });
        rig.Sftp.OperationTimeout = TimeSpan.FromMilliseconds(200);

        var error = await Assert.That(async () => await rig.Sftp.OpenReadAsync("f", Timeout())).Throws<SshException>();
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.Timeout);

        // The server opens the file after all; the client closes the handle it never handed out.
        hold.SetResult();
        await WaitUntilAsync(() => rig.Files.OpenHandles == 0 && rig.Files.Requests.Contains(4));
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }
}
