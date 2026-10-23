using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>Pipelined READDIR, name patterns and recursive listings (#266).</summary>
public sealed class SftpListingTests
{
    private const string Home = FakeSftpServer.Home;

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

        /// <summary>Waits until the server has no handle open: a handle whose OPENDIR was given up on is closed in the background.</summary>
        public async Task HandlesClosedAsync()
        {
            var token = Timeout();
            while (Files.OpenHandles != 0)
            {
                await Task.Delay(10, token);
            }
        }
    }

    private static async Task<List<string>> ListAsync(SftpClient sftp, string path, SftpListOptions options)
    {
        var paths = new List<string>();
        await foreach (var entry in sftp.ListDirectoryAsync(path, options, Timeout()))
        {
            paths.Add(entry.FullPath);
        }

        return paths;
    }

    /// <summary>The same paths in the same order (shown joined, so a failure shows both lists).</summary>
    private static async Task AssertInOrder(IEnumerable<string> actual, IEnumerable<string> expected) =>
        await Assert.That(string.Join(" | ", actual)).IsEqualTo(string.Join(" | ", expected));

    private static void AddFiles(FakeSftpServer files, string directory, int count)
    {
        files.AddDirectory(directory);
        for (var i = 0; i < count; i++)
        {
            files.AddFile($"{directory}/f{i:D3}", [(byte)i]);
        }
    }

    // ---- pipelined READDIR ----

    [Test]
    public async Task ListDirectory_KeepsSeveralReaddirsInFlight_WithinTheBound()
    {
        // The first READDIR is held, so the requests the client sent without waiting are all at the server together: two to begin with.
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingBatch = 1;
            f.HoldListings = hold;
            AddFiles(f, Home + "/big", 100);
        });

        var listing = ListAsync(rig.Sftp, "big", new SftpListOptions());
        var token = Timeout();
        while (rig.Files.ListingRequestsInFlight < 2)
        {
            await Task.Delay(10, token);
        }

        await Assert.That(listing.IsCompleted).IsFalse();
        hold.SetResult();
        var names = await listing;

        await AssertInOrder(names, Enumerable.Range(0, 100).Select(i => $"big/f{i:D3}"));
        await Assert.That(rig.Files.MaxListingRequestsInFlight).IsBetween(2, SftpClient.ListingRequestsInFlight);

        // Every READDIR was answered before the handle was closed: none follows the CLOSE.
        var requests = rig.Files.Requests;
        await Assert.That(requests[^1]).IsEqualTo((byte)4);
        await Assert.That(requests.Count(r => r == 4)).IsEqualTo(1);
        await Assert.That(rig.Files.ListingRequestsInFlight).IsEqualTo(0);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task ListDirectory_TakesBatchesInRequestOrder_WhateverOrderTheRepliesCome()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingBatch = 2;
            f.ReorderReplies = true;
            AddFiles(f, Home + "/dir", 40);
        });

        var names = await ListAsync(rig.Sftp, "dir", new SftpListOptions());

        await AssertInOrder(names, Enumerable.Range(0, 40).Select(i => $"dir/f{i:D3}"));
    }

    [Test]
    public async Task ListDirectory_IgnoresAnErrorForReaddirsPastTheEnd()
    {
        // Some servers answer a READDIR after the end with an error, not EOF again: the requests in flight past the end are dropped.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingBatch = 100;
            f.FailReaddirAfterEof = true;
            AddFiles(f, Home + "/dir", 5);
        });

        var names = await ListAsync(rig.Sftp, "dir", new SftpListOptions());

        await Assert.That(names.Count).IsEqualTo(5);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task ListDirectory_StoppedEarly_ClosesTheHandle_AfterTheRepliesInFlight()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListingBatch = 1;
            AddFiles(f, Home + "/dir", 50);
        });

        await foreach (var entry in rig.Sftp.ListDirectoryAsync("dir", Timeout()))
        {
            break;
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
        await Assert.That(rig.Files.ListingRequestsInFlight).IsEqualTo(0);
        var requests = rig.Files.Requests;
        await Assert.That(requests[^1]).IsEqualTo((byte)4);
    }

    // ---- patterns ----

    [Test]
    public async Task Pattern_ListsOnlyTheMatchingNames()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/logs");
            foreach (var name in new[] { "app.log", "app.log.1", "db-01.log", "db-1.log", ".hidden.log", "notes.txt" })
            {
                f.AddFile(Home + "/logs/" + name, [1]);
            }
        });

        await AssertInOrder(await ListAsync(rig.Sftp, "logs", new SftpListOptions { Pattern = "*.log" }), new[] { "logs/.hidden.log", "logs/app.log", "logs/db-01.log", "logs/db-1.log" });
        await AssertInOrder(await ListAsync(rig.Sftp, "logs", new SftpListOptions { Pattern = "db-[0-9][0-9].log" }), new[] { "logs/db-01.log" });
        await AssertInOrder(await ListAsync(rig.Sftp, "logs", new SftpListOptions { Pattern = "app.log.?" }), new[] { "logs/app.log.1" });
        await AssertInOrder(await ListAsync(rig.Sftp, "logs", new SftpListOptions { Pattern = "[!.a]*" }), new[] { "logs/db-01.log", "logs/db-1.log", "logs/notes.txt" });
    }

    [Test]
    public async Task Pattern_IgnoreCase_MatchesWithoutRegardToCase_InEveryDirectory()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/photos");
            f.AddFile(Home + "/photos/a.jpg", [1]);
            f.AddFile(Home + "/photos/B.JPG", [2]);
            f.AddFile(Home + "/photos/c.Jpg", [3]);
            f.AddFile(Home + "/photos/d.png", [4]);
            f.AddDirectory(Home + "/photos/Trip");
            f.AddFile(Home + "/photos/Trip/E.JPG", [5]);
        });

        await AssertInOrder(await ListAsync(rig.Sftp, "photos", new SftpListOptions { Pattern = "*.jpg" }), new[] { "photos/a.jpg" });
        await AssertInOrder(await ListAsync(rig.Sftp, "photos", new SftpListOptions { Pattern = "*.jpg", IgnoreCase = true }),
            new[] { "photos/B.JPG", "photos/a.jpg", "photos/c.Jpg" });
        await AssertInOrder(await ListAsync(rig.Sftp, "photos", new SftpListOptions { Pattern = "*.jpg", IgnoreCase = true, Recursive = true }),
            new[] { "photos/B.JPG", "photos/Trip/E.JPG", "photos/a.jpg", "photos/c.Jpg" });
    }

    [Test]
    public async Task Options_RejectOutOfRangeValues_AndANullOptions()
    {
        await Assert.That(() => new SftpListOptions { MaxDepth = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpListOptions { MaxDepth = 1025 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpListOptions { MaxConcurrentDirectories = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpListOptions { MaxConcurrentDirectories = 65 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(new SftpListOptions { MaxDepth = 1024, MaxConcurrentDirectories = 64 }.MaxDepth).IsEqualTo(1024);

        await using var rig = await Rig.StartAsync();
        await Assert.That(() => rig.Sftp.ListDirectoryAsync(".", null!, Timeout())).Throws<ArgumentNullException>();
        await Assert.That(() => rig.Sftp.ListDirectoryAsync("", new SftpListOptions(), Timeout())).Throws<ArgumentException>();
    }

    // ---- recursive listings ----

    /// <summary>
    /// tree/a.log, b.txt, dangling (a link to nothing), empty/, link (to ../elsewhere, a directory outside), sub/back (a link to tree:
    /// a loop), sub/c.log, sub/deeper/d.log; and elsewhere/e.log.
    /// </summary>
    private static void AddTree(FakeSftpServer files)
    {
        files.AddDirectory(Home + "/tree");
        files.AddFile(Home + "/tree/a.log", [1]);
        files.AddFile(Home + "/tree/b.txt", [2]);
        files.AddLink(Home + "/tree/dangling", "/nowhere");
        files.AddDirectory(Home + "/tree/empty");
        files.AddLink(Home + "/tree/link", Home + "/elsewhere");
        files.AddDirectory(Home + "/tree/sub");
        files.AddLink(Home + "/tree/sub/back", Home + "/tree");
        files.AddFile(Home + "/tree/sub/c.log", [3]);
        files.AddDirectory(Home + "/tree/sub/deeper");
        files.AddFile(Home + "/tree/sub/deeper/d.log", [4]);
        files.AddDirectory(Home + "/elsewhere");
        files.AddFile(Home + "/elsewhere/e.log", [5]);
    }

    [Test]
    public async Task Recursive_ListsDepthFirst_InTheServersOrder_WithoutFollowingLinks()
    {
        await using var rig = await Rig.StartAsync(AddTree);

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true });

        await AssertInOrder(paths, new[]
        {
            "tree/a.log", "tree/b.txt", "tree/dangling", "tree/empty", "tree/link",
            "tree/sub", "tree/sub/back", "tree/sub/c.log", "tree/sub/deeper", "tree/sub/deeper/d.log",
        });
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task Recursive_FollowsTheServersOrder_NotTheAlphabet_EachSubtreeRightAfterItsDirectory()
    {
        // A server whose order is not alphabetical (here: reversed). Nothing is sorted: each directory's entries come as the server
        // listed them, and a subdirectory's whole subtree follows its own entry, before the entries listed after it. So a file listed
        // after a subdirectory comes after everything below that subdirectory.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ReverseListing = true;
            AddTree(f);
        });

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true });

        await AssertInOrder(paths, new[]
        {
            "tree/sub", "tree/sub/deeper", "tree/sub/deeper/d.log", "tree/sub/c.log", "tree/sub/back",
            "tree/link", "tree/empty", "tree/dangling", "tree/b.txt", "tree/a.log",
        });

        var logs = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, Pattern = "*.log" });
        await AssertInOrder(logs, new[] { "tree/sub/deeper/d.log", "tree/sub/c.log", "tree/a.log" });
    }

    [Test]
    public async Task Recursive_WithAPattern_SelectsEntries_ButDescendsIntoEveryDirectory()
    {
        await using var rig = await Rig.StartAsync(AddTree);

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, Pattern = "*.log" });

        await AssertInOrder(paths, new[] { "tree/a.log", "tree/sub/c.log", "tree/sub/deeper/d.log" });
    }

    [Test]
    [Arguments(1, new[] { "tree/a.log", "tree/b.txt", "tree/dangling", "tree/empty", "tree/link", "tree/sub" })]
    [Arguments(2, new[] { "tree/a.log", "tree/b.txt", "tree/dangling", "tree/empty", "tree/link", "tree/sub", "tree/sub/back", "tree/sub/c.log", "tree/sub/deeper" })]
    public async Task Recursive_StopsDescendingAtMaxDepth(int maxDepth, string[] expected)
    {
        await using var rig = await Rig.StartAsync(AddTree);

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, MaxDepth = maxDepth });

        await AssertInOrder(paths, expected);
    }

    [Test]
    public async Task Recursive_DefaultDepth_StopsAt64Levels_WithoutAnError()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            var path = Home + "/deep";
            f.AddDirectory(path);
            for (var i = 0; i < 70; i++)
            {
                path += "/d";
                f.AddDirectory(path);
            }
        });

        var paths = await ListAsync(rig.Sftp, "deep", new SftpListOptions { Recursive = true });

        await Assert.That(paths.Count).IsEqualTo(64);
        await Assert.That(paths[^1]).IsEqualTo("deep" + string.Concat(Enumerable.Repeat("/d", 64)));
    }

    [Test]
    public async Task Recursive_FollowingLinks_EntersLinkedDirectories_ButNotALoopOrADanglingLink()
    {
        await using var rig = await Rig.StartAsync(AddTree);

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, FollowSymbolicLinks = true });

        await AssertInOrder(paths, new[]
        {
            "tree/a.log", "tree/b.txt", "tree/dangling", "tree/empty", "tree/link", "tree/link/e.log",
            "tree/sub", "tree/sub/back", "tree/sub/c.log", "tree/sub/deeper", "tree/sub/deeper/d.log",
        });
    }

    [Test]
    public async Task Recursive_EntersANameListedTwice_Once()
    {
        // A broken or hostile server lists every entry twice: the entries are returned as listed, but each directory is entered once,
        // or every level would double the work.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.ListEntriesTwice = true;
            AddTree(f);
        });

        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true });

        await Assert.That(paths.Count(p => p == "tree/sub")).IsEqualTo(2);
        await Assert.That(paths.Count(p => p == "tree/sub/deeper/d.log")).IsEqualTo(2); // deeper was listed once, its entry twice
    }

    [Test]
    public async Task Recursive_ReadsAtMostMaxConcurrentDirectoriesAtOnce()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/wide");
            for (var i = 0; i < 30; i++)
            {
                AddFiles(f, $"{Home}/wide/d{i:D2}", 3);
            }
        });

        var paths = await ListAsync(rig.Sftp, "wide", new SftpListOptions { Recursive = true, MaxConcurrentDirectories = 3 });

        await Assert.That(paths.Count).IsEqualTo(30 * 4);
        await AssertInOrder(paths.Take(5), new[] { "wide/d00", "wide/d00/f000", "wide/d00/f001", "wide/d00/f002", "wide/d01" });
        await Assert.That(rig.Files.MaxOpenDirectoryHandles).IsLessThanOrEqualTo(3);
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task Recursive_HoldsAtMostMaxConcurrentDirectoriesListingsReadAhead()
    {
        // A slot is free again as soon as a listing read ahead has been read; the listings themselves stay until the walk reaches them.
        // Those must stay bounded too, not just the handles: a wide directory must not be listed ahead whole and held.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/wide");
            for (var i = 0; i < 30; i++)
            {
                AddFiles(f, $"{Home}/wide/d{i:D2}", 3);
            }
        });

        var reached = 0; // subdirectories returned so far
        var mostAhead = 0;
        await foreach (var entry in rig.Sftp.ListDirectoryAsync("wide", new SftpListOptions { Recursive = true, MaxConcurrentDirectories = 3 }, Timeout()))
        {
            if (entry.Attributes.IsDirectory)
            {
                reached++;
            }

            // Let what was started ahead be read whole, so freed slots would be taken again were nothing else holding them back.
            await rig.HandlesClosedAsync();
            await Task.Delay(5);
            await rig.HandlesClosedAsync();
            var opened = rig.Files.Requests.Count(r => r == 11) - 1; // OPENDIRs, the top directory's aside
            mostAhead = Math.Max(mostAhead, opened - reached);
        }

        await Assert.That(reached).IsEqualTo(30);
        await Assert.That(mostAhead).IsLessThanOrEqualTo(3);
        await Assert.That(mostAhead).IsGreaterThan(0).Because("listings are still read ahead");
    }

    [Test]
    public async Task Recursive_ASubdirectoryThatCannotBeListed_EndsTheListingThere()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddTree(f);
            f.DenyOpenDir = path => path == Home + "/tree/sub";
        });

        var paths = new List<string>();
        var thrown = await Assert.That(async () =>
        {
            await foreach (var entry in rig.Sftp.ListDirectoryAsync("tree", new SftpListOptions { Recursive = true }, Timeout()))
            {
                paths.Add(entry.FullPath);
            }
        }).Throws<SftpException>();

        await Assert.That(thrown!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
        await Assert.That(paths[^1]).IsEqualTo("tree/sub"); // everything before it, in order
        await rig.HandlesClosedAsync();
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task Recursive_SkipUnreadableDirectories_LeavesThemOut_AndGoesOn(int concurrentDirectories)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddTree(f);
            f.AddDirectory(Home + "/tree/zz");
            f.AddFile(Home + "/tree/zz/f.log", [6]);
            f.DenyOpenDir = path => path is Home + "/tree/sub" or Home + "/tree/empty";
        });
        var skipped = new List<string>();
        var paths = new List<string>();

        await foreach (var entry in rig.Sftp.ListDirectoryAsync("tree", new SftpListOptions
        {
            Recursive = true,
            MaxConcurrentDirectories = concurrentDirectories,
            SkipUnreadableDirectories = true,
            UnreadableDirectory = directory => skipped.Add(directory.FullPath),
        }, Timeout()))
        {
            paths.Add(entry.FullPath);
        }

        // Their own entries are listed, then nothing below them; the listing goes on after each, and reports it right after its entry.
        await AssertInOrder(paths, new[] { "tree/a.log", "tree/b.txt", "tree/dangling", "tree/empty", "tree/link", "tree/sub", "tree/zz", "tree/zz/f.log" });
        await AssertInOrder(skipped, new[] { "tree/empty", "tree/sub" });
        await rig.HandlesClosedAsync();
    }

    [Test]
    public async Task Recursive_SkipUnreadableDirectories_WithoutACallback_AndAFollowedLink()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddTree(f);
            f.DenyOpenDir = path => path == Home + "/tree/link";
        });

        // tree/link leads to a directory that cannot be read: left out like a subdirectory.
        var paths = await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, FollowSymbolicLinks = true, SkipUnreadableDirectories = true, Pattern = "*.log" });

        await AssertInOrder(paths, new[] { "tree/a.log", "tree/sub/c.log", "tree/sub/deeper/d.log" });
    }

    [Test]
    [Arguments(2u, "No such file")] // deleted meanwhile
    [Arguments(4u, "Failure")]
    public async Task Recursive_SkipUnreadableDirectories_StillEndsTheListing_OnOtherErrors(uint code, string message)
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddTree(f);
            f.DenyOpenDir = path => path == Home + "/tree/sub";
            f.DenyOpenDirStatus = (code, message);
        });

        var thrown = await Assert.That(async () => await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, SkipUnreadableDirectories = true }))
            .Throws<SftpException>();

        await Assert.That((uint)thrown!.Status).IsEqualTo(code);
        await rig.HandlesClosedAsync();
    }

    [Test]
    public async Task Recursive_SkipUnreadableDirectories_TheTopDirectoryStillFails()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            AddTree(f);
            f.DenyOpenDir = path => path == Home + "/tree";
        });

        var thrown = await Assert.That(async () => await ListAsync(rig.Sftp, "tree", new SftpListOptions { Recursive = true, SkipUnreadableDirectories = true }))
            .Throws<SftpException>();

        await Assert.That(thrown!.Status).IsEqualTo(SftpStatusCode.PermissionDenied);
    }

    [Test]
    public async Task Recursive_StoppedEarly_StopsTheListingsReadAhead_AndClosesTheirHandles()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/wide");
            for (var i = 0; i < 20; i++)
            {
                AddFiles(f, $"{Home}/wide/d{i:D2}", 20);
            }
        });

        await foreach (var entry in rig.Sftp.ListDirectoryAsync("wide", new SftpListOptions { Recursive = true, MaxConcurrentDirectories = 8 }, Timeout()))
        {
            if (entry.FullPath == "wide/d00/f000")
            {
                break;
            }
        }

        await rig.HandlesClosedAsync();
    }

    [Test]
    public async Task Recursive_Cancelled_ThrowsAndClosesTheHandles()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddDirectory(Home + "/wide");
            for (var i = 0; i < 20; i++)
            {
                AddFiles(f, $"{Home}/wide/d{i:D2}", 20);
            }
        });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Timeout());
        var seen = 0;
        await Assert.That(async () =>
        {
            await foreach (var entry in rig.Sftp.ListDirectoryAsync("wide", new SftpListOptions { Recursive = true }, cts.Token))
            {
                if (++seen == 30)
                {
                    await cts.CancelAsync();
                }
            }
        }).Throws<OperationCanceledException>();

        await rig.HandlesClosedAsync();
    }
}
