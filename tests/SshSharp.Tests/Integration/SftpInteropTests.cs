using System.Security.Cryptography;
using SshSharp.Sftp;

namespace SshSharp.Tests.Integration;

/// <summary>The SFTP client against a real server's <c>sftp</c> subsystem (OpenSSH's internal-sftp in CI). Needs the usual SSHSHARP_TEST_* variables.</summary>
public class SftpInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    [Test]
    public async Task ADirectoryTree_RoundTrips_AndAResumedDownloadCompletes()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-sftptree-");
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = RealServer.SftpPath(".sshsharp-sftptree-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            var source = Path.Combine(local.FullName, "source");
            Directory.CreateDirectory(Path.Combine(source, "a", "b"));
            var big = RandomNumberGenerator.GetBytes(700_000);
            await File.WriteAllBytesAsync(Path.Combine(source, "top.bin"), big);
            await File.WriteAllTextAsync(Path.Combine(source, "a", "middle.txt"), "middle");
            await File.WriteAllTextAsync(Path.Combine(source, "a", "b", "leaf.txt"), "leaf");

            var up = await sftp.UploadDirectoryAsync(source, remote, cancellationToken: Timeout());
            await Assert.That(up.Files).IsEqualTo(3);

            var copy = Path.Combine(local.FullName, "copy");
            var down = await sftp.DownloadDirectoryAsync(remote, copy, cancellationToken: Timeout());
            await Assert.That(down.Files).IsEqualTo(3);
            await Assert.That(down.Directories).IsEqualTo(2);
            await Assert.That((await File.ReadAllBytesAsync(Path.Combine(copy, "top.bin"))).AsSpan().SequenceEqual(big)).IsTrue();
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(copy, "a", "b", "leaf.txt"))).IsEqualTo("leaf");

            // The OpenSSH extensions, where this server version has them.
            if (sftp.Extensions.ContainsKey("statvfs@openssh.com"))
            {
                try
                {
                    var space = await sftp.GetFileSystemInfoAsync(remote, Timeout());
                    await Assert.That(space.TotalBytes).IsGreaterThan(0L);
                    await Assert.That(space.AvailableBytes).IsLessThanOrEqualTo(space.TotalBytes);
                }
                catch (SftpException ex) when (ex.Status == SftpStatusCode.OperationUnsupported || !RealServer.IsOpenSsh)
                {
                    // Announced but not implemented on this platform: pkg/sftp's Windows build answers Failure, "operation not supported".
                }
            }

            if (sftp.Extensions.ContainsKey("copy-data"))
            {
                await sftp.CopyFileAsync(remote + "/top.bin", remote + "/top-copy.bin", cancellationToken: Timeout());
                var copied = new MemoryStream();
                await sftp.DownloadAsync(remote + "/top-copy.bin", copied, cancellationToken: Timeout());
                await Assert.That(copied.ToArray().AsSpan().SequenceEqual(big)).IsTrue();
            }

            await using (var synced = await sftp.OpenWriteAsync(remote + "/synced", Timeout()))
            {
                await synced.WriteAsync("durable"u8.ToArray(), Timeout());
                await synced.FlushAsync(Timeout()); // fsync@openssh.com where the server has it
            }

            // The same tree through the IFileProvider adapter, read synchronously and asynchronously.
            var provider = new SshSharp.FileProviders.SftpFileProvider(sftp, remote);
            await Assert.That(provider.GetDirectoryContents("a").Select(f => f.Name)).Contains("middle.txt");
            using (var reader = new StreamReader(provider.GetFileInfo("a/b/leaf.txt").CreateReadStream()))
            {
                await Assert.That(reader.ReadToEnd()).IsEqualTo("leaf");
            }

            await using (var served = provider.GetFileInfo("top.bin").CreateReadStream())
            {
                var viaProvider = new MemoryStream();
                await served.CopyToAsync(viaProvider, Timeout());
                await Assert.That(viaProvider.ToArray().AsSpan().SequenceEqual(big)).IsTrue();
            }

            await Assert.That(provider.GetFileInfo("../" + remote + "/top.bin").Exists).IsFalse();

            // Cut the copy short, then resume it.
            var partial = Path.Combine(local.FullName, "partial.bin");
            await File.WriteAllBytesAsync(partial, big[..300_000]);
            var rest = await sftp.DownloadFileAsync(remote + "/top.bin", partial, new SftpTransferOptions { Resume = true }, Timeout());
            await Assert.That(rest).IsEqualTo(400_000L);
            await Assert.That((await File.ReadAllBytesAsync(partial)).AsSpan().SequenceEqual(big)).IsTrue();
        }
        finally
        {
            local.Delete(recursive: true);
            await DeleteTreeAsync(sftp, remote);
        }
    }

    [Test]
    public async Task ATreeOfManyFiles_RoundTrips_WithSeveralFilesAtOnce()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-sftpmany-");
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = RealServer.SftpPath(".sshsharp-sftpmany-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            var tree = WriteTree(Path.Combine(local.FullName, "source"));
            var transfer = new SftpTransferOptions { MaxConcurrentFiles = 4 };

            var up = await sftp.UploadDirectoryAsync(Path.Combine(local.FullName, "source"), remote, transfer, Timeout());
            await Assert.That(up.Files).IsEqualTo(tree.Count);
            await Assert.That(up.Directories).IsEqualTo(6);

            var copy = Path.Combine(local.FullName, "copy");
            var down = await sftp.DownloadDirectoryAsync(remote, copy, transfer, Timeout());
            await Assert.That(down).IsEqualTo(up);
            foreach (var (path, data) in tree)
            {
                await Assert.That((await File.ReadAllBytesAsync(Path.Combine(copy, path))).AsSpan().SequenceEqual(data)).IsTrue();
            }
        }
        finally
        {
            local.Delete(recursive: true);
            await DeleteTreeAsync(sftp, remote);
        }
    }

    [Test]
    public async Task ATreeOfManyFiles_OverLatency_Measure()
    {
        // A measurement, not a check: with SSHSHARP_MEASURE=1, prints how long a tree of small files takes through a proxy that adds
        // 25 ms each way, one file at a time and several. Nothing here asserts a time.
        if (Environment.GetEnvironmentVariable("SSHSHARP_MEASURE") != "1")
        {
            Skip.Test("Set SSHSHARP_MEASURE=1 to measure.");
            return;
        }

        if (RealServer.Endpoint is not { } endpoint || await RealServer.OptionsAsync() is not { } options || !RealServer.HasSftp)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key, and a server with SFTP, are needed.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-sftpmeasure-");
        await using var proxy = new FaultyProxy(endpoint) { Latency = TimeSpan.FromMilliseconds(25) };
        await using var client = await SshClient.ConnectAsync("127.0.0.1", proxy.Port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = RealServer.SftpPath(".sshsharp-sftpmeasure-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            var source = Path.Combine(local.FullName, "source");
            var tree = WriteTree(source);
            await sftp.CreateDirectoryAsync(remote, cancellationToken: Timeout());
            foreach (var files in new[] { 1, 4, 8, 16 })
            {
                var transfer = new SftpTransferOptions { MaxConcurrentFiles = files };
                var clock = System.Diagnostics.Stopwatch.StartNew();
                await sftp.UploadDirectoryAsync(source, $"{remote}/up{files}", transfer, Timeout());
                var up = clock.Elapsed;
                clock.Restart();
                await sftp.DownloadDirectoryAsync($"{remote}/up{files}", Path.Combine(local.FullName, "down" + files), transfer, Timeout());
                var down = clock.Elapsed;
                Console.WriteLine($"{tree.Count} files, 25 ms each way, MaxConcurrentFiles={files}: upload {up.TotalSeconds:F2} s, download {down.TotalSeconds:F2} s");
            }
        }
        finally
        {
            local.Delete(recursive: true);
            await using var direct = await SshClient.ConnectAsync(endpoint.Host, endpoint.Port, options, Timeout());
            await using var cleanup = await direct.OpenSftpAsync(Timeout());
            await DeleteTreeAsync(cleanup, remote);
        }
    }

    [Test]
    public async Task AStream_WritesBehind_AndReadsBackWhatItWrote()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options || !RealServer.HasSftp)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key, and a server with SFTP, are needed.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var root = RealServer.SftpPath(".sshsharp-writebehind-" + Guid.NewGuid().ToString("N")[..12]);
        await sftp.CreateDirectoryAsync(root, cancellationToken: Timeout());
        try
        {
            // Copied in, with many writes in flight; then flushed, which waits for them all.
            var data = RandomNumberGenerator.GetBytes(3 * 1024 * 1024 + 17);
            await using (var stream = await sftp.OpenWriteAsync(root + "/copied", Timeout()))
            {
                await new PlainStream(data).CopyToAsync(stream, Timeout());
                await stream.FlushAsync(Timeout());
            }

            var back = new MemoryStream();
            await sftp.DownloadAsync(root + "/copied", back, cancellationToken: Timeout());
            await Assert.That(back.ToArray().AsSpan().SequenceEqual(data)).IsTrue();

            // Back over bytes that may still be in flight, then read: the read sees the later write. Disposing waits for the rest.
            var expected = data[..(1024 * 1024)];
            await using (var stream = await sftp.OpenAsync(root + "/patched", FileMode.CreateNew, FileAccess.ReadWrite, Timeout()))
            {
                await stream.WriteAsync(expected, Timeout());
                var patch = RandomNumberGenerator.GetBytes(100_000);
                stream.Position = 5000;
                await stream.WriteAsync(patch, Timeout());
                patch.CopyTo(expected, 5000);
                stream.Position = 0;
                var read = new byte[expected.Length];
                await stream.ReadExactlyAsync(read, Timeout());
                await Assert.That(read.AsSpan().SequenceEqual(expected)).IsTrue();
                stream.Position = expected.Length;
                await stream.WriteAsync(data.AsMemory(0, 300_000), Timeout());
            }

            await Assert.That((await sftp.GetAttributesAsync(root + "/patched", cancellationToken: Timeout())).Size).IsEqualTo(expected.Length + 300_000L);
        }
        finally
        {
            await DeleteTreeAsync(sftp, root);
        }
    }

    [Test]
    public async Task AStreamCopy_Measure()
    {
        // A measurement, not a check: with SSHSHARP_MEASURE=1, prints how long 64 MiB takes copied into OpenWriteAsync and with
        // UploadAsync, the best of three each. Nothing here asserts a time. (FaultyProxy delays each chunk in turn, which caps the
        // throughput of anything pipelined, so this runs directly; SftpWriteBehindTests has the same measurement over latency.)
        if (Environment.GetEnvironmentVariable("SSHSHARP_MEASURE") != "1")
        {
            Skip.Test("Set SSHSHARP_MEASURE=1 to measure.");
            return;
        }

        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options || !RealServer.HasSftp)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key, and a server with SFTP, are needed.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var root = RealServer.SftpPath(".sshsharp-streammeasure-" + Guid.NewGuid().ToString("N")[..12]);
        await sftp.CreateDirectoryAsync(root, cancellationToken: Timeout());
        try
        {
            var data = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);
            TimeSpan upload = TimeSpan.MaxValue, copy = TimeSpan.MaxValue;
            for (var run = 0; run < 3; run++)
            {
                var clock = System.Diagnostics.Stopwatch.StartNew();
                await sftp.UploadAsync(new MemoryStream(data), root + "/uploaded", cancellationToken: Timeout());
                upload = TimeSpan.FromTicks(Math.Min(upload.Ticks, clock.Elapsed.Ticks));

                clock.Restart();
                await using (var stream = await sftp.OpenWriteAsync(root + "/copied", Timeout()))
                {
                    await new PlainStream(data).CopyToAsync(stream, Timeout());
                }

                copy = TimeSpan.FromTicks(Math.Min(copy.Ticks, clock.Elapsed.Ticks));
            }

            Console.WriteLine($"64 MiB: UploadAsync {upload.TotalSeconds:F2} s, CopyToAsync into OpenWriteAsync {copy.TotalSeconds:F2} s");
        }
        finally
        {
            await DeleteTreeAsync(sftp, root);
        }
    }

    /// <summary>A tree of 60 small files and one larger one, six directories deep and wide; the relative paths and contents.</summary>
    private static Dictionary<string, byte[]> WriteTree(string root)
    {
        var tree = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        string[] directories = ["a", Path.Combine("a", "b"), Path.Combine("a", "b", "c"), "d", Path.Combine("d", "e"), "empty"];
        foreach (var directory in directories)
        {
            Directory.CreateDirectory(Path.Combine(root, directory));
        }

        for (var i = 0; i < 60; i++)
        {
            var path = Path.Combine(directories[i % 5], $"f{i:D2}.txt");
            tree[path] = RandomNumberGenerator.GetBytes(100 + i * 37);
        }

        tree["big.bin"] = RandomNumberGenerator.GetBytes(700_000);
        foreach (var (path, data) in tree)
        {
            File.WriteAllBytes(Path.Combine(root, path), data);
        }

        return tree;
    }

    [Test]
    public async Task TheFileSystemAbstraction_WorksAgainstARealServer()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var fs = new SshSharp.IO.Abstractions.SftpFileSystem(sftp);
        var root = RealServer.SftpPath(".sshsharp-iofs-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            fs.Directory.CreateDirectory(fs.Path.Combine(root, "a", "b"));
            fs.File.WriteAllText(fs.Path.Combine(root, "a", "note.txt"), "über");
            using (var writer = fs.File.CreateText(fs.Path.Combine(root, "a", "b", "log.txt")))
            {
                for (var i = 0; i < 500; i++)
                {
                    writer.WriteLine($"entry {i}");
                }
            }

            await Assert.That(fs.File.ReadAllText(fs.Path.Combine(root, "a", "note.txt"))).IsEqualTo("über");
            await Assert.That(fs.File.ReadAllLines(fs.Path.Combine(root, "a", "b", "log.txt")).Length).IsEqualTo(500);
            await Assert.That(fs.Directory.GetFiles(root, "*.txt", SearchOption.AllDirectories).Length).IsEqualTo(2);
            await Assert.That(fs.FileInfo.New(fs.Path.Combine(root, "a", "note.txt")).Length).IsEqualTo(5L);

            fs.File.Copy(fs.Path.Combine(root, "a", "note.txt"), fs.Path.Combine(root, "copy.txt"));
            fs.File.Move(fs.Path.Combine(root, "copy.txt"), fs.Path.Combine(root, "moved.txt"));
            await Assert.That(fs.File.Exists(fs.Path.Combine(root, "moved.txt"))).IsTrue();
            await Assert.That(() => fs.File.ReadAllText(fs.Path.Combine(root, "missing.txt"))).Throws<FileNotFoundException>();
        }
        finally
        {
            if (fs.Directory.Exists(root))
            {
                fs.Directory.Delete(root, recursive: true);
            }
        }

        await Assert.That(fs.Directory.Exists(root)).IsFalse();
    }

    private static async Task DeleteTreeAsync(SftpClient sftp, string path)
    {
        if (!await sftp.ExistsAsync(path, Timeout()))
        {
            return;
        }

        await foreach (var entry in sftp.ListDirectoryAsync(path, Timeout()))
        {
            if (entry.Attributes.IsDirectory)
            {
                await DeleteTreeAsync(sftp, entry.FullPath);
            }
            else
            {
                await sftp.DeleteFileAsync(entry.FullPath, Timeout());
            }
        }

        await sftp.DeleteDirectoryAsync(path, Timeout());
    }

    [Test]
    public async Task FilesDirectoriesAndLinks_RoundTripOnARealServer()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        await Assert.That(sftp.ProtocolVersion).IsEqualTo(3);

        var root = RealServer.SftpPath(".sshsharp-sftp-" + Guid.NewGuid().ToString("N")[..12]);
        await sftp.CreateDirectoryAsync(root, cancellationToken: Timeout());
        try
        {
            // OpenSSH's path and owner extensions, where the server has them: ~ is the home directory, ~/x resolves under it, and the
            // owner of a new file has a name, except on a chrooted SFTP-only server, which has no user database to name it from (the
            // name is then left out).
            if (sftp.Extensions.ContainsKey("expand-path@openssh.com"))
            {
                var home = await sftp.ExpandPathAsync("~", Timeout());
                await Assert.That(await sftp.ExpandPathAsync("~/" + root, Timeout())).IsEqualTo(home.TrimEnd('/') + "/" + root);
            }

            if (sftp.Extensions.ContainsKey("users-groups-by-id@openssh.com")
                && await sftp.GetAttributesAsync(root, cancellationToken: Timeout()) is { UserId: { } uid, GroupId: { } gid })
            {
                var (users, groups) = await sftp.GetOwnerNamesAsync([uid], [gid], Timeout());
                if (!RealServer.SftpOnly)
                {
                    await Assert.That(users[uid]).IsNotEmpty();
                    await Assert.That(groups[gid]).IsNotEmpty();
                }
            }

            // A few MiB both ways, pipelined; the bytes must come back identical.
            var data = RandomNumberGenerator.GetBytes(3 * 1024 * 1024 + 17);
            var uploaded = await sftp.UploadAsync(new MemoryStream(data), root + "/blob", cancellationToken: Timeout());
            await Assert.That(uploaded).IsEqualTo((long)data.Length);
            var copy = new MemoryStream();
            await sftp.DownloadAsync(root + "/blob", copy, cancellationToken: Timeout());
            await Assert.That(copy.ToArray().AsSpan().SequenceEqual(data)).IsTrue();

            var attributes = await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout());
            await Assert.That(attributes.IsRegularFile).IsTrue();
            await Assert.That(attributes.Size).IsEqualTo((long)data.Length);

            // A stream: write, seek, read back, truncate.
            await using (var stream = await sftp.OpenAsync(root + "/text", FileMode.CreateNew, FileAccess.ReadWrite, Timeout()))
            {
                await stream.WriteAsync("hello sftp"u8.ToArray(), Timeout());
                stream.Seek(6, SeekOrigin.Begin);
                var word = new byte[4];
                await stream.ReadExactlyAsync(word, Timeout());
                await Assert.That(System.Text.Encoding.ASCII.GetString(word)).IsEqualTo("sftp");
                stream.SetLength(5);
            }

            if (!RealServer.IsErlang)
            {
                // Erlang/OTP's ssh_sftpd applies SETSTAT and FSETSTAT through file:write_file_info, which ignores the size, and still
                // answers OK: the file keeps its length there.
                await Assert.That((await sftp.GetAttributesAsync(root + "/text", cancellationToken: Timeout())).Size).IsEqualTo(5L);
            }

            // Renames, links, times, permissions.
            await sftp.RenameAsync(root + "/text", root + "/renamed", cancellationToken: Timeout());
            if (sftp.Extensions.ContainsKey("posix-rename@openssh.com"))
            {
                await sftp.RenameAsync(root + "/renamed", root + "/blob", overwrite: true, Timeout());
                await Assert.That((await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout())).Size).IsEqualTo(5L);
            }

            if (!RealServer.IsWindows)
            {
                try
                {
                    await sftp.CreateSymbolicLinkAsync(root + "/link", "blob", Timeout());
                }
                catch (SftpException) when (RealServer.IsMsys)
                {
                    // An MSYS2 or Cygwin server without the privilege to create links: nothing to check here.
                }

                // The link itself, not what it points to: Go's pkg/sftp stores a relative target as a path under its working directory
                // (<root>/blob), so the link exists but leads nowhere, which a check that follows it would take for a missing link.
                SftpFileAttributes? link;
                try
                {
                    link = await sftp.GetAttributesAsync(root + "/link", followSymbolicLinks: false, Timeout());
                }
                catch (SftpException ex) when (ex.Status == SftpStatusCode.NoSuchFile)
                {
                    link = null;
                }

                if (link is null)
                {
                    // Not created (above), which only an MSYS2 or Cygwin server may do. Anywhere else the link must be there: a server that
                    // took the arguments in the other order would have created it at the target's path instead.
                    if (!RealServer.IsMsys)
                    {
                        Assert.Fail("The symbolic link is missing: the server may take SSH_FXP_SYMLINK's arguments in the other order (see "
                            + "SftpClient.TakesSymlinkInDraftOrder). For an MSYS2 or Cygwin server, set SSHSHARP_TEST_SERVER_OS=msys.");
                    }
                }
                else if (link.IsSymbolicLink)
                {
                    await Assert.That((await sftp.ReadSymbolicLinkAsync(root + "/link", Timeout())).EndsWith("blob", StringComparison.Ordinal)).IsTrue();
                    if (sftp.Extensions.ContainsKey("lsetstat@openssh.com"))
                    {
                        // The link's own times (Linux cannot change a link's permissions, so OpenSSH refuses those); the file keeps its own.
                        var linkTime = new DateTimeOffset(2001, 2, 3, 4, 5, 6, TimeSpan.Zero);
                        await sftp.SetAttributesAsync(root + "/link", new SftpFileAttributes { LastAccessTime = linkTime, LastWriteTime = linkTime },
                            followSymbolicLinks: false, Timeout());
                        await Assert.That((await sftp.GetAttributesAsync(root + "/link", followSymbolicLinks: false, Timeout())).LastWriteTime).IsEqualTo(linkTime);
                        await Assert.That((await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout())).LastWriteTime).IsNotEqualTo(linkTime);
                    }
                }
                else
                {
                    // MSYS2 and Cygwin servers on Windows make a copy instead of a link unless told otherwise (winsymlinks).
                    await Assert.That(RealServer.IsMsys).IsTrue();
                }

                await sftp.SetAttributesAsync(root + "/blob", new SftpFileAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite }, Timeout());
                if (!RealServer.IsMsys)
                {
                    // (An MSYS2 or Cygwin server on NTFS keeps the group and other bits.)
                    await Assert.That((await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout())).Permissions)
                        .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }

            var modified = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000);
            await sftp.SetAttributesAsync(root + "/blob", new SftpFileAttributes { LastWriteTime = modified }, Timeout());
            await Assert.That((await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout())).LastWriteTime).IsEqualTo(modified);

            await sftp.CreateDirectoryAsync(root + "/sub", cancellationToken: Timeout());
            var names = new List<string>();
            await foreach (var entry in sftp.ListDirectoryAsync(root, Timeout()))
            {
                names.Add(entry.Name);
            }

            await Assert.That(names).Contains("blob");
            await Assert.That(names).Contains("sub");
            await Assert.That(names).DoesNotContain(".");

            var missing = await Assert.That(async () => await sftp.GetAttributesAsync(root + "/missing", cancellationToken: Timeout())).Throws<SftpException>();
            await Assert.That(missing!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
            await Assert.That((await sftp.GetFullPathAsync(root, Timeout())).EndsWith(root, StringComparison.Ordinal)).IsTrue();
        }
        finally
        {
            await foreach (var entry in sftp.ListDirectoryAsync(root, Timeout()))
            {
                if (entry.Attributes.IsDirectory)
                {
                    await sftp.DeleteDirectoryAsync(entry.FullPath, Timeout());
                }
                else
                {
                    await sftp.DeleteFileAsync(entry.FullPath, Timeout());
                }
            }

            await sftp.DeleteDirectoryAsync(root, Timeout());
        }
    }

    [Test]
    public async Task CreateWithParents_WholeFiles_AndRecursiveDelete_WorkOnARealServer()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("This server has no sftp-server.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        sftp.OperationTimeout = TimeSpan.FromSeconds(60); // every request below goes through the timeout's path, and none should need it

        var name = ".sshsharp-conv-" + Guid.NewGuid().ToString("N")[..12];
        var root = RealServer.SftpPath(name);
        var outside = RealServer.SftpPath(name + "-outside");
        try
        {
            // mkdir -p: missing parents are created, from the first that exists (a chrooted server's top is never touched); an existing
            // directory is fine; a file in the way is not.
            await sftp.CreateDirectoryAsync(root + "/a/b/c", createParents: true, cancellationToken: Timeout());
            await sftp.CreateDirectoryAsync(root + "/a/b/c", createParents: true, cancellationToken: Timeout());
            await sftp.CreateDirectoryAsync(root + "/a", createParents: true, cancellationToken: Timeout());
            await Assert.That((await sftp.GetAttributesAsync(root + "/a/b/c", cancellationToken: Timeout())).IsDirectory).IsTrue();

            // Whole files, both ways.
            await sftp.WriteAllTextAsync(root + "/a/b/c/note.txt", "héllo, server", cancellationToken: Timeout());
            await Assert.That(await sftp.ReadAllTextAsync(root + "/a/b/c/note.txt", cancellationToken: Timeout())).IsEqualTo("héllo, server");
            var data = RandomNumberGenerator.GetBytes(300_000);
            await sftp.WriteAllBytesAsync(root + "/a/blob", data, Timeout());
            await Assert.That((await sftp.ReadAllBytesAsync(root + "/a/blob", Timeout())).AsSpan().SequenceEqual(data)).IsTrue();
            await sftp.WriteAllBytesAsync(root + "/a/blob", "short"u8.ToArray(), Timeout());
            await Assert.That(await sftp.ReadAllTextAsync(root + "/a/blob", cancellationToken: Timeout())).IsEqualTo("short");

            await Assert.That(async () => await sftp.CreateDirectoryAsync(root + "/a/blob/x", createParents: true, cancellationToken: Timeout()))
                .Throws<SftpException>();

            // A wider tree to delete: several directories, each with files.
            for (var d = 0; d < 4; d++)
            {
                await sftp.CreateDirectoryAsync($"{root}/a/d{d}/inner", createParents: true, cancellationToken: Timeout());
                for (var f = 0; f < 8; f++)
                {
                    await sftp.WriteAllBytesAsync($"{root}/a/d{d}/inner/f{f}", new[] { (byte)f }, Timeout());
                }
            }

            // A link out of the tree: the delete removes the link, never what it points to.
            var linked = false;
            if (!RealServer.IsWindows)
            {
                await sftp.CreateDirectoryAsync(outside, cancellationToken: Timeout());
                await sftp.WriteAllTextAsync(outside + "/keep", "keep", cancellationToken: Timeout());
                try
                {
                    // Relative, so it resolves the same on servers that store a relative target under their working directory.
                    await sftp.CreateSymbolicLinkAsync(root + "/a/to-outside", "../../" + name + "-outside", Timeout());
                    linked = true;
                }
                catch (SftpException) when (RealServer.IsMsys)
                {
                    // An MSYS2 or Cygwin server without the privilege to create links.
                }
            }

            await sftp.DeleteDirectoryAsync(root, recursive: true, Timeout());

            await Assert.That(await sftp.ExistsAsync(root, Timeout())).IsFalse();
            if (linked)
            {
                await Assert.That(await sftp.ReadAllTextAsync(outside + "/keep", cancellationToken: Timeout())).IsEqualTo("keep");
            }
        }
        finally
        {
            foreach (var path in new[] { root, outside })
            {
                try
                {
                    await sftp.DeleteDirectoryAsync(path, recursive: true, Timeout());
                }
                catch (SftpException)
                {
                    // Not there (deleted above, or never created).
                }
            }
        }
    }

    [Test]
    public async Task ASegmentedDownload_FetchesTheFileOverSeveralSessions()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("This server has no sftp-server.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-segments-");
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = RealServer.SftpPath(".sshsharp-segments-" + Guid.NewGuid().ToString("N")[..12]);
        try
        {
            // Six MiB in four ranges, each fetched over its own session (sshd allows ten per connection by default).
            var data = RandomNumberGenerator.GetBytes((6 * 1024 * 1024) + 4321);
            await using (var source = new MemoryStream(data))
            {
                await sftp.UploadAsync(source, remote, cancellationToken: Timeout());
            }

            var copy = Path.Combine(local.FullName, "copy.bin");
            long reported = 0;
            var progress = new SynchronousProgress(value => reported = value);
            var total = await sftp.DownloadFileAsync(remote, copy, new SftpTransferOptions { Segments = 4, Progress = progress }, Timeout());

            await Assert.That(total).IsEqualTo(data.Length);
            await Assert.That(reported).IsEqualTo(data.Length);
            await Assert.That((await File.ReadAllBytesAsync(copy)).AsSpan().SequenceEqual(data)).IsTrue();
        }
        finally
        {
            try
            {
                await sftp.DeleteFileAsync(remote, Timeout());
            }
            catch (SftpException)
            {
                // Not created.
            }

            local.Delete(recursive: true);
        }
    }

    [Test]
    public async Task PipelinedPatternAndRecursiveListings_AndFilteredTransfers_WorkOnARealServer()
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync() is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return;
        }

        if (!RealServer.HasSftp)
        {
            Skip.Test("This server has no sftp-server.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-listing-");
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var name = ".sshsharp-list-" + Guid.NewGuid().ToString("N")[..12];
        var root = RealServer.SftpPath(name);
        var outside = RealServer.SftpPath(name + "-outside");
        try
        {
            // 300 names in one directory: several READDIR batches on every server (OpenSSH sends at most 100 a batch), pipelined.
            await sftp.CreateDirectoryAsync(root + "/many", createParents: true, cancellationToken: Timeout());
            for (var i = 0; i < 300; i++)
            {
                await sftp.WriteAllBytesAsync($"{root}/many/f{i:D3}.{(i % 3 == 0 ? "log" : "txt")}", new[] { (byte)i }, Timeout());
            }

            await sftp.CreateDirectoryAsync(root + "/a/b", createParents: true, cancellationToken: Timeout());
            await sftp.WriteAllTextAsync(root + "/a/top.log", "top", cancellationToken: Timeout());
            await sftp.WriteAllTextAsync(root + "/a/b/deep.log", "deep", cancellationToken: Timeout());
            await sftp.WriteAllTextAsync(root + "/a/b/skip.tmp", "tmp", cancellationToken: Timeout());

            var all = new List<string>();
            await foreach (var entry in sftp.ListDirectoryAsync(root + "/many", Timeout()))
            {
                all.Add(entry.Name);
            }

            // The server's order is its own; every name once.
            await Assert.That(all.Order(StringComparer.Ordinal)).IsEquivalentTo(Enumerable.Range(0, 300).Select(i => $"f{i:D3}.{(i % 3 == 0 ? "log" : "txt")}"));

            var logs = new List<string>();
            await foreach (var entry in sftp.ListDirectoryAsync(root, new SftpListOptions { Pattern = "*.log", Recursive = true }, Timeout()))
            {
                logs.Add(entry.FullPath[(root.Length + 1)..]);
            }

            await Assert.That(logs.Count).IsEqualTo(102);
            await Assert.That(logs).Contains("a/top.log");
            await Assert.That(logs).Contains("a/b/deep.log");
            await Assert.That(logs.IndexOf("a/top.log")).IsLessThan(logs.IndexOf("a/b/deep.log")); // depth first, a's entries before b's

            // A link to a directory outside the tree: listed, and entered only when links are followed.
            if (!RealServer.IsWindows)
            {
                await sftp.CreateDirectoryAsync(outside, cancellationToken: Timeout());
                await sftp.WriteAllTextAsync(outside + "/linked.log", "linked", cancellationToken: Timeout());
                var linked = false;
                try
                {
                    // Relative, so it resolves the same on servers that store a relative target under their working directory.
                    await sftp.CreateSymbolicLinkAsync(root + "/a/out", "../../" + name + "-outside", Timeout());
                    linked = true;
                }
                catch (SftpException) when (RealServer.IsMsys)
                {
                    // An MSYS2 or Cygwin server without the privilege to create links.
                }

                // Only a real link that leads to the directory: Go's pkg/sftp stores a relative target under its working directory (the
                // link leads nowhere), and MSYS2 or Cygwin may make a copy instead.
                if (linked
                    && (await sftp.GetAttributesAsync(root + "/a/out", followSymbolicLinks: false, Timeout())).IsSymbolicLink
                    && await sftp.ExistsAsync(root + "/a/out/linked.log", Timeout()))
                {
                    var plain = new List<string>();
                    await foreach (var entry in sftp.ListDirectoryAsync(root + "/a", new SftpListOptions { Recursive = true }, Timeout()))
                    {
                        plain.Add(entry.Name);
                    }

                    var followed = new List<string>();
                    await foreach (var entry in sftp.ListDirectoryAsync(root + "/a", new SftpListOptions { Recursive = true, FollowSymbolicLinks = true, MaxDepth = 4 }, Timeout()))
                    {
                        followed.Add(entry.Name);
                    }

                    await Assert.That(plain).Contains("out");
                    await Assert.That(plain).DoesNotContain("linked.log");
                    await Assert.That(followed).Contains("linked.log");
                }
            }

            // A download that leaves out *.tmp, then again with SkipUnchanged: the files kept their times (Preserve), so none moves.
            var down = Path.Combine(local.FullName, "down");
            var keepLogs = new SftpTransferOptions { Preserve = true, Filter = e => !e.Name.EndsWith(".tmp", StringComparison.Ordinal) && e.Name != "out", MaxConcurrentFiles = 4 };
            var first = await sftp.DownloadDirectoryAsync(root + "/a", down, keepLogs, Timeout());
            await Assert.That(first.Files).IsEqualTo(2);
            await Assert.That(File.Exists(Path.Combine(down, "b", "skip.tmp"))).IsFalse();

            var again = await sftp.DownloadDirectoryAsync(root + "/a", down, new SftpTransferOptions
            {
                Preserve = true,
                SkipUnchanged = true,
                Filter = keepLogs.Filter,
            }, Timeout());
            await Assert.That(again.Files).IsEqualTo(0);
            await Assert.That(again.Unchanged).IsEqualTo(2);

            // Uploaded back with Preserve, then again with SkipUnchanged: unchanged where the server kept the times it was given.
            var up = root + "/up";
            await sftp.UploadDirectoryAsync(down, up, new SftpTransferOptions { Preserve = true }, Timeout());
            var kept = (await sftp.GetAttributesAsync(up + "/top.log", cancellationToken: Timeout())).LastWriteTime
                == DateTimeOffset.FromUnixTimeSeconds(new DateTimeOffset(File.GetLastWriteTimeUtc(Path.Combine(down, "top.log"))).ToUnixTimeSeconds());
            var reupload = await sftp.UploadDirectoryAsync(down, up, new SftpTransferOptions { Preserve = true, SkipUnchanged = true, MaxConcurrentFiles = 4 }, Timeout());
            await Assert.That(reupload.Unchanged).IsEqualTo(kept ? 2 : 0);
            await Assert.That(reupload.Files).IsEqualTo(kept ? 0 : 2);
        }
        finally
        {
            foreach (var path in new[] { root, outside })
            {
                try
                {
                    await sftp.DeleteDirectoryAsync(path, recursive: true, Timeout());
                }
                catch (SftpException)
                {
                    // Not there (never created).
                }
            }

            local.Delete(recursive: true);
        }
    }

    private sealed class SynchronousProgress(Action<long> report) : IProgress<SftpTransferProgress>
    {
        public void Report(SftpTransferProgress value) => report(value.BytesTransferred);
    }

    /// <summary>A memory stream copied the way any stream is, in many writes (<see cref="MemoryStream"/> writes itself in one call).</summary>
    private sealed class PlainStream(byte[] data) : MemoryStream(data);
}
