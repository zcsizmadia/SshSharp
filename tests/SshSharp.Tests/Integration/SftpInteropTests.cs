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

    private sealed class SynchronousProgress(Action<long> report) : IProgress<SftpTransferProgress>
    {
        public void Report(SftpTransferProgress value) => report(value.BytesTransferred);
    }
}
