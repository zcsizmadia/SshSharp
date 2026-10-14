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

        if (!RealServer.IsOpenSsh)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        var local = Directory.CreateTempSubdirectory("sshsharp-sftptree-");
        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = ".sshsharp-sftptree-" + Guid.NewGuid().ToString("N")[..12];
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
                var space = await sftp.GetFileSystemInfoAsync(remote, Timeout());
                await Assert.That(space.TotalBytes).IsGreaterThan(0L);
                await Assert.That(space.AvailableBytes).IsLessThanOrEqualTo(space.TotalBytes);
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

        if (!RealServer.IsOpenSsh)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        await using var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        await using var sftp = await client.OpenSftpAsync(Timeout());
        await Assert.That(sftp.ProtocolVersion).IsEqualTo(3);

        var root = ".sshsharp-sftp-" + Guid.NewGuid().ToString("N")[..12];
        await sftp.CreateDirectoryAsync(root, cancellationToken: Timeout());
        try
        {
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

            await Assert.That((await sftp.GetAttributesAsync(root + "/text", cancellationToken: Timeout())).Size).IsEqualTo(5L);

            // Renames, links, times, permissions.
            await sftp.RenameAsync(root + "/text", root + "/renamed", cancellationToken: Timeout());
            if (sftp.Extensions.ContainsKey("posix-rename@openssh.com"))
            {
                await sftp.RenameAsync(root + "/renamed", root + "/blob", overwrite: true, Timeout());
                await Assert.That((await sftp.GetAttributesAsync(root + "/blob", cancellationToken: Timeout())).Size).IsEqualTo(5L);
            }

            if (!RealServer.IsWindows)
            {
                await sftp.CreateSymbolicLinkAsync(root + "/link", "blob", Timeout());

                // MSYS2 and Cygwin servers on Windows make a copy instead of a link unless told otherwise (winsymlinks); a real one is checked.
                if ((await sftp.GetAttributesAsync(root + "/link", followSymbolicLinks: false, Timeout())).IsSymbolicLink)
                {
                    await Assert.That(await sftp.ReadSymbolicLinkAsync(root + "/link", Timeout())).IsEqualTo("blob");
                }
                else
                {
                    await Assert.That(OperatingSystem.IsWindows()).IsTrue(); // only expected from a server on this machine's Windows
                }
                await sftp.SetAttributesAsync(root + "/blob", new SftpFileAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite }, Timeout());
                if (!OperatingSystem.IsWindows())
                {
                    // (An MSYS2 server on this machine's NTFS keeps the group and other bits.)
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
}
