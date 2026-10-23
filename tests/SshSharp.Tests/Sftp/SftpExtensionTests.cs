using System.Security.Cryptography;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>The OpenSSH SFTP extensions beyond the basics: statvfs, fsync, copy-data (#7).</summary>
public class SftpExtensionTests
{
    private const string Home = FakeSftpServer.Home;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<(FakeSessionServer Ssh, SshClient Client, SftpClient Sftp)> StartAsync(FakeSftpServer files)
    {
        var ssh = new FakeSessionServer();
        files.Install(ssh);
        _ = ssh.StartAsync();
        var client = await SshClient.ConnectAsync(ssh.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
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

    [Test]
    public async Task FileSystemInfo_ReportsSpaceInBytes()
    {
        var rig = await StartAsync(new FakeSftpServer());
        try
        {
            var info = await rig.Sftp.GetFileSystemInfoAsync(".", Timeout());

            await Assert.That(info).IsEqualTo(new SftpFileSystemInfo(1000 * 4096L, 400 * 4096L, 300 * 4096L, 5000, 2000, 1500, IsReadOnly: true, MaxNameLength: 255));
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task CopyFile_CopiesOnTheServer_AndRespectsOverwrite()
    {
        var data = RandomNumberGenerator.GetBytes(50_000);
        var files = new FakeSftpServer();
        files.AddFile(Home + "/original", data);
        files.AddFile(Home + "/taken", [1]);
        var rig = await StartAsync(files);
        try
        {
            await rig.Sftp.CopyFileAsync("original", "copy", cancellationToken: Timeout());
            await Assert.That(files.FileData(Home + "/copy").AsSpan().SequenceEqual(data)).IsTrue();
            await Assert.That(files.Requests.Count(t => t is 5 or 6)).IsEqualTo(0); // no reads or writes: the data stayed on the server

            await Assert.That(async () => await rig.Sftp.CopyFileAsync("original", "taken", cancellationToken: Timeout())).Throws<SftpException>();
            await rig.Sftp.CopyFileAsync("original", "taken", overwrite: true, Timeout());
            await Assert.That(files.FileData(Home + "/taken").AsSpan().SequenceEqual(data)).IsTrue();
            await Assert.That(files.OpenHandles).IsEqualTo(0);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task FlushingAWritableStream_AsksTheServerToSync()
    {
        var files = new FakeSftpServer();
        var rig = await StartAsync(files);
        try
        {
            await using (var stream = await rig.Sftp.OpenWriteAsync("synced", Timeout()))
            {
                await stream.WriteAsync(new byte[10], Timeout());
                await stream.FlushAsync(Timeout());
            }

            await using (var reader = await rig.Sftp.OpenReadAsync("synced", Timeout()))
            {
                await reader.FlushAsync(Timeout()); // nothing to sync for a read-only stream
            }

            await Assert.That(files.Fsyncs).IsEqualTo(1);
        }
        finally
        {
            await StopAsync(rig);
        }
    }

    [Test]
    public async Task WithoutTheExtensions_TheyAreNotSupported_AndFlushIsANoOp()
    {
        var files = new FakeSftpServer();
        files.Extensions.Clear();
        files.AddFile(Home + "/a", [1]);
        var rig = await StartAsync(files);
        try
        {
            await Assert.That(async () => await rig.Sftp.GetFileSystemInfoAsync(".", Timeout())).Throws<NotSupportedException>();
            await Assert.That(async () => await rig.Sftp.CopyFileAsync("a", "b", cancellationToken: Timeout())).Throws<NotSupportedException>();
            await using var stream = await rig.Sftp.OpenWriteAsync("c", Timeout());
            await stream.FlushAsync(Timeout());
            await Assert.That(files.Fsyncs).IsEqualTo(0);
        }
        finally
        {
            await StopAsync(rig);
        }
    }
}
