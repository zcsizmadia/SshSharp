using System.Buffers;
using System.Buffers.Binary;
using SshSharp.FileProviders;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>The stream <see cref="SftpFileProvider"/> files open: every way to read it, seeking, and what a read-only provider refuses.</summary>
public class SftpFileProviderStreamTests
{
    private const string Site = FakeSftpServer.Home + "/site";
    private static readonly byte[] Data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync(Action<FakeSftpServer>? setup = null)
        {
            var rig = new Rig();
            rig.Files.AddDirectory(Site);
            rig.Files.AddFile(Site + "/f.bin", Data);
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
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    [Test]
    public async Task TheStream_ReadsEveryWay_Seeks_AndRefusesToWrite()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");

        await using (var stream = provider.GetFileInfo("f.bin").CreateReadStream())
        {
            await Assert.That(stream.CanRead).IsTrue();
            await Assert.That(stream.CanWrite).IsFalse();
            await Assert.That(stream.CanSeek).IsTrue();
            await Assert.That(stream.Length).IsEqualTo(10L);

            var first = new byte[3];
            var count = stream.Read(first.AsSpan()); // the Span overload
            await Assert.That(count).IsEqualTo(3);
            await Assert.That(first).IsEquivalentTo(new byte[] { 0, 1, 2 });

            var buffer = new byte[2];
#pragma warning disable CA1835 // the array overload is what is tested
            await Assert.That(await stream.ReadAsync(buffer, 0, 2, Timeout())).IsEqualTo(2);
#pragma warning restore CA1835
            await Assert.That(buffer).IsEquivalentTo(new byte[] { 3, 4 });
            await Assert.That(await stream.ReadAsync(buffer.AsMemory(), Timeout())).IsEqualTo(2);
            await Assert.That(buffer).IsEquivalentTo(new byte[] { 5, 6 });

            await Assert.That(stream.Seek(-2, SeekOrigin.End)).IsEqualTo(8L);
            await Assert.That(stream.ReadByte()).IsEqualTo(8);
            stream.Position = 1;
            await Assert.That(stream.Position).IsEqualTo(1L);
            await Assert.That(stream.Seek(1, SeekOrigin.Current)).IsEqualTo(2L);
            await Assert.That(stream.ReadByte()).IsEqualTo(2);

            stream.Flush(); // nothing to flush
            await Assert.That(() => stream.SetLength(0)).Throws<NotSupportedException>();
            await Assert.That(() => stream.Write([1], 0, 1)).Throws<NotSupportedException>();
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0); // closed on DisposeAsync
        await Assert.That(rig.Files.FileData(Site + "/f.bin")).IsEquivalentTo(Data);
    }

    [Test]
    public async Task AFileListedWithoutASize_HasTheLengthTheOpenStreamReports()
    {
        // The lookup's STAT carries no size (only the type and permissions); the open file's FSTAT does, so the stream still knows it.
        await using var rig = await Rig.StartAsync(f => f.RawFrame = request => request[0] is 7 or 17 && PathOf(request).EndsWith("f.bin", StringComparison.Ordinal)
            ? Reply(request, 105, w => { w.WriteUInt32(0x04); w.WriteUInt32(0x81A4); })
            : null);
        var provider = new SftpFileProvider(rig.Sftp, "site");
        var info = provider.GetFileInfo("f.bin");

        await Assert.That(info.Exists).IsTrue();
        await Assert.That(info.Length).IsEqualTo(-1L);
        using var stream = info.CreateReadStream();
        await Assert.That(stream.Length).IsEqualTo(10L);
        await Assert.That(stream.Seek(-1, SeekOrigin.End)).IsEqualTo(9L);
        await Assert.That(stream.ReadByte()).IsEqualTo(9);
    }

    [Test]
    public async Task AProviderAtTheServersRoot_MapsPathsFromThere()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "/");

        await Assert.That(provider.Root).IsEqualTo("/");
        await Assert.That(provider.GetFileInfo("home/tester/site/f.bin").Length).IsEqualTo(10L);
        await Assert.That(provider.GetFileInfo(null!).Exists).IsFalse();
        var top = provider.GetDirectoryContents("");
        await Assert.That(top.Exists).IsTrue();
        await Assert.That(top.Select(e => e.Name)).Contains("home");
        await Assert.That(new SftpFileProvider(rig.Sftp, "site/").Root).IsEqualTo("site");
    }

    private static string PathOf(byte[] request)
    {
        var reader = new SshReader(request.AsSpan(5));
        return reader.ReadUtf8String();
    }

    private static byte[] Reply(byte[] request, byte type, Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new SshWriter(buffer);
        writer.WriteByte(type);
        writer.WriteUInt32(BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(1)));
        body(writer);
        var frame = new byte[4 + buffer.WrittenCount];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(frame.AsSpan(4));
        return frame;
    }
}
