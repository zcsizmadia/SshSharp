using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>File hashes the server computes (<c>check-file</c>, <c>md5-hash</c>) and raw extended requests.</summary>
public sealed class SftpFileHashTests
{
    private const string Home = FakeSftpServer.Home;

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

    private static readonly byte[] Data = RandomNumberGenerator.GetBytes(300_000);

    /// <summary>A reply frame to <paramref name="request"/> (the raw request packet, type first), written by <paramref name="body"/> after the id.</summary>
    private static byte[] ReplyTo(byte[] request, byte type, Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteByte(type);
        w.WriteUInt32(BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(1)));
        body(w);
        var frame = new byte[4 + buffer.WrittenCount];
        BinaryPrimitives.WriteInt32BigEndian(frame, buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(frame.AsSpan(4));
        return frame;
    }

    /// <summary>Whether a raw request packet is the extended request <paramref name="name"/>.</summary>
    private static bool IsExtended(byte[] packet, string name)
    {
        if (packet[0] != 200)
        {
            return false;
        }

        var reader = new SshReader(packet.AsSpan(5));
        return reader.ReadUtf8String() == name;
    }

    [Test]
    public async Task CheckFile_HashesTheWholeFile_WithSha256ByDefault()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "md5,sha1,sha256,sha384,sha512";
        });

        await Assert.That(rig.Sftp.SupportsFileHash).IsTrue();
        var hash = await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout());

        await Assert.That(hash.Algorithm).IsEqualTo("sha256");
        await Assert.That(hash.Matches(SHA256.HashData(Data))).IsTrue();
        await Assert.That(hash.Matches(SHA256.HashData(Data.AsSpan(1)))).IsFalse();
        await Assert.That(rig.Files.HashRequests.Single()).IsEqualTo(("check-file-name", Home + "/data.bin", "sha256,sha512,sha384,sha224", 0L, 0L));
    }

    [Test]
    public async Task CheckFile_HashesARange_WithTheFirstAlgorithmTheServerHas()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "1"; // no list: the server is asked and picks
            f.HashAlgorithms.Remove("sha256");
        });

        var hash = await rig.Sftp.GetFileHashAsync("data.bin", ["sha256", "sha512", "md5"], offset: 1000, length: 50_000, Timeout());

        await Assert.That(hash.Algorithm).IsEqualTo("sha512");
        await Assert.That(hash.Hash.ToArray().SequenceEqual(SHA512.HashData(Data.AsSpan(1000, 50_000)))).IsTrue();
        await Assert.That(rig.Files.HashRequests.Single()).IsEqualTo(("check-file-name", Home + "/data.bin", "sha256,sha512,md5", 1000L, 50_000L));
    }

    [Test]
    public async Task LegacyAlgorithms_AreUsedOnlyWhenAskedFor()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "md5,sha1";
        });

        // SHA-2 only by default: the server lists none of them, so nothing is sent.
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<NotSupportedException>();
        await Assert.That(rig.Files.HashRequests).IsEmpty();

#pragma warning disable CA5350, CA5351 // checking an interop hash the test asked for, not security
        var md5 = await rig.Sftp.GetFileHashAsync("data.bin", ["md5"], cancellationToken: Timeout());
        await Assert.That(md5.Algorithm).IsEqualTo("md5");
        await Assert.That(md5.Matches(MD5.HashData(Data))).IsTrue();

        var sha1 = await rig.Sftp.GetFileHashAsync("data.bin", ["sha1"], cancellationToken: Timeout());
        await Assert.That(sha1.Matches(SHA1.HashData(Data))).IsTrue();
#pragma warning restore CA5350, CA5351
    }

    [Test]
    public async Task AServerWithOnlyTheHandleRequest_IsAskedWithAHandle_ThatIsClosed()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file-handle"] = "sha256,sha512";
        });

        var hash = await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout());

        await Assert.That(hash.Matches(SHA256.HashData(Data))).IsTrue();
        await Assert.That(rig.Files.HashRequests.Single().Request).IsEqualTo("check-file-handle");
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task APlainCheckFile_ThatDoesNotTakePaths_IsAskedAgainWithAHandle()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "sha256";
            f.UnsupportedRequests.Add("check-file-name");
        });

        var hash = await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout());

        await Assert.That(hash.Matches(SHA256.HashData(Data))).IsTrue();
        await Assert.That(rig.Files.HashRequests.Single().Request).IsEqualTo("check-file-handle");
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task AServerThatAnnouncesCheckFileName_AndRefusesIt_ReportsTheRefusal()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file-name"] = "sha256";
            f.UnsupportedRequests.Add("check-file-name");
        });

        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<SftpException>();

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.OperationUnsupported);
        await Assert.That(error.Path).IsEqualTo("data.bin");
    }

    [Test]
    public async Task AMissingFile_IsNoSuchFile()
    {
        await using var rig = await Rig.StartAsync(f => f.Extensions["check-file"] = "sha256");

        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("missing.bin", cancellationToken: Timeout())).Throws<SftpException>();

        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.NoSuchFile);
    }

    [Test]
    public async Task WithoutAHashExtension_ItIsNotSupported()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/data.bin", Data));

        await Assert.That(rig.Sftp.SupportsFileHash).IsFalse();
        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<NotSupportedException>();

        await Assert.That(error!.Message).Contains("check-file");
        await Assert.That(rig.Files.HashRequests).IsEmpty();
    }

    [Test]
    public async Task Md5Hash_IsUsedWhenMd5IsAskedFor_ByPathOrHandle()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["md5-hash"] = "1";
        });

        await Assert.That(rig.Sftp.SupportsFileHash).IsTrue();
        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<NotSupportedException>();
        await Assert.That(error!.Message).Contains("md5");

#pragma warning disable CA5351 // checking an interop hash the test asked for, not security
        var hash = await rig.Sftp.GetFileHashAsync("data.bin", ["sha256", "md5"], offset: 10, length: 100, Timeout());
        await Assert.That(hash.Algorithm).IsEqualTo("md5");
        await Assert.That(hash.Matches(MD5.HashData(Data.AsSpan(10, 100)))).IsTrue();
        await Assert.That(rig.Files.HashRequests.Single()).IsEqualTo(("md5-hash", Home + "/data.bin", "md5", 10L, 100L));

        rig.Files.HashRequests.Clear();
        rig.Files.Extensions.Remove("md5-hash");
        rig.Files.Extensions["md5-hash-handle"] = "1";
        await using var other = await rig.Client.OpenSftpAsync(Timeout());
        var byHandle = await other.GetFileHashAsync("data.bin", ["md5"], cancellationToken: Timeout());
        await Assert.That(byHandle.Matches(MD5.HashData(Data))).IsTrue();
#pragma warning restore CA5351
        await Assert.That(rig.Files.HashRequests.Single().Request).IsEqualTo("md5-hash-handle");
        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task AReplyWithAnAlgorithmNotAskedFor_IsAProtocolError()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "sha256";
            f.RawFrame = packet => IsExtended(packet, "check-file-name")
                ? ReplyTo(packet, 201, w => { w.WriteString("check-file"); w.WriteString("md5"); w.WriteBytes(new byte[16]); })
                : null;
        });

        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<SshException>();

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task AReplyWithoutTheExtensionsName_AsProFtpdSendsIt_IsRead()
    {
        // ProFTPD's mod_sftp announces check-file with the data "1" and replies with the algorithm and the hash, leaving out the
        // "check-file" that draft-ietf-secsh-filexfer-extensions puts first.
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "1";
            f.RawFrame = packet => IsExtended(packet, "check-file-name")
                ? ReplyTo(packet, 201, w => { w.WriteString("sha256"); w.WriteBytes(SHA256.HashData(Data)); })
                : null;
        });

        var hash = await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout());

        await Assert.That(hash.Algorithm).IsEqualTo("sha256");
        await Assert.That(hash.Matches(SHA256.HashData(Data))).IsTrue();
    }

    [Test]
    public async Task AHashOfTheWrongLength_IsAProtocolError()
    {
        await using var rig = await Rig.StartAsync(f =>
        {
            f.AddFile(Home + "/data.bin", Data);
            f.Extensions["check-file"] = "sha256";
            f.RawFrame = packet => IsExtended(packet, "check-file-name")
                ? ReplyTo(packet, 201, w => { w.WriteString("check-file"); w.WriteString("sha256"); w.WriteBytes(new byte[31]); })
                : null;
        });

        var error = await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", cancellationToken: Timeout())).Throws<SshException>();

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task BadArguments_AreRejectedBeforeAnythingIsSent()
    {
        await using var rig = await Rig.StartAsync(f => f.Extensions["check-file"] = "sha256");

        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", [], cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", ["SHA256"], cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", ["sha256,md5"], cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", offset: -1, cancellationToken: Timeout())).Throws<ArgumentOutOfRangeException>();
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("data.bin", length: 0, cancellationToken: Timeout())).Throws<ArgumentOutOfRangeException>();
        await Assert.That(async () => await rig.Sftp.GetFileHashAsync("", cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(rig.Files.HashRequests).IsEmpty();
    }

    // ---- raw extended requests ----

    [Test]
    public async Task AVendorExtension_GetsItsPayload_AndItsReplyComesBackAsItIs()
    {
        await using var rig = await Rig.StartAsync();
        byte[] payload = [0, 0, 0, 3, (byte)'a', (byte)'b', (byte)'c', 42];

        var reply = await rig.Sftp.SendExtendedRequestAsync("echo@example.com", payload, Timeout());

        await Assert.That(reply.IsExtendedReply).IsTrue();
        await Assert.That(reply.PacketType).IsEqualTo((byte)201);
        await Assert.That(reply.Status).IsNull();
        await Assert.That(reply.StatusMessage).IsNull();
        await Assert.That(reply.Data.ToArray().SequenceEqual(payload)).IsTrue();
        await Assert.That(reply.EnsureSuccess()).IsSameReferenceAs(reply);
        await Assert.That(rig.Files.Echoes.Single().SequenceEqual(payload)).IsTrue();
    }

    [Test]
    public async Task AnUnknownExtension_IsAnUnsupportedStatus_ThatEnsureSuccessThrows()
    {
        await using var rig = await Rig.StartAsync();

        var reply = await rig.Sftp.SendExtendedRequestAsync("unknown@example.com", cancellationToken: Timeout());

        await Assert.That(reply.IsExtendedReply).IsFalse();
        await Assert.That(reply.PacketType).IsEqualTo((byte)101);
        await Assert.That(reply.Status).IsEqualTo(SftpStatusCode.OperationUnsupported);
        await Assert.That(reply.StatusMessage).IsEqualTo("Unsupported");
        var error = await Assert.That(() => reply.EnsureSuccess()).Throws<SftpException>();
        await Assert.That(error!.Status).IsEqualTo(SftpStatusCode.OperationUnsupported);
        await Assert.That(error.Message).Contains("unknown@example.com");
    }

    [Test]
    public async Task KnownExtensions_AnswerThroughTheRawRequestToo()
    {
        await using var rig = await Rig.StartAsync(f => f.AddFile(Home + "/a.txt", [1]));

        // statvfs@openssh.com: an EXTENDED_REPLY of eleven uint64 values.
        var space = await rig.Sftp.SendExtendedRequestAsync("statvfs@openssh.com", SshString("."), Timeout());
        await Assert.That(space.IsExtendedReply).IsTrue();
        await Assert.That(space.Data.Length).IsEqualTo(88);
        await Assert.That(BinaryPrimitives.ReadUInt64BigEndian(space.Data.Span)).IsEqualTo(4096UL);

        // posix-rename@openssh.com: a status of OK.
        var renamed = await rig.Sftp.SendExtendedRequestAsync("posix-rename@openssh.com", SshString("a.txt").Concat(SshString("b.txt")).ToArray(), Timeout());
        await Assert.That(renamed.Status).IsEqualTo(SftpStatusCode.Ok);
        renamed.EnsureSuccess();
        await Assert.That(rig.Files.Exists(Home + "/b.txt")).IsTrue();

        // expand-path@openssh.com: a NAME reply.
        var expanded = await rig.Sftp.SendExtendedRequestAsync("expand-path@openssh.com", SshString("~"), Timeout());
        await Assert.That(expanded.PacketType).IsEqualTo((byte)104);
        await Assert.That(expanded.Status).IsNull();
    }

    [Test]
    public async Task AStatusMessage_IsSanitized()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = packet => IsExtended(packet, "noisy@example.com")
            ? ReplyTo(packet, 101, w => { w.WriteUInt32(4); w.WriteString("disk\r\nfull\u001b[31m" + new string('x', 300)); w.WriteString("en"); })
            : null);

        var reply = await rig.Sftp.SendExtendedRequestAsync("noisy@example.com", cancellationToken: Timeout());

        await Assert.That(reply.Status).IsEqualTo(SftpStatusCode.Failure);
        await Assert.That(reply.StatusMessage!.Any(char.IsControl)).IsFalse();
        await Assert.That(reply.StatusMessage!.Length).IsLessThanOrEqualTo(200);
        await Assert.That(reply.StatusMessage).StartsWith("diskfull[31m");
    }

    [Test]
    public async Task AMalformedStatus_IsAProtocolError()
    {
        await using var rig = await Rig.StartAsync(f => f.RawFrame = packet => IsExtended(packet, "broken@example.com")
            ? ReplyTo(packet, 101, w => w.WriteByte(0))
            : null);

        var error = await Assert.That(async () => await rig.Sftp.SendExtendedRequestAsync("broken@example.com", cancellationToken: Timeout())).Throws<SshException>();

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task BadRawRequests_AreRejectedBeforeAnythingIsSent()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(async () => await rig.Sftp.SendExtendedRequestAsync("", cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.SendExtendedRequestAsync("a\0b", cancellationToken: Timeout())).Throws<ArgumentException>();
        await Assert.That(async () => await rig.Sftp.SendExtendedRequestAsync("echo@example.com", new byte[(255 * 1024) + 1], Timeout()))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(rig.Files.Echoes).IsEmpty();

        // The largest payload goes.
        var reply = await rig.Sftp.SendExtendedRequestAsync("echo@example.com", new byte[255 * 1024], Timeout());
        await Assert.That(reply.Data.Length).IsEqualTo(255 * 1024);
    }

    private static byte[] SshString(string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        var result = new byte[4 + bytes.Length];
        BinaryPrimitives.WriteInt32BigEndian(result, bytes.Length);
        bytes.CopyTo(result, 4);
        return result;
    }
}
