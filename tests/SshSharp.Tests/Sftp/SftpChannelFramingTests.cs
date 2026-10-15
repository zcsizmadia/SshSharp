using System.Buffers.Binary;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>How the SFTP channel reads its packets from a broken or hostile server: lengths, a session that ends early, the version reply.</summary>
public class SftpChannelFramingTests
{
    private const string Home = FakeSftpServer.Home;
    private const byte Stat = 17;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public static async Task<Rig> ConnectAsync(Action<FakeSftpServer> setup)
        {
            var rig = new Rig();
            rig.Files.AddFile(Home + "/f", [1, 2, 3]);
            setup(rig.Files);
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = "secret",
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            }, leaveOpen: true, Timeout());
            return rig;
        }

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    private static byte[] Length(uint length)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, length);
        return bytes;
    }

    /// <summary>Answers the first STAT with <paramref name="raw"/>; the request fails, and so does the session from then on.</summary>
    private static async Task<SshException> FirstStatFailsAsync(byte[] raw, bool endSession)
    {
        await using var rig = await Rig.ConnectAsync(f =>
        {
            f.RawFrame = packet => packet[0] == Stat ? raw : null;
            f.EndSessionAfterRawFrame = endSession;
        });
        await using var sftp = await rig.Client.OpenSftpAsync(Timeout());

        var error = await Assert.ThrowsAsync<SshException>(async () => await sftp.GetAttributesAsync(Home + "/f", cancellationToken: Timeout()));

        // The session is over: a later request fails at once, with the same kind of error, rather than hanging.
        var later = await Assert.ThrowsAsync<SshException>(async () => await sftp.ExistsAsync(Home + "/f", Timeout()));
        await Assert.That(later!.Reason).IsNotEqualTo(SshFailureReason.SftpFailed);
        return error!;
    }

    [Test]
    [Arguments(0u)]
    [Arguments(4u)] // shorter than a type byte and a request id
    [Arguments(1024u * 1024 + 1)] // over the 1 MiB limit
    [Arguments(uint.MaxValue)]
    public async Task APacketLengthOutOfBounds_EndsTheSessionWithAProtocolError(uint length)
    {
        var error = await FirstStatFailsAsync([.. Length(length), .. new byte[16]], endSession: false);

        await Assert.That(error.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains($"{length} bytes");
    }

    [Test]
    public async Task ASessionEndingInsideThePacketHeader_IsAProtocolError()
    {
        var error = await FirstStatFailsAsync([0, 0], endSession: true);

        await Assert.That(error.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("inside a packet");
    }

    [Test]
    public async Task ASessionEndingInsideThePacketBody_IsAProtocolError()
    {
        var error = await FirstStatFailsAsync([.. Length(100), 105, 0, 0, 0], endSession: true);

        await Assert.That(error.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("inside a packet");
    }

    [Test]
    public async Task ASessionEndingBetweenPackets_FailsTheWaitingRequestAsClosed()
    {
        var error = await FirstStatFailsAsync([], endSession: true);

        await Assert.That(error.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
    }

    [Test]
    public async Task AReplyToAnUnknownRequest_IsIgnored()
    {
        // A STATUS for request 999999, which was never sent, then the real answer: the stray one is dropped.
        await using var rig = await Rig.ConnectAsync(f => f.RawFrame = packet =>
        {
            if (packet[0] != Stat)
            {
                return null;
            }

            f.RawFrame = null; // only once: the real reply follows below
            byte[] stray = [101, 0, 0x0F, 0x42, 0x3F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            return [.. Length((uint)stray.Length), .. stray];
        });
        await using var sftp = await rig.Client.OpenSftpAsync(Timeout());

        // The first STAT got only the stray reply, so it waits until its caller gives up; the session is not disturbed and answers the next.
        using var shortWait = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await sftp.GetAttributesAsync(Home + "/f", cancellationToken: shortWait.Token));
        await Assert.That((await sftp.GetAttributesAsync(Home + "/f", cancellationToken: Timeout())).Size).IsEqualTo(3L);
    }

    [Test]
    public async Task AVersionReplyOfTheWrongType_FailsOpening()
    {
        // The INIT is answered with a STATUS (type 101) instead of a VERSION (type 2).
        await using var rig = await Rig.ConnectAsync(f => f.RawFrame = packet =>
            packet[0] == 1 ? [.. Length(9), 101, 0, 0, 0, 0, 0, 0, 0, 0] : null);

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Client.OpenSftpAsync(Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("did not answer with its version");
    }

    [Test]
    public async Task ASessionThatEndsBeforeTheVersion_FailsOpening()
    {
        await using var rig = await Rig.ConnectAsync(f =>
        {
            f.RawFrame = packet => packet[0] == 1 ? [] : null;
            f.EndSessionAfterRawFrame = true;
        });

        var error = await Assert.ThrowsAsync<SshException>(async () => await rig.Client.OpenSftpAsync(Timeout()));

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(error.Message).Contains("before saying its version");
    }
}
