using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>Connection-layer robustness: cancellation, odd peer limits and messages the client does not use.</summary>
public class SshConnectionTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static SshClientOptions Options() => new()
    {
        UserName = "tester",
        Password = "secret",
        HostKeyVerifier = (_, _) => ValueTask.FromResult(true),
    };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, Stream? stream = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(stream ?? server.ClientStream, Options(), leaveOpen: true, Timeout());
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    [Test]
    public async Task ACancelledSend_StillSendsThePacketWhole_SoTheConnectionSurvives()
    {
        await using var server = new FakeSessionServer();
        var gated = new GatedStream(server.ClientStream);
        await using var client = await ConnectAsync(server, gated);

        // Writes now stall half-way through. The caller gives up, but the packet already has its sequence number: it must still go out
        // whole once the stream moves again, or the server sees a broken MAC and the connection is lost.
        gated.Stall();
        using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
        {
            await Assert.That(async () => await client.Connection.OpenSessionAsync(cts.Token)).Throws<OperationCanceledException>();
        }

        gated.Resume();
        var result = await client.RunCommandAsync("after", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(client.Connection.Failure).IsNull();
    }

    [Test]
    public async Task CancellingAChannelOpen_KeepsTheConnection_AndClosesTheChannelWhenItIsConfirmed()
    {
        var hold = new TaskCompletionSource();
        await using var server = new FakeSessionServer { HoldChannelOpen = hold.Task };
        await using var client = await ConnectAsync(server);

        using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
        {
            await Assert.That(async () => await client.Connection.OpenSessionAsync(cts.Token)).Throws<OperationCanceledException>();
        }

        // The confirmation arrives after the caller gave up: the client recognises the channel and closes it.
        hold.SetResult();
        await WaitUntilAsync(() => server.Channels is [{ CloseReceived: true }]);

        var result = await client.RunCommandAsync("after", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(client.Connection.Failure).IsNull();
    }

    [Test]
    public async Task ARequestCancelledBeforeItWasSent_DoesNotTakeTheNextRequestsReply()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var channel = await client.Connection.OpenSessionAsync(Timeout());

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.That(async () => await channel.RequestAsync("pty-req", true, null, cancelled.Token)).Throws<OperationCanceledException>();

        // The server refuses nothing here; if the cancelled request had left a waiter behind, it would take this reply and exec would hang.
        var accepted = await channel.RequestAsync("exec", true, w => w.WriteString("after"), Timeout());
        await Assert.That(accepted).IsTrue();
    }

    [Test]
    public async Task ExtendedDataOfAnUnknownType_IsDropped_ButItsWindowIsGivenBack()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await client.Connection.OpenSessionAsync(Timeout());
        var serverChannel = server.Channels.Single();
        var windowBefore = serverChannel.ClientWindow;

        // 1.25 MiB of type-2 data: more than half the 2 MiB window, so a WINDOW_ADJUST is due once it has been accounted for.
        var chunk = new byte[32 * 1024];
        for (var i = 0; i < 40; i++)
        {
            await server.SendRawAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelExtendedData);
                w.WriteUInt32(serverChannel.ClientId);
                w.WriteUInt32(2);
                w.WriteString(chunk);
            }));
        }

        await serverChannel.WindowChanged.WaitAsync(Timeout());
        await Assert.That(serverChannel.ClientWindow).IsGreaterThan(windowBefore);
        await Assert.That(client.Connection.Failure).IsNull();
    }

    [Test]
    public async Task AChannelOpenedByTheServer_IsRefusedWithOpenFailure()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await server.SendRawAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpen);
            w.WriteString("forwarded-tcpip");
            w.WriteUInt32(7);
            w.WriteUInt32(65536);
            w.WriteUInt32(32768);
        }));

        await WaitUntilAsync(() => Unrecognized(server).Any(p => p[0] == SshMessage.ChannelOpenFailure));
        var (recipient, reason) = ParseOpenFailure(Unrecognized(server).First(p => p[0] == SshMessage.ChannelOpenFailure));
        await Assert.That(recipient).IsEqualTo(7u);
        await Assert.That(reason).IsEqualTo((uint)ChannelOpenFailureReason.AdministrativelyProhibited);
        await Assert.That(server.UnimplementedReceived).IsFalse();
        await Assert.That(client.Connection.Failure).IsNull();
    }

    [Test]
    public async Task AHugePeerMaximumPacketSize_IsClampedToWhatOnePacketCanCarry()
    {
        await using var server = new FakeSessionServer { ServerMaxPacket = uint.MaxValue, ServerWindow = 4 * 1024 * 1024 };
        await using var client = await ConnectAsync(server);
        var channel = await client.Connection.OpenSessionAsync(Timeout());

        await channel.SendDataAsync(new byte[600_000], Timeout());

        await WaitUntilAsync(() => Received(server).Sum(d => d.Length) == 600_000);
        await Assert.That(Received(server).Max(d => d.Length)).IsLessThanOrEqualTo(SshChannel.MaxDataPerPacket);
    }

    [Test]
    public async Task AZeroPeerMaximumPacketSize_RefusesDataInsteadOfSpinning()
    {
        await using var server = new FakeSessionServer { ServerMaxPacket = 0 };
        await using var client = await ConnectAsync(server);
        var channel = await client.Connection.OpenSessionAsync(Timeout());

        await Assert.That(async () => await channel.SendDataAsync(new byte[10], Timeout())).Throws<InvalidOperationException>();
    }

    private static (uint Recipient, uint Reason) ParseOpenFailure(byte[] payload)
    {
        var reader = new SshReader(payload);
        reader.ReadByte();
        return (reader.ReadUInt32(), reader.ReadUInt32());
    }

    private static byte[][] Unrecognized(FakeSessionServer server)
    {
        lock (server.Unrecognized)
        {
            return [.. server.Unrecognized];
        }
    }

    private static byte[][] Received(FakeSessionServer server)
    {
        lock (server.ReceivedData)
        {
            return [.. server.ReceivedData];
        }
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// A stream whose writes can be made to stall half-way: the first half of a write goes through, the rest waits until
    /// <see cref="Resume"/>, and cancelling the write leaves it torn (as a cancelled socket write can).
    /// </summary>
    private sealed class GatedStream(Stream inner) : Stream
    {
        private volatile TaskCompletionSource? _stalled;

        public void Stall() => _stalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Resume()
        {
            var stalled = _stalled;
            _stalled = null;
            stalled?.TrySetResult();
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_stalled is { } stalled && buffer.Length > 1)
            {
                var half = buffer.Length / 2;
                await inner.WriteAsync(buffer[..half], cancellationToken);
                await stalled.Task.WaitAsync(cancellationToken);
                await inner.WriteAsync(buffer[half..], cancellationToken);
                return;
            }

            await inner.WriteAsync(buffer, cancellationToken);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
