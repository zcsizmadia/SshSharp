using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// A channel's state before it is used: the stderr queue, created only when stderr is split, and the peer's window, which exists only once
/// the open is confirmed. No connection is made; the channel only needs one to exist.
/// </summary>
public class SshChannelStateTests
{
    private static SshChannel NewChannel(out MemoryStream wire)
    {
        // Unconnected: packets go out unencrypted (the initial state), into the memory stream.
        wire = new MemoryStream();
        var transport = new SshTransport(wire, new SshTransportOptions { VerifyHostKey = (_, _) => ValueTask.FromResult(true) });
        return new SshChannel(new SshConnection(transport), 0);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    [Test]
    public async Task StderrSplitAfterTheEndOfData_EndsToo()
    {
        // The peer's EOF can arrive before a reader asks for stderr: the queue made then is already at its end, not waiting for ever.
        var channel = NewChannel(out _);
        channel.OnEof();
        await Assert.That(channel.SplitExtended).IsFalse();
        channel.SplitExtended = true;
        await Assert.That(channel.SplitExtended).IsTrue();
        await Assert.That(await channel.ReadExtendedAsync(Timeout())).IsNull();
        await Assert.That(await channel.ReadAsync(Timeout())).IsNull();
    }

    [Test]
    public async Task StderrSplitAfterAFailure_FailsWithIt()
    {
        var channel = NewChannel(out _);
        var failure = new SshException(SshFailureReason.ConnectionClosed, "gone");
        channel.Fail(failure);
        channel.OnClose(); // a later, normal end does not replace the failure
        channel.SplitExtended = true;
        var thrown = await Assert.ThrowsAsync<SshException>(async () => await channel.ReadExtendedAsync(Timeout()));
        await Assert.That(thrown).IsSameReferenceAs(failure);
    }

    [Test]
    public async Task StderrSplitBeforeTheEnd_EndsWithTheData_AndSplittingTwiceKeepsOneQueue()
    {
        var channel = NewChannel(out _);
        channel.SplitExtended = true;
        var read = channel.ReadExtendedAsync(Timeout());
        channel.SplitExtended = true;
        channel.SplitExtended = false; // never turned off once on
        await Assert.That(channel.SplitExtended).IsTrue();
        channel.OnEof();
        await Assert.That(await read).IsNull();
    }

    [Test]
    public async Task WithoutSplitting_ThereIsNoStderrToRead()
    {
        var channel = NewChannel(out _);
        await Assert.That(async () => await channel.ReadExtendedAsync(Timeout())).Throws<InvalidOperationException>();
        channel.DiscardUnread(); // nothing to discard, and no queue needed for it
    }

    [Test]
    public async Task BeforeTheOpenIsConfirmed_ThereIsNoWindow_AndTheConfirmedOneIsUsed()
    {
        var channel = NewChannel(out var wire);
        channel.OnWindowAdjust(1000); // a misbehaving peer: nothing to add to, and no failure
        channel.OnOpenConfirmed(5, 0, 32 * 1024);
        channel.OnWindowAdjust(10);

        // The window is the confirmed one, not 1000: 10 bytes go, in one packet, and the rest waits for more until given up.
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.That(async () => await channel.SendDataAsync(new byte[20], cancel.Token)).Throws<OperationCanceledException>();
        var packet = wire.ToArray();
        await Assert.That(packet[5]).IsEqualTo(SshMessage.ChannelData);
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(6))).IsEqualTo(5u); // the recipient
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(10))).IsEqualTo(10u); // the length
        await Assert.That(packet.Length).IsEqualTo(4 + (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(packet));
    }
}
