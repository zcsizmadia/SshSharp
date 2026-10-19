using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// Regression tests for a deadlock found by CI: the connection's receive loop used to send its replies itself, but while a key
/// re-exchange runs, application sends wait for it, and only the receive loop can finish it. A reply needed during a re-exchange
/// therefore made the loop wait on itself. Replies are now queued and sent by a separate task.
/// </summary>
public class SshConnectionRekeyTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static (byte Type, uint Channel) ParseChannelOpen(ReadOnlySpan<byte> payload)
    {
        var reader = new SshReader(payload);
        var type = reader.ReadByte();
        reader.ReadUtf8String();
        return (type, reader.ReadUInt32());
    }

    private static (byte Type, uint Channel) ParseChannelMessage(ReadOnlySpan<byte> payload)
    {
        var reader = new SshReader(payload);
        return (reader.ReadByte(), reader.ReadUInt32());
    }

    [Test]
    public async Task ARepliedToMessageArrivingWhileWeAreRekeying_DoesNotStallTheReceiveLoop()
    {
        await using var server = new FakeSshServer();
        var transport = new SshTransport(server.ClientStream, new SshTransportOptions
        {
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
            RekeyBytes = 1, // every application send crosses the threshold, so our KEXINIT follows our first message
        });
        var token = Timeout();
        var serverStart = server.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverStart;

        // Thresholds count only once the user is authenticated.
        await server.SendAsync(new byte[] { SshMessage.UserAuthSuccess }, token);
        (await transport.ReceiveAsync(token)).Dispose();

        await using var connection = new SshConnection(transport);
        connection.Start();
        var opening = connection.OpenSessionAsync(token);

        // The server sees CHANNEL_OPEN first and answers it, then closes the channel, all before it has read the client's KEXINIT.
        // The client is by then mid-rekey, and the CLOSE it receives needs a CLOSE back.
        uint clientChannel;
        using (var open = await server.ReceiveAsync(token))
        {
            var (type, channel) = ParseChannelOpen(open.Payload.Span);
            await Assert.That(type).IsEqualTo(SshMessage.ChannelOpen);
            clientChannel = channel;
        }

        await server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpenConfirmation);
            w.WriteUInt32(clientChannel);
            w.WriteUInt32(7);
            w.WriteUInt32(1_000_000);
            w.WriteUInt32(32_768);
        }), token);
        await server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelClose);
            w.WriteUInt32(clientChannel);
        }), token);

        await opening;

        // Now the server reads: the client's KEXINIT is handled here (a full re-exchange), and then the client's CLOSE reply arrives.
        using var reply = await server.ReceiveAsync(token);
        var (closeType, closeChannel) = ParseChannelMessage(reply.Payload.Span);
        await Assert.That(closeType).IsEqualTo(SshMessage.ChannelClose);
        await Assert.That(closeChannel).IsEqualTo(7u);

        // The CLOSE went out after the client's NEWKEYS; the client counts the exchange only when the server's NEWKEYS reaches its
        // receive loop, which may be a moment later.
        for (var i = 0; i < 500 && transport.KeyExchangeCount < 2; i++)
        {
            await Task.Delay(20);
        }

        await Assert.That(transport.KeyExchangeCount).IsGreaterThanOrEqualTo(2);
        await Assert.That(server.KeyExchangeCount).IsGreaterThanOrEqualTo(2);
        await Assert.That(connection.Failure).IsNull();
    }
}