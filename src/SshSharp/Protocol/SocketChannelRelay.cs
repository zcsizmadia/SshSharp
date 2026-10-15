using System.Buffers;
using System.Net.Sockets;

namespace SshSharp.Protocol;

/// <summary>
/// Relays a TCP socket and an open channel to each other, as port forwarding does in both directions: data straight from the received
/// packets, half-closes carried both ways (socket end-of-stream becomes channel EOF, channel EOF shuts down the socket's sending side),
/// and what the peer sent before closing is delivered before teardown.
/// </summary>
internal static class SocketChannelRelay
{
    private const int BufferSize = 32 * 1024;

    /// <summary>Runs until both directions have finished, the peer closed the channel, either side failed, or <paramref name="stop"/>.</summary>
    public static async Task RunAsync(Socket socket, SshChannel channel, CancellationToken stop)
    {
        using var teardown = CancellationTokenSource.CreateLinkedTokenSource(stop);
        var toChannel = GuardAsync(() => SocketToChannelAsync(socket, channel, teardown.Token), teardown);
        var toSocket = GuardAsync(() => ChannelToSocketAsync(socket, channel, teardown.Token), teardown);

        // Done when both directions have ended, the peer closed the channel, or something failed (which cancels teardown).
        var closed = channel.WaitClosedAsync(teardown.Token);
        var first = await Task.WhenAny(Task.WhenAll(toChannel, toSocket), closed).ConfigureAwait(false);
        _ = closed.Exception; // observed: a failed connection faults it
        if (first == closed && closed.IsCompletedSuccessfully)
        {
            // The peer closed: what it sent before CLOSE is still queued, and the queue has ended, so deliver it before tearing down.
            await toSocket.ConfigureAwait(false);
        }

        await teardown.CancelAsync().ConfigureAwait(false);
        await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        socket.Dispose();
        await Task.WhenAll(toChannel, toSocket).ConfigureAwait(false);
        channel.DiscardUnread();
    }

    private static async Task GuardAsync(Func<Task> pump, CancellationTokenSource teardown)
    {
        try
        {
            await pump().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // A reset socket, a closed channel or the connection ending: stop both directions.
            await teardown.CancelAsync().ConfigureAwait(false);
        }
    }

    private static async Task SocketToChannelAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        Instrumentation.Rented(buffer, nameof(SocketToChannelAsync));
        try
        {
            while (await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false) is var read and > 0)
            {
                await channel.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Instrumentation.Returning(buffer, nameof(SocketToChannelAsync));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ChannelToSocketAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken)
    {
        while (await channel.ReadAsync(cancellationToken).ConfigureAwait(false) is { } chunk)
        {
            using (chunk)
            {
                if (chunk.IsExtended)
                {
                    continue; // a TCP stream has no stderr
                }

                var data = chunk.Data;
                while (!data.IsEmpty)
                {
                    var sent = await socket.SendAsync(data, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    data = data[sent..];
                }
            }
        }

        socket.Shutdown(SocketShutdown.Send);
    }
}
