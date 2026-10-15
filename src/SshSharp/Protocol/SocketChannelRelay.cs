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

    /// <summary>Numbers relays for the instrumented build's trace (channel numbers repeat across connections).</summary>
    private static long _relays;

    /// <summary>Runs until both directions have finished, the peer closed the channel, either side failed, or <paramref name="stop"/>.</summary>
    public static async Task RunAsync(Socket socket, SshChannel channel, CancellationToken stop)
    {
        var id = Interlocked.Increment(ref _relays);
        Instrumentation.Trace($"relay#{id}: start, channel {channel.LocalId}, {socket.AddressFamily} {socket.RemoteEndPoint}");
        using var teardown = CancellationTokenSource.CreateLinkedTokenSource(stop);
        var toChannel = GuardAsync(() => SocketToChannelAsync(socket, channel, id, teardown.Token), teardown, id, "socket->channel");
        var toSocket = GuardAsync(() => ChannelToSocketAsync(socket, channel, id, teardown.Token), teardown, id, "channel->socket");

        // Done when both directions have ended, the peer closed the channel, or something failed (which cancels teardown).
        var closed = channel.WaitClosedAsync(teardown.Token);
        var first = await Task.WhenAny(Task.WhenAll(toChannel, toSocket), closed).ConfigureAwait(false);
        _ = closed.Exception; // observed: a failed connection faults it
        Instrumentation.Trace($"relay#{id}: first to end: {(first == closed ? $"the channel closing ({closed.Status})" : "both directions")}");
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
        Instrumentation.Trace($"relay#{id}: done");
    }

    private static async Task GuardAsync(Func<Task> pump, CancellationTokenSource teardown, long id, string direction)
    {
        try
        {
            await pump().ConfigureAwait(false);
            Instrumentation.Trace($"relay#{id}: {direction} finished");
        }
        catch (Exception ex) when (ex is SocketException or SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // A reset socket, a closed channel or the connection ending: stop both directions.
            Instrumentation.Trace($"relay#{id}: {direction} failed: {ex.GetType().Name}: {ex.Message}");
            await teardown.CancelAsync().ConfigureAwait(false);
        }
    }

    private static async Task SocketToChannelAsync(Socket socket, SshChannel channel, long id, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        Instrumentation.Rented(buffer, nameof(SocketToChannelAsync));
        try
        {
            while (await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false) is var read and > 0)
            {
                Instrumentation.Trace($"relay#{id}: {read} bytes from the socket");
                await channel.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            Instrumentation.Trace($"relay#{id}: the socket's end of stream; sending EOF on the channel");
            await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Instrumentation.Returning(buffer, nameof(SocketToChannelAsync));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ChannelToSocketAsync(Socket socket, SshChannel channel, long id, CancellationToken cancellationToken)
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
                Instrumentation.Trace($"relay#{id}: {data.Length} bytes from the channel");
                while (!data.IsEmpty)
                {
                    var sent = await socket.SendAsync(data, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    data = data[sent..];
                }
            }
        }

        Instrumentation.Trace($"relay#{id}: the channel's EOF; shutting down the socket's sending side");
        socket.Shutdown(SocketShutdown.Send);
    }
}
