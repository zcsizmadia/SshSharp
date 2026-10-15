using System.Buffers;

namespace SshSharp.Protocol;

/// <summary>
/// Relays a local stream (an agent's socket or pipe) and a channel opened by the server, until either side ends: the agent protocol is
/// request and answer, so there is no half-close to carry.
/// </summary>
internal static class StreamChannelRelay
{
    private const int BufferSize = 16 * 1024;

    public static async Task RunAsync(Stream stream, SshChannel channel, CancellationToken stop)
    {
        using var teardown = CancellationTokenSource.CreateLinkedTokenSource(stop);
        var toStream = PumpAsync(async ct =>
        {
            while (await channel.ReadAsync(ct).ConfigureAwait(false) is { } chunk)
            {
                using (chunk)
                {
                    await stream.WriteAsync(chunk.Data, ct).ConfigureAwait(false);
                    await stream.FlushAsync(ct).ConfigureAwait(false);
                }
            }
        }, teardown);
        var toChannel = PumpAsync(async ct =>
        {
            var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            Instrumentation.Rented(buffer, nameof(StreamChannelRelay));
            try
            {
                while (await stream.ReadAsync(buffer, ct).ConfigureAwait(false) is var read and > 0)
                {
                    await channel.SendDataAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                }
            }
            finally
            {
                Instrumentation.Returning(buffer, nameof(StreamChannelRelay));
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }, teardown);

        // Either side finishing ends the relay; the other direction is cancelled.
        await Task.WhenAny(toStream, toChannel).ConfigureAwait(false);
        await teardown.CancelAsync().ConfigureAwait(false);
        await Task.WhenAll(toStream, toChannel).ConfigureAwait(false);
        await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        channel.DiscardUnread();
    }

    private static async Task PumpAsync(Func<CancellationToken, Task> pump, CancellationTokenSource teardown)
    {
        try
        {
            await pump(teardown.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // The agent went away, the channel closed, or the connection ended.
        }
    }
}
