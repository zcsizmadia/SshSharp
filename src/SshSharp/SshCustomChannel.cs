using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A channel of a type SshSharp has no API of its own for, opened with <see cref="SshClient.OpenChannelAsync"/>. Disposing it (or
/// <see cref="Stream"/>) closes the channel.
/// </summary>
public sealed class SshCustomChannel : IAsyncDisposable, IDisposable
{
    private readonly SshChannelStream _stream;

    internal SshCustomChannel(string channelType, SshChannelStream stream)
    {
        ChannelType = channelType;
        _stream = stream;
    }

    /// <summary>The channel type it was opened with.</summary>
    public string ChannelType { get; }

    /// <summary>
    /// The channel's data as a duplex stream (asynchronous only): reads return what the server sends, and end (return 0) when it has
    /// finished sending. Writes go to the server. Extended data (<c>SSH_MSG_CHANNEL_EXTENDED_DATA</c>) is dropped. While nothing reads it,
    /// the server may send no more than the channel's window (<see cref="SshClientOptions.ChannelWindowSize"/>, 2 MiB by default).
    /// <see cref="ShutdownSendAsync"/> ends the writing side only.
    /// </summary>
    public Stream Stream => _stream;

    /// <summary>
    /// Ends the writing side of <see cref="Stream"/> without closing the channel: the server is sent end-of-file
    /// (<c>SSH_MSG_CHANNEL_EOF</c>), and what it sends can still be read. For a protocol where the end of a request is the end of the
    /// stream.
    /// </summary>
    /// <param name="cancellationToken">Cancels waiting to send.</param>
    /// <remarks>
    /// Call it once the writes have completed, not while one is in progress. Writes after it throw <see cref="InvalidOperationException"/>,
    /// and a second call does nothing.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The channel was disposed.</exception>
    public Task ShutdownSendAsync(CancellationToken cancellationToken = default) => _stream.ShutdownSendAsync(cancellationToken).AsTask();

    /// <summary>Closes the channel.</summary>
    public ValueTask DisposeAsync() => _stream.DisposeAsync();

    /// <summary>Closes the channel.</summary>
    public void Dispose() => _stream.Dispose();
}
