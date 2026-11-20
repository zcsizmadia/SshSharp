using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    // RFC 4253 section 6.1: every implementation takes packets of 32768 bytes; the rest of the message and the packet's framing fit in
    // what this leaves.
    private const int MaxRequestDataLength = 32_000;

    /// <summary>
    /// Opens a channel of any type (RFC 4254 section 5.1), for a server's own or vendor channel types that SshSharp has no API for, and
    /// returns it. <paramref name="typeSpecificData"/> is sent as is after the channel type, so encode it
    /// as the type defines (an SSH <c>string</c> is a big-endian <c>uint32</c> length followed by its bytes). Disposing the channel closes
    /// it; <see cref="SshCustomChannel.ShutdownSendAsync"/> ends only the writing side.
    /// </summary>
    /// <param name="channelType">The channel type: printable US-ASCII without spaces or commas, at most 64 characters (RFC 4251
    /// section 6), for example <c>my-channel@example.com</c>. Session channels are opened with <see cref="StartCommandAsync"/>,
    /// <see cref="StartShellAsync"/> or <see cref="StartSubsystemAsync"/>, not here.</param>
    /// <param name="typeSpecificData">The bytes that follow the channel type in <c>SSH_MSG_CHANNEL_OPEN</c>; empty when the type has
    /// none.</param>
    /// <param name="cancellationToken">Cancels waiting for the server's answer.</param>
    /// <exception cref="ArgumentException"><paramref name="channelType"/> is not a valid name or is <c>session</c>, or
    /// <paramref name="typeSpecificData"/> is longer than 32,000 bytes.</exception>
    /// <exception cref="SshException">The server refused to open the channel (for example, it does not know the type).</exception>
    /// <example>
    /// <code>
    /// await using var channel = await client.OpenChannelAsync("my-channel@example.com");
    /// await channel.Stream.WriteAsync(request);
    /// await channel.ShutdownSendAsync();
    /// var reply = new MemoryStream();
    /// await channel.Stream.CopyToAsync(reply);
    /// </code>
    /// </example>
    public async Task<SshCustomChannel> OpenChannelAsync(string channelType, ReadOnlyMemory<byte> typeSpecificData = default, CancellationToken cancellationToken = default)
    {
        ValidateName(channelType, nameof(channelType));
        if (channelType == "session")
        {
            // A session opened here would get past PreventNewSessionsAsync and the session options; the session APIs do it properly.
            throw new ArgumentException("Open session channels with StartCommandAsync, StartShellAsync or StartSubsystemAsync.", nameof(channelType));
        }

        ValidateRequestData(typeSpecificData, nameof(typeSpecificData));
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var data = typeSpecificData.ToArray();
        var channel = await _connection.OpenChannelAsync(channelType, data.Length == 0 ? null : w => w.WriteBytes(data), cancellationToken).ConfigureAwait(false);
        return new SshCustomChannel(channelType, new SshChannelStream(channel));
    }

    /// <summary>
    /// Sends a global request (RFC 4254 section 4), for a server's own or vendor requests that SshSharp has no API for, and waits for the
    /// answer. <paramref name="requestData"/> is sent as is after the request name and <c>want reply</c> flag, so encode it as the request
    /// defines. A server answers a request it does not know with a failure, which is returned, not thrown.
    /// </summary>
    /// <param name="requestName">The request name: printable US-ASCII without spaces or commas, at most 64 characters (RFC 4251
    /// section 6), for example <c>my-request@example.com</c>.</param>
    /// <param name="requestData">The bytes that follow the <c>want reply</c> flag in <c>SSH_MSG_GLOBAL_REQUEST</c>; empty when the request
    /// has none.</param>
    /// <param name="cancellationToken">Cancels waiting for the answer. The request has gone out by then, and its late answer is
    /// dropped.</param>
    /// <returns>Whether the server granted the request, and the data of its answer.</returns>
    /// <exception cref="ArgumentException"><paramref name="requestName"/> is not a valid name, or <paramref name="requestData"/> is
    /// longer than 32,000 bytes.</exception>
    /// <exception cref="SshException">The connection failed before the answer came.</exception>
    public async Task<SshGlobalRequestResult> SendGlobalRequestAsync(string requestName, ReadOnlyMemory<byte> requestData = default, CancellationToken cancellationToken = default)
    {
        ValidateName(requestName, nameof(requestName));
        ValidateRequestData(requestData, nameof(requestData));
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var data = requestData.ToArray();
        var reply = await _connection.SendGlobalRequestAsync(requestName, wantReply: true, data.Length == 0 ? null : w => w.WriteBytes(data), cancellationToken)
            .ConfigureAwait(false);
        return new SshGlobalRequestResult(reply.Success, reply.Data);
    }

    /// <summary>Checks an SSH algorithm-style name (RFC 4251 section 6): 1 to 64 printable US-ASCII characters, no comma, at most one @.</summary>
    private static void ValidateName(string name, string parameterName)
    {
        ArgumentException.ThrowIfNullOrEmpty(name, parameterName);
        var at = 0;
        foreach (var c in name)
        {
            at += c == '@' ? 1 : 0;
            if (c is < '!' or > '~' or ',')
            {
                throw new ArgumentException("The name must be printable US-ASCII without spaces or commas.", parameterName);
            }
        }

        if (name.Length > 64 || at > 1 || name[0] == '@' || name[^1] == '@')
        {
            throw new ArgumentException("The name must be at most 64 characters, with at most one @ that is neither first nor last.", parameterName);
        }
    }

    private static void ValidateRequestData(ReadOnlyMemory<byte> data, string parameterName)
    {
        if (data.Length > MaxRequestDataLength)
        {
            throw new ArgumentException($"The data must be at most {MaxRequestDataLength} bytes.", parameterName);
        }
    }
}
