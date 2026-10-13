using System.Buffers;
using System.Collections.Concurrent;

namespace SshSharp.Protocol;

/// <summary>
/// The SSH connection layer (RFC 4254) over an authenticated transport: a single receive loop dispatches incoming messages to
/// channels, which own their flow control. Everything that is waiting fails promptly when the connection does.
/// </summary>
internal sealed class SshConnection : IAsyncDisposable
{
    private readonly SshTransport _transport;
    private readonly ConcurrentDictionary<uint, SshChannel> _channels = new();
    private readonly CancellationTokenSource _stop = new();
    private uint _nextChannelId;
    private Task? _loop;
    private Exception? _failure;

    public SshConnection(SshTransport transport) => _transport = transport;

    /// <summary>Why the connection ended, if it did.</summary>
    public Exception? Failure => _failure;

    /// <summary>Starts the receive loop. Call once, after authentication succeeded.</summary>
    public void Start() => _loop = Task.Run(RunAsync);

    public ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
        _failure is { } failure ? throw failure : _transport.SendAsync(payload, cancellationToken);

    /// <summary>Opens a <c>session</c> channel.</summary>
    public async Task<SshChannel> OpenSessionAsync(CancellationToken cancellationToken)
    {
        if (_failure is { } failure)
        {
            throw failure;
        }

        var channel = new SshChannel(this, Interlocked.Increment(ref _nextChannelId) - 1);
        _channels[channel.LocalId] = channel;
        try
        {
            await channel.OpenAsync("session", cancellationToken).ConfigureAwait(false);
            return channel;
        }
        catch
        {
            _channels.TryRemove(channel.LocalId, out _);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Everything still waiting (commands, channel opens, window waits) fails now with a clear reason, not with a disposed-object error.
        Fail(new SshException(SshFailureReason.ConnectionClosed, "The connection was closed by the client."));
        await _stop.CancelAsync().ConfigureAwait(false);
        try
        {
            await _transport.DisconnectAsync(DisconnectReason.ByApplication, "disconnected by user").ConfigureAwait(false);
        }
        catch (SshException)
        {
            // Already disconnected.
        }
        catch (IOException)
        {
            // The socket is gone.
        }

        await _transport.DisposeAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        _stop.Dispose();
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                var packet = await _transport.ReceiveAsync(_stop.Token).ConfigureAwait(false);
                var keep = false;
                try
                {
                    keep = await DispatchAsync(packet).ConfigureAwait(false);
                }
                finally
                {
                    if (!keep)
                    {
                        packet.Dispose();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Fail(ex is OperationCanceledException ? new SshException(SshFailureReason.ConnectionClosed, "The connection was closed.") : ex);
        }
    }

    private void Fail(Exception exception)
    {
        _failure ??= exception;
        foreach (var channel in _channels.Values)
        {
            channel.Fail(exception);
        }
    }

    /// <summary>Handles one message. Returns true when the channel took ownership of the packet buffer.</summary>
    private async ValueTask<bool> DispatchAsync(DecodedPacket packet)
    {
        var memory = packet.Payload;
        var reader = new SshReader(memory.Span);
        var type = reader.ReadByte();
        switch (type)
        {
            case SshMessage.GlobalRequest:
                reader.ReadUtf8String();
                if (reader.ReadBoolean())
                {
                    await _transport.SendAsync(new byte[] { SshMessage.RequestFailure }, CancellationToken.None).ConfigureAwait(false);
                }

                return false;

            case SshMessage.RequestSuccess or SshMessage.RequestFailure:
                return false;

            case SshMessage.ChannelOpenConfirmation:
            {
                var channel = Find(reader.ReadUInt32());
                var remote = reader.ReadUInt32();
                var window = reader.ReadUInt32();
                var max = reader.ReadUInt32();
                channel.OnOpenConfirmed(remote, window, max);
                return false;
            }

            case SshMessage.ChannelOpenFailure:
            {
                var channel = Find(reader.ReadUInt32());
                var reason = reader.ReadUInt32();
                var description = reader.ReadUtf8String();
                _channels.TryRemove(channel.LocalId, out _);
                channel.OnOpenFailed(reason, description);
                return false;
            }

            case SshMessage.ChannelWindowAdjust:
            {
                var channel = Find(reader.ReadUInt32());
                channel.OnWindowAdjust(reader.ReadUInt32());
                return false;
            }

            case SshMessage.ChannelData:
            {
                var channel = Find(reader.ReadUInt32());
                var length = reader.ReadUInt32();
                var offset = memory.Length - reader.Remaining.Length;
                if (length != reader.Remaining.Length)
                {
                    throw new SshProtocolException("Channel data length does not match the packet.");
                }

                channel.OnData(packet, offset, (int)length, isExtended: false);
                return true;
            }

            case SshMessage.ChannelExtendedData:
            {
                var channel = Find(reader.ReadUInt32());
                var dataType = reader.ReadUInt32();
                var length = reader.ReadUInt32();
                var offset = memory.Length - reader.Remaining.Length;
                if (length != reader.Remaining.Length)
                {
                    throw new SshProtocolException("Channel data length does not match the packet.");
                }

                if (dataType != 1)
                {
                    return false; // Only stderr (1) is defined; ignore anything else.
                }

                channel.OnData(packet, offset, (int)length, isExtended: true);
                return true;
            }

            case SshMessage.ChannelEof:
                Find(reader.ReadUInt32()).OnEof();
                return false;

            case SshMessage.ChannelClose:
            {
                var channel = Find(reader.ReadUInt32());
                await channel.OnCloseAsync().ConfigureAwait(false);
                _channels.TryRemove(channel.LocalId, out _);
                return false;
            }

            case SshMessage.ChannelRequest:
            {
                var channel = Find(reader.ReadUInt32());
                var requestType = reader.ReadUtf8String();
                var wantReply = reader.ReadBoolean();
                await channel.OnRequestAsync(requestType, wantReply, memory[(memory.Length - reader.Remaining.Length)..]).ConfigureAwait(false);
                return false;
            }

            case SshMessage.ChannelSuccess:
                Find(reader.ReadUInt32()).OnReply(true);
                return false;

            case SshMessage.ChannelFailure:
                Find(reader.ReadUInt32()).OnReply(false);
                return false;

            default:
                // RFC 4253 section 11.4: tell the peer we do not implement this message, quoting its sequence number.
                await _transport.SendUnimplementedAsync().ConfigureAwait(false);
                return false;
        }
    }

    private SshChannel Find(uint id) =>
        _channels.TryGetValue(id, out var channel) ? channel : throw new SshProtocolException($"Message for unknown channel {id}.");
}