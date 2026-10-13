using System.Buffers;
using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

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

    private readonly ILogger _logger;

    // Replies generated while receiving (CLOSE, request replies, window adjustments, UNIMPLEMENTED) are queued here and sent by their own task.
    // The receive loop must never wait on a send: while a key re-exchange is running, application sends wait for it to finish, and only the
    // receive loop can finish it, so a loop that sent directly would wait on itself (or on a peer that is blocked the same way).
    private readonly Channel<byte[]> _outbox = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true });
    private Task? _outboxLoop;

    public SshConnection(SshTransport transport, ILogger? logger = null)
    {
        _transport = transport;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>How many key exchanges have completed, including the first.</summary>
    public int KeyExchangeCount => _transport.KeyExchangeCount;

    /// <summary>Why the connection ended, if it did.</summary>
    public Exception? Failure => _failure;

    /// <summary>Starts the receive loop. Call once, after authentication succeeded.</summary>
    public void Start()
    {
        _loop = Task.Run(RunAsync);
        _outboxLoop = Task.Run(RunOutboxAsync);
    }

    /// <summary>Queues a message to be sent without waiting. For use from the receive loop and from synchronous callbacks.</summary>
    internal void Post(byte[] payload) => _outbox.Writer.TryWrite(payload);

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
            if (channel.TryMarkOpen())
            {
                SshTelemetry.Channels.Add(1);
                SshLog.ChannelOpened(_logger, channel.LocalId);
            }

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
        SshLog.Disconnecting(_logger);
        Fail(new SshException(SshFailureReason.ConnectionClosed, "The connection was closed by the client."));
        _outbox.Writer.TryComplete();
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

        if (_outboxLoop is not null)
        {
            await _outboxLoop.ConfigureAwait(false);
        }

        _stop.Dispose();
    }

    private async Task RunOutboxAsync()
    {
        try
        {
            await foreach (var payload in _outbox.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                await _transport.SendAsync(payload, _stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SshException or ObjectDisposedException or IOException or InvalidOperationException)
        {
            // The connection is going away; the receive loop reports the reason to whoever is waiting.
        }
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
                    keep = Dispatch(packet);
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
            if (ex is not OperationCanceledException)
            {
                SshLog.ConnectionFailed(_logger, ex);
            }

            Fail(ex is OperationCanceledException ? new SshException(SshFailureReason.ConnectionClosed, "The connection was closed.") : ex);
        }
    }

    private void Fail(Exception exception)
    {
        _failure ??= exception;
        foreach (var channel in _channels.Values)
        {
            ChannelGone(channel);
            channel.Fail(exception);
        }
    }

    /// <summary>Handles one message. Returns true when the channel took ownership of the packet buffer.</summary>
    private bool Dispatch(DecodedPacket packet)
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
                    Post([SshMessage.RequestFailure]);
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
                channel.OnClose();
                _channels.TryRemove(channel.LocalId, out _);
                ChannelGone(channel);
                return false;
            }

            case SshMessage.ChannelRequest:
            {
                var channel = Find(reader.ReadUInt32());
                var requestType = reader.ReadUtf8String();
                var wantReply = reader.ReadBoolean();
                channel.OnRequest(requestType, wantReply, memory[(memory.Length - reader.Remaining.Length)..]);
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
                SshLog.UnimplementedMessage(_logger, type);
                Post(_transport.BuildUnimplemented());
                return false;
        }
    }

    private void ChannelGone(SshChannel channel)
    {
        if (channel.TryMarkGone())
        {
            SshTelemetry.Channels.Add(-1);
            SshLog.ChannelClosed(_logger, channel.LocalId);
        }
    }

    private SshChannel Find(uint id) =>
        _channels.TryGetValue(id, out var channel) ? channel : throw new SshProtocolException($"Message for unknown channel {id}.");
}