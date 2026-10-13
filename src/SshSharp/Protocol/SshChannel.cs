using System.Buffers;
using System.Threading.Channels;

namespace SshSharp.Protocol;

/// <summary>
/// Data received on a channel. It holds the pooled packet buffer the bytes arrived in (no copy); disposing it releases the buffer and
/// tells the peer, through the channel window, that it may send more. Hold it only as long as you are processing it.
/// </summary>
internal sealed class ChannelData : IDisposable
{
    private readonly DecodedPacket _packet;
    private readonly int _offset;
    private readonly int _length;
    private readonly SshChannel _channel;
    private bool _disposed;

    public ChannelData(SshChannel channel, DecodedPacket packet, int offset, int length, bool isExtended)
    {
        _channel = channel;
        _packet = packet;
        _offset = offset;
        _length = length;
        IsExtended = isExtended;
    }

    /// <summary>True for stderr (<c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> type 1).</summary>
    public bool IsExtended { get; }

    public ReadOnlyMemory<byte> Data => _disposed ? throw new ObjectDisposedException(nameof(ChannelData)) : _packet.Payload.Slice(_offset, _length);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _packet.Dispose();
        _channel.Consumed(_length);
    }
}

/// <summary>One channel of the SSH connection layer (RFC 4254 section 5): open/close, requests, flow-controlled data.</summary>
internal sealed class SshChannel
{
    /// <summary>The window we advertise: how much the peer may send before we have processed some (OpenSSH uses the same).</summary>
    public const uint LocalWindowSize = 2 * 1024 * 1024;

    /// <summary>The largest data packet we accept.</summary>
    public const uint LocalMaxPacketSize = 32 * 1024;

    private readonly SshConnection _connection;
    private readonly Channel<ChannelData> _incoming = Channel.CreateUnbounded<ChannelData>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly TaskCompletionSource _confirmed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Queue<TaskCompletionSource<bool>> _pendingReplies = new();
    private readonly object _lock = new();
    private SendWindow _sendWindow = new(0);
    private long _localWindow = LocalWindowSize;
    private long _consumedSinceAdjust;
    private uint _remoteMaxPacket;
    private bool _closeSent;
    private bool _remoteClosed;

    public SshChannel(SshConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
    }

    public uint LocalId { get; }

    public uint RemoteId { get; private set; }

    /// <summary>The command's exit status, from the peer's <c>exit-status</c> request.</summary>
    public uint? ExitStatus { get; private set; }

    /// <summary>The signal that ended the command, from <c>exit-signal</c>.</summary>
    public string? ExitSignal { get; private set; }

    // ---- opening and closing ----

    public async Task OpenAsync(string type, CancellationToken cancellationToken)
    {
        var payload = Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpen);
            w.WriteString(type);
            w.WriteUInt32(LocalId);
            w.WriteUInt32(LocalWindowSize);
            w.WriteUInt32(LocalMaxPacketSize);
        });
        await _connection.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        await _confirmed.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends our <c>CLOSE</c> (once). The channel is fully closed when the peer's <c>CLOSE</c> has arrived too.</summary>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_closeSent)
            {
                return;
            }

            _closeSent = true;
        }

        try
        {
            await _connection.SendAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelClose);
                w.WriteUInt32(RemoteId);
            }), cancellationToken).ConfigureAwait(false);
        }
        catch (SshException)
        {
            // The connection is already gone; the channel is failed by the connection.
        }
    }

    /// <summary>Completes when the peer has closed the channel (or the connection failed).</summary>
    public Task WaitClosedAsync(CancellationToken cancellationToken) => _closed.Task.WaitAsync(cancellationToken);

    // ---- sending ----

    /// <summary>Sends a channel request. When <paramref name="wantReply"/> is set, returns whether the peer accepted it.</summary>
    public async Task<bool> RequestAsync(string type, bool wantReply, Action<SshWriter>? body, CancellationToken cancellationToken)
    {
        TaskCompletionSource<bool>? reply = null;
        if (wantReply)
        {
            reply = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_lock)
            {
                _pendingReplies.Enqueue(reply);
            }
        }

        await _connection.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelRequest);
            w.WriteUInt32(RemoteId);
            w.WriteString(type);
            w.WriteBoolean(wantReply);
            body?.Invoke(w);
        }), cancellationToken).ConfigureAwait(false);

        return reply is null || await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends data, split to the peer's maximum packet size and paced by its window.</summary>
    public async ValueTask SendDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        while (!data.IsEmpty)
        {
            var count = await _sendWindow.AcquireAsync((int)Math.Min(data.Length, _remoteMaxPacket), cancellationToken).ConfigureAwait(false);
            var buffer = ArrayPool<byte>.Shared.Rent(9 + count);
            try
            {
                buffer[0] = SshMessage.ChannelData;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(1), RemoteId);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(5), (uint)count);
                data.Span[..count].CopyTo(buffer.AsSpan(9));
                await _connection.SendAsync(buffer.AsMemory(0, 9 + count), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            data = data[count..];
        }
    }

    public ValueTask SendEofAsync(CancellationToken cancellationToken) => _connection.SendAsync(Build(w =>
    {
        w.WriteByte(SshMessage.ChannelEof);
        w.WriteUInt32(RemoteId);
    }), cancellationToken);

    // ---- receiving ----

    /// <summary>Returns the next chunk of data, or null once the peer has sent EOF (or closed) and everything has been read.</summary>
    public async ValueTask<ChannelData?> ReadAsync(CancellationToken cancellationToken)
    {
        while (await _incoming.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (_incoming.Reader.TryRead(out var item))
            {
                return item;
            }
        }

        return null;
    }

    /// <summary>Called when the consumer is done with received bytes: replenishes the peer's window in large steps.</summary>
    internal void Consumed(int length)
    {
        var total = Interlocked.Add(ref _consumedSinceAdjust, length);
        if (total < LocalWindowSize / 2)
        {
            return;
        }

        var adjust = Interlocked.Exchange(ref _consumedSinceAdjust, 0);
        if (adjust <= 0 || _remoteClosed)
        {
            return;
        }

        Interlocked.Add(ref _localWindow, adjust);
        _ = SendWindowAdjustAsync((uint)adjust);
    }

    private async Task SendWindowAdjustAsync(uint bytes)
    {
        try
        {
            await _connection.SendAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelWindowAdjust);
                w.WriteUInt32(RemoteId);
                w.WriteUInt32(bytes);
            }), CancellationToken.None).ConfigureAwait(false);
        }
        catch (SshException)
        {
            // The connection failed; nothing left to adjust.
        }
    }

    // ---- events from the connection's receive loop ----

    internal void OnOpenConfirmed(uint remoteId, uint window, uint maxPacket)
    {
        RemoteId = remoteId;
        _remoteMaxPacket = Math.Min(maxPacket, SshReader.MaxStringLength);
        _sendWindow = new SendWindow(window);
        _confirmed.TrySetResult();
    }

    internal void OnOpenFailed(uint reason, string description) =>
        _confirmed.TrySetException(new SshException(SshFailureReason.ChannelClosed, $"The server refused to open the channel (reason {reason}): {description}"));

    internal void OnWindowAdjust(uint bytes) => _sendWindow.Add(bytes);

    internal void OnData(DecodedPacket packet, int offset, int length, bool isExtended)
    {
        if (length > LocalMaxPacketSize || length > Interlocked.Read(ref _localWindow))
        {
            packet.Dispose();
            throw new SshProtocolException("The peer sent more channel data than the window or maximum packet size allows.");
        }

        Interlocked.Add(ref _localWindow, -length);
        if (!_incoming.Writer.TryWrite(new ChannelData(this, packet, offset, length, isExtended)))
        {
            packet.Dispose();
        }
    }

    internal void OnEof() => _incoming.Writer.TryComplete();

    internal async ValueTask OnCloseAsync()
    {
        _remoteClosed = true;
        _incoming.Writer.TryComplete();
        await CloseAsync().ConfigureAwait(false); // reply to the peer's CLOSE
        _sendWindow.Fail(new SshException(SshFailureReason.ChannelClosed, "The channel is closed."));
        FailReplies(new SshException(SshFailureReason.ChannelClosed, "The channel was closed before the request was answered."));
        _closed.TrySetResult();
    }

    internal void OnReply(bool success)
    {
        TaskCompletionSource<bool>? reply;
        lock (_lock)
        {
            _pendingReplies.TryDequeue(out reply);
        }

        reply?.TrySetResult(success);
    }

    internal async ValueTask OnRequestAsync(string type, bool wantReply, ReadOnlyMemory<byte> body)
    {
        var handled = false;
        try
        {
            var reader = new SshReader(body.Span);
            switch (type)
            {
                case "exit-status":
                    ExitStatus = reader.ReadUInt32();
                    handled = true;
                    break;
                case "exit-signal":
                    ExitSignal = reader.ReadUtf8String();
                    handled = true;
                    break;
            }
        }
        catch (SshProtocolException)
        {
            handled = false;
        }

        if (wantReply)
        {
            await _connection.SendAsync(Build(w =>
            {
                w.WriteByte(handled ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure);
                w.WriteUInt32(RemoteId);
            }), CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>The connection failed: wake everything that is waiting.</summary>
    internal void Fail(Exception exception)
    {
        _confirmed.TrySetException(exception);
        _incoming.Writer.TryComplete(exception);
        _sendWindow.Fail(exception);
        FailReplies(exception);
        _closed.TrySetException(exception);
    }

    private void FailReplies(Exception exception)
    {
        lock (_lock)
        {
            while (_pendingReplies.TryDequeue(out var reply))
            {
                reply.TrySetException(exception);
            }
        }
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(64);
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }
}