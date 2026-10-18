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
    private int _disposed;

    public ChannelData(SshChannel channel, DecodedPacket packet, int offset, int length, bool isExtended)
    {
        _channel = channel;
        _packet = packet;
        _offset = offset;
        _length = length;
        IsExtended = isExtended;
#if SSHSHARP_INSTRUMENT
        _checksum = Instrumentation.Checksum(packet.Payload.Span.Slice(offset, length));
#endif
    }

#if SSHSHARP_INSTRUMENT
    private readonly ulong _checksum;
    private int _checkedOnRead;
#endif

    /// <summary>True for stderr (<c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> type 1).</summary>
    public bool IsExtended { get; }

    public ReadOnlyMemory<byte> Data
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, typeof(ChannelData));
            var data = _packet.Payload.Slice(_offset, _length);
#if SSHSHARP_INSTRUMENT
            if (Interlocked.Exchange(ref _checkedOnRead, 1) == 0)
            {
                Instrumentation.CheckData(data.Span, _checksum, _channel.LocalId, "before it was read");
            }
#endif
            return data;
        }
    }

    /// <summary>
    /// Releases the buffer and gives the window back, once: a stream disposed while a read is in progress releases its current chunk from
    /// both threads, and a second release would return the buffer to the pool twice and grant the peer the window twice.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

#if SSHSHARP_INSTRUMENT
        Instrumentation.CheckData(_packet.Payload.Span.Slice(_offset, _length), _checksum, _channel.LocalId, "while it was being read");
#endif
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
    // Not single-reader: besides the reader, DiscardUnread and StopReceiving take what is queued, and can do so while a read is in
    // progress (a session disposed under a read). The single-reader queue is unsafe for that and can hand one item to both.
    private readonly Channel<ChannelData> _incoming = Channel.CreateUnbounded<ChannelData>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly Channel<ChannelData> _extended = Channel.CreateUnbounded<ChannelData>(new UnboundedChannelOptions { SingleWriter = true });
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
    private bool _openConfirmed;
    private volatile bool _abandoned;
    private Exception? _repliesFailure;

    public SshChannel(SshConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
        _isOpenForSending = () => !Volatile.Read(ref _closeSent);
        _lastActivity = connection.Time.GetTimestamp();
    }

    private long _lastActivity;

    /// <summary>
    /// The channel's type as OpenSSH's ChannelTimeout names it (<c>session</c>, <c>direct-tcpip</c>, <c>forwarded-tcpip</c>,
    /// <c>agent-connection</c>, ...), or null while unknown; channels without one are never timed out.
    /// </summary>
    internal string? TimeoutType { get; set; }

    /// <summary>When data last went either way on the channel (a <see cref="TimeProvider"/> timestamp), for ChannelTimeout.</summary>
    internal long LastActivity => Interlocked.Read(ref _lastActivity);

    /// <summary>Whether the channel is open and our CLOSE is still unsent.</summary>
    internal bool IsOpenForTimeout => Volatile.Read(ref _state) == 1 && !Volatile.Read(ref _closeSent);

    /// <summary>Whether our CLOSE is still unsent, so data may still be sent.</summary>
    internal bool IsOpenForSending => !Volatile.Read(ref _closeSent);

    private void Touch() => Interlocked.Exchange(ref _lastActivity, _connection.Time.GetTimestamp());

    /// <summary>Whether our CLOSE is still unsent; checked under the transport's send lock (one delegate per channel, not per packet).</summary>
    private readonly Func<bool> _isOpenForSending;

    public uint LocalId { get; }

    private int _state; // 0 = not open yet, 1 = open, 2 = gone

    /// <summary>Records that the channel is open. True the first time only.</summary>
    internal bool TryMarkOpen() => Interlocked.CompareExchange(ref _state, 1, 0) == 0;

    /// <summary>Records that an open channel is gone (closed or failed). True once, and only for channels that were open.</summary>
    internal bool TryMarkGone() => Interlocked.CompareExchange(ref _state, 2, 1) == 1;

    public uint RemoteId { get; private set; }

    /// <summary>The command's exit status, from the peer's <c>exit-status</c> request.</summary>
    public uint? ExitStatus { get; private set; }

    /// <summary>The signal that ended the command, from <c>exit-signal</c>.</summary>
    public SshExitSignal? ExitSignal { get; private set; }

    // ---- opening and closing ----

    public async Task OpenAsync(string type, Action<SshWriter>? typeSpecificData, CancellationToken cancellationToken)
    {
        var payload = Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpen);
            w.WriteString(type);
            w.WriteUInt32(LocalId);
            w.WriteUInt32(LocalWindowSize);
            w.WriteUInt32(LocalMaxPacketSize);
            typeSpecificData?.Invoke(w);
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
        catch (Exception ex) when (ex is SshException or ObjectDisposedException or IOException)
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
        // Replies arrive in request order, so the waiter is queued exactly when the request takes its place on the wire: a request
        // cancelled before that leaves nothing behind to swallow the reply meant for the next one.
        TaskCompletionSource<bool>? reply = wantReply ? new(TaskCreationOptions.RunContinuationsAsynchronously) : null;
        await _connection.SendAsync(
            Build(w =>
            {
                w.WriteByte(SshMessage.ChannelRequest);
                w.WriteUInt32(RemoteId);
                w.WriteString(type);
                w.WriteBoolean(wantReply);
                body?.Invoke(w);
            }),
            reply is null ? null : () => EnqueueReply(reply),
            cancellationToken).ConfigureAwait(false);

        return reply is null || await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private void EnqueueReply(TaskCompletionSource<bool> reply)
    {
        lock (_lock)
        {
            if (_repliesFailure is { } failure)
            {
                reply.TrySetException(failure);
                return;
            }

            _pendingReplies.Enqueue(reply);
        }
    }

    /// <summary>The most data we put in one packet, whatever the peer allows: keeps every packet within <see cref="PacketCodec.MaxPacketLength"/>.</summary>
    internal const int MaxDataPerPacket = PacketCodec.MaxPacketLength - 1024;

    /// <summary>Sends data, split to the peer's maximum packet size and paced by its window.</summary>
    public async ValueTask SendDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closeSent))
        {
            // Usually the remote program has exited and the server closed the channel: a connection-level fact, not a misuse.
            throw new SshException(SshFailureReason.ChannelClosed, "The channel is closed; no more data can be sent.");
        }

        if (!data.IsEmpty && _remoteMaxPacket == 0)
        {
            throw new InvalidOperationException("The peer does not accept data on this channel (maximum packet size 0).");
        }

        if (!data.IsEmpty && PeerStoppedReading)
        {
            // As writing to a pipe whose reader has gone: the remote program closed its input (eow@openssh.com).
            throw new SshException(SshFailureReason.ChannelClosed, "The server no longer reads this channel's data: the remote program closed its input.");
        }

        while (!data.IsEmpty)
        {
            var count = await _sendWindow.AcquireAsync((int)Math.Min(data.Length, _remoteMaxPacket), cancellationToken).ConfigureAwait(false);
            var buffer = ArrayPool<byte>.Shared.Rent(9 + count);
            Instrumentation.Rented(buffer, nameof(SendDataAsync));
            try
            {
                buffer[0] = SshMessage.ChannelData;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(1), RemoteId);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(5), (uint)count);
                data.Span[..count].CopyTo(buffer.AsSpan(9));
                bool sent;
                try
                {
                    sent = await _connection.SendIfAsync(buffer.AsMemory(0, 9 + count), _isOpenForSending, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Cancelled before the packet was committed (SendIfAsync reports a committed one as sent): the peer never sees these
                    // bytes and will never grant them again, so give the window back.
                    _sendWindow.Add((uint)count);
                    throw;
                }

                if (!sent)
                {
                    // Closed while we were writing (the peer closed the channel): the rest cannot be sent.
                    throw new SshException(SshFailureReason.ChannelClosed, "The channel was closed while data was being sent.");
                }

                Touch();
            }
            finally
            {
                Instrumentation.Returning(buffer, nameof(SendDataAsync));
                ArrayPool<byte>.Shared.Return(buffer);
            }

            data = data[count..];
        }
    }

    /// <summary>
    /// Sends EOF: no more data from us. Nothing is sent once the channel is closing: EOF after CLOSE is a protocol error, and Dropbear drops
    /// the connection for it. The check is made where the packet takes its place on the wire, because the receive loop can answer the
    /// peer's CLOSE at any moment.
    /// </summary>
    public async ValueTask SendEofAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closeSent))
        {
            return;
        }

        await _connection.SendIfAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelEof);
            w.WriteUInt32(RemoteId);
        }), _isOpenForSending, cancellationToken).ConfigureAwait(false);
    }

    // ---- receiving ----

    /// <summary>
    /// Deliver stderr separately, to <see cref="ReadExtendedAsync"/>, instead of interleaved with stdout in <see cref="ReadAsync"/>.
    /// Set before the channel's command starts.
    /// </summary>
    public bool SplitExtended { get; set; }

    /// <summary>Returns the next chunk of data, or null once the peer has sent EOF (or closed) and everything has been read.</summary>
    public ValueTask<ChannelData?> ReadAsync(CancellationToken cancellationToken) => ReadQueueAsync(_incoming, cancellationToken);

    /// <summary>With <see cref="SplitExtended"/>: the next chunk of stderr, or null at its end.</summary>
    public ValueTask<ChannelData?> ReadExtendedAsync(CancellationToken cancellationToken) => ReadQueueAsync(_extended, cancellationToken);

    /// <summary>
    /// Takes the next chunk of data if one is already queued, without waiting. False when none is (more may still come: only
    /// <see cref="ReadAsync"/> tells the end of the data, or a failure, apart from a pause).
    /// </summary>
    public bool TryRead([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ChannelData? data) => _incoming.Reader.TryRead(out data);

    /// <summary>With <see cref="SplitExtended"/>: <see cref="TryRead"/> for stderr.</summary>
    public bool TryReadExtended([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ChannelData? data) => _extended.Reader.TryRead(out data);

    // Pooled: completes asynchronously for nearly every packet, and would otherwise allocate a state machine box each time.
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    private static async ValueTask<ChannelData?> ReadQueueAsync(Channel<ChannelData> queue, CancellationToken cancellationToken)
    {
        while (await queue.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (queue.Reader.TryRead(out var item))
            {
                return item;
            }
        }

        return null;
    }

    /// <summary>Releases data nobody will read any more (the owner is done with the channel).</summary>
    public void DiscardUnread()
    {
        while (_incoming.Reader.TryRead(out var item))
        {
            item.Dispose();
        }

        while (_extended.Reader.TryRead(out var item))
        {
            item.Dispose();
        }
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
        if (adjust <= 0 || _remoteClosed || Volatile.Read(ref _closeSent))
        {
            return; // a closing channel needs no more window, and nothing may follow our CLOSE
        }

        Interlocked.Add(ref _localWindow, adjust);
        PostWindowAdjust((uint)adjust);
    }

    // A method of its own: a lambda capturing `adjust` in Consumed would allocate its closure on every call, which is every packet.
    private void PostWindowAdjust(uint adjust) => _connection.PostIf(Build(w =>
    {
        w.WriteByte(SshMessage.ChannelWindowAdjust);
        w.WriteUInt32(RemoteId);
        w.WriteUInt32(adjust);
    }), _isOpenForSending); // checked when it is sent: the receive loop may answer a CLOSE before then

    // ---- events from the connection's receive loop ----

    internal void OnOpenConfirmed(uint remoteId, uint window, uint maxPacket)
    {
        bool abandoned;
        lock (_lock)
        {
            if (_openConfirmed)
            {
                throw new SshProtocolException($"Channel {LocalId} was confirmed twice.");
            }

            RemoteId = remoteId;
            _remoteMaxPacket = Math.Min(maxPacket, (uint)MaxDataPerPacket);
            _sendWindow = new SendWindow(window);
            _openConfirmed = true;
            abandoned = _abandoned;
        }

        if (abandoned)
        {
            PostCloseOnce();
        }

        _confirmed.TrySetResult();
    }

    /// <summary>
    /// The opener gave up (cancelled) before the server answered. The channel stays registered: when the confirmation arrives it is
    /// closed straight away, and anything received meanwhile is dropped.
    /// </summary>
    internal void Abandon()
    {
        lock (_lock)
        {
            _abandoned = true;
            if (!_openConfirmed)
            {
                return;
            }
        }

        PostCloseOnce();
    }

    private void PostCloseOnce()
    {
        lock (_lock)
        {
            if (_closeSent)
            {
                return;
            }

            _closeSent = true;
        }

        _connection.Post(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelClose);
            w.WriteUInt32(RemoteId);
        }));
    }

    /// <summary>Data the peer sent that we do not deliver (an unknown extended data type): it still used the window, so give it back.</summary>
    internal void OnDiscardedData(int length)
    {
        Reserve(length);
        Consumed(length);
    }

    private int _peerStoppedReading;
    private int _discardIncoming;

    /// <summary>
    /// The peer sent <c>eow@openssh.com</c> (OpenSSH PROTOCOL 2.1): it no longer reads this channel's data (on a session, the program
    /// closed its input), so sending more would only be thrown away there.
    /// </summary>
    internal bool PeerStoppedReading => Volatile.Read(ref _peerStoppedReading) != 0;

    /// <summary>
    /// The local reader of this channel's data is gone (a session's standard output was disposed while the session goes on): what is
    /// queued and what still arrives is dropped, its window given back, and an OpenSSH peer is asked to stop sending
    /// (<c>eow@openssh.com</c>, as ssh sends when its local output closes; only to OpenSSH, as some others abort on it).
    /// </summary>
    internal void StopReceiving()
    {
        if (Interlocked.Exchange(ref _discardIncoming, 1) != 0)
        {
            return;
        }

        DrainIncoming();

        if (_connection.PeerIsOpenSsh)
        {
            _connection.PostIf(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelRequest);
                w.WriteUInt32(RemoteId);
                w.WriteString("eow@openssh.com");
                w.WriteBoolean(false);
            }), _isOpenForSending);
        }
    }

    /// <summary>Releases what is queued for a reader that is gone, giving its window back.</summary>
    private void DrainIncoming()
    {
        while (_incoming.Reader.TryRead(out var item))
        {
            item.Dispose();
        }
    }

    internal static byte[] BuildOpenFailure(uint recipientChannel, ChannelOpenFailureReason reason, string description) => Build(w =>
    {
        w.WriteByte(SshMessage.ChannelOpenFailure);
        w.WriteUInt32(recipientChannel);
        w.WriteUInt32((uint)reason);
        w.WriteString(description);
        w.WriteString(string.Empty);
    });

    internal void OnOpenFailed(uint reason, string description) =>
        _confirmed.TrySetException(new SshException(SshFailureReason.ChannelClosed, $"The server refused to open the channel (reason {reason}): {description}"));

    internal void OnWindowAdjust(uint bytes) => _sendWindow.Add(bytes);

    internal void OnData(DecodedPacket packet, int offset, int length, bool isExtended)
    {
        Touch();
        try
        {
            Reserve(length);
        }
        catch
        {
            packet.Dispose();
            throw;
        }

        // Nobody will read an abandoned channel; don't hold its buffers until it closes.
        var queue = isExtended && SplitExtended ? _extended : _incoming;
        if (queue == _incoming && Volatile.Read(ref _discardIncoming) != 0)
        {
            // Its reader is gone (StopReceiving): dropped, and the window given back as if read, until the peer stops sending.
            packet.Dispose();
            Consumed(length);
            return;
        }

        if (_abandoned || !queue.Writer.TryWrite(new ChannelData(this, packet, offset, length, isExtended)))
        {
            packet.Dispose();
        }
        else if (queue == _incoming && Volatile.Read(ref _discardIncoming) != 0)
        {
            // StopReceiving ran between the check above and the write, and drained before this chunk was queued: drop it too, or it would
            // hold its buffer and its share of the window until the channel closes.
            DrainIncoming();
        }
    }

    /// <summary>Takes received bytes out of our window, or fails if the peer sent more than it allows.</summary>
    private void Reserve(int length)
    {
        if (length > LocalMaxPacketSize || length > Interlocked.Read(ref _localWindow))
        {
            throw new SshProtocolException("The peer sent more channel data than the window or maximum packet size allows.");
        }

        Interlocked.Add(ref _localWindow, -length);
    }

    internal void OnEof()
    {
        _incoming.Writer.TryComplete();
        _extended.Writer.TryComplete();
    }

    internal void OnClose()
    {
        _remoteClosed = true;
        _incoming.Writer.TryComplete();
        _extended.Writer.TryComplete();

        // Reply to the peer's CLOSE (once), without waiting: this runs on the receive loop.
        var reply = false;
        lock (_lock)
        {
            if (!_closeSent)
            {
                _closeSent = true;
                reply = true;
            }
        }

        if (reply)
        {
            _connection.Post(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelClose);
                w.WriteUInt32(RemoteId);
            }));
        }

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

    internal void OnRequest(string type, bool wantReply, ReadOnlyMemory<byte> body)
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
                    // RFC 4254 6.10: signal name, core dumped, error message, language tag (ignored). The name is what matters: a flag or
                    // message that is missing or malformed (the message is the server's free text, and must be UTF-8) leaves those
                    // fields unset rather than losing the signal.
                    ExitSignal = ReadExitSignal(ref reader);
                    handled = true;
                    break;
                case "eow@openssh.com":
                    Volatile.Write(ref _peerStoppedReading, 1);
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
            _connection.Post(Build(w =>
            {
                w.WriteByte(handled ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure);
                w.WriteUInt32(RemoteId);
            }));
        }
    }
    /// <summary>The longest signal name kept (RFC 4254's names are a few letters; extension names add an <c>@domain</c>).</summary>
    private const int MaxSignalNameLength = 64;

    /// <summary>Parses <c>exit-signal</c>; only the signal name is required (a bad name is a protocol error, as before).</summary>
    private static SshExitSignal ReadExitSignal(ref SshReader reader)
    {
        // A signal name is a short word (TERM, KILL, or a vendor's name@domain); it is logged, so no control characters and no essay.
        var raw = reader.ReadUtf8String();
        var name = new string(raw.Where(c => !char.IsControl(c)).Take(MaxSignalNameLength).ToArray());
        var coreDumped = false;
        string? message = null;
        try
        {
            coreDumped = !reader.Remaining.IsEmpty && reader.ReadBoolean();
            message = reader.Remaining.IsEmpty ? null : reader.ReadUtf8String();
        }
        catch (SshProtocolException)
        {
            // Truncated, or not UTF-8: keep what was read.
        }

        return new SshExitSignal(name, coreDumped, string.IsNullOrEmpty(message) ? null : message);
    }

    /// <summary>The connection failed: wake everything that is waiting.</summary>
    internal void Fail(Exception exception)
    {
        _confirmed.TrySetException(exception);
        _incoming.Writer.TryComplete(exception);
        _extended.Writer.TryComplete(exception);
        _sendWindow.Fail(exception);
        FailReplies(exception);
        _closed.TrySetException(exception);

        // Nobody may be waiting on these; mark the exceptions observed so they are not reported as unobserved.
        _ = _confirmed.Task.Exception;
        _ = _closed.Task.Exception;
    }

    private void FailReplies(Exception exception)
    {
        lock (_lock)
        {
            _repliesFailure ??= exception;
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