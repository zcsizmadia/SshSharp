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
    private bool _closing; // set when DisposeAsync starts: failures after that are the client's own doing

    private readonly ILogger _logger;

    // Replies generated while receiving (CLOSE, request replies, window adjustments, UNIMPLEMENTED) are queued here and sent by their own task.
    // The receive loop must never wait on a send: while a key re-exchange is running, application sends wait for it to finish, and only the
    // receive loop can finish it, so a loop that sent directly would wait on itself (or on a peer that is blocked the same way).
    private readonly Channel<(byte[] Payload, Func<bool>? Condition)> _outbox =
        Channel.CreateUnbounded<(byte[] Payload, Func<bool>? Condition)>(new UnboundedChannelOptions { SingleReader = true });

    private Task? _outboxLoop;

    // Global requests are answered in order (RFC 4254 section 4), so waiters are queued exactly when their request is committed to the wire.
    private readonly Queue<TaskCompletionSource<GlobalReply>> _globalReplies = new();
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource> _pings = new();
    private long _pingCounter;
    private long _queuedPongBytes;
    private const long MaxQueuedPongBytes = 256 * 1024;
    private readonly CancellationTokenSource _closed = new();
    private readonly TimeProvider _time;
    private long _lastReceived;
    private Task? _keepAliveLoop;
    private Task? _channelTimeoutLoop;

    /// <summary>The clock for keep-alives and channel timeouts; replaceable in tests.</summary>
    internal TimeProvider Time => _time;

    public SshConnection(SshTransport transport, ILogger? logger = null, TimeProvider? timeProvider = null)
    {
        _transport = transport;
        _logger = logger ?? NullLogger.Instance;
        _time = timeProvider ?? TimeProvider.System;
        _lastReceived = _time.GetTimestamp();
        _transport.KeyReexchanged = ResendPings;
    }

    /// <summary>
    /// After a key re-exchange: the pings still waiting for a pong are sent again, since OpenSSH drops a PING that arrives during a key
    /// exchange and never answers it. They keep their numbers, so a late pong to the first one and the pong to the second complete the
    /// same wait; the extra one is ignored.
    /// </summary>
    private void ResendPings()
    {
        foreach (var id in _pings.Keys)
        {
            Instrumentation.Trace($"kex: ping {id} sent again after the re-exchange");
            Post(PingMessage(id));
        }
    }

    /// <summary>How many key exchanges have completed, including the first.</summary>
    public int KeyExchangeCount => _transport.KeyExchangeCount;

    /// <summary>The window each channel advertises (<see cref="SshClientOptions.ChannelWindowSize"/>).</summary>
    public uint ChannelWindowSize { get; init; } = SshChannel.DefaultWindowSize;

    /// <summary>The largest data packet each channel accepts (<see cref="SshClientOptions.ChannelMaxPacketSize"/>); at most the window.</summary>
    public uint ChannelMaxPacketSize { get; init; } = SshChannel.DefaultMaxPacketSize;

    /// <summary>Message payload bytes sent over the connection's life.</summary>
    public long BytesSent => _transport.BytesSent;

    /// <summary>Message payload bytes received over the connection's life.</summary>
    public long BytesReceived => _transport.BytesReceived;

    /// <summary>Re-exchanges keys now and completes when the new keys are in use both ways (see <see cref="SshTransport.RekeyAsync"/>).</summary>
    public async Task RekeyAsync(CancellationToken cancellationToken)
    {
        if (_failure is { } failure)
        {
            throw failure;
        }

        try
        {
            await _transport.RekeyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            throw SendFailed(ex);
        }
    }

    /// <summary>Why the connection ended, if it did.</summary>
    public Exception? Failure => _failure;

    /// <summary>Called on the receive loop with the host keys a server announces (<c>hostkeys-00@openssh.com</c>); must not block.</summary>
    public Action<IReadOnlyList<byte[]>>? HostKeysAnnounced { get; set; }

    /// <summary>The session identifier (the first exchange hash), which host key proofs are bound to.</summary>
    public ReadOnlyMemory<byte> SessionId => _transport.SessionId;

    /// <summary>When the last packet arrived (a <see cref="TimeProvider"/> timestamp), for tests.</summary>
    internal long LastReceived => Interlocked.Read(ref _lastReceived);

    /// <summary>The extensions the server announced in <c>SSH_MSG_EXT_INFO</c> (RFC 8308).</summary>
    internal IReadOnlyDictionary<string, string> ServerExtensions => _transport.ServerExtensions;

    /// <summary>The algorithms in use now (updated by each key re-exchange).</summary>
    internal NegotiatedAlgorithms Algorithms => _transport.Algorithms!;

    /// <summary>Cancelled when the connection ends, for any reason (see <see cref="Failure"/>).</summary>
    public CancellationToken Closed => _closed.Token;

    /// <summary>Starts the receive loop. Call once, after authentication succeeded.</summary>
    public void Start()
    {
        _loop = Task.Run(RunAsync);
        _outboxLoop = Task.Run(RunOutboxAsync);
    }

    /// <summary>
    /// Starts sending <c>keepalive@openssh.com</c> when the server has been silent for <paramref name="interval"/>, like OpenSSH's
    /// <c>ServerAliveInterval</c>. After <paramref name="countMax"/> silent intervals in a row the connection is declared dead.
    /// </summary>
    public void StartKeepAlive(TimeSpan interval, int countMax)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfNegative(countMax);
        _keepAliveLoop = Task.Run(() => RunKeepAliveAsync(interval, countMax));
    }

    /// <summary>
    /// Starts closing channels that carry no data for the timeout their type has under <paramref name="timeouts"/>, as OpenSSH's
    /// <c>ChannelTimeout</c> does on the client. Nothing starts when no entry sets a timeout.
    /// </summary>
    public void StartChannelTimeouts(IReadOnlyList<SshChannelTimeout> timeouts)
    {
        var shortest = timeouts.Where(t => t.Timeout > TimeSpan.Zero).Select(t => t.Timeout).DefaultIfEmpty().Min();
        if (shortest <= TimeSpan.Zero)
        {
            return;
        }

        // Checked four times per shortest timeout, so a channel is closed between 1 and 1.25 times its timeout after its last data.
        var period = TimeSpan.FromTicks(Math.Max(shortest.Ticks / 4, TimeSpan.FromMilliseconds(10).Ticks));
        _channelTimeoutLoop = Task.Run(() => RunChannelTimeoutsAsync(timeouts, period));
    }

    private async Task RunChannelTimeoutsAsync(IReadOnlyList<SshChannelTimeout> timeouts, TimeSpan period)
    {
        try
        {
            while (true)
            {
                await Task.Delay(period, _time, _stop.Token).ConfigureAwait(false);
                foreach (var channel in _channels.Values)
                {
                    if (channel.TimeoutType is not { } type || !channel.IsOpenForTimeout || SshChannelTimeout.For(timeouts, type) is not { } limit
                        || _time.GetElapsedTime(channel.LastActivity) < limit)
                    {
                        continue;
                    }

                    // As OpenSSH: an ordinary close. The peer answers with its CLOSE, which ends the channel's streams; forwarded and
                    // tunnelled connections close their local sockets with it.
                    SshLog.ChannelTimedOut(_logger, channel.LocalId, type, (int)limit.TotalSeconds);
                    _ = channel.CloseAsync(CancellationToken.None).AsTask().ContinueWith(static t => _ = t.Exception, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default); // a close racing the connection's end has nobody to tell
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    /// <summary>
    /// Sends a global request (RFC 4254 section 4). With <paramref name="wantReply"/>, waits for the server's answer and returns it;
    /// otherwise returns a success at once.
    /// </summary>
    public async Task<GlobalReply> SendGlobalRequestAsync(string name, bool wantReply, Action<SshWriter>? body, CancellationToken cancellationToken)
    {
        var reply = wantReply ? new TaskCompletionSource<GlobalReply>(TaskCreationOptions.RunContinuationsAsynchronously) : null;
        await SendAsync(
            Build(w =>
            {
                w.WriteByte(SshMessage.GlobalRequest);
                w.WriteString(name);
                w.WriteBoolean(wantReply);
                body?.Invoke(w);
            }),
            reply is null ? null : () => EnqueueGlobalReply(reply),
            cancellationToken).ConfigureAwait(false);
        return reply is null ? new GlobalReply(true, []) : await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Whether the server answers transport pings (it announced <c>ping@openssh.com</c> version 0 in EXT_INFO).</summary>
    internal bool SupportsPing => ServerExtensions.TryGetValue("ping@openssh.com", out var version) && version == "0";

    /// <summary>
    /// Measures a round trip to the server: an OpenSSH transport ping (<c>ping@openssh.com</c>) where the server announces it, otherwise
    /// a <c>keepalive@openssh.com</c> global request, whose answer (a refusal, usually) arrives just as fast.
    /// </summary>
    public async Task<TimeSpan> PingAsync(CancellationToken cancellationToken)
    {
        var started = _time.GetTimestamp();
        if (!SupportsPing)
        {
            await SendGlobalRequestAsync("keepalive@openssh.com", wantReply: true, null, cancellationToken).ConfigureAwait(false);
            return _time.GetElapsedTime(started);
        }

        // Each ping carries its own number, so concurrent pings are told apart by their pongs (which echo it).
        var id = (ulong)Interlocked.Increment(ref _pingCounter);
        var pong = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _pings[id] = pong;
        try
        {
            if (_failure is { } failure)
            {
                throw failure;
            }

            Instrumentation.Trace($"kex: ping {id} sending");
            await SendAsync(PingMessage(id), cancellationToken).ConfigureAwait(false);
            Instrumentation.Trace($"kex: ping {id} sent");
            await pong.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return _time.GetElapsedTime(started);
        }
        finally
        {
            _pings.TryRemove(id, out _);
        }
    }

    /// <summary>Whether a key re-exchange is running.</summary>
    internal bool IsRekeying => _transport.IsRekeying;

    /// <summary>
    /// Queues a chaff packet for <see cref="KeystrokeTimingObfuscator"/>: a PING the size of a one-keystroke CHANNEL_DATA, as OpenSSH's
    /// <c>ObscureKeystrokeTiming</c> sends (its 5-byte data, unlike our pings' 8, makes the pong one nobody waits for). False when the
    /// server does not answer pings, which then gets no chaff.
    /// </summary>
    internal bool PostChaff()
    {
        if (!SupportsPing || _failure is not null)
        {
            return false;
        }

        // Fixed size: byte, then the string "PING!" (length and bytes), written directly.
        var chaff = new byte[1 + 4 + 5];
        chaff[0] = SshMessage.Ping;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(chaff.AsSpan(1), 5);
        "PING!"u8.CopyTo(chaff.AsSpan(5));
        Post(chaff);
        return true;
    }

    /// <summary>SSH2_MSG_PING with an 8-byte number as its data (0 for keep-alive probes, which nobody waits for).</summary>
    private static byte[] PingMessage(ulong id)
    {
        // Fixed size: byte, then a string of 8 bytes (length and bytes), written directly.
        var message = new byte[1 + 4 + 8];
        message[0] = SshMessage.Ping;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(1), 8);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(message.AsSpan(5), id);
        return message;
    }

    private void EnqueueGlobalReply(TaskCompletionSource<GlobalReply> reply)
    {
        lock (_globalReplies)
        {
            if (_failure is { } failure)
            {
                reply.TrySetException(failure);
                return;
            }

            _globalReplies.Enqueue(reply);
        }
    }

    private void CompleteGlobalReply(GlobalReply result)
    {
        TaskCompletionSource<GlobalReply>? reply;
        lock (_globalReplies)
        {
            // A reply nobody asked for is ignored, as OpenSSH's client does.
            _globalReplies.TryDequeue(out reply);
        }

        reply?.TrySetResult(result);
    }

    private async Task RunKeepAliveAsync(TimeSpan interval, int countMax)
    {
        var missed = 0;
        var lastTick = _time.GetTimestamp();
        try
        {
            while (true)
            {
                await Task.Delay(interval, _time, _stop.Token).ConfigureAwait(false);
                var received = Interlocked.Read(ref _lastReceived);
                if (received >= lastTick)
                {
                    missed = 0; // the server spoke since the last tick (an answer to the last probe counts)
                }

                lastTick = _time.GetTimestamp();
                if (_time.GetElapsedTime(received) < interval)
                {
                    continue; // recent traffic: no probe needed
                }

                if (++missed > countMax)
                {
                    var dead = new SshException(SshFailureReason.Timeout, $"The server did not respond to {countMax} keep-alive messages.");
                    SshLog.ConnectionFailed(_logger, dead);
                    Fail(dead);
                    await _stop.CancelAsync().ConfigureAwait(false);
                    return;
                }

                // Any packet from the server counts as an answer; the reply itself is not awaited (a dead server never sends it). A transport
                // ping where the server has one (cheaper, and answered by servers whose global-request replies get lost), otherwise the
                // keepalive@openssh.com global request, as OpenSSH's client sends.
                if (SupportsPing)
                {
                    Post(PingMessage(0));
                }
                else
                {
                    var probe = SendGlobalRequestAsync("keepalive@openssh.com", wantReply: true, null, _stop.Token);
                    _ = probe.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            // Shutting down.
        }
        catch (SshException)
        {
            // The connection failed while sending; the receive loop reports why.
        }
    }

    /// <summary>Queues a message to be sent without waiting. For use from the receive loop and from synchronous callbacks.</summary>
    internal void Post(byte[] payload) => _outbox.Writer.TryWrite((payload, null));

    /// <summary>Queues a message that is sent only if <paramref name="condition"/> still holds when its turn comes (see <see cref="SendIfAsync"/>).</summary>
    internal void PostIf(byte[] payload, Func<bool> condition) => _outbox.Writer.TryWrite((payload, condition));

    /// <summary>Sends a message, or throws if the connection has failed.</summary>
    public ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) => SendAsync(payload, null, cancellationToken);

    /// <summary>Sends a message; <paramref name="onCommitted"/> runs once the message has its place on the wire.</summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, Action? onCommitted, CancellationToken cancellationToken)
    {
        if (_failure is { } failure)
        {
            throw failure;
        }

        try
        {
            await _transport.SendAsync(payload, onCommitted, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            throw SendFailed(ex);
        }
    }

    /// <summary>Sends a message only if <paramref name="condition"/> holds when it takes its place on the wire (see <see cref="SshTransport.SendIfAsync"/>).</summary>
    public ValueTask<bool> SendIfAsync(ReadOnlyMemory<byte> payload, Func<bool> condition, CancellationToken cancellationToken) =>
        SendIfCoreAsync(null, payload, condition, cancellationToken);

    /// <summary>
    /// Sends <c>SSH_MSG_CHANNEL_DATA</c> carrying <paramref name="data"/> to <paramref name="recipientChannel"/>, only if
    /// <paramref name="condition"/> holds when it takes its place on the wire (see <see cref="SshTransport.SendDataIfAsync"/>).
    /// </summary>
    public ValueTask<bool> SendDataIfAsync(uint recipientChannel, ReadOnlyMemory<byte> data, Func<bool> condition, CancellationToken cancellationToken) =>
        SendIfCoreAsync(recipientChannel, data, condition, cancellationToken);

    // Pooled: every data packet comes this way, and it completes asynchronously whenever the transport does.
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<bool> SendIfCoreAsync(uint? dataRecipient, ReadOnlyMemory<byte> payload, Func<bool> condition, CancellationToken cancellationToken)
    {
        if (_failure is { } failure)
        {
            throw failure;
        }

        try
        {
            return dataRecipient is { } recipient
                ? await _transport.SendDataIfAsync(recipient, payload, condition, cancellationToken).ConfigureAwait(false)
                : await _transport.SendIfAsync(payload, condition, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            throw SendFailed(ex);
        }
    }

    /// <summary>
    /// A send failed in the stream, so the connection is gone: it fails now, as when the outbox's send fails, before the caller hears of
    /// it. Otherwise <see cref="SshClient.IsConnected"/> would stay true until the receive loop noticed, and the caller of a command
    /// that failed this way could still find the client connected.
    /// </summary>
    private SshException SendFailed(IOException exception)
    {
        var lost = ConnectionLost(exception);
        if (Volatile.Read(ref _failure) is null && !Volatile.Read(ref _closing))
        {
            SshLog.ConnectionFailed(_logger, lost); // once, not for every send that fails after it
        }

        Fail(lost);
        return lost;
    }

    /// <summary>A failure of the underlying stream, as the <see cref="SshException"/> callers handle.</summary>
    internal static SshException ConnectionLost(Exception inner) =>
        new(SshFailureReason.ConnectionClosed, "The connection was lost: " + inner.Message, inner);

    /// <summary>
    /// Decides on channels the server opens: given the channel type and its type-specific data, returns what to run with the open channel,
    /// or null to refuse it. Runs on the receive loop, so it must decide without blocking; the returned action runs once the channel is
    /// confirmed.
    /// </summary>
    public Func<string, byte[], Action<SshChannel>?>? AcceptChannel { get; set; }

    /// <summary>What <see cref="AcceptChannel"/> returns to refuse a channel for lack of resources (too many open), not as unsupported.</summary>
    public static readonly Action<SshChannel> RefuseResourceShortage = _ => { };

    /// <summary>Opens a <c>session</c> channel.</summary>
    public Task<SshChannel> OpenSessionAsync(CancellationToken cancellationToken) => Volatile.Read(ref _noMoreSessions)
        ? Task.FromException<SshChannel>(new NoMoreSessionsException())
        : OpenChannelAsync("session", null, cancellationToken);

    private bool _noMoreSessions;

    /// <summary>The software part of the server's identification line (<c>OpenSSH_9.9</c>, <c>AsyncSSH_2.21.0</c>), for quirks by server.</summary>
    internal string? ServerSoftware => _transport.ServerIdentification?.SoftwareVersion;

    /// <summary>Whether the server is OpenSSH (its identification line says so), for extensions OpenSSH sends only to OpenSSH peers.</summary>
    internal bool PeerIsOpenSsh => _transport.ServerIdentification?.SoftwareVersion.StartsWith("OpenSSH", StringComparison.Ordinal) == true;

    /// <summary>
    /// <c>no-more-sessions@openssh.com</c> (OpenSSH PROTOCOL 2.2): from now on this connection opens no session channels, and an OpenSSH
    /// server is told to refuse any (it then drops the connection), so a compromised process using this client cannot quietly open one.
    /// As in OpenSSH, only OpenSSH servers are sent the request: some others abort on it. Returns whether the server was told.
    /// </summary>
    public async Task<bool> PreventNewSessionsAsync(CancellationToken cancellationToken)
    {
        Volatile.Write(ref _noMoreSessions, true);
        if (!PeerIsOpenSsh)
        {
            return false;
        }

        await SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.GlobalRequest);
            w.WriteString("no-more-sessions@openssh.com");
            w.WriteBoolean(false);
        }), cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Opens a <c>direct-tcpip</c> channel (RFC 4254 section 7.2): the server connects to <paramref name="host"/>:<paramref name="port"/>
    /// and relays. This is what ProxyJump and local port forwarding use.
    /// </summary>
    public Task<SshChannel> OpenDirectTcpIpAsync(string host, int port, string originatorAddress, int originatorPort, CancellationToken cancellationToken) =>
        OpenChannelAsync("direct-tcpip", w =>
        {
            w.WriteString(host);
            w.WriteUInt32((uint)port);
            w.WriteString(originatorAddress);
            w.WriteUInt32((uint)originatorPort);
        }, cancellationToken);

    /// <summary>
    /// Opens a <c>direct-streamlocal@openssh.com</c> channel (OpenSSH PROTOCOL 2.4): the server connects to the Unix domain socket at
    /// <paramref name="path"/> and relays.
    /// </summary>
    public Task<SshChannel> OpenDirectStreamLocalAsync(string path, CancellationToken cancellationToken) =>
        OpenChannelAsync("direct-streamlocal@openssh.com", w =>
        {
            w.WriteString(path);
            w.WriteString(string.Empty); // reserved
            w.WriteUInt32(0); // reserved
        }, cancellationToken);

    private async Task<SshChannel> OpenChannelAsync(string type, Action<SshWriter>? typeSpecificData, CancellationToken cancellationToken)
    {
        if (_failure is { } failure)
        {
            throw failure;
        }

        var channel = new SshChannel(this, Interlocked.Increment(ref _nextChannelId) - 1) { TimeoutType = type };
        _channels[channel.LocalId] = channel;

        // Fail sets _failure before it walks _channels: if it ran before the add above, it missed this channel, so check again.
        if (Volatile.Read(ref _failure) is { } late)
        {
            _channels.TryRemove(channel.LocalId, out _);
            throw late;
        }

        try
        {
            await channel.OpenAsync(type, typeSpecificData, cancellationToken).ConfigureAwait(false);
            if (channel.TryMarkOpen())
            {
                SshTelemetry.Channels.Add(1);
                SshLog.ChannelOpened(_logger, channel.LocalId);
            }

            return channel;
        }
        catch (OperationCanceledException)
        {
            // The server may still confirm the open: keep the channel registered so its messages are recognised, and close it when it does.
            channel.Abandon();
            throw;
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
        // The loops see that failure too; it is the client closing, not the connection failing, so they must not log it as an error.
        SshLog.Disconnecting(_logger);
        Volatile.Write(ref _closing, true);
        Fail(new SshException(SshFailureReason.ConnectionClosed, "The connection was closed by the client."));
        _outbox.Writer.TryComplete();
        await _stop.CancelAsync().ConfigureAwait(false);

        // Saying goodbye is best effort: a peer that stopped reading must not keep us here.
        using (var timeout = new CancellationTokenSource(DisconnectTimeout))
        {
            try
            {
                await _transport.DisconnectAsync(DisconnectReason.ByApplication, "disconnected by user", timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
                // Already disconnected, the socket is gone, or the peer is not reading.
            }
        }

        // Stop pending reads and flushes, wait for both loops to leave the transport, and only then release it.
        _transport.Abort();
        await WaitQuietlyAsync(_loop).ConfigureAwait(false);
        await WaitQuietlyAsync(_outboxLoop).ConfigureAwait(false);
        await WaitQuietlyAsync(_keepAliveLoop).ConfigureAwait(false);
        await WaitQuietlyAsync(_channelTimeoutLoop).ConfigureAwait(false);
        await _transport.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
    }

    /// <summary>How long <see cref="DisposeAsync"/> waits to send <c>SSH_MSG_DISCONNECT</c>.</summary>
    internal static TimeSpan DisconnectTimeout { get; set; } = TimeSpan.FromSeconds(2);

    private static async Task WaitQuietlyAsync(Task? task)
    {
        if (task is null)
        {
            return;
        }

        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown.
        }
    }

    private async Task RunOutboxAsync()
    {
        try
        {
            await foreach (var (payload, condition) in _outbox.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                if (condition is null)
                {
                    await _transport.SendAsync(payload, _stop.Token).ConfigureAwait(false);
                }
                else
                {
                    await _transport.SendIfAsync(payload, condition, _stop.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            // Shutting down.
        }
        catch (Exception) when (Volatile.Read(ref _closing))
        {
            // The client is closing the connection: sends fail on purpose.
        }
        catch (Exception ex)
        {
            // Window adjustments and CLOSE replies can no longer be sent, so every channel would stall: end the connection now.
            SshLog.ConnectionFailed(_logger, ex);
            Fail(ex as SshException ?? ConnectionLost(ex));
            try
            {
                await _stop.CancelAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                // Already disposed.
            }
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                var packet = await _transport.ReceiveAsync(_stop.Token).ConfigureAwait(false);
                Interlocked.Exchange(ref _lastReceived, _time.GetTimestamp());
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
            if (ex is not OperationCanceledException && !Volatile.Read(ref _closing))
            {
                SshLog.ConnectionFailed(_logger, ex);
            }

            Fail(ex switch
            {
                OperationCanceledException => new SshException(SshFailureReason.ConnectionClosed, "The connection was closed."),
                SshException => ex,
                _ => ConnectionLost(ex), // IOException, or ObjectDisposedException when a caller-owned stream is disposed underneath
            });
        }
    }

    private void Fail(Exception exception)
    {
        Interlocked.CompareExchange(ref _failure, exception, null);

        // Closed is signalled before any waiting operation fails: a caller resuming from a failed command or read can rely on
        // ConnectionClosed being cancelled already, as IsConnected is already false.
        try
        {
            _closed.Cancel();
        }
        catch (AggregateException ex)
        {
            // A callback registered by the application threw; the connection is closed regardless.
            SshLog.ConnectionFailed(_logger, ex);
        }

        // Senders waiting for a key re-exchange that can no longer finish are released, and later sends refused.
        _transport.Fail(exception);
        foreach (var channel in _channels.Values)
        {
            ChannelGone(channel);
            channel.Fail(exception);
        }

        lock (_globalReplies)
        {
            while (_globalReplies.TryDequeue(out var reply))
            {
                reply.TrySetException(exception);
                _ = reply.Task.Exception; // observed: the keep-alive does not wait for its replies
            }
        }

        // A ping registers before it checks for a failure, so either it sees the failure or the failure reaches it here.
        foreach (var ping in _pings.Values)
        {
            ping.TrySetException(exception);
        }
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(64);
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
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
            {
                var name = reader.ReadUtf8String();
                var wantReply = reader.ReadBoolean();
                if (name == "hostkeys-00@openssh.com" && !wantReply && HostKeysAnnounced is { } announced)
                {
                    // OpenSSH's UpdateHostKeys (PROTOCOL 2.5): the server lists all its host keys after authentication.
                    var keys = new List<byte[]>();
                    while (!reader.IsEmpty && keys.Count < 64)
                    {
                        keys.Add(reader.ReadString().ToArray());
                    }

                    announced(keys);
                }
                else if (wantReply)
                {
                    Post([SshMessage.RequestFailure]);
                }

                return false;
            }

            case SshMessage.RequestSuccess or SshMessage.RequestFailure:
                CompleteGlobalReply(new GlobalReply(type == SshMessage.RequestSuccess, reader.Remaining.ToArray()));
                return false;

            case SshMessage.Ping:
            {
                // PROTOCOL 1.8: the pong echoes the ping's data. A server that pings but does not read would grow the outbox by what it
                // sends, so pongs not yet sent are capped; the pings past that go unanswered, which only a misbehaving server notices.
                var data = reader.ReadString().ToArray();
                var pong = Build(w =>
                {
                    w.WriteByte(SshMessage.Pong);
                    w.WriteString(data);
                });
                if (Interlocked.Add(ref _queuedPongBytes, pong.Length) <= MaxQueuedPongBytes)
                {
                    PostIf(pong, () =>
                    {
                        Interlocked.Add(ref _queuedPongBytes, -pong.Length);
                        return true;
                    });
                }
                else
                {
                    Interlocked.Add(ref _queuedPongBytes, -pong.Length);
                }

                return false;
            }

            case SshMessage.Pong:
            {
                var data = reader.ReadString();
                Instrumentation.Trace($"kex: pong ({data.Length} bytes)");
                if (data.Length == 8 && _pings.TryGetValue(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(data), out var waiting))
                {
                    waiting.TrySetResult();
                }

                return false; // a keep-alive's pong, or one nobody waits for any more: receiving it was the point
            }

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
                    // Only stderr (1) is defined. Drop anything else, but give the window back or the peer stalls.
                    channel.OnDiscardedData((int)length);
                    return false;
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

            case SshMessage.ChannelOpen:
            {
                // The server opens a channel to us (forwarded-tcpip, auth-agent@openssh.com). RFC 4254 section 5.1 requires an answer:
                // confirm it when AcceptChannel takes it, otherwise refuse rather than leave the server's channel half-open.
                var channelType = reader.ReadUtf8String();
                var senderChannel = reader.ReadUInt32();
                var window = reader.ReadUInt32();
                var maxPacket = reader.ReadUInt32();
                OnChannelOpen(channelType, senderChannel, window, maxPacket, reader.Remaining.ToArray());
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

    /// <summary>
    /// A channel the server opens. A method of its own: its lambdas capture locals, and inside Dispatch their closure would be allocated
    /// for every packet, not only for this message.
    /// </summary>
    private void OnChannelOpen(string channelType, uint senderChannel, uint window, uint maxPacket, byte[] typeSpecificData)
    {
        if (AcceptChannel?.Invoke(channelType, typeSpecificData) is not { } start)
        {
            Post(SshChannel.BuildOpenFailure(senderChannel, ChannelOpenFailureReason.AdministrativelyProhibited, "Channel type not supported."));
            return;
        }

        if (ReferenceEquals(start, RefuseResourceShortage))
        {
            Post(SshChannel.BuildOpenFailure(senderChannel, ChannelOpenFailureReason.ResourceShortage, "Too many forwarded connections."));
            return;
        }

        var accepted = new SshChannel(this, Interlocked.Increment(ref _nextChannelId) - 1)
        {
            // OpenSSH's ChannelTimeout calls both agent channel types (OpenSSH's and RFC 9987's) "agent-connection".
            TimeoutType = channelType is "auth-agent@openssh.com" or "agent-connect" ? "agent-connection" : channelType,
        };
        _channels[accepted.LocalId] = accepted;
        accepted.OnOpenConfirmed(senderChannel, window, maxPacket);
        if (accepted.TryMarkOpen())
        {
            SshTelemetry.Channels.Add(1);
            SshLog.ChannelOpened(_logger, accepted.LocalId);
        }

        // The confirmation must be on the wire before anything the handler sends on the channel, so it is sent first, not posted.
        var confirmation = SshChannel.FixedMessage(SshMessage.ChannelOpenConfirmation, senderChannel, accepted.LocalId, ChannelWindowSize,
            ChannelMaxPacketSize);
        _ = Task.Run(async () =>
        {
            try
            {
                await SendAsync(confirmation, _stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
            {
                return; // the connection is ending; the channel fails with it
            }

            start(accepted);
        }, CancellationToken.None);
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

/// <summary>
/// The refusal to open a session after <see cref="SshConnection.PreventNewSessionsAsync"/>: an <see cref="InvalidOperationException"/>, as
/// documented, of its own type so that code which falls back (a segmented download) tells it from other failures.
/// </summary>
#pragma warning disable CA1064 // callers see an InvalidOperationException; the type only lets the library tell this refusal apart
internal sealed class NoMoreSessionsException() : InvalidOperationException("No more sessions: PreventNewSessionsAsync was called on this connection.");
#pragma warning restore CA1064

/// <summary>The server's answer to a global request: success or failure, and any request-specific data (for example a bound port).</summary>
internal sealed record GlobalReply(bool Success, byte[] Data);
