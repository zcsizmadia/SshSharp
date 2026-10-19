using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>A reply from the SFTP server: its type and whole packet (type, then the request id, then the body).</summary>
/// <remarks>
/// <para>
/// A DATA reply (the answer to a READ, up to 255 KiB with OpenSSH) is read into a buffer rented from the shared pool rather than a new
/// array each time; other replies are small and get a plain array.
/// </para>
/// <para>
/// Ownership: the code a reply is handed to (the caller of <see cref="SftpChannel.RequestAsync(byte, Action{SshWriter}, CancellationToken, Action{SftpResponse}?)"/>)
/// owns it and disposes it once it is done with <see cref="Packet"/> and with every slice of it, such as the data
/// <see cref="SftpClient.ExpectData"/> returns. Disposing returns a pooled buffer, after which no slice of it may be used: the next renter
/// owns those bytes. Disposing a reply with a plain array does nothing, and a pooled reply that is never disposed only costs the pool an
/// array, so a reply is disposed when it may be DATA and need not be otherwise.
/// </para>
/// </remarks>
internal sealed class SftpResponse : IDisposable
{
    private readonly int _length;
    private readonly bool _pooled;
    private byte[]? _buffer;
#if SSHSHARP_INSTRUMENT
    private readonly ulong _checksum;
#endif

    /// <summary>A reply in a plain array: <paramref name="packet"/> is the whole packet.</summary>
    public SftpResponse(byte type, byte[] packet)
        : this(type, packet, packet.Length, pooled: false)
    {
    }

    private SftpResponse(byte type, byte[] buffer, int length, bool pooled)
    {
        Type = type;
        _buffer = buffer;
        _length = length;
        _pooled = pooled;
#if SSHSHARP_INSTRUMENT
        _checksum = pooled ? Instrumentation.Checksum(buffer.AsSpan(0, length)) : 0;
#endif
    }

    /// <summary>A reply in <paramref name="rented"/>, rented from the shared pool: its first <paramref name="length"/> bytes are the packet. The reply now owns it.</summary>
    public static SftpResponse Pooled(byte[] rented, int length) => new(rented[0], rented, length, pooled: true);

    public byte Type { get; }

    /// <summary>A reader positioned after the type and request id.</summary>
    public SshReader Body => new(Packet.Span[5..]);

    /// <summary>The packet, for slicing data out of it without a copy; a slice is valid until the reply is disposed.</summary>
    /// <exception cref="ObjectDisposedException">The reply's pooled buffer was returned.</exception>
    public ReadOnlyMemory<byte> Packet =>
        (_pooled ? Volatile.Read(ref _buffer) : _buffer) is { } buffer ? buffer.AsMemory(0, _length) : throw new ObjectDisposedException(nameof(SftpResponse));

    /// <summary>Returns a pooled buffer (once; later calls, and calls on a reply in a plain array, do nothing).</summary>
    public void Dispose()
    {
        if (!_pooled || Interlocked.Exchange(ref _buffer, null) is not { } buffer)
        {
            return;
        }

#if SSHSHARP_INSTRUMENT
        Instrumentation.CheckUnchanged(buffer.AsSpan(0, _length), _checksum, nameof(SftpResponse));
        buffer.AsSpan(0, _length).Fill(0xDD); // whatever still reads a slice of it now reads this pattern, which content checks catch
#endif
        Instrumentation.Returning(buffer, nameof(SftpResponse));
        ArrayPool<byte>.Shared.Return(buffer);
    }
}

/// <summary>
/// The SFTP packet layer over a <c>sftp</c> subsystem session: <c>uint32 length || byte type || uint32 id || body</c>. Requests are
/// numbered and may be in flight together; a read loop matches each reply to its request by id, so pipelined reads and writes and
/// concurrent callers all work, and replies may come in any order (the draft allows it).
/// </summary>
internal sealed class SftpChannel : IAsyncDisposable
{
    private readonly SshSession _session;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<SftpResponse>> _pending = new();
    private readonly CancellationTokenSource _stop = new();

    // A packet's length and type. Only one read of a packet is ever in progress (OpenAsync's, then the read loop's), so it is reused.
    private readonly byte[] _header = new byte[5];
    private readonly Task _errorDrain;
    private Task _readLoop = Task.CompletedTask;
    private Exception? _failure;
    private int _nextId;
    private int _disposed;

    // OperationTimeout in ticks (negative: none), and when the server last sent anything (a timestamp of _clock).
    private long _timeoutTicks = Timeout.InfiniteTimeSpan.Ticks;
    private TimeProvider _clock = TimeProvider.System;
    private long _lastReceived = TimeProvider.System.GetTimestamp();

    private SftpChannel(SshSession session)
    {
        _session = session;

        // The subsystem's stderr (sftp-server -e logs there) shares the channel window with the replies: unread, every byte of it would
        // shrink the window for good, until the server could not answer at all. It is read and dropped.
        _errorDrain = DrainAsync(session.StandardError);
    }

    /// <summary>The server's protocol version (3 for OpenSSH).</summary>
    public uint Version { get; private set; }

    /// <summary>The extensions the server announced in SSH_FXP_VERSION, with their data (usually a version number).</summary>
    public IReadOnlyDictionary<string, string> Extensions { get; private set; } = new Dictionary<string, string>();

    /// <summary>
    /// How long a request may wait for its reply, for its turn to be sent, or for its send to complete, while the server sends nothing
    /// at all (<see cref="Timeout.InfiniteTimeSpan"/>: no limit). See <see cref="SftpClient.OperationTimeout"/>.
    /// </summary>
    public TimeSpan OperationTimeout
    {
        get => TimeSpan.FromTicks(Volatile.Read(ref _timeoutTicks));
        set => Volatile.Write(ref _timeoutTicks, value.Ticks);
    }

    /// <summary>
    /// The clock <see cref="OperationTimeout"/> is measured with (the connection's <c>SshClientOptions.TimeProvider</c>). Setting it
    /// starts the measure of the server's silence again, on the new clock.
    /// </summary>
    public TimeProvider Clock
    {
        get => Volatile.Read(ref _clock);
        set
        {
            Volatile.Write(ref _clock, value);
            Volatile.Write(ref _lastReceived, value.GetTimestamp());
        }
    }

    /// <summary>
    /// Whether the channel has failed or been disposed: the session or the connection under it ended, the server broke the protocol, or
    /// a request could not be sent within <see cref="OperationTimeout"/> (also one whose caller stopped waiting), or a send failed. Every
    /// request fails from then on.
    /// </summary>
    public bool IsClosed => Volatile.Read(ref _failure) is not null;

    /// <summary>Sends SSH_FXP_INIT, reads SSH_FXP_VERSION, and starts matching replies to requests.</summary>
    public static async Task<SftpChannel> OpenAsync(SshSession session, CancellationToken cancellationToken)
    {
        var channel = new SftpChannel(session);
        try
        {
            // SSH_FXP_INIT has no request id: uint32 length (5), byte type, uint32 version.
            var init = new byte[9];
            BinaryPrimitives.WriteUInt32BigEndian(init, 5);
            init[4] = SftpProtocol.Init;
            BinaryPrimitives.WriteUInt32BigEndian(init.AsSpan(5), SftpProtocol.Version);
            await channel.SendAsync(init, cancellationToken).ConfigureAwait(false);

            using var version = await channel.ReadPacketAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new SshException(SshFailureReason.ProtocolError, "The SFTP server closed the session before saying its version.");
            (channel.Version, channel.Extensions) = ParseVersion(version.Packet.Span);
            channel._readLoop = Task.Run(channel.ReadLoopAsync, CancellationToken.None);
            return channel;
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>SSH_FXP_VERSION: the server's version and its extensions.</summary>
    internal static (uint Version, IReadOnlyDictionary<string, string> Extensions) ParseVersion(ReadOnlySpan<byte> packet)
    {
        try
        {
            var reader = new SshReader(packet);
            if (reader.ReadByte() != SftpProtocol.VersionReply)
            {
                throw new SshException(SshFailureReason.ProtocolError, "The SFTP server did not answer with its version.");
            }

            var version = reader.ReadUInt32();
            if (version < SftpProtocol.Version)
            {
                throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server speaks version {version}; version 3 is needed.");
            }

            // Extension data is defined per extension and may be binary: it is decoded leniently (invalid bytes become U+FFFD) rather than
            // failing the session over an extension this client does not use.
            var extensions = new Dictionary<string, string>(StringComparer.Ordinal);
            while (!reader.IsEmpty)
            {
                var name = Lenient(reader.ReadString());
                extensions[name] = Lenient(reader.ReadString());
            }

            return (version, extensions);
        }
        catch (SshProtocolException ex)
        {
            throw new SshException(SshFailureReason.ProtocolError, "The SFTP server's version message is malformed.", ex);
        }
    }

    /// <summary>UTF-8 with invalid bytes replaced by U+FFFD.</summary>
    internal static string Lenient(ReadOnlySpan<byte> bytes) => System.Text.Encoding.UTF8.GetString(bytes);

    private static async Task DrainAsync(Stream errors)
    {
        var buffer = new byte[4096];
        try
        {
            while (await errors.ReadAsync(buffer).ConfigureAwait(false) > 0)
            {
                // Dropped.
            }
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException or OperationCanceledException)
        {
            // The session ended.
        }
    }

    /// <summary>Sends a request and waits for its reply. <paramref name="body"/> writes what follows the request id.</summary>
    /// <remarks>
    /// The request is built (and <paramref name="body"/> run) before this returns, so data it copies from the caller's buffers may change
    /// as soon as it does. When the caller gives up after the request was sent, the reply is normally dropped. <paramref name="orphaned"/>
    /// gets it instead, when it comes: a request that opens something (OPEN, OPENDIR) passes a callback that closes the handle, which would
    /// otherwise stay open on the server until the session ends. The reply is the caller's to dispose (see <see cref="SftpResponse"/>).
    /// </remarks>
    public Task<SftpResponse> RequestAsync(byte type, Action<SshWriter> body, CancellationToken cancellationToken, Action<SftpResponse>? orphaned = null)
    {
        var frame = SftpRequestFrame.Start(type);
        try
        {
            body(frame.Writer);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Reported through the task, as a failed send would be; the frame is not handed over, so it is returned here.
            frame.Dispose();
            return Task.FromException<SftpResponse>(ex);
        }

        return RequestAsync(frame, cancellationToken, orphaned);
    }

    /// <summary>
    /// Sends <paramref name="frame"/> as a request and waits for its reply. The frame is taken over whatever happens (see
    /// <see cref="SftpRequestFrame"/>): it is disposed once its send has completed or failed, before the reply arrives.
    /// </summary>
    public async Task<SftpResponse> RequestAsync(SftpRequestFrame frame, CancellationToken cancellationToken, Action<SftpResponse>? orphaned = null)
    {
        var id = (uint)Interlocked.Increment(ref _nextId);
        var reply = new TaskCompletionSource<SftpResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sent = false;
        try
        {
            _pending[id] = reply;
            ReadOnlyMemory<byte> bytes;
            try
            {
                if (Volatile.Read(ref _failure) is { } failed)
                {
                    throw Ended(failed);
                }

                bytes = frame.Complete(id);
            }
            catch
            {
                frame.Dispose();
                throw;
            }

            // The write takes the frame over and disposes it once the bytes are on their way (the channel copies them into packets of its
            // own), which may be after this request stopped waiting for it.
            var write = await StartSendAsync(bytes, frame, cancellationToken).ConfigureAwait(false);
            sent = true; // from here the server gets the whole request, unless the channel fails
            await FinishSendAsync(write, cancellationToken).ConfigureAwait(false);
            return await WaitAsync(reply.Task, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (sent && orphaned is not null && (ex is OperationCanceledException || IsTimeout(ex)))
        {
            // The server will still answer: hand the reply over when it does (the session failing completes it with an exception).
            _ = reply.Task.ContinueWith(
                done =>
                {
                    using var orphan = done.Result;
                    orphaned(orphan);
                },
                CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
        catch
        {
            // Cancelled or failed: the reply, if it still comes, is dropped (an unknown id is ignored). One that came already, or comes
            // while the request is being forgotten, has nobody to read it: its buffer goes back to the pool.
            _pending.TryRemove(id, out _);
            _ = reply.Task.ContinueWith(
                static done => done.Result.Dispose(),
                CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>
    /// Waits for <paramref name="reply"/> within <see cref="OperationTimeout"/>. The limit is on the server's silence, not on this one
    /// request: while other replies keep arriving (a window of pipelined reads working through the server's queue on a slow link), the
    /// server is answering and the wait goes on; once it has sent nothing for the whole timeout, the request fails.
    /// </summary>
    private async Task<SftpResponse> WaitAsync(Task<SftpResponse> reply, CancellationToken cancellationToken)
    {
        var timeout = OperationTimeout;
        if (timeout < TimeSpan.Zero)
        {
            return await reply.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        var wait = timeout;
        while (true)
        {
            try
            {
                return await reply.WaitAsync(wait, Clock, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException ex)
            {
                wait = Remaining(timeout) ?? throw TimedOut(timeout, ex);
            }
        }
    }

    /// <summary>How much longer to wait before the server has been silent for <paramref name="timeout"/>; null once it has.</summary>
    private TimeSpan? Remaining(TimeSpan timeout)
    {
        var quiet = Clock.GetElapsedTime(Volatile.Read(ref _lastReceived));
        return quiet >= timeout ? null : TimeSpan.FromMilliseconds(Math.Max(1, (timeout - quiet).TotalMilliseconds));
    }

    /// <summary>What a passed <see cref="OperationTimeout"/> is reported as: <see cref="SshFailureReason.Timeout"/>, with a <see cref="TimeoutException"/> inside.</summary>
    private static SshException TimedOut(TimeSpan timeout, TimeoutException inner) => new(SshFailureReason.Timeout,
        $"The SFTP server sent nothing for OperationTimeout ({timeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s).", inner);

    private static bool IsTimeout(Exception ex) => ex is SshException { Reason: SshFailureReason.Timeout };

    /// <summary>Takes the send lock, within <see cref="OperationTimeout"/> of the server's silence (see <see cref="WaitAsync"/>).</summary>
    private async Task LockAsync(CancellationToken cancellationToken)
    {
        var timeout = OperationTimeout;
        if (timeout < TimeSpan.Zero)
        {
            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        // A send waits here while another is held up by the channel's flow-control window, which only a server that reads opens again.
        // The send holding the lock is bounded by its guard (GuardAsync), whether or not its caller still waits for it: once the server
        // has been silent for the timeout, the guard fails the channel. The requests behind it give up here at the same point.
        var wait = timeout;
        while (true)
        {
            using var limit = new CancellationTokenSource(wait, Clock);
            using var either = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, limit.Token);
            try
            {
                await _sendLock.WaitAsync(either.Token).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                wait = Remaining(timeout) ?? throw TimedOut(timeout, new TimeoutException());
            }
        }
    }

    /// <summary>Writes one whole frame (length included) to the session and waits for it.</summary>
    private async Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
    {
        var send = await StartSendAsync(frame, owner: null, cancellationToken).ConfigureAwait(false);
        await FinishSendAsync(send, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Takes the send lock and starts writing <paramref name="frame"/>, under its guard (see <see cref="GuardAsync"/>). The write releases
    /// the lock, and disposes <paramref name="owner"/> (the frame's buffer), when it ends, whether or not anybody still waits for it; when
    /// the lock is not taken, <paramref name="owner"/> is disposed here.
    /// </summary>
    private async Task<Task> StartSendAsync(ReadOnlyMemory<byte> frame, SftpRequestFrame? owner, CancellationToken cancellationToken)
    {
        try
        {
            await LockAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            owner?.Dispose();
            throw;
        }

        var write = WriteLockedAsync(frame, owner);
        var timeout = OperationTimeout;
        return write.IsCompleted || timeout < TimeSpan.Zero ? write : GuardAsync(write, timeout);
    }

    /// <summary>
    /// Waits for a send <see cref="StartSendAsync"/> started. A packet is written whole: stopping halfway would leave the server reading
    /// a broken stream. So a caller who cancels stops waiting, and the write goes on in the background, holding the send lock until the
    /// channel's window lets it finish, or until its guard cuts it off (see <see cref="GuardAsync"/>).
    /// </summary>
    private static async Task FinishSendAsync(Task send, CancellationToken cancellationToken)
    {
        try
        {
            await send.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch when (!send.IsCompleted)
        {
            // Nobody waits for the send any more: its failure, if it fails (the channel closing), is observed here.
            _ = send.ContinueWith(static done => _ = done.Exception, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>
    /// Bounds a write in progress by <paramref name="timeout"/> of the server's silence, whether or not its caller still waits for it: a
    /// caller who cancelled leaves the write holding the send lock. A write held up while the server sends nothing for that long (an
    /// <c>sftp-server</c> that stopped reading, while sshd still answers keep-alives) is cut off, and the whole channel fails with it:
    /// part of the packet may be on its way, after which nothing more can be sent, and failing the channel completes every request
    /// waiting on it. So a stuck write can never leave the channel holding its send lock while it still reports itself open.
    /// </summary>
    private async Task GuardAsync(Task write, TimeSpan timeout)
    {
        var wait = timeout;
        while (true)
        {
            try
            {
                await write.WaitAsync(wait, Clock, CancellationToken.None).ConfigureAwait(false);
                return;
            }
            catch (TimeoutException ex)
            {
                if (write.IsCompleted)
                {
                    await write.ConfigureAwait(false); // it ended as the wait ran out
                    return;
                }

                if (Remaining(timeout) is { } more)
                {
                    wait = more;
                    continue;
                }

                var error = new SshException(SshFailureReason.Timeout,
                    $"The SFTP server took no more of a request and sent nothing for OperationTimeout ({timeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s); the SFTP session is closed.",
                    ex);
                Fail(error);
                try
                {
                    await _stop.CancelAsync().ConfigureAwait(false); // cuts the write off and stops the read loop: the channel is done
                }
                catch (ObjectDisposedException)
                {
                    // Disposed meanwhile, which cut the write off already.
                }

                // The write, cut off, fails with this error; nobody waits for it but this guard.
                _ = write.ContinueWith(static done => _ = done.Exception, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                throw error;
            }
        }
    }

    /// <summary>
    /// Writes one whole frame (length included) under the send lock, then releases the lock and disposes <paramref name="owner"/>. A write
    /// that fails fails the channel, before its caller hears of it: part of the frame may have gone out, so nothing can follow it.
    /// </summary>
    private async Task WriteLockedAsync(ReadOnlyMemory<byte> frame, SftpRequestFrame? owner)
    {
        // Disposed last, after the lock is released below.
        using (owner)
        {
            try
            {
                // A request that waited for the lock while the channel failed (a write cut off halfway) must not follow it onto the stream.
                if (Volatile.Read(ref _failure) is { } failed)
                {
                    throw Ended(failed);
                }

                // Only the channel ending stops a write (see GuardAsync); the caller's token does not.
                var stop = _stop.Token;
                await _session.StandardInput.WriteAsync(frame, stop).ConfigureAwait(false);
                await _session.StandardInput.FlushAsync(stop).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // The session or the connection under it ended (an SshException), the stream failed or was shut, or the channel was
                // stopped. The channel fails here, not only once the read loop notices the end too: until then a caller could see its
                // request fail while IsConnected still said the session was up, and an adapter would not replace it.
                Fail(ex);
                throw Ended(Volatile.Read(ref _failure) ?? ex);
            }
            finally
            {
                _sendLock.Release();
            }
        }
    }

    /// <summary>One packet (without its length), or null at the end of the session. A DATA reply is in a pooled buffer.</summary>
    private async Task<SftpResponse?> ReadPacketAsync(CancellationToken cancellationToken)
    {
        var stream = _session.StandardOutput;
        var read = 0;
        while (read < 4)
        {
            var n = await stream.ReadAsync(_header.AsMemory(read, 4 - read), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                return read == 0 ? null : throw new SshException(SshFailureReason.ProtocolError, "The SFTP session ended inside a packet.");
            }

            read += n;
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(_header);
        if (length is < 5 or > SftpProtocol.MaxPacket)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server sent a packet of {length} bytes.");
        }

        byte[]? packet = null;
        var pooled = false;
        try
        {
            // The type decides where the rest goes: data is rented (and returned by whoever reads it), the small replies are not.
            await stream.ReadExactlyAsync(_header.AsMemory(4, 1), cancellationToken).ConfigureAwait(false);
            pooled = _header[4] == SftpProtocol.Data;
            if (pooled)
            {
                packet = ArrayPool<byte>.Shared.Rent((int)length);
                Instrumentation.Rented(packet, nameof(SftpResponse));
            }
            else
            {
                packet = new byte[length];
            }

            packet[0] = _header[4];
            await stream.ReadExactlyAsync(packet.AsMemory(1, (int)length - 1), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (pooled)
            {
                Instrumentation.Returning(packet!, nameof(SftpResponse));
                ArrayPool<byte>.Shared.Return(packet!);
            }

            if (ex is EndOfStreamException)
            {
                throw new SshException(SshFailureReason.ProtocolError, "The SFTP session ended inside a packet.", ex);
            }

            throw;
        }

        return pooled ? SftpResponse.Pooled(packet, (int)length) : new SftpResponse(packet[0], packet);
    }

    private async Task ReadLoopAsync()
    {
        Exception? failure = null;
        try
        {
            while (await ReadPacketAsync(_stop.Token).ConfigureAwait(false) is { } packet)
            {
                Volatile.Write(ref _lastReceived, Clock.GetTimestamp());
                var id = BinaryPrimitives.ReadUInt32BigEndian(packet.Packet.Span[1..]);

                // The request takes the reply over. An unknown id belongs to a request that was cancelled, and a request that failed
                // already (the session ending) does not take it: either way it is dropped here.
                if (!_pending.TryRemove(id, out var reply) || !reply.TrySetResult(packet))
                {
                    packet.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            failure = ex;
        }

        Fail(failure ?? new SshException(SshFailureReason.ChannelClosed, "The SFTP session ended."));
    }

    private void Fail(Exception failure)
    {
        Interlocked.CompareExchange(ref _failure, failure, null);
        foreach (var id in _pending.Keys)
        {
            if (_pending.TryRemove(id, out var reply))
            {
                reply.TrySetException(Ended(failure));
            }
        }
    }

    private static SshException Ended(Exception failure) => failure switch
    {
        SshException ssh when ssh.Reason != SshFailureReason.SftpFailed => ssh,
        OperationCanceledException => new SshException(SshFailureReason.ChannelClosed, "The SFTP session was closed."),
        _ => new SshException(SshFailureReason.ChannelClosed, "The SFTP session ended: " + failure.Message, failure),
    };

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        Fail(new SshException(SshFailureReason.ChannelClosed, "The SFTP client was disposed."));
        try
        {
            await _session.CloseInputAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException or InvalidOperationException)
        {
            // Already gone.
        }

        await _session.DisposeAsync().ConfigureAwait(false);
        await _readLoop.ConfigureAwait(false); // never faults: it reports its failure to the requests instead
        await _errorDrain.ConfigureAwait(false); // never faults either

        _stop.Dispose();
    }
}
