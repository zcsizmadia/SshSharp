using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
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

            // Sent or not, the frame is no longer needed afterwards: the channel copied the bytes into packets of its own before the send
            // completed.
            using (frame)
            {
                if (Volatile.Read(ref _failure) is { } failed)
                {
                    throw Ended(failed);
                }

                await SendAsync(frame.Complete(id), cancellationToken).ConfigureAwait(false);
            }

            sent = true;
            return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (sent && orphaned is not null)
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

    /// <summary>Writes one whole frame (length included) to the session.</summary>
    private async Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // A packet is written whole: cancelling halfway would leave the server reading a broken stream.
            await _session.StandardInput.WriteAsync(frame, CancellationToken.None).ConfigureAwait(false);
            await _session.StandardInput.FlushAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            throw Ended(ex);
        }
        finally
        {
            _sendLock.Release();
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
