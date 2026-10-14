using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>A reply from the SFTP server: its type and whole packet (type, then the request id, then the body).</summary>
internal sealed class SftpResponse
{
    public SftpResponse(byte type, byte[] packet)
    {
        Type = type;
        Packet = packet;
    }

    public byte Type { get; }

    /// <summary>A reader positioned after the type and request id.</summary>
    public SshReader Body => new(Packet.AsSpan(5));

    /// <summary>The packet, for slicing data out of it without a copy.</summary>
    public byte[] Packet { get; }
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
            await channel.SendAsync(SshPrivateKey.Encode(w =>
            {
                w.WriteByte(SftpProtocol.Init);
                w.WriteUInt32(SftpProtocol.Version);
            }), cancellationToken).ConfigureAwait(false);

            var version = await channel.ReadPacketAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new SshException(SshFailureReason.ProtocolError, "The SFTP server closed the session before saying its version.");
            (channel.Version, channel.Extensions) = ParseVersion(version);
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
    internal static (uint Version, IReadOnlyDictionary<string, string> Extensions) ParseVersion(byte[] packet)
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
    /// When the caller gives up after the request was sent, the reply is normally dropped. <paramref name="orphaned"/> gets it instead,
    /// when it comes: a request that opens something (OPEN, OPENDIR) passes a callback that closes the handle, which would otherwise stay
    /// open on the server until the session ends.
    /// </remarks>
    public async Task<SftpResponse> RequestAsync(byte type, Action<SshWriter> body, CancellationToken cancellationToken, Action<SftpResponse>? orphaned = null)
    {
        var id = (uint)Interlocked.Increment(ref _nextId);
        var reply = new TaskCompletionSource<SftpResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = reply;
        if (Volatile.Read(ref _failure) is { } failed)
        {
            _pending.TryRemove(id, out _);
            throw Ended(failed);
        }

        var sent = false;
        try
        {
            await SendAsync(SshPrivateKey.Encode(w =>
            {
                w.WriteByte(type);
                w.WriteUInt32(id);
                body(w);
            }), cancellationToken).ConfigureAwait(false);
            sent = true;
            return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (sent && orphaned is not null)
        {
            // The server will still answer: hand the reply over when it does (the session failing completes it with an exception).
            _ = reply.Task.ContinueWith(
                done => orphaned(done.Result),
                CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
        catch
        {
            // Cancelled or failed: the reply, if it still comes, is dropped (an unknown id is ignored).
            _pending.TryRemove(id, out _);
            throw;
        }
    }

    private async Task SendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var frame = new byte[4 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)payload.Length);
        payload.CopyTo(frame, 4);
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

    /// <summary>One packet (without its length), or null at the end of the session.</summary>
    private async Task<byte[]?> ReadPacketAsync(CancellationToken cancellationToken)
    {
        var header = new byte[4];
        var read = 0;
        while (read < 4)
        {
            var n = await _session.StandardOutput.ReadAsync(header.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                return read == 0 ? null : throw new SshException(SshFailureReason.ProtocolError, "The SFTP session ended inside a packet.");
            }

            read += n;
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is < 5 or > SftpProtocol.MaxPacket)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The SFTP server sent a packet of {length} bytes.");
        }

        var packet = new byte[length];
        try
        {
            await _session.StandardOutput.ReadExactlyAsync(packet, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException ex)
        {
            throw new SshException(SshFailureReason.ProtocolError, "The SFTP session ended inside a packet.", ex);
        }

        return packet;
    }

    private async Task ReadLoopAsync()
    {
        Exception? failure = null;
        try
        {
            while (await ReadPacketAsync(_stop.Token).ConfigureAwait(false) is { } packet)
            {
                var id = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(1));
                if (_pending.TryRemove(id, out var reply))
                {
                    reply.TrySetResult(new SftpResponse(packet[0], packet));
                }

                // An unknown id belongs to a request that was cancelled: its reply is dropped.
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
