using System.Buffers;
using System.IO.Pipelines;
using System.Security.Cryptography;
using SshSharp.Keys;

namespace SshSharp.Protocol;

/// <summary>
/// The client side of the SSH transport layer (RFC 4253) over a <see cref="Stream"/>: identification exchange, algorithm negotiation,
/// key exchange, host key verification, strict KEX (against Terrapin), re-exchange of keys, and encrypted packet send/receive.
/// </summary>
/// <remarks>
/// A re-exchange starts when the peer sends KEXINIT, or when our byte/time thresholds pass (we send KEXINIT, and the exchange
/// is completed by whoever is calling <see cref="ReceiveAsync"/>). From our KEXINIT until our NEWKEYS, application sends wait, so
/// no data packet is ever sent between the two; data already in flight from the peer is still received normally.
/// </remarks>
internal sealed class SshTransport : IAsyncDisposable
{
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SshTransportOptions _options;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    // Flushes run under this token, never the caller's: once a packet is encoded it has its sequence number and must reach the wire whole,
    // so a cancelled caller stops waiting but the flush continues. Only aborting the transport cancels it.
    private readonly CancellationTokenSource _lifetime = new();

    private PacketProtector _sendProtector = PacketProtector.None;
    private PacketProtector _receiveProtector = PacketProtector.None;
    private uint _sendSequence;
    private uint _receiveSequence;
    private bool _connected;
    private bool _disposed;
    private bool _strictKex;

    // Set when the connection has failed or is being disposed; checked under _sendLock, so no application message is encoded after it.
    private Exception? _failed;

    // Re-exchange state; _rekeying and the pending KEXINIT are protected by _sendLock.
    private bool _rekeying;
    private TaskCompletionSource _rekeyDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private KexInitMessage? _pendingClientInit;
    private byte[]? _pendingClientInitPayload;
    private long _bytesSinceKex;
    private long _packetsSentSinceKex;
    private long _packetsReceivedSinceKex;
    private long _kexStartedAt;

    public SshTransport(Stream stream, SshTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _reader = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true));
        _writer = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
    }

    /// <summary>The server's identification, available after <see cref="ConnectAsync"/>.</summary>
    public SshIdentification? ServerIdentification { get; private set; }

    /// <summary>The session identifier (the exchange hash of the first key exchange); it never changes on re-exchange.</summary>
    public byte[]? SessionId { get; private set; }

    /// <summary>The algorithms in use (updated by each re-exchange).</summary>
    public NegotiatedAlgorithms? Algorithms { get; private set; }

    /// <summary>The host key the server proved possession of.</summary>
    public HostKeyInfo? HostKey { get; private set; }

    /// <summary>
    /// The server's signature over the session identifier from the first key exchange (the host key's proof), which an SSH agent
    /// verifies when a connection is bound to this session (<c>session-bind@openssh.com</c>).
    /// </summary>
    public byte[]? InitialSignature { get; private set; }

    /// <summary>What binds an agent connection to this session, once the first key exchange is done.</summary>
    public AgentBinding? AgentBinding => HostKey is { } hostKey && SessionId is { } sessionId && InitialSignature is { } signature
        ? new AgentBinding(hostKey.Presented, sessionId, signature)
        : null;

    /// <summary>The host key algorithms the server offered in its first KEXINIT; set before negotiation, so also when it fails.</summary>
    public IReadOnlyList<string>? ServerHostKeyAlgorithms { get; private set; }

    /// <summary>How many key exchanges have completed, including the first.</summary>
    public int KeyExchangeCount { get; private set; }

    /// <summary>Extensions announced by the server in <c>SSH_MSG_EXT_INFO</c> (RFC 8308), for example <c>server-sig-algs</c>.</summary>
    public IReadOnlyDictionary<string, string> ServerExtensions { get; private set; } = new Dictionary<string, string>();

    /// <summary>Exchanges identifications, negotiates, performs the first key exchange, and switches both directions to the new keys.</summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_connected)
        {
            throw new InvalidOperationException("The transport is already connected.");
        }

        _options.ClientIdentification.Write(_writer);
        await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        ServerIdentification = await SshIdentification.ReadAsync(_reader, cancellationToken).ConfigureAwait(false);
        SshLog.ServerIdentified(_options.Logger, ServerIdentification.Line);

        var clientInit = KexInitMessage.ForClient(_options.Preferences);
        var clientInitPayload = Serialize(clientInit.Write);
        await SendPacketAsync(clientInitPayload, kexMessage: true, null, null, cancellationToken).ConfigureAwait(false);

        var serverInitPayload = await ReceiveKexMessageAsync(SshMessage.KexInit, strict: false, cancellationToken).ConfigureAwait(false);

        // The KEXINIT's own sequence number: anything skipped before it (IGNORE, DEBUG) shifts it away from 0.
        var serverInitSequence = _receiveSequence - 1;
        await ExchangeKeysAsync(clientInit, clientInitPayload, serverInitPayload, initial: true, serverInitSequence, cancellationToken).ConfigureAwait(false);
        _connected = true;
    }

    /// <summary>
    /// Sends one message (the payload starts with the message number). Waits while a key re-exchange is in progress.
    /// If the caller is cancelled after the packet was encoded, it is still sent.
    /// </summary>
    public ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default) => SendAsync(payload, null, cancellationToken);

    /// <summary>
    /// Sends one message like <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/>. <paramref name="onCommitted"/> runs under the
    /// send lock as soon as the packet is encoded, so callers can record state in wire order (for example a pending reply).
    /// </summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, Action? onCommitted, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await SendPacketAsync(payload, kexMessage: false, onCommitted, null, cancellationToken).ConfigureAwait(false);
        if (_connected && !_rekeying && RekeyDue())
        {
            await StartRekeyAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Sends one message only if <paramref name="condition"/> still holds when the packet takes its place on the wire: it is checked under
    /// the send lock, so nothing can be sent in between. Returns whether the message was sent. A channel uses this so that its EOF or data
    /// never follows its CLOSE, which the receive loop may send at any moment.
    /// </summary>
    public async ValueTask<bool> SendIfAsync(ReadOnlyMemory<byte> payload, Func<bool> condition, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!await SendPacketAsync(payload, kexMessage: false, null, condition, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        if (_connected && !_rekeying && RekeyDue())
        {
            await StartRekeyAsync(cancellationToken).ConfigureAwait(false);
        }

        return true;
    }

    /// <summary>
    /// Receives the next application-level message. Transport housekeeping is handled here: <c>IGNORE</c>, <c>DEBUG</c> and
    /// <c>UNIMPLEMENTED</c> are skipped, <c>EXT_INFO</c> is recorded, a key re-exchange is carried out, and <c>DISCONNECT</c> raises an
    /// <see cref="SshException"/>. The caller must dispose the returned packet.
    /// </summary>
    // Pooled: completes asynchronously for nearly every packet, and would otherwise allocate a state machine box each time.
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<DecodedPacket> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        while (true)
        {
            var packet = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            var payload = packet.Payload.Span;
            switch (payload[0])
            {
                case SshMessage.Ignore:
                case SshMessage.Debug:
                case SshMessage.Unimplemented:
                    packet.Dispose();
                    continue;
                case SshMessage.Disconnect:
                    var error = ParseDisconnect(payload);
                    packet.Dispose();
                    throw error;
                case SshMessage.ExtInfo:
                    try
                    {
                        ServerExtensions = ParseExtInfo(payload, ServerExtensions);
                    }
                    finally
                    {
                        packet.Dispose();
                    }

                    continue;
                case SshMessage.KexInit:
                    var serverInit = payload.ToArray();
                    packet.Dispose();
                    await RekeyFromPeerAsync(serverInit, cancellationToken).ConfigureAwait(false);
                    continue;
                default:
                    // A connection that mostly receives (a big download) must also re-key on its own: the threshold counts both directions.
                    if (_connected && !_rekeying && RekeyDue())
                    {
                        try
                        {
                            await StartRekeyAsync(cancellationToken).ConfigureAwait(false);
                        }
                        catch
                        {
                            packet.Dispose();
                            throw;
                        }
                    }

                    return packet;
            }
        }
    }

    /// <summary>
    /// Builds <c>SSH_MSG_UNIMPLEMENTED</c> (RFC 4253 section 11.4) for the message that was just received. It quotes that message's sequence
    /// number, so it must be built right away; sending it can be deferred.
    /// </summary>
    public byte[] BuildUnimplemented() => Serialize(output =>
    {
        var writer = new SshWriter(output);
        writer.WriteByte(SshMessage.Unimplemented);
        writer.WriteUInt32(_receiveSequence - 1);
    });
    /// <summary>Tells the server we are leaving (<c>SSH_MSG_DISCONNECT</c>), best effort.</summary>
    public async ValueTask DisconnectAsync(DisconnectReason reason, string description, CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return;
        }

        var payload = Serialize(output =>
        {
            var writer = new SshWriter(output);
            writer.WriteByte(SshMessage.Disconnect);
            writer.WriteUInt32((uint)reason);
            writer.WriteString(description);
            writer.WriteString(string.Empty);
        });
        await SendPacketAsync(payload, kexMessage: true, null, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Cancels every pending read and flush: the connection is being torn down and nothing more will be sent.</summary>
    public void Abort()
    {
        try
        {
            _lifetime.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed.
        }
    }

    /// <summary>
    /// The connection has failed: later application sends throw <paramref name="exception"/>, and senders waiting for a key re-exchange
    /// that will never finish are released with it.
    /// </summary>
    public void Fail(Exception exception)
    {
        Interlocked.CompareExchange(ref _failed, exception, null);
        FailRekeyWaiters(exception);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var closed = new SshException(SshFailureReason.ConnectionClosed, "The connection was closed.");
        Interlocked.CompareExchange(ref _failed, closed, null);
        Abort();
        FailRekeyWaiters(closed);

        // A sender already inside the send lock finishes first (Abort cancels its flush), and later ones see _failed: the writer and the
        // protectors are never used while they are being torn down.
        var locked = await _sendLock.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        try
        {
            await _writer.CompleteAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // The stream is already broken; there is nothing left to flush to.
        }
        finally
        {
            if (locked)
            {
                _sendLock.Release();
            }
        }

        await _reader.CompleteAsync().ConfigureAwait(false);
        _sendProtector.Dispose();
        _receiveProtector.Dispose();
        if (SessionId is not null)
        {
            CryptographicOperations.ZeroMemory(SessionId);
        }

        // _sendLock is not disposed: a flush abandoned by a cancelled caller may still release it from a continuation.
        _lifetime.Dispose();
    }

    // ---- key exchange (initial and re-exchange) ----

    /// <summary>
    /// Runs a key exchange once both KEXINIT messages are known: negotiate, exchange, verify the host key, derive keys, and switch to them.
    /// </summary>
    private async Task ExchangeKeysAsync(KexInitMessage clientInit, byte[] clientInitPayload, byte[] serverInitPayload, bool initial, uint serverInitSequence, CancellationToken cancellationToken)
    {
        var serverInit = KexInitMessage.Parse(serverInitPayload);
        if (initial)
        {
            ServerHostKeyAlgorithms = serverInit.ServerHostKeyAlgorithms;
        }

        var negotiated = AlgorithmNegotiator.Negotiate(clientInit, serverInit);

        // Strict KEX is decided by the first exchange only (the markers are not repeated afterwards).
        if (initial)
        {
            _strictKex = negotiated.StrictKex;

            // The server's KEXINIT must be the very first packet, or an attacker may have injected or removed packets (Terrapin).
            if (_strictKex && serverInitSequence != 0)
            {
                throw new SshProtocolException("Strict key exchange requires KEXINIT to be the first packet.");
            }
        }

        Algorithms = negotiated with { StrictKex = _strictKex };

        // Strict KEX forbids stray messages only during the initial exchange; sequence numbers reset on every NEWKEYS.
        var strict = _strictKex;
        var strictMessages = strict && initial;
        SshLog.Negotiated(_options.Logger, negotiated.Kex, negotiated.HostKey, negotiated.CipherClientToServer, negotiated.CipherServerToClient, strict);

        if (negotiated.ServerGuessedWrong)
        {
            // The server sent a guessed key exchange packet that does not match what was negotiated: discard it.
            using var discarded = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
        }

        using var kex = ClientKeyExchange.Create(negotiated.Kex);
        await SendPacketAsync(kex.CreateInit(), kexMessage: true, null, null, cancellationToken).ConfigureAwait(false);
        var reply = await ReceiveKexMessageAsync(SshMessage.KexEcdhReply, strictMessages, cancellationToken).ConfigureAwait(false);

        var context = new KexContext(_options.ClientIdentification.Line, ServerIdentification!.Line, clientInitPayload, serverInitPayload);
        using var result = kex.ProcessReply(reply, context);
        await VerifyHostKeyAsync(negotiated, result, initial, cancellationToken).ConfigureAwait(false);

        if (initial)
        {
            SessionId = (byte[])result.ExchangeHash.Clone();
        }

        SshAlgorithms.TryGetCipher(negotiated.CipherClientToServer, out var cipherC2S);
        SshAlgorithms.TryGetCipher(negotiated.CipherServerToClient, out var cipherS2C);
        SshAlgorithms.TryGetMac(negotiated.MacClientToServer, out var macC2S);
        SshAlgorithms.TryGetMac(negotiated.MacServerToClient, out var macS2C);
        using var keys = KeyDerivation.DeriveAll(kex.Hash, result.SharedSecret, result.ExchangeHash, SessionId!, cipherC2S, cipherS2C, macC2S, macS2C, result.SharedSecretIsString);
        var newSend = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
        PacketProtector newReceive;
        try
        {
            newReceive = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);
        }
        catch
        {
            newSend.Dispose();
            throw;
        }

        // After the first exchange, a client may announce its own extensions (RFC 8308) when the server asked for them (ext-info-s).
        await SwitchKeysAsync(newSend, newReceive, strict, strictMessages, sendExtInfo: initial && negotiated.ServerSupportsExtInfo, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends NEWKEYS and installs the new keys for each direction. Takes ownership of both protectors: one that is not installed when the
    /// exchange fails part way is wiped here, rather than left to the garbage collector.
    /// </summary>
    private async Task SwitchKeysAsync(PacketProtector newSend, PacketProtector newReceive, bool strict, bool strictMessages, bool sendExtInfo,
        CancellationToken cancellationToken)
    {
        var sendInstalled = false;
        var receiveInstalled = false;
        try
        {
            await SwitchKeysCoreAsync(newSend, newReceive, strict, strictMessages, sendExtInfo, () => sendInstalled = true, () => receiveInstalled = true,
                cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            if (!sendInstalled)
            {
                newSend.Dispose();
            }

            if (!receiveInstalled)
            {
                newReceive.Dispose();
            }

            throw;
        }
    }

    private async Task SwitchKeysCoreAsync(PacketProtector newSend, PacketProtector newReceive, bool strict, bool strictMessages, bool sendExtInfo, Action sendInstalled,
        Action receiveInstalled, CancellationToken cancellationToken)
    {
        // Each side sends NEWKEYS under the old keys, then protects what it sends with the new ones; incoming switches on the peer's NEWKEYS.
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PacketCodec.Encode(_writer, new[] { SshMessage.NewKeys }, _sendProtector, _sendSequence++);
            await _writer.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            _sendProtector.Dispose();
            _sendProtector = newSend;
            sendInstalled();
            if (strict)
            {
                _sendSequence = 0;
            }

            if (sendExtInfo)
            {
                // The first packet under the new keys (RFC 8308 section 2.4). ext-info-in-auth@openssh.com (PROTOCOL 1.10) lets the server
                // send server-sig-algs again during authentication, for example when a Match block changes them for this user; the
                // authentication reads the current list before each key.
                PacketCodec.Encode(_writer, ClientExtInfo, _sendProtector, _sendSequence++);
                await _writer.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            }

            // Our side of the exchange is complete: application sends may resume, under the new keys.
            _rekeying = false;
            _pendingClientInit = null;
            _pendingClientInitPayload = null;
            _bytesSinceKex = 0;
            _packetsSentSinceKex = 0;
            Interlocked.Exchange(ref _packetsReceivedSinceKex, 0);
            _kexStartedAt = _options.TimeProvider.GetTimestamp();
            var done = _rekeyDone;
            _rekeyDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            done.TrySetResult();
        }
        finally
        {
            _sendLock.Release();
        }

        await ReceiveKexMessageAsync(SshMessage.NewKeys, strictMessages, cancellationToken).ConfigureAwait(false);
        _receiveProtector.Dispose();
        _receiveProtector = newReceive;
        receiveInstalled();
        if (strict)
        {
            _receiveSequence = 0;
        }

        KeyExchangeCount++;
        SshTelemetry.KeyExchanges.Add(1);
        SshLog.KeyExchangeCompleted(_options.Logger, KeyExchangeCount);
    }

    private bool RekeyDue() =>
        Interlocked.Read(ref _bytesSinceKex) >= _options.RekeyBytes
        || Interlocked.Read(ref _packetsSentSinceKex) >= _options.RekeyPackets
        || Interlocked.Read(ref _packetsReceivedSinceKex) >= _options.RekeyPackets
        || _options.TimeProvider.GetElapsedTime(_kexStartedAt) >= _options.RekeyInterval;

    /// <summary>
    /// Runs on the receive side after each key re-exchange completes, before the next message is read. OpenSSH drops a PING that
    /// arrives during a key exchange (no PONG is ever sent), so the connection sends again the pings still waiting for theirs.
    /// </summary>
    public Action? KeyReexchanged { get; set; }

    /// <summary>We start a re-exchange: send KEXINIT and hold application sends back. The receive side completes it.</summary>
    private async ValueTask StartRekeyAsync(CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_rekeying || !RekeyDue())
            {
                return; // another sender started it, or a re-exchange just finished
            }

            SshLog.RekeyStarting(_options.Logger, "size or time threshold reached");
            Instrumentation.Trace($"kex: we start a re-exchange (sent {Interlocked.Read(ref _bytesSinceKex)} bytes, received {Interlocked.Read(ref _packetsReceivedSinceKex)} packets since the last)");
            await SendClientKexInitLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>The peer started a re-exchange (or answered ours): make sure our KEXINIT is out, then run the exchange.</summary>
    private async ValueTask RekeyFromPeerAsync(byte[] serverInitPayload, CancellationToken cancellationToken)
    {
        KexInitMessage clientInit;
        byte[] clientInitPayload;
        Instrumentation.Trace($"kex: the server's KEXINIT (we were {(_rekeying ? "already re-keying" : "not re-keying")})");
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_rekeying)
            {
                SshLog.RekeyStarting(_options.Logger, "requested by the server");
                await SendClientKexInitLockedAsync(cancellationToken).ConfigureAwait(false);
            }

            clientInit = _pendingClientInit!;
            clientInitPayload = _pendingClientInitPayload!;
        }
        finally
        {
            _sendLock.Release();
        }

        try
        {
            await ExchangeKeysAsync(clientInit, clientInitPayload, serverInitPayload, initial: false, serverInitSequence: 0, cancellationToken).ConfigureAwait(false);
            Instrumentation.Trace("kex: re-exchange finished");
            KeyReexchanged?.Invoke();
        }
        catch (Exception ex)
        {
            // The connection cannot continue: wake everything that is waiting for the exchange to finish.
            FailRekeyWaiters(ex);
            throw;
        }
    }

    /// <summary>Sends our KEXINIT and closes the application send gate. The caller holds <see cref="_sendLock"/>.</summary>
    private async ValueTask SendClientKexInitLockedAsync(CancellationToken cancellationToken)
    {
        var clientInit = KexInitMessage.ForClient(_options.Preferences, initial: false);
        var payload = Serialize(clientInit.Write);
        Instrumentation.Trace($"kex: our KEXINIT out (bytes since the last exchange {Interlocked.Read(ref _bytesSinceKex)}, packets received {Interlocked.Read(ref _packetsReceivedSinceKex)})");
        _rekeying = true;
        _pendingClientInit = clientInit;
        _pendingClientInitPayload = payload;
        PacketCodec.Encode(_writer, payload, _sendProtector, _sendSequence++);
        await _writer.FlushAsync(_lifetime.Token).ConfigureAwait(false);
    }

    // ---- packet I/O ----

    private static byte[] Serialize(Action<IBufferWriter<byte>> write)
    {
        var buffer = new ArrayBufferWriter<byte>(512);
        write(buffer);
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Sends a packet. Application messages wait out a re-exchange (checked under the lock, so none can slip in after our KEXINIT);
    /// key exchange and transport messages (<paramref name="kexMessage"/>) go straight through.
    /// </summary>
    /// <remarks>
    /// The caller's token can cancel the wait for the lock or for a re-exchange. Once the packet is encoded it is committed: if the caller
    /// is cancelled during the flush, it gets <see cref="OperationCanceledException"/> right away, the flush finishes in the background,
    /// and the lock is released when it does.
    /// </remarks>
    private async ValueTask<bool> SendPacketAsync(ReadOnlyMemory<byte> payload, bool kexMessage, Action? onCommitted, Func<bool>? condition, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task? wait = null;
            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            var release = true;
            try
            {
                if (!kexMessage && _rekeying)
                {
                    Instrumentation.Trace($"kex: message {payload.Span[0]} waits for the re-exchange");
                    wait = _rekeyDone.Task;
                }
                else
                {
                    if (!kexMessage && _failed is { } failed)
                    {
                        throw failed;
                    }

                    if (condition is not null && !condition())
                    {
                        return false;
                    }

                    PacketCodec.Encode(_writer, payload.Span, _sendProtector, _sendSequence++);
                    onCommitted?.Invoke();
                    Interlocked.Add(ref _bytesSinceKex, payload.Length);
                    Interlocked.Increment(ref _packetsSentSinceKex);
                    SshTelemetry.BytesSent.Add(payload.Length);
                    var flush = _writer.FlushAsync(_lifetime.Token);
                    if (flush.IsCompleted)
                    {
                        flush.GetAwaiter().GetResult();
                        return true;
                    }

                    var pending = flush.AsTask();
                    try
                    {
                        await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested && !pending.IsCompleted)
                    {
                        release = false;
                        _ = ReleaseAfterAsync(pending);

                        // The packet is committed and will be sent. For SendIfAsync that is "sent": its callers treat a cancellation as
                        // "not sent" (a channel then returns the window it reserved).
                        if (condition is not null)
                        {
                            return true;
                        }

                        throw;
                    }

                    return true;
                }
            }
            finally
            {
                if (release)
                {
                    _sendLock.Release();
                }
            }

            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Releases the send lock once a flush abandoned by a cancelled caller has finished.</summary>
    private async Task ReleaseAfterAsync(Task flush)
    {
        try
        {
            await flush.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The transport is failing; the receive side reports it.
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private void FailRekeyWaiters(Exception exception)
    {
        _rekeyDone.TrySetException(exception);
        _ = _rekeyDone.Task.Exception; // mark observed: nobody may be waiting
    }

    // Pooled: completes asynchronously for nearly every packet, and would otherwise allocate a state machine box each time.
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<DecodedPacket> ReadPacketAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var result = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            var buffer = result.Buffer;
            if (PacketCodec.TryDecode(buffer, _receiveProtector, _receiveSequence, out var packet, out var consumed))
            {
                _reader.AdvanceTo(buffer.GetPosition(consumed));
                _receiveSequence++;
                if (packet!.Payload.Length == 0)
                {
                    packet.Dispose();
                    throw new SshProtocolException("Received an empty packet.");
                }

                Interlocked.Add(ref _bytesSinceKex, packet.Payload.Length);
                Interlocked.Increment(ref _packetsReceivedSinceKex);
                SshTelemetry.BytesReceived.Add(packet.Payload.Length);
                return packet;
            }

            if (result.IsCompleted)
            {
                throw new SshException(SshFailureReason.ConnectionClosed, "The connection was closed by the server.");
            }

            _reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    /// <summary>Reads packets until one of the expected type arrives, skipping IGNORE/DEBUG/UNIMPLEMENTED unless strict KEX forbids them.</summary>
    private async ValueTask<byte[]> ReceiveKexMessageAsync(byte expected, bool strict, CancellationToken cancellationToken)
    {
        while (true)
        {
            using var packet = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            var payload = packet.Payload.Span;
            var type = payload[0];
            if (type == expected)
            {
                return payload.ToArray();
            }

            switch (type)
            {
                case SshMessage.Disconnect:
                    throw ParseDisconnect(payload);
                case SshMessage.Ignore or SshMessage.Debug or SshMessage.Unimplemented when !strict:
                    continue;
                default:
                    throw new SshProtocolException($"Unexpected message {type} during key exchange (expected {expected}).");
            }
        }
    }

    private async ValueTask VerifyHostKeyAsync(NegotiatedAlgorithms negotiated, KexResult result, bool initial, CancellationToken cancellationToken)
    {
        // A certificate host key (PROTOCOL.certkeys): the server proves possession of the certified key, signing with the base algorithm.
        // Whether the certificate itself is trusted (authority, principals, validity) is the verifier's decision.
        SshPublicKey key;
        SshCertificate? certificate = null;
        var signatureAlgorithm = negotiated.HostKey;
        if (SshCertificate.IsCertificateAlgorithm(negotiated.HostKey))
        {
            try
            {
                certificate = SshCertificate.FromBlob(result.HostKeyBlob);
            }
            catch (SshProtocolException ex)
            {
                throw new SshHostKeyException("The server's host certificate is malformed: " + ex.Message);
            }

            if (certificate.CertificateType != SshCertificate.CertificateKeyType(negotiated.HostKey))
            {
                throw new SshHostKeyException($"The server sent a {certificate.CertificateType} certificate but negotiated {negotiated.HostKey}.");
            }

            key = certificate.Key;
            signatureAlgorithm = SshCertificate.BaseAlgorithm(negotiated.HostKey);
        }
        else
        {
            key = SshPublicKey.Parse(result.HostKeyBlob);
            var expectedType = negotiated.HostKey is SshAlgorithms.RsaSha2_256 or SshAlgorithms.RsaSha2_512 ? "ssh-rsa" : negotiated.HostKey;
            if (key.KeyType != expectedType)
            {
                throw new SshHostKeyException($"The server sent a {key.KeyType} host key but negotiated {negotiated.HostKey}.");
            }
        }

        if (!key.VerifySignature(signatureAlgorithm, result.Signature, result.ExchangeHash))
        {
            throw new SshHostKeyException("The server's signature over the exchange hash is invalid.");
        }

        if (!initial)
        {
            // A re-exchange must prove possession of the same key we already trusted; a different key is never silently accepted.
            if (!result.HostKeyBlob.AsSpan().SequenceEqual(HostKey!.Presented.Span))
            {
                throw new SshHostKeyException("The server's host key changed during a key re-exchange.");
            }

            return;
        }

        if (key.KeyType == "ssh-rsa" && key.KeySizeBits < _options.MinimumRsaBits)
        {
            throw new SshHostKeyException($"The server's RSA host key is only {key.KeySizeBits} bits (minimum {_options.MinimumRsaBits}).");
        }

        var info = new HostKeyInfo(negotiated.HostKey, key.KeyType, key.Blob, key.Fingerprint, key.KeySizeBits, result.HostKeyBlob, certificate);
        HostKey = info;
        InitialSignature = result.Signature;
        if (!await _options.VerifyHostKey(info, cancellationToken).ConfigureAwait(false))
        {
            throw new SshHostKeyException($"The host key {info.Fingerprint} was not accepted.");
        }
    }

    private static SshException ParseDisconnect(ReadOnlySpan<byte> payload)
    {
        try
        {
            var reader = new SshReader(payload);
            reader.ReadByte();
            var code = reader.ReadUInt32();
            var description = reader.ReadUtf8String();
            return new SshException(SshFailureReason.ConnectionClosed, $"The server closed the connection (reason {code}): {description}");
        }
        catch (SshProtocolException)
        {
            return new SshException(SshFailureReason.ConnectionClosed, "The server closed the connection.");
        }
    }

    /// <summary>The client's EXT_INFO: <c>ext-info-in-auth@openssh.com</c> = "0".</summary>
    private static readonly byte[] ClientExtInfo = BuildClientExtInfo();

    private static byte[] BuildClientExtInfo()
    {
        var buffer = new ArrayBufferWriter<byte>(64);
        var writer = new SshWriter(buffer);
        writer.WriteByte(SshMessage.ExtInfo);
        writer.WriteUInt32(1);
        writer.WriteString("ext-info-in-auth@openssh.com");
        writer.WriteString("0");
        return buffer.WrittenSpan.ToArray();
    }

    private static Dictionary<string, string> ParseExtInfo(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> previous)
    {
        // RFC 8308 section 2.4: a later EXT_INFO (after authentication) adds to or updates the first one.
        var extensions = new Dictionary<string, string>(previous, StringComparer.Ordinal);
        var reader = new SshReader(payload);
        reader.ReadByte();
        var count = reader.ReadUInt32();
        for (var i = 0u; i < count && i < 1024; i++)
        {
            var name = reader.ReadUtf8String();
            var value = System.Text.Encoding.UTF8.GetString(reader.ReadString());
            extensions[name] = value;
        }

        return extensions;
    }
}