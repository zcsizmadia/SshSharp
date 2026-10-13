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
        await SendPacketAsync(clientInitPayload, kexMessage: true, null, cancellationToken).ConfigureAwait(false);

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
        await SendPacketAsync(payload, kexMessage: false, onCommitted, cancellationToken).ConfigureAwait(false);
        if (_connected && !_rekeying && RekeyDue())
        {
            await StartRekeyAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Receives the next application-level message. Transport housekeeping is handled here: <c>IGNORE</c>, <c>DEBUG</c> and
    /// <c>UNIMPLEMENTED</c> are skipped, <c>EXT_INFO</c> is recorded, a key re-exchange is carried out, and <c>DISCONNECT</c> raises an
    /// <see cref="SshException"/>. The caller must dispose the returned packet.
    /// </summary>
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
                    ServerExtensions = ParseExtInfo(payload, ServerExtensions);
                    packet.Dispose();
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
                        await StartRekeyAsync(cancellationToken).ConfigureAwait(false);
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
        await SendPacketAsync(payload, kexMessage: true, null, cancellationToken).ConfigureAwait(false);
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

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Abort();
        FailRekeyWaiters(new SshException(SshFailureReason.ConnectionClosed, "The connection was closed."));
        try
        {
            await _writer.CompleteAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // The stream is already broken; there is nothing left to flush to.
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
        await SendPacketAsync(kex.CreateInit(), kexMessage: true, null, cancellationToken).ConfigureAwait(false);
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
        using var keys = KeyDerivation.DeriveAll(kex.Hash, result.SharedSecret, result.ExchangeHash, SessionId!, cipherC2S, cipherS2C, macC2S, macS2C);
        var newSend = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
        var newReceive = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);

        // Each side sends NEWKEYS under the old keys, then protects what it sends with the new ones; incoming switches on the peer's NEWKEYS.
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PacketCodec.Encode(_writer, new[] { SshMessage.NewKeys }, _sendProtector, _sendSequence++);
            await _writer.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            _sendProtector.Dispose();
            _sendProtector = newSend;
            if (strict)
            {
                _sendSequence = 0;
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
    private async ValueTask SendPacketAsync(ReadOnlyMemory<byte> payload, bool kexMessage, Action? onCommitted, CancellationToken cancellationToken)
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
                    wait = _rekeyDone.Task;
                }
                else
                {
                    PacketCodec.Encode(_writer, payload.Span, _sendProtector, _sendSequence++);
                    onCommitted?.Invoke();
                    Interlocked.Add(ref _bytesSinceKex, payload.Length);
                    Interlocked.Increment(ref _packetsSentSinceKex);
                    SshTelemetry.BytesSent.Add(payload.Length);
                    var flush = _writer.FlushAsync(_lifetime.Token);
                    if (flush.IsCompleted)
                    {
                        flush.GetAwaiter().GetResult();
                        return;
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
                        throw;
                    }

                    return;
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