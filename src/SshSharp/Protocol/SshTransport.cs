using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Security.Cryptography;
using SshSharp.Keys;

namespace SshSharp.Protocol;

/// <summary>
/// The client side of the SSH transport layer (RFC 4253) over a <see cref="Stream"/>: identification exchange, algorithm negotiation,
/// key exchange, host key verification, strict KEX (against Terrapin), and encrypted packet send/receive.
/// </summary>
internal sealed class SshTransport : IAsyncDisposable
{
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SshTransportOptions _options;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    private PacketProtector _sendProtector = PacketProtector.None;
    private PacketProtector _receiveProtector = PacketProtector.None;
    private uint _sendSequence;
    private uint _receiveSequence;
    private bool _connected;
    private bool _disposed;

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

    /// <summary>The session identifier (the exchange hash of the first key exchange).</summary>
    public byte[]? SessionId { get; private set; }

    /// <summary>The algorithms in use.</summary>
    public NegotiatedAlgorithms? Algorithms { get; private set; }

    /// <summary>The host key the server proved possession of.</summary>
    public HostKeyInfo? HostKey { get; private set; }

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

        var clientInit = KexInitMessage.ForClient(_options.Preferences);
        var clientInitPayload = Serialize(clientInit.Write);
        await SendPacketAsync(clientInitPayload, cancellationToken).ConfigureAwait(false);

        var serverInitPayload = await ReceiveKexMessageAsync(SshMessage.KexInit, strict: false, cancellationToken).ConfigureAwait(false);

        // The KEXINIT's own sequence number: anything skipped before it (IGNORE, DEBUG) shifts it away from 0.
        var serverInitSequence = _receiveSequence - 1;
        var serverInit = KexInitMessage.Parse(serverInitPayload);
        var negotiated = AlgorithmNegotiator.Negotiate(clientInit, serverInit);
        Algorithms = negotiated;

        // Strict KEX: the server's KEXINIT must be the very first packet, or an attacker may have injected or removed packets (Terrapin).
        if (negotiated.StrictKex && serverInitSequence != 0)
        {
            throw new SshProtocolException("Strict key exchange requires KEXINIT to be the first packet.");
        }

        if (negotiated.ServerGuessedWrong)
        {
            // The server sent a guessed key exchange packet that does not match what was negotiated: discard it.
            using var discarded = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
        }

        using var kex = ClientKeyExchange.Create(negotiated.Kex);
        await SendPacketAsync(kex.CreateInit(), cancellationToken).ConfigureAwait(false);
        var reply = await ReceiveKexMessageAsync(SshMessage.KexEcdhReply, negotiated.StrictKex, cancellationToken).ConfigureAwait(false);

        var context = new KexContext(_options.ClientIdentification.Line, ServerIdentification.Line, clientInitPayload, serverInitPayload);
        using var result = kex.ProcessReply(reply, context);
        await VerifyHostKeyAsync(negotiated, result, cancellationToken).ConfigureAwait(false);

        SessionId = (byte[])result.ExchangeHash.Clone();
        SshAlgorithms.TryGetCipher(negotiated.CipherClientToServer, out var cipherC2S);
        SshAlgorithms.TryGetCipher(negotiated.CipherServerToClient, out var cipherS2C);
        SshAlgorithms.TryGetMac(negotiated.MacClientToServer, out var macC2S);
        SshAlgorithms.TryGetMac(negotiated.MacServerToClient, out var macS2C);
        using var keys = KeyDerivation.DeriveAll(kex.Hash, result.SharedSecret, result.ExchangeHash, SessionId, cipherC2S, cipherS2C, macC2S, macS2C);
        var newSend = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
        var newReceive = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);

        // Each side sends NEWKEYS under the old keys, then protects what it sends with the new ones; incoming switches on the peer's NEWKEYS.
        await SendPacketAsync(new[] { SshMessage.NewKeys }, cancellationToken).ConfigureAwait(false);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _sendProtector.Dispose();
            _sendProtector = newSend;
            if (negotiated.StrictKex)
            {
                _sendSequence = 0;
            }
        }
        finally
        {
            _sendLock.Release();
        }

        await ReceiveKexMessageAsync(SshMessage.NewKeys, negotiated.StrictKex, cancellationToken).ConfigureAwait(false);
        _receiveProtector.Dispose();
        _receiveProtector = newReceive;
        if (negotiated.StrictKex)
        {
            _receiveSequence = 0;
        }

        _connected = true;
    }

    /// <summary>Sends one message (the payload starts with the message number).</summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await SendPacketAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives the next application-level message. Transport housekeeping is handled here: <c>IGNORE</c>, <c>DEBUG</c> and
    /// <c>UNIMPLEMENTED</c> are skipped, <c>EXT_INFO</c> is recorded, and <c>DISCONNECT</c> raises an <see cref="SshException"/>.
    /// The caller must dispose the returned packet.
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
                    ServerExtensions = ParseExtInfo(payload);
                    packet.Dispose();
                    continue;
                case SshMessage.KexInit:
                    packet.Dispose();
                    throw new SshException(SshFailureReason.ProtocolError, "The server started a re-exchange of keys, which this version does not support yet.");
                default:
                    return packet;
            }
        }
    }

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
        await SendPacketAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _writer.CompleteAsync().ConfigureAwait(false);
        await _reader.CompleteAsync().ConfigureAwait(false);
        _sendProtector.Dispose();
        _receiveProtector.Dispose();
        if (SessionId is not null)
        {
            CryptographicOperations.ZeroMemory(SessionId);
        }

        _sendLock.Dispose();
    }

    private static byte[] Serialize(Action<IBufferWriter<byte>> write)
    {
        var buffer = new ArrayBufferWriter<byte>(512);
        write(buffer);
        return buffer.WrittenSpan.ToArray();
    }

    private async ValueTask SendPacketAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PacketCodec.Encode(_writer, payload.Span, _sendProtector, _sendSequence++);
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
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

                return packet;
            }

            if (result.IsCompleted)
            {
                throw new SshException(SshFailureReason.ConnectionClosed, "The connection was closed by the server.");
            }

            _reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    /// <summary>Reads packets until one of the expected type arrives, skipping IGNORE/DEBUG unless strict KEX forbids them.</summary>
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
                case SshMessage.Ignore or SshMessage.Debug when !strict:
                    continue;
                default:
                    throw new SshProtocolException($"Unexpected message {type} during key exchange (expected {expected}).");
            }
        }
    }

    private async ValueTask VerifyHostKeyAsync(NegotiatedAlgorithms negotiated, KexResult result, CancellationToken cancellationToken)
    {
        var key = SshPublicKey.Parse(result.HostKeyBlob);
        var expectedType = negotiated.HostKey is SshAlgorithms.RsaSha2_256 or SshAlgorithms.RsaSha2_512 ? "ssh-rsa" : negotiated.HostKey;
        if (key.KeyType != expectedType)
        {
            throw new SshException(SshFailureReason.HostKeyRejected, $"The server sent a {key.KeyType} host key but negotiated {negotiated.HostKey}.");
        }

        if (!key.VerifySignature(negotiated.HostKey, result.Signature, result.ExchangeHash))
        {
            throw new SshException(SshFailureReason.HostKeyRejected, "The server's signature over the exchange hash is invalid.");
        }

        if (key.KeyType == "ssh-rsa" && key.KeySizeBits < _options.MinimumRsaBits)
        {
            throw new SshException(SshFailureReason.HostKeyRejected, $"The server's RSA host key is only {key.KeySizeBits} bits (minimum {_options.MinimumRsaBits}).");
        }

        var info = new HostKeyInfo(negotiated.HostKey, key.KeyType, result.HostKeyBlob, key.Fingerprint, key.KeySizeBits);
        HostKey = info;
        if (!await _options.VerifyHostKey(info, cancellationToken).ConfigureAwait(false))
        {
            throw new SshException(SshFailureReason.HostKeyRejected, $"The host key {info.Fingerprint} was not accepted.");
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

    private static Dictionary<string, string> ParseExtInfo(ReadOnlySpan<byte> payload)
    {
        var extensions = new Dictionary<string, string>(StringComparer.Ordinal);
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