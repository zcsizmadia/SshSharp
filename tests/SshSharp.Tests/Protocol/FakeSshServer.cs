using System.Buffers;
using System.IO.Pipelines;
using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>Two pipes glued into a duplex stream for in-memory client/server tests.</summary>
internal sealed class DuplexStream(Stream read, Stream write) : Stream
{
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() => write.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => write.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => read.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => read.ReadAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => write.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => write.WriteAsync(buffer, cancellationToken);

    /// <summary>Ends the writing direction only (the reader on the other side sees end-of-stream), like a socket's shutdown(SHUT_WR).</summary>
    public void CloseWrite() => write.Dispose();

    /// <summary>Two connected ends: what one writes, the other reads.</summary>
    public static (DuplexStream A, DuplexStream B) CreatePair()
    {
        var aToB = UnpooledMemoryPool.CreatePipe();
        var bToA = UnpooledMemoryPool.CreatePipe();
        return (new DuplexStream(bToA.Reader.AsStream(), aToB.Writer.AsStream()), new DuplexStream(aToB.Reader.AsStream(), bToA.Writer.AsStream()));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            read.Dispose();
            write.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>A server-side host key of a chosen type, able to sign exchange hashes the way an SSH server would.</summary>
internal sealed class FakeHostKey
{
    private readonly Func<string, byte[], byte[]> _sign;

    private FakeHostKey(string keyType, byte[] blob, Func<string, byte[], byte[]> sign)
    {
        KeyType = keyType;
        Blob = blob;
        _sign = sign;
    }

    public string KeyType { get; }

    public byte[] Blob { get; }

    public string Fingerprint => VerifyingKey.Parse(Blob).Fingerprint;

    /// <summary>Returns the SSH signature blob (<c>string type || string signature</c>) of <paramref name="data"/> under <paramref name="algorithm"/>.</summary>
    public byte[] Sign(string algorithm, byte[] data) => _sign(algorithm, data);

    private static byte[] Write(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    public static FakeHostKey Ed25519()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Ed25519Impl.GetPublicKey(seed, pub);
        var blob = Write(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });
        return new FakeHostKey("ssh-ed25519", blob, (alg, data) =>
        {
            var sig = new byte[64];
            Ed25519Impl.Sign(seed, data, sig);
            return Write(w => { w.WriteString(alg); w.WriteString(sig); });
        });
    }

    public static FakeHostKey Ecdsa(int bits)
    {
        var curve = bits switch { 256 => NistCurve.P256, 384 => NistCurve.P384, _ => NistCurve.P521 };
        var key = ECDsa.Create(curve.Curve);
        var q = key.ExportParameters(false).Q;
        var point = new byte[1 + (2 * curve.FieldSize)];
        point[0] = 4;
        q.X!.CopyTo(point, 1 + curve.FieldSize - q.X.Length);
        q.Y!.CopyTo(point, 1 + (2 * curve.FieldSize) - q.Y.Length);
        var type = "ecdsa-sha2-" + curve.Name;
        var blob = Write(w => { w.WriteString(type); w.WriteString(curve.Name); w.WriteString(point); });
        return new FakeHostKey(type, blob, (alg, data) =>
        {
            var raw = key.SignData(data, curve.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var inner = Write(w => { w.WriteMpint(raw.AsSpan(0, curve.FieldSize)); w.WriteMpint(raw.AsSpan(curve.FieldSize)); });
            return Write(w => { w.WriteString(alg); w.WriteString(inner); });
        });
    }

    public static FakeHostKey Rsa(int bits)
    {
        var key = RSA.Create(bits);
        var p = key.ExportParameters(false);
        var blob = Write(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent!); w.WriteMpint(p.Modulus!); });
        return new FakeHostKey("ssh-rsa", blob, (alg, data) =>
        {
            var hash = alg == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
            var signature = key.SignData(data, hash, RSASignaturePadding.Pkcs1);
            return Write(w => { w.WriteString(alg); w.WriteString(signature); });
        });
    }

    /// <summary>
    /// <paramref name="key"/> presented with a certificate for it (made with <see cref="Keys.TestKeys.Certificate"/>): the server sends the
    /// certificate and signs with the key under the base algorithm, as sshd does with a HostCertificate.
    /// </summary>
    public static FakeHostKey Certified(FakeHostKey key, byte[] certificateBlob) =>
        new(new SshReader(certificateBlob).ReadUtf8String(), certificateBlob, (alg, data) => key.Sign(SshCertificate.BaseAlgorithm(alg), data));

    // Alias so this file does not clash with the Ed25519 test class name.
    private static class Ed25519Impl
    {
        public static void GetPublicKey(byte[] seed, byte[] pub) => global::SshSharp.Crypto.Ed25519.GetPublicKey(seed, pub);

        public static void Sign(byte[] seed, byte[] data, byte[] sig) => global::SshSharp.Crypto.Ed25519.Sign(seed, data, sig);
    }
}

/// <summary>How the fake server behaves.</summary>
internal sealed class FakeServerOptions
{
    public string Kex { get; init; } = SshAlgorithms.Curve25519Sha256;

    public string Cipher { get; init; } = "chacha20-poly1305@openssh.com";

    public string Mac { get; init; } = "hmac-sha2-256-etm@openssh.com";

    public FakeHostKey HostKey { get; init; } = FakeHostKey.Ed25519();

    /// <summary>The host key algorithm to offer; defaults to the key's type.</summary>
    public string? HostKeyAlgorithm { get; init; }

    /// <summary>More host keys of other types, offered after <see cref="HostKey"/> (as sshd with several HostKey lines).</summary>
    public IReadOnlyList<FakeHostKey> ExtraHostKeys { get; init; } = [];

    /// <summary>A host certificate offered in addition to <see cref="HostKey"/> (see <see cref="FakeHostKey.Certified"/>).</summary>
    public FakeHostKey? HostCertificate { get; init; }

    /// <summary>The certificate algorithm to offer, when it differs from the certificate type (RSA: <c>rsa-sha2-512-cert-v01@openssh.com</c>).</summary>
    public string? HostCertificateAlgorithm { get; init; }

    public bool AdvertiseStrictKex { get; init; } = true;

    public bool SendExtInfo { get; init; } = true;

    /// <summary>The <c>server-sig-algs</c> extension value (what OpenSSH sends by default).</summary>
    public string ServerSigAlgs { get; init; } = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";

    /// <summary>More EXT_INFO entries after <c>server-sig-algs</c>, for example RFC 9987's <c>agent-forward</c>.</summary>
    public IReadOnlyDictionary<string, string> ExtraExtensions { get; init; } = new Dictionary<string, string>();

    public string[] BannerLines { get; init; } = [];

    public string Identification { get; init; } = "SSH-2.0-FakeServer_1.0";

    /// <summary>Send this many SSH_MSG_IGNORE packets before the server's KEXINIT.</summary>
    public int IgnoresBeforeKexInit { get; init; }

    /// <summary>Send an SSH_MSG_IGNORE between KEXINIT and the key exchange reply.</summary>
    public bool IgnoreDuringKex { get; init; }

    public bool CorruptSignature { get; init; }

    /// <summary>Claim a guessed first key exchange packet follows, using a different kex than the one negotiated.</summary>
    public bool WrongGuess { get; init; }

    /// <summary>Close the connection right after receiving the client's KEXINIT.</summary>
    public bool CloseAfterKexInit { get; init; }

    /// <summary>Send SSH_MSG_DISCONNECT in place of the key exchange reply.</summary>
    public string? DisconnectInsteadOfReply { get; init; }

    /// <summary>Do not send the server identification at all.</summary>
    public bool SilentOnConnect { get; init; }

    /// <summary>The group sent for <c>diffie-hellman-group-exchange-sha256</c>: RFC 3526 group 14 when null.</summary>
    public (BigInteger P, BigInteger G)? GexGroup { get; init; }

    /// <summary>Send this as the server's group exchange value f instead of a real one.</summary>
    public BigInteger? GexServerValue { get; init; }

    // ---- behaviour of key re-exchanges ----

    /// <summary>Use this host key (instead of <see cref="HostKey"/>) when re-exchanging keys.</summary>
    public FakeHostKey? RekeyHostKey { get; init; }

    /// <summary>Negotiate this cipher on re-exchange (the client must allow it).</summary>
    public string? RekeyCipher { get; init; }

    /// <summary>Negotiate this key exchange method on re-exchange.</summary>
    public string? RekeyKex { get; init; }

    /// <summary>Send an SSH_MSG_IGNORE between KEXINIT and the reply of a re-exchange.</summary>
    public bool IgnoreDuringRekey { get; init; }

    /// <summary>Send this application message (channel data, for example) between KEXINIT and the reply of a re-exchange: a protocol violation.</summary>
    public byte[]? ApplicationMessageDuringRekey { get; init; }
}

/// <summary>
/// A scriptable in-memory SSH server speaking the real protocol with this library's primitives. After <see cref="StartAsync"/>
/// completes, tests drive it with <see cref="SendAsync"/> and <see cref="ReceiveAsync"/>. It also takes part in key re-exchanges:
/// call <see cref="RekeyAsync"/> to start one, and a client-initiated one is carried out transparently inside <see cref="ReceiveAsync"/>.
/// </summary>
internal sealed class FakeSshServer : IAsyncDisposable
{
    private readonly Pipe _toServer = UnpooledMemoryPool.CreatePipe();
    private readonly Pipe _toClient = UnpooledMemoryPool.CreatePipe();
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private bool _writerCompleted; // protected by _sendLock
    private PacketProtector _send = PacketProtector.None;
    private PacketProtector _receive = PacketProtector.None;
    private uint _sendSeq;
    private uint _receiveSeq;
    private bool _strict;

    // Re-exchange state (protected by _sendLock, like the client's).
    private bool _rekeying;
    private TaskCompletionSource _rekeyDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private KexInitMessage? _pendingServerInit;
    private byte[]? _pendingServerInitPayload;

    public FakeSshServer(FakeServerOptions? options = null)
    {
        Options = options ?? new FakeServerOptions();
        ClientStream = new DuplexStream(_toClient.Reader.AsStream(), _toServer.Writer.AsStream());
        _reader = _toServer.Reader;
        _writer = _toClient.Writer;
    }

    public FakeServerOptions Options { get; }

    /// <summary>The stream to hand to the transport under test.</summary>
    public Stream ClientStream { get; }

    public SshIdentification? ClientIdentification { get; private set; }

    public KexInitMessage? ClientKexInit { get; private set; }

    public NegotiatedAlgorithms? Negotiated { get; private set; }

    /// <summary>The client's last group exchange request (min, n, max).</summary>
    public (uint Min, uint Preferred, uint Max)? GexRequest { get; private set; }

    public byte[]? SessionId { get; private set; }

    /// <summary>How many key exchanges have completed on the server side, including the first.</summary>
    public int KeyExchangeCount { get; private set; }

    /// <summary>Runs the server side of the handshake. Await it together with the client's ConnectAsync.</summary>
    /// <summary>How far the initial handshake got, for tests that time out waiting for it (#188).</summary>
    public string Stage
    {
        get => Volatile.Read(ref _stage);
        private set => Volatile.Write(ref _stage, value);
    }

    private string _stage = "not started";

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        Stage = "reading the client's identification";
        ClientIdentification = await SshIdentification.ReadAsync(_reader, cancellationToken);
        Stage = "sending the identification and KEXINIT";

        if (!Options.SilentOnConnect)
        {
            foreach (var line in Options.BannerLines)
            {
                var bytes = System.Text.Encoding.ASCII.GetBytes(line + "\r\n");
                await _writer.WriteAsync(bytes, cancellationToken);
            }

            var identBytes = System.Text.Encoding.ASCII.GetBytes(Options.Identification + "\r\n");
            await _writer.WriteAsync(identBytes, cancellationToken);
        }

        for (var i = 0; i < Options.IgnoresBeforeKexInit; i++)
        {
            await SendKexAsync(IgnorePayload(), cancellationToken);
        }

        var serverInit = BuildServerKexInit(initial: true);
        var serverInitPayload = Serialize(serverInit.Write);
        await SendKexAsync(serverInitPayload, cancellationToken);

        Stage = "reading the client's KEXINIT";
        using var clientInitPacket = await ReceiveRawAsync(cancellationToken);
        var clientInitPayload = clientInitPacket.Payload.ToArray();
        ClientKexInit = KexInitMessage.Parse(clientInitPayload);

        if (Options.CloseAfterKexInit)
        {
            Negotiated = AlgorithmNegotiator.Negotiate(ClientKexInit, serverInit);
            await CompleteWriterAsync();
            return;
        }

        await ExchangeAsync(ClientKexInit, clientInitPayload, serverInit, serverInitPayload, initial: true, cancellationToken);
        Stage = "handshake done";
    }

    /// <summary>Starts a key re-exchange from the server side. It completes when the client's KEXINIT arrives in <see cref="ReceiveAsync"/>.</summary>
    public async Task RekeyAsync(CancellationToken cancellationToken = default)
    {
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            if (!_rekeying)
            {
                await SendServerKexInitLockedAsync(cancellationToken);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>Sends an application message. Like the client, the server holds these back while a key exchange is in progress.</summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            Task? wait = null;
            await _sendLock.WaitAsync(cancellationToken);
            try
            {
                if (_rekeying)
                {
                    wait = _rekeyDone.Task;
                }
                else
                {
                    EncodeLocked(payload.Span);
                    await _writer.FlushAsync(cancellationToken);
                    return;
                }
            }
            finally
            {
                _sendLock.Release();
            }

            await wait.WaitAsync(cancellationToken);
        }
    }

    /// <summary>The extensions the client announced in its EXT_INFO.</summary>
    public Dictionary<string, string> ClientExtensions { get; } = new(StringComparer.Ordinal);

    /// <summary>Receives the next application message; a client-initiated re-exchange is handled on the way.</summary>
    public async ValueTask<DecodedPacket> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var packet = await ReceiveRawAsync(cancellationToken);
            if (packet.Payload.Span[0] == SshMessage.ExtInfo)
            {
                // The client's own extensions (RFC 8308), sent right after its first NEWKEYS; recorded, not handed to the test.
                var reader = new SshReader(packet.Payload.Span);
                reader.ReadByte();
                var count = reader.ReadUInt32();
                for (var i = 0u; i < count; i++)
                {
                    ClientExtensions[reader.ReadUtf8String()] = reader.ReadUtf8String();
                }

                packet.Dispose();
                continue;
            }

            if (packet.Payload.Span[0] != SshMessage.KexInit)
            {
                return packet;
            }

            var clientInitPayload = packet.Payload.ToArray();
            packet.Dispose();
            await HandleClientKexInitAsync(clientInitPayload, cancellationToken);
        }
    }

    /// <summary>Writes raw bytes to the client, bypassing the packet layer (to simulate corruption).</summary>
    public async ValueTask WriteRawAsync(byte[] bytes, CancellationToken cancellationToken = default)
    {
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            ThrowIfWriterCompleted();
            await _writer.WriteAsync(bytes, cancellationToken);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// Closes the server's side of the connection. If a sender holds the send lock too long (see <see cref="CompleteWriterAsync"/>), the
    /// connection is cut instead: a test that closes the server relies on the client noticing, and a close that silently did nothing
    /// made such a test wait out its timeout (stress run 39100315796, windows-latest).
    /// </summary>
    public async ValueTask CloseAsync()
    {
        if (!await CompleteWriterAsync())
        {
            ClientStream.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CompleteWriterAsync();
        await _reader.CompleteAsync();
        _send.Dispose();
        _receive.Dispose();
        ClientStream.Dispose();
    }

    /// <summary>Encodes a packet into the server-to-client pipe. The caller holds <see cref="_sendLock"/>.</summary>
    private void EncodeLocked(ReadOnlySpan<byte> payload)
    {
        ThrowIfWriterCompleted();
        PacketCodec.Encode(_writer, payload, _send, _sendSeq++);
    }

    /// <summary>Writing after the close fails as the completed pipe would have failed it.</summary>
    private void ThrowIfWriterCompleted()
    {
        if (_writerCompleted)
        {
            throw new InvalidOperationException("The server's side of the connection is closed.");
        }
    }

    /// <summary>
    /// Completes the server-to-client pipe under the send lock, so no packet is being encoded into the pipe's memory meanwhile, as the
    /// client's transport does. A sender stuck holding the lock (writing into a pipe nobody reads) keeps the pipe open instead; the
    /// unpooled pipe memory makes a late write harmless either way. Returns whether the pipe is completed.
    /// </summary>
    private async ValueTask<bool> CompleteWriterAsync()
    {
        var locked = await _sendLock.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            if (locked && !_writerCompleted)
            {
                _writerCompleted = true;
                await _writer.CompleteAsync();
            }

            return _writerCompleted;
        }
        finally
        {
            if (locked)
            {
                _sendLock.Release();
            }
        }
    }

    public static byte[] IgnorePayload() => [SshMessage.Ignore, 0, 0, 0, 1, 0x41];

    /// <summary>The host key algorithms a plain key is offered under.</summary>
    private static string[] AlgorithmsFor(FakeHostKey key) => key.KeyType == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [key.KeyType];

    public static byte[] DisconnectPayload(string description)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteByte(SshMessage.Disconnect);
        w.WriteUInt32((uint)DisconnectReason.ByApplication);
        w.WriteString(description);
        w.WriteString(string.Empty);
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] Serialize(Action<IBufferWriter<byte>> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(buffer);
        return buffer.WrittenSpan.ToArray();
    }

    // ---- key exchange, initial and re-exchange ----

    /// <summary>The client's KEXINIT arrived during normal operation: answer with ours (unless we started it) and run the exchange.</summary>
    private async Task HandleClientKexInitAsync(byte[] clientInitPayload, CancellationToken cancellationToken)
    {
        KexInitMessage serverInit;
        byte[] serverInitPayload;
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            if (!_rekeying)
            {
                await SendServerKexInitLockedAsync(cancellationToken);
            }

            serverInit = _pendingServerInit!;
            serverInitPayload = _pendingServerInitPayload!;
        }
        finally
        {
            _sendLock.Release();
        }

        await ExchangeAsync(KexInitMessage.Parse(clientInitPayload), clientInitPayload, serverInit, serverInitPayload, initial: false, cancellationToken);
    }

    private async Task SendServerKexInitLockedAsync(CancellationToken cancellationToken)
    {
        var serverInit = BuildServerKexInit(initial: false);
        var payload = Serialize(serverInit.Write);
        _rekeying = true;
        _pendingServerInit = serverInit;
        _pendingServerInitPayload = payload;
        EncodeLocked(payload);
        await _writer.FlushAsync(cancellationToken);
    }

    private async Task ExchangeAsync(KexInitMessage clientInit, byte[] clientInitPayload, KexInitMessage serverInit, byte[] serverInitPayload, bool initial, CancellationToken cancellationToken)
    {
        var negotiated = AlgorithmNegotiator.Negotiate(clientInit, serverInit);
        if (initial)
        {
            _strict = negotiated.StrictKex;
        }

        Negotiated = negotiated with { StrictKex = _strict };

        if (initial && Options.WrongGuess)
        {
            await SendKexAsync(new byte[] { SshMessage.KexEcdhReply, 0, 0, 0, 0 }, cancellationToken); // the "guessed" packet, to be discarded
        }

        if (initial)
        {
            Stage = $"reading the client's key exchange init ({negotiated.Kex}, {negotiated.HostKey})";
        }

        GexState? gex = null;
        if (negotiated.Kex == SshAlgorithms.DhGroupExchangeSha256)
        {
            // RFC 4419: the client's request (min, n, max), then the server's group.
            using var requestPacket = await ReceiveRawAsync(cancellationToken);
            var request = new SshReader(requestPacket.Payload.Span);
            if (request.ReadByte() != SshMessage.KexDhGexRequest)
            {
                throw new InvalidOperationException("Expected SSH_MSG_KEX_DH_GEX_REQUEST.");
            }

            GexRequest = (request.ReadUInt32(), request.ReadUInt32(), request.ReadUInt32());
            var (p, g) = Options.GexGroup ?? (ModpGroup.Group14.Prime, ModpGroup.Generator);
            gex = new GexState(GexRequest.Value, p.ToByteArray(isUnsigned: true, isBigEndian: true), g.ToByteArray(isUnsigned: true, isBigEndian: true));
            var group = new ArrayBufferWriter<byte>();
            var groupWriter = new SshWriter(group);
            groupWriter.WriteByte(SshMessage.KexDhGexGroup);
            groupWriter.WriteMpint(gex.P);
            groupWriter.WriteMpint(gex.G);
            await SendKexAsync(group.WrittenMemory, cancellationToken);
        }

        using var kexInitPacket = await ReceiveRawAsync(cancellationToken);
        var init = kexInitPacket.Payload.ToArray();

        if (initial ? Options.IgnoreDuringKex : Options.IgnoreDuringRekey)
        {
            await SendKexAsync(IgnorePayload(), cancellationToken);
        }

        if (!initial && Options.ApplicationMessageDuringRekey is { } misplaced)
        {
            await SendKexAsync(misplaced, cancellationToken);
        }

        if (initial && Options.DisconnectInsteadOfReply is { } why)
        {
            await SendKexAsync(DisconnectPayload(why), cancellationToken);
            return;
        }

        var hostKey = SshCertificate.IsCertificateAlgorithm(negotiated.HostKey) && Options.HostCertificate is { } certificate
            ? certificate
            : !initial && Options.RekeyHostKey is { } replacement ? replacement
            : Options.ExtraHostKeys.FirstOrDefault(k => AlgorithmsFor(k).Contains(negotiated.HostKey)) ?? Options.HostKey;
        if (initial)
        {
            Stage = "computing and sending the key exchange reply";
        }

        var (reply, secret, hash, kexHash) = RunKex(negotiated.Kex, negotiated.HostKey, hostKey, init, clientInitPayload, serverInitPayload, gex);
        await SendKexAsync(reply, cancellationToken);
        if (initial)
        {
            Stage = "reply sent; sending NEWKEYS";
        }

        if (initial)
        {
            SessionId = hash;
        }

        SshAlgorithms.TryGetCipher(negotiated.CipherClientToServer, out var cipherC2S);
        SshAlgorithms.TryGetCipher(negotiated.CipherServerToClient, out var cipherS2C);
        SshAlgorithms.TryGetMac(negotiated.MacClientToServer, out var macC2S);
        SshAlgorithms.TryGetMac(negotiated.MacServerToClient, out var macS2C);
        using var keys = KeyDerivation.DeriveAll(kexHash, secret, hash, SessionId!, cipherC2S, cipherS2C, macC2S, macS2C,
            sharedSecretIsString: SshAlgorithms.IsPostQuantum(negotiated.Kex));
        var newSend = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);
        var newReceive = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);

        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            EncodeLocked(new byte[] { SshMessage.NewKeys });
            await _writer.FlushAsync(cancellationToken);
            _send.Dispose();
            _send = newSend;
            if (_strict)
            {
                _sendSeq = 0;
            }

            _rekeying = false;
            _pendingServerInit = null;
            _pendingServerInitPayload = null;
            var done = _rekeyDone;
            _rekeyDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            done.TrySetResult();
        }
        finally
        {
            _sendLock.Release();
        }

        if (initial)
        {
            Stage = "NEWKEYS sent; reading the client's";
        }

        using var newKeysPacket = await ReceiveRawAsync(cancellationToken);
        if (newKeysPacket.Payload.Span[0] != SshMessage.NewKeys)
        {
            throw new InvalidOperationException("The client did not send NEWKEYS.");
        }

        _receive.Dispose();
        _receive = newReceive;
        if (_strict)
        {
            _receiveSeq = 0;
        }

        KeyExchangeCount++;

        if (initial && Options.SendExtInfo && negotiated.ServerSupportsExtInfo)
        {
            await SendAsync(Serialize(output =>
            {
                var w = new SshWriter(output);
                w.WriteByte(SshMessage.ExtInfo);
                w.WriteUInt32((uint)(1 + Options.ExtraExtensions.Count));
                w.WriteString("server-sig-algs");
                w.WriteString(Options.ServerSigAlgs);
                foreach (var (name, value) in Options.ExtraExtensions)
                {
                    w.WriteString(name);
                    w.WriteString(value);
                }
            }), cancellationToken);
        }
    }

    /// <summary>Sends a key exchange or transport message: allowed while a key exchange is in progress.</summary>
    private async ValueTask SendKexAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            EncodeLocked(payload.Span);
            await _writer.FlushAsync(cancellationToken);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async ValueTask<DecodedPacket> ReceiveRawAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var result = await _reader.ReadAsync(cancellationToken);
            var buffer = result.Buffer;
            if (PacketCodec.TryDecode(buffer, _receive, _receiveSeq, out var packet, out var consumed))
            {
                _reader.AdvanceTo(buffer.GetPosition(consumed));
                _receiveSeq++;
                return packet!;
            }

            if (result.IsCompleted)
            {
                throw new EndOfStreamException("The client closed the connection.");
            }

            _reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    private KexInitMessage BuildServerKexInit(bool initial)
    {
        var offeredKex = initial ? Options.Kex : Options.RekeyKex ?? Options.Kex;
        var kex = new List<string> { initial && Options.WrongGuess ? SshAlgorithms.EcdhNistp256 : offeredKex };
        if (initial && Options.WrongGuess)
        {
            kex.Add(offeredKex);
        }

        if (initial && Options.SendExtInfo)
        {
            kex.Add(SshAlgorithms.ExtInfoServer);
        }

        if (initial && Options.AdvertiseStrictKex)
        {
            kex.Add(SshAlgorithms.StrictKexServer);
        }

        var cipher = initial ? Options.Cipher : Options.RekeyCipher ?? Options.Cipher;
        var hostKey = !initial && Options.RekeyHostKey is { } replacement ? replacement : Options.HostKey;
        return new KexInitMessage
        {
            Cookie = RandomNumberGenerator.GetBytes(16),
            KexAlgorithms = kex,
            // Like sshd with HostCertificate: the certificate algorithm first, then the plain key's.
            ServerHostKeyAlgorithms =
            [
                .. Options.HostCertificate is { } certificate ? [Options.HostCertificateAlgorithm ?? certificate.KeyType] : Array.Empty<string>(),
                .. Options.HostKeyAlgorithm is { } algorithm ? new[] { algorithm } : AlgorithmsFor(hostKey),
                .. Options.ExtraHostKeys.SelectMany(AlgorithmsFor),
            ],
            EncryptionClientToServer = [cipher],
            EncryptionServerToClient = [cipher],
            MacClientToServer = [Options.Mac],
            MacServerToClient = [Options.Mac],
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
            FirstKexPacketFollows = initial && Options.WrongGuess,
        };
    }

    private (byte[] Reply, byte[] Secret, byte[] Hash, HashAlgorithmName HashAlgorithm) RunKex(string method, string hostKeyAlgorithm, FakeHostKey hostKey, byte[] init, byte[] clientInit, byte[] serverInit,
        GexState? gex)
    {
        var clientVersion = ClientIdentification!.Line;
        var serverVersion = Options.Identification;

        byte[] Reply(Action<SshWriter> body, byte[] hash)
        {
            var signature = hostKey.Sign(hostKeyAlgorithm, hash);
            if (Options.CorruptSignature)
            {
                signature[^1] ^= 1;
            }

            var buffer = new ArrayBufferWriter<byte>();
            var w = new SshWriter(buffer);
            w.WriteByte(gex is null ? SshMessage.KexEcdhReply : SshMessage.KexDhGexReply);
            w.WriteString(hostKey.Blob);
            body(w);
            w.WriteString(signature);
            return buffer.WrittenSpan.ToArray();
        }

        var reader = new SshReader(init);
        reader.ReadByte();
        switch (method)
        {
#if NET10_0_OR_GREATER
            case SshAlgorithms.MlKem768X25519Sha256:
            {
                // The server side of mlkem768x25519-sha256: encapsulate to the client's ML-KEM key, add an X25519 share, K = SHA-256 of both.
                var clientInitValue = reader.ReadString().ToArray();
                using var encapsulationKey = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, clientInitValue.AsSpan(0, 1184));
                encapsulationKey.Encapsulate(out var ciphertext, out var pqSecret);
                var priv = RandomNumberGenerator.GetBytes(32);
                var qs = new byte[32];
                X25519.GetPublicKey(priv, qs);
                var classic = new byte[32];
                X25519.TryAgree(priv, clientInitValue.AsSpan(1184), classic);
                var k = SHA256.HashData([.. pqSecret, .. classic]);
                byte[] serverReply = [.. ciphertext, .. qs];
                var h = ExchangeHash.Compute(HashAlgorithmName.SHA256, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob,
                    w => { w.WriteString(clientInitValue); w.WriteString(serverReply); }, k, sharedSecretIsString: true);
                return (Reply(w => w.WriteString(serverReply), h), k, h, HashAlgorithmName.SHA256);
            }

            case SshAlgorithms.MlKem768Nistp256Sha256 or SshAlgorithms.MlKem1024Nistp384Sha384:
            {
                // RFC 10042, the server side: C_INIT = ML-KEM encapsulation key || uncompressed point; S_REPLY = ciphertext || point;
                // K = HASH(ML-KEM secret || ECDH x coordinate), as a string.
                var (algorithm, curve) = method == SshAlgorithms.MlKem768Nistp256Sha256
                    ? (MLKemAlgorithm.MLKem768, NistCurve.P256)
                    : (MLKemAlgorithm.MLKem1024, NistCurve.P384);
                var clientInitValue = reader.ReadString().ToArray();
                var keySize = algorithm.EncapsulationKeySizeInBytes;
                using var encapsulationKey = MLKem.ImportEncapsulationKey(algorithm, clientInitValue.AsSpan(0, keySize));
                encapsulationKey.Encapsulate(out var ciphertext, out var pqSecret);
                var qc = clientInitValue.AsSpan(keySize);
                using var server = ECDiffieHellman.Create(curve.Curve);
                var q = server.ExportParameters(false).Q;
                var qs = new byte[1 + (2 * curve.FieldSize)];
                qs[0] = 4;
                q.X!.CopyTo(qs, 1 + curve.FieldSize - q.X.Length);
                q.Y!.CopyTo(qs, 1 + (2 * curve.FieldSize) - q.Y.Length);
                using var peer = ECDiffieHellman.Create(new ECParameters
                {
                    Curve = curve.Curve,
                    Q = new ECPoint { X = qc.Slice(1, curve.FieldSize).ToArray(), Y = qc.Slice(1 + curve.FieldSize).ToArray() },
                });
                var classic = server.DeriveRawSecretAgreement(peer.PublicKey);
                byte[] both = [.. pqSecret, .. classic];
                var k = curve.Hash == HashAlgorithmName.SHA384 ? SHA384.HashData(both) : SHA256.HashData(both);
                byte[] serverReply = [.. ciphertext, .. qs];
                var h = ExchangeHash.Compute(curve.Hash, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob,
                    w => { w.WriteString(clientInitValue); w.WriteString(serverReply); }, k, sharedSecretIsString: true);
                return (Reply(w => w.WriteString(serverReply), h), k, h, curve.Hash);
            }
#endif

            case SshAlgorithms.Sntrup761X25519Sha512 or SshAlgorithms.Sntrup761X25519Sha512OpenSsh:
            {
                // The server side of sntrup761x25519-sha512: encapsulate to the client's sntrup761 key, add an X25519 share, K = SHA-512 of both.
                var clientInitValue = reader.ReadString().ToArray();
                var ciphertext = new byte[Sntrup761.CiphertextSize];
                var pqSecret = new byte[Sntrup761.SharedSecretSize];
                Sntrup761.Encapsulate(ciphertext, pqSecret, clientInitValue.AsSpan(0, Sntrup761.PublicKeySize));
                var priv = RandomNumberGenerator.GetBytes(32);
                var qs = new byte[32];
                X25519.GetPublicKey(priv, qs);
                var classic = new byte[32];
                X25519.TryAgree(priv, clientInitValue.AsSpan(Sntrup761.PublicKeySize), classic);
                var k = SHA512.HashData([.. pqSecret, .. classic]);
                byte[] serverReply = [.. ciphertext, .. qs];
                var h = ExchangeHash.Compute(HashAlgorithmName.SHA512, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob,
                    w => { w.WriteString(clientInitValue); w.WriteString(serverReply); }, k, sharedSecretIsString: true);
                return (Reply(w => w.WriteString(serverReply), h), k, h, HashAlgorithmName.SHA512);
            }

            case SshAlgorithms.Curve25519Sha256 or SshAlgorithms.Curve25519Sha256Libssh:
            {
                var qc = reader.ReadString().ToArray();
                var priv = RandomNumberGenerator.GetBytes(32);
                var qs = new byte[32];
                X25519.GetPublicKey(priv, qs);
                var k = new byte[32];
                X25519.TryAgree(priv, qc, k);
                var h = ExchangeHash.Compute(HashAlgorithmName.SHA256, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob, w => { w.WriteString(qc); w.WriteString(qs); }, k);
                return (Reply(w => w.WriteString(qs), h), k, h, HashAlgorithmName.SHA256);
            }

            case SshAlgorithms.EcdhNistp256 or SshAlgorithms.EcdhNistp384 or SshAlgorithms.EcdhNistp521:
            {
                var curve = method switch { SshAlgorithms.EcdhNistp256 => NistCurve.P256, SshAlgorithms.EcdhNistp384 => NistCurve.P384, _ => NistCurve.P521 };
                var qc = reader.ReadString().ToArray();
                using var server = ECDiffieHellman.Create(curve.Curve);
                var q = server.ExportParameters(false).Q;
                var qs = new byte[1 + (2 * curve.FieldSize)];
                qs[0] = 4;
                q.X!.CopyTo(qs, 1 + curve.FieldSize - q.X.Length);
                q.Y!.CopyTo(qs, 1 + (2 * curve.FieldSize) - q.Y.Length);
                using var peer = ECDiffieHellman.Create(new ECParameters
                {
                    Curve = curve.Curve,
                    Q = new ECPoint { X = qc.AsSpan(1, curve.FieldSize).ToArray(), Y = qc.AsSpan(1 + curve.FieldSize).ToArray() },
                });
                var k = server.DeriveRawSecretAgreement(peer.PublicKey);
                var h = ExchangeHash.Compute(curve.Hash, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob, w => { w.WriteString(qc); w.WriteString(qs); }, k);
                return (Reply(w => w.WriteString(qs), h), k, h, curve.Hash);
            }

            case SshAlgorithms.DhGroupExchangeSha256:
            {
                // RFC 4419 section 3: the exchange in the group sent, H over min, n, max, p, g, e, f.
                var p = new BigInteger(gex!.P, isUnsigned: true, isBigEndian: true);
                var g = new BigInteger(gex.G, isUnsigned: true, isBigEndian: true);
                var eBytes = reader.ReadMpint().ToArray();
                var e = new BigInteger(eBytes, isUnsigned: true, isBigEndian: true);
                var y = new BigInteger(RandomNumberGenerator.GetBytes(64), isUnsigned: true, isBigEndian: true) + 2;
                var fBytes = Options.GexServerValue?.ToByteArray(isUnsigned: true, isBigEndian: true)
                    ?? BigInteger.ModPow(g, y, p).ToByteArray(isUnsigned: true, isBigEndian: true);
                var k = BigInteger.ModPow(e, y, p).ToByteArray(isUnsigned: true, isBigEndian: true);
                var h = ExchangeHash.Compute(HashAlgorithmName.SHA256, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob, w =>
                {
                    w.WriteUInt32(gex.Request.Min);
                    w.WriteUInt32(gex.Request.Preferred);
                    w.WriteUInt32(gex.Request.Max);
                    w.WriteMpint(gex.P);
                    w.WriteMpint(gex.G);
                    w.WriteMpint(eBytes);
                    w.WriteMpint(fBytes);
                }, k);
                return (Reply(w => w.WriteMpint(fBytes), h), k, h, HashAlgorithmName.SHA256);
            }

            default:
            {
                var (group, hash) = method switch
                {
                    SshAlgorithms.DhGroup14Sha256 => (ModpGroup.Group14, HashAlgorithmName.SHA256),
                    SshAlgorithms.DhGroup18Sha512 => (ModpGroup.Group18, HashAlgorithmName.SHA512),
                    _ => (ModpGroup.Group16, HashAlgorithmName.SHA512),
                };
                var eBytes = reader.ReadMpint().ToArray();
                var e = new BigInteger(eBytes, isUnsigned: true, isBigEndian: true);
                var y = new BigInteger(RandomNumberGenerator.GetBytes(64), isUnsigned: true, isBigEndian: true) + 2;
                var fBytes = BigInteger.ModPow(2, y, group.Prime).ToByteArray(isUnsigned: true, isBigEndian: true);
                var k = BigInteger.ModPow(e, y, group.Prime).ToByteArray(isUnsigned: true, isBigEndian: true);
                var h = ExchangeHash.Compute(hash, clientVersion, serverVersion, clientInit, serverInit, hostKey.Blob, w => { w.WriteMpint(eBytes); w.WriteMpint(fBytes); }, k);
                return (Reply(w => w.WriteMpint(fBytes), h), k, h, hash);
            }
        }
    }
}

/// <summary>A group exchange in progress on the fake server: the client's request and the group sent (p and g as unsigned magnitudes).</summary>
internal sealed record GexState((uint Min, uint Preferred, uint Max) Request, byte[] P, byte[] G);
