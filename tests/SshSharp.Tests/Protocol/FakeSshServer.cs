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

    public string Fingerprint => SshPublicKey.Parse(Blob).Fingerprint;

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

    /// <summary>A host certificate offered in addition to <see cref="HostKey"/> (see <see cref="FakeHostKey.Certified"/>).</summary>
    public FakeHostKey? HostCertificate { get; init; }

    /// <summary>The certificate algorithm to offer, when it differs from the certificate type (RSA: <c>rsa-sha2-512-cert-v01@openssh.com</c>).</summary>
    public string? HostCertificateAlgorithm { get; init; }

    public bool AdvertiseStrictKex { get; init; } = true;

    public bool SendExtInfo { get; init; } = true;

    /// <summary>The <c>server-sig-algs</c> extension value (what OpenSSH sends by default).</summary>
    public string ServerSigAlgs { get; init; } = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";

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

    // ---- behaviour of key re-exchanges ----

    /// <summary>Use this host key (instead of <see cref="HostKey"/>) when re-exchanging keys.</summary>
    public FakeHostKey? RekeyHostKey { get; init; }

    /// <summary>Negotiate this cipher on re-exchange (the client must allow it).</summary>
    public string? RekeyCipher { get; init; }

    /// <summary>Negotiate this key exchange method on re-exchange.</summary>
    public string? RekeyKex { get; init; }

    /// <summary>Send an SSH_MSG_IGNORE between KEXINIT and the reply of a re-exchange.</summary>
    public bool IgnoreDuringRekey { get; init; }
}

/// <summary>
/// A scriptable in-memory SSH server speaking the real protocol with this library's primitives. After <see cref="StartAsync"/>
/// completes, tests drive it with <see cref="SendAsync"/> and <see cref="ReceiveAsync"/>. It also takes part in key re-exchanges:
/// call <see cref="RekeyAsync"/> to start one, and a client-initiated one is carried out transparently inside <see cref="ReceiveAsync"/>.
/// </summary>
internal sealed class FakeSshServer : IAsyncDisposable
{
    private readonly Pipe _toServer = new();
    private readonly Pipe _toClient = new();
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
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

    public byte[]? SessionId { get; private set; }

    /// <summary>How many key exchanges have completed on the server side, including the first.</summary>
    public int KeyExchangeCount { get; private set; }

    /// <summary>Runs the server side of the handshake. Await it together with the client's ConnectAsync.</summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ClientIdentification = await SshIdentification.ReadAsync(_reader, cancellationToken);

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

        using var clientInitPacket = await ReceiveRawAsync(cancellationToken);
        var clientInitPayload = clientInitPacket.Payload.ToArray();
        ClientKexInit = KexInitMessage.Parse(clientInitPayload);

        if (Options.CloseAfterKexInit)
        {
            Negotiated = AlgorithmNegotiator.Negotiate(ClientKexInit, serverInit);
            await _writer.CompleteAsync();
            return;
        }

        await ExchangeAsync(ClientKexInit, clientInitPayload, serverInit, serverInitPayload, initial: true, cancellationToken);
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
                    PacketCodec.Encode(_writer, payload.Span, _send, _sendSeq++);
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

    /// <summary>Receives the next application message; a client-initiated re-exchange is handled on the way.</summary>
    public async ValueTask<DecodedPacket> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var packet = await ReceiveRawAsync(cancellationToken);
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
        await _writer.WriteAsync(bytes, cancellationToken);
    }

    /// <summary>Closes the server's side of the connection.</summary>
    public async ValueTask CloseAsync()
    {
        await _writer.CompleteAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _writer.CompleteAsync();
        await _reader.CompleteAsync();
        _send.Dispose();
        _receive.Dispose();
        ClientStream.Dispose();
    }

    public static byte[] IgnorePayload() => [SshMessage.Ignore, 0, 0, 0, 1, 0x41];

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
        PacketCodec.Encode(_writer, payload, _send, _sendSeq++);
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

        using var kexInitPacket = await ReceiveRawAsync(cancellationToken);
        var init = kexInitPacket.Payload.ToArray();

        if (initial ? Options.IgnoreDuringKex : Options.IgnoreDuringRekey)
        {
            await SendKexAsync(IgnorePayload(), cancellationToken);
        }

        if (initial && Options.DisconnectInsteadOfReply is { } why)
        {
            await SendKexAsync(DisconnectPayload(why), cancellationToken);
            return;
        }

        var hostKey = SshCertificate.IsCertificateAlgorithm(negotiated.HostKey) && Options.HostCertificate is { } certificate
            ? certificate
            : !initial && Options.RekeyHostKey is { } replacement ? replacement : Options.HostKey;
        var (reply, secret, hash, kexHash) = RunKex(negotiated.Kex, negotiated.HostKey, hostKey, init, clientInitPayload, serverInitPayload);
        await SendKexAsync(reply, cancellationToken);

        if (initial)
        {
            SessionId = hash;
        }

        SshAlgorithms.TryGetCipher(negotiated.CipherClientToServer, out var cipherC2S);
        SshAlgorithms.TryGetCipher(negotiated.CipherServerToClient, out var cipherS2C);
        SshAlgorithms.TryGetMac(negotiated.MacClientToServer, out var macC2S);
        SshAlgorithms.TryGetMac(negotiated.MacServerToClient, out var macS2C);
        using var keys = KeyDerivation.DeriveAll(kexHash, secret, hash, SessionId!, cipherC2S, cipherS2C, macC2S, macS2C);
        var newSend = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);
        var newReceive = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);

        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            PacketCodec.Encode(_writer, new byte[] { SshMessage.NewKeys }, _send, _sendSeq++);
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
                w.WriteUInt32(1);
                w.WriteString("server-sig-algs");
                w.WriteString(Options.ServerSigAlgs);
            }), cancellationToken);
        }
    }

    /// <summary>Sends a key exchange or transport message: allowed while a key exchange is in progress.</summary>
    private async ValueTask SendKexAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            PacketCodec.Encode(_writer, payload.Span, _send, _sendSeq++);
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
                .. Options.HostKeyAlgorithm is { } algorithm
                    ? new[] { algorithm }
                    : hostKey.KeyType == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [hostKey.KeyType],
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

    private (byte[] Reply, byte[] Secret, byte[] Hash, HashAlgorithmName HashAlgorithm) RunKex(string method, string hostKeyAlgorithm, FakeHostKey hostKey, byte[] init, byte[] clientInit, byte[] serverInit)
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
            w.WriteByte(SshMessage.KexEcdhReply);
            w.WriteString(hostKey.Blob);
            body(w);
            w.WriteString(signature);
            return buffer.WrittenSpan.ToArray();
        }

        var reader = new SshReader(init);
        reader.ReadByte();
        switch (method)
        {
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

            default:
            {
                var group = method == SshAlgorithms.DhGroup14Sha256 ? ModpGroup.Group14 : ModpGroup.Group16;
                var hash = method == SshAlgorithms.DhGroup14Sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
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