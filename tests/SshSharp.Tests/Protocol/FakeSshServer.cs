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

    public bool AdvertiseStrictKex { get; init; } = true;

    public bool SendExtInfo { get; init; } = true;

    public string[] BannerLines { get; init; } = [];

    public string Identification { get; init; } = "SSH-2.0-FakeServer_1.0";

    /// <summary>Send this many SSH_MSG_IGNORE packets before the server's KEXINIT.</summary>
    public int IgnoresBeforeKexInit { get; init; }

    /// <summary>Send an SSH_MSG_IGNORE between KEXINIT and the key exchange reply.</summary>
    public bool IgnoreDuringKex { get; init; }

    public bool CorruptSignature { get; init; }

    /// <summary>Claim a guessed first key exchange packet follows, using a different kex than the one negotiated.</summary>
    public bool WrongGuess { get; init; }

    /// <summary>Send ident, KEXINIT and everything else without waiting for the client (tests leftover bytes after the ident line).</summary>
    public bool Eager { get; init; }

    /// <summary>Close the connection right after receiving the client's KEXINIT.</summary>
    public bool CloseAfterKexInit { get; init; }

    /// <summary>Send SSH_MSG_DISCONNECT in place of the key exchange reply.</summary>
    public string? DisconnectInsteadOfReply { get; init; }

    /// <summary>Do not send the server identification at all.</summary>
    public bool SilentOnConnect { get; init; }
}

/// <summary>
/// A scriptable in-memory SSH server speaking the real protocol with this library's primitives. After <see cref="StartAsync"/>
/// completes, tests drive it with <see cref="SendAsync"/> and <see cref="ReceiveAsync"/>.
/// </summary>
internal sealed class FakeSshServer : IAsyncDisposable
{
    private readonly Pipe _toServer = new();
    private readonly Pipe _toClient = new();
    private readonly PipeReader _reader;
    private readonly PipeWriter _writer;
    private PacketProtector _send = PacketProtector.None;
    private PacketProtector _receive = PacketProtector.None;
    private uint _sendSeq;
    private uint _receiveSeq;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

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
            await SendAsync(IgnorePayload(), cancellationToken);
        }

        var serverInit = BuildServerKexInit();
        var serverInitPayload = Serialize(serverInit.Write);
        await SendAsync(serverInitPayload, cancellationToken);

        using var clientInitPacket = await ReceiveAsync(cancellationToken);
        var clientInitPayload = clientInitPacket.Payload.ToArray();
        ClientKexInit = KexInitMessage.Parse(clientInitPayload);
        Negotiated = AlgorithmNegotiator.Negotiate(ClientKexInit, serverInit);

        if (Options.CloseAfterKexInit)
        {
            await _writer.CompleteAsync();
            return;
        }

        if (Options.WrongGuess)
        {
            await SendAsync(new byte[] { SshMessage.KexEcdhReply, 0, 0, 0, 0 }, cancellationToken); // the "guessed" packet, to be discarded
        }

        using var kexInitPacket = await ReceiveAsync(cancellationToken);
        var init = kexInitPacket.Payload.ToArray();

        if (Options.IgnoreDuringKex)
        {
            await SendAsync(IgnorePayload(), cancellationToken);
        }

        if (Options.DisconnectInsteadOfReply is { } why)
        {
            await SendAsync(DisconnectPayload(why), cancellationToken);
            return;
        }

        var hostKeyAlgorithm = Negotiated.HostKey;
        var (reply, secret, hash, kexHash) = RunKex(Negotiated.Kex, hostKeyAlgorithm, init, clientInitPayload, serverInitPayload);
        await SendAsync(reply, cancellationToken);

        SessionId = hash;
        SshAlgorithms.TryGetCipher(Negotiated.CipherClientToServer, out var cipherC2S);
        SshAlgorithms.TryGetCipher(Negotiated.CipherServerToClient, out var cipherS2C);
        SshAlgorithms.TryGetMac(Negotiated.MacClientToServer, out var macC2S);
        SshAlgorithms.TryGetMac(Negotiated.MacServerToClient, out var macS2C);
        using var keys = KeyDerivation.DeriveAll(kexHash, secret, hash, hash, cipherC2S, cipherS2C, macC2S, macS2C);
        var newSend = PacketProtectorFactory.Create(cipherS2C, macS2C, keys.EncryptionKeyServerToClient, keys.IvServerToClient, keys.IntegrityKeyServerToClient);
        var newReceive = PacketProtectorFactory.Create(cipherC2S, macC2S, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);

        var strict = Negotiated.StrictKex;
        await SendAsync(new byte[] { SshMessage.NewKeys }, cancellationToken);
        _send = newSend;
        if (strict)
        {
            _sendSeq = 0;
        }

        using var newKeysPacket = await ReceiveAsync(cancellationToken);
        if (newKeysPacket.Payload.Span[0] != SshMessage.NewKeys)
        {
            throw new InvalidOperationException("The client did not send NEWKEYS.");
        }

        _receive = newReceive;
        if (strict)
        {
            _receiveSeq = 0;
        }

        if (Options.SendExtInfo && Negotiated.ServerSupportsExtInfo)
        {
            await SendAsync(Serialize(output =>
            {
                var w = new SshWriter(output);
                w.WriteByte(SshMessage.ExtInfo);
                w.WriteUInt32(1);
                w.WriteString("server-sig-algs");
                w.WriteString("ssh-ed25519,rsa-sha2-512,rsa-sha2-256");
            }), cancellationToken);
        }
    }

    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
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

    public async ValueTask<DecodedPacket> ReceiveAsync(CancellationToken cancellationToken = default)
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

    private KexInitMessage BuildServerKexInit()
    {
        var kex = new List<string> { Options.WrongGuess ? SshAlgorithms.EcdhNistp256 : Options.Kex };
        if (Options.WrongGuess)
        {
            kex.Add(Options.Kex);
        }

        if (Options.SendExtInfo)
        {
            kex.Add(SshAlgorithms.ExtInfoServer);
        }

        if (Options.AdvertiseStrictKex)
        {
            kex.Add(SshAlgorithms.StrictKexServer);
        }

        return new KexInitMessage
        {
            Cookie = RandomNumberGenerator.GetBytes(16),
            KexAlgorithms = kex,
            ServerHostKeyAlgorithms = Options.HostKeyAlgorithm is { } algorithm
                ? [algorithm]
                : Options.HostKey.KeyType == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [Options.HostKey.KeyType],
            EncryptionClientToServer = [Options.Cipher],
            EncryptionServerToClient = [Options.Cipher],
            MacClientToServer = [Options.Mac],
            MacServerToClient = [Options.Mac],
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
            FirstKexPacketFollows = Options.WrongGuess,
        };
    }

    private (byte[] Reply, byte[] Secret, byte[] Hash, HashAlgorithmName HashAlgorithm) RunKex(string method, string hostKeyAlgorithm, byte[] init, byte[] clientInit, byte[] serverInit)
    {
        var hostKey = Options.HostKey;
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