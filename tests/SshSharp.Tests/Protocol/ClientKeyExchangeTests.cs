using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class ClientKeyExchangeTests
{
    public static IEnumerable<string> Methods() =>
    [
        SshAlgorithms.Curve25519Sha256, SshAlgorithms.Curve25519Sha256Libssh, SshAlgorithms.EcdhNistp256, SshAlgorithms.EcdhNistp384,
        SshAlgorithms.EcdhNistp521, SshAlgorithms.DhGroup14Sha256, SshAlgorithms.DhGroup16Sha512, SshAlgorithms.DhGroup18Sha512,
    ];

    private static readonly KexContext Context = new("SSH-2.0-SshSharp_test", "SSH-2.0-FakeServer", [20, 1, 2, 3], [20, 4, 5, 6]);

    private static readonly byte[] HostSeed = RandomNumberGenerator.GetBytes(32);

    private static byte[] HostKeyBlob()
    {
        var pub = new byte[32];
        Ed25519.GetPublicKey(HostSeed, pub);
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteString("ssh-ed25519");
        w.WriteString(pub);
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] SignatureBlob(byte[] data)
    {
        var sig = new byte[64];
        Ed25519.Sign(HostSeed, data, sig);
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteString("ssh-ed25519");
        w.WriteString(sig);
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>What the fake server computed, to compare with what the client derived.</summary>
    private sealed record ServerSide(byte[] Reply, byte[] SharedSecret, byte[] ExchangeHash);

    private static byte[] ClientValue(byte[] init, bool mpint)
    {
        var r = new SshReader(init);
        r.ReadByte();
        return mpint ? r.ReadMpint().ToArray() : r.ReadString().ToArray();
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteByte(31);
        body(w);
        return buffer.WrittenSpan.ToArray();
    }

    // The fake servers are written against the framework primitives and the RFC, not against the client's code.
    private static ServerSide RunServer(string method, byte[] init)
    {
        var hostKey = HostKeyBlob();
        switch (method)
        {
            case SshAlgorithms.Curve25519Sha256 or SshAlgorithms.Curve25519Sha256Libssh:
            {
                var qc = ClientValue(init, mpint: false);
                var priv = RandomNumberGenerator.GetBytes(32);
                var qs = new byte[32];
                X25519.GetPublicKey(priv, qs);
                var k = new byte[32];
                X25519.TryAgree(priv, qc, k);
                var h = ExchangeHash.Compute(HashAlgorithmName.SHA256, Context.ClientVersion, Context.ServerVersion, Context.ClientKexInit, Context.ServerKexInit, hostKey,
                    w => { w.WriteString(qc); w.WriteString(qs); }, k);
                return new ServerSide(Build(w => { w.WriteString(hostKey); w.WriteString(qs); w.WriteString(SignatureBlob(h)); }), k, h);
            }

            case SshAlgorithms.EcdhNistp256 or SshAlgorithms.EcdhNistp384 or SshAlgorithms.EcdhNistp521:
            {
                var curve = method switch { SshAlgorithms.EcdhNistp256 => NistCurve.P256, SshAlgorithms.EcdhNistp384 => NistCurve.P384, _ => NistCurve.P521 };
                var qc = ClientValue(init, mpint: false);
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
                var h = ExchangeHash.Compute(curve.Hash, Context.ClientVersion, Context.ServerVersion, Context.ClientKexInit, Context.ServerKexInit, hostKey,
                    w => { w.WriteString(qc); w.WriteString(qs); }, k);
                return new ServerSide(Build(w => { w.WriteString(hostKey); w.WriteString(qs); w.WriteString(SignatureBlob(h)); }), k, h);
            }

            default:
            {
                var (group, hash) = method switch
                {
                    SshAlgorithms.DhGroup14Sha256 => (ModpGroup.Group14, HashAlgorithmName.SHA256),
                    SshAlgorithms.DhGroup18Sha512 => (ModpGroup.Group18, HashAlgorithmName.SHA512),
                    _ => (ModpGroup.Group16, HashAlgorithmName.SHA512),
                };
                var eBytes = ClientValue(init, mpint: true);
                var e = new BigInteger(eBytes, isUnsigned: true, isBigEndian: true);
                var y = new BigInteger(RandomNumberGenerator.GetBytes(64), isUnsigned: true, isBigEndian: true) + 2;
                var f = BigInteger.ModPow(2, y, group.Prime);
                var k = BigInteger.ModPow(e, y, group.Prime).ToByteArray(isUnsigned: true, isBigEndian: true);
                var fBytes = f.ToByteArray(isUnsigned: true, isBigEndian: true);
                var h = ExchangeHash.Compute(hash, Context.ClientVersion, Context.ServerVersion, Context.ClientKexInit, Context.ServerKexInit, hostKey,
                    w => { w.WriteMpint(eBytes); w.WriteMpint(fBytes); }, k);
                return new ServerSide(Build(w => { w.WriteString(hostKey); w.WriteMpint(fBytes); w.WriteString(SignatureBlob(h)); }), k, h);
            }
        }
    }

    [Test]
    [MethodDataSource(nameof(Methods))]
    public async Task ClientAndServerAgreeOnSecretAndHash_AndTheHostSignatureVerifies(string method)
    {
        using var client = ClientKeyExchange.Create(method);
        var init = client.CreateInit();
        await Assert.That(init[0]).IsEqualTo((byte)30);

        var server = RunServer(method, init);
        using var result = client.ProcessReply(server.Reply, Context);

        await Assert.That(Convert.ToHexString(result.SharedSecret.AsSpan().TrimStart((byte)0))).IsEqualTo(Convert.ToHexString(server.SharedSecret.AsSpan().TrimStart((byte)0)));
        await Assert.That(Convert.ToHexString(result.ExchangeHash)).IsEqualTo(Convert.ToHexString(server.ExchangeHash));
        await Assert.That(result.ExchangeHash.Length).IsEqualTo(ExchangeHash.HashSize(client.Hash));

        var key = SshPublicKey.Parse(result.HostKeyBlob);
        await Assert.That(key.VerifySignature("ssh-ed25519", result.Signature, result.ExchangeHash)).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Methods))]
    public async Task TwoExchangesNeverShareTheirEphemeralValue(string method)
    {
        using var a = ClientKeyExchange.Create(method);
        using var b = ClientKeyExchange.Create(method);
        await Assert.That(Convert.ToHexString(a.CreateInit())).IsNotEqualTo(Convert.ToHexString(b.CreateInit()));
    }

    [Test]
    [MethodDataSource(nameof(Methods))]
    public async Task RejectsWrongMessageTypeTruncationAndTrailingData(string method)
    {
        using var client = ClientKeyExchange.Create(method);
        var server = RunServer(method, client.CreateInit());

        var wrongType = (byte[])server.Reply.Clone();
        wrongType[0] = 33;
        await Assert.That(() => client.ProcessReply(wrongType, Context)).Throws<SshProtocolException>();
        await Assert.That(() => client.ProcessReply(server.Reply.AsSpan(0, server.Reply.Length - 3), Context)).Throws<SshProtocolException>();
        await Assert.That(() => client.ProcessReply([.. server.Reply, 0], Context)).Throws<SshProtocolException>();
        await Assert.That(() => client.ProcessReply([], Context)).Throws<SshProtocolException>();
    }

    [Test]
    public async Task Curve25519_RejectsLowOrderAndWrongSizedPoints()
    {
        using var client = ClientKeyExchange.Create(SshAlgorithms.Curve25519Sha256);
        var hostKey = HostKeyBlob();

        var lowOrder = Build(w => { w.WriteString(hostKey); w.WriteString(new byte[32]); w.WriteString(SignatureBlob([1])); });
        var ex = Assert.Throws<SshException>(() => client.ProcessReply(lowOrder, Context));
        await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);

        var wrongSize = Build(w => { w.WriteString(hostKey); w.WriteString(new byte[31]); w.WriteString(SignatureBlob([1])); });
        await Assert.That(() => client.ProcessReply(wrongSize, Context)).Throws<SshProtocolException>();
    }

    [Test]
    [Arguments(SshAlgorithms.EcdhNistp256, 32)]
    [Arguments(SshAlgorithms.EcdhNistp384, 48)]
    [Arguments(SshAlgorithms.EcdhNistp521, 66)]
    public async Task Ecdh_RejectsOffCurveCompressedAndWrongSizedPoints(string method, int size)
    {
        using var client = ClientKeyExchange.Create(method);
        var hostKey = HostKeyBlob();
        byte[] Reply(byte[] point) => Build(w => { w.WriteString(hostKey); w.WriteString(point); w.WriteString(SignatureBlob([1])); });

        var offCurve = new byte[1 + (2 * size)];
        offCurve[0] = 4;
        offCurve[size] = 1;
        offCurve[^1] = 1;
        var ex = Assert.Throws<SshException>(() => client.ProcessReply(Reply(offCurve), Context));
        await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        await Assert.That(ex.Message).Contains("not on the curve");

        var compressed = new byte[1 + (2 * size)];
        compressed[0] = 2;
        await Assert.That(() => client.ProcessReply(Reply(compressed), Context)).Throws<SshProtocolException>();
        await Assert.That(() => client.ProcessReply(Reply(new byte[size]), Context)).Throws<SshProtocolException>();
    }

    [Test]
    public async Task Dh_RejectsOutOfRangeValues()
    {
        var group = ModpGroup.Group14;
        var hostKey = HostKeyBlob();
        using var client = ClientKeyExchange.Create(SshAlgorithms.DhGroup14Sha256);

        foreach (var bad in new[] { BigInteger.Zero, BigInteger.One, group.Prime - 1, group.Prime, group.Prime + 1 })
        {
            var reply = Build(w =>
            {
                w.WriteString(hostKey);
                w.WriteMpint(bad.ToByteArray(isUnsigned: true, isBigEndian: true));
                w.WriteString(SignatureBlob([1]));
            });
            var ex = Assert.Throws<SshException>(() => client.ProcessReply(reply, Context));
            await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        }
    }

    [Test]
    public async Task Create_MapsNamesAndRejectsUnknownOnes()
    {
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.Curve25519Sha256Libssh)).IsTypeOf<Curve25519KeyExchange>();
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.EcdhNistp384).Hash).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroup16Sha512).Hash).IsEqualTo(HashAlgorithmName.SHA512);
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroup14Sha256).Hash).IsEqualTo(HashAlgorithmName.SHA256);
        await Assert.That(() => ClientKeyExchange.Create("diffie-hellman-group1-sha1")).Throws<ArgumentException>();
    }

    [Test]
    public async Task KexResult_ZeroesTheSecretOnDispose()
    {
        using var client = ClientKeyExchange.Create(SshAlgorithms.Curve25519Sha256);
        var server = RunServer(SshAlgorithms.Curve25519Sha256, client.CreateInit());
        var result = client.ProcessReply(server.Reply, Context);
        var secret = result.SharedSecret;
        await Assert.That(secret.Any(b => b != 0)).IsTrue();
        result.Dispose();
        await Assert.That(secret.All(b => b == 0)).IsTrue();
    }
}