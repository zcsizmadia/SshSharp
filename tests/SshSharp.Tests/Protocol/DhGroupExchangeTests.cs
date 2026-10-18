using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary><c>diffie-hellman-group-exchange-sha256</c> (RFC 4419) and <c>diffie-hellman-group18-sha512</c>.</summary>
public class DhGroupExchangeTests
{
    private static readonly KexContext Context = new("SSH-2.0-SshSharp_test", "SSH-2.0-FakeServer", [20, 1, 2, 3], [20, 4, 5, 6]);

    private static readonly byte[] HostSeed = RandomNumberGenerator.GetBytes(32);

    private static readonly BigInteger P14 = ModpGroup.Group14.Prime;

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static byte[] Message(byte type, Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        w.WriteByte(type);
        body(w);
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] Unsigned(BigInteger value) => value.ToByteArray(isUnsigned: true, isBigEndian: true);

    private static byte[] Group(BigInteger p, BigInteger g) => Message(31, w =>
    {
        w.WriteMpint(Unsigned(p));
        w.WriteMpint(Unsigned(g));
    });

    private static byte[] HostKeyBlob()
    {
        var pub = new byte[32];
        Ed25519.GetPublicKey(HostSeed, pub);
        return Message(0, w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); })[1..];
    }

    private static byte[] SignatureBlob(byte[] data)
    {
        var sig = new byte[64];
        Ed25519.Sign(HostSeed, data, sig);
        return Message(0, w => { w.WriteString("ssh-ed25519"); w.WriteString(sig); })[1..];
    }

    // The exchange hash written out by hand from RFC 4419 section 3, without the library's ExchangeHash or SshWriter.
    private static byte[] IndependentHash(uint min, uint n, uint max, BigInteger p, BigInteger g, BigInteger e, BigInteger f, BigInteger k, byte[] hostKey)
    {
        var data = new List<byte>();
        void Uint32(uint value)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            data.AddRange(bytes);
        }

        void String(byte[] value)
        {
            Uint32((uint)value.Length);
            data.AddRange(value);
        }

        void Mpint(BigInteger value) => String(value.ToByteArray(isUnsigned: false, isBigEndian: true)); // two's complement, minimal

        String(Encoding.ASCII.GetBytes(Context.ClientVersion));
        String(Encoding.ASCII.GetBytes(Context.ServerVersion));
        String(Context.ClientKexInit);
        String(Context.ServerKexInit);
        String(hostKey);
        Uint32(min);
        Uint32(n);
        Uint32(max);
        Mpint(p);
        Mpint(g);
        Mpint(e);
        Mpint(f);
        Mpint(k);
        return SHA256.HashData([.. data]);
    }

    [Test]
    public async Task TheRequestCarriesOpenSshsSizes()
    {
        using var client = new DhGroupExchangeKeyExchange(3072);
        var request = client.CreateGroupRequest();
        await Assert.That(Convert.ToHexString(request)).IsEqualTo("22" + "00000800" + "00000C00" + "00002000");
        await Assert.That(client.ReplyMessage).IsEqualTo((byte)33);
        await Assert.That(client.Hash).IsEqualTo(HashAlgorithmName.SHA256);
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroupExchangeSha256).CreateGroupRequest()![7]).IsEqualTo((byte)0x20); // n = 8192
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroup14Sha256).CreateGroupRequest()).IsNull();
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroup14Sha256).ReplyMessage).IsEqualTo((byte)31);
    }

    [Test]
    [Arguments("2")]
    [Arguments("5")]
    [Arguments("258")] // two bytes, so byte order matters
    [Arguments("p-2")] // the top bit set
    public async Task RoundTrip_AgreesOnK_AndTheHashCoversMinNMaxPGEF(string generatorText)
    {
        var generator = generatorText == "p-2" ? P14 - 2 : BigInteger.Parse(generatorText, System.Globalization.CultureInfo.InvariantCulture);
        using var client = new DhGroupExchangeKeyExchange(4096);
        client.ProcessGroup(Group(P14, generator));
        var init = client.CreateInit();
        await Assert.That(init[0]).IsEqualTo((byte)32);

        // The server side, from the RFC: f = g^y, K = e^y.
        var reader = new SshReader(init);
        reader.ReadByte();
        var e = new BigInteger(reader.ReadMpint(), isUnsigned: true, isBigEndian: true);
        await Assert.That(reader.IsEmpty).IsTrue();
        await Assert.That(e > 1 && e < P14 - 1).IsTrue();
        var y = new BigInteger(RandomNumberGenerator.GetBytes(64), isUnsigned: true, isBigEndian: true) + 2;
        var f = BigInteger.ModPow(generator, y, P14);
        var k = BigInteger.ModPow(e, y, P14);
        var hostKey = HostKeyBlob();
        var h = IndependentHash(2048, 4096, 8192, P14, generator, e, f, k, hostKey);
        var reply = Message(33, w => { w.WriteString(hostKey); w.WriteMpint(Unsigned(f)); w.WriteString(SignatureBlob(h)); });

        var result = client.ProcessReply(reply, Context);
        await Assert.That(Convert.ToHexString(result.SharedSecret)).IsEqualTo(Convert.ToHexString(Unsigned(k)));
        await Assert.That(Convert.ToHexString(result.ExchangeHash)).IsEqualTo(Convert.ToHexString(h));
        await Assert.That(result.SharedSecretIsString).IsFalse();
        await Assert.That(VerifyingKey.Parse(result.HostKeyBlob).VerifySignature("ssh-ed25519", result.Signature, result.ExchangeHash)).IsTrue();

        // K lives only in the result, which wipes it.
        var secret = result.SharedSecret;
        result.Dispose();
        await Assert.That(secret.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task TheExponentIsSizedForTheGroup_AndFreshPerExchange()
    {
        await Assert.That(DhGroupExchangeKeyExchange.ExponentBits(2048)).IsEqualTo(512);
        await Assert.That(DhGroupExchangeKeyExchange.ExponentBits(2049)).IsEqualTo(768);
        await Assert.That(DhGroupExchangeKeyExchange.ExponentBits(4096)).IsEqualTo(768);
        await Assert.That(DhGroupExchangeKeyExchange.ExponentBits(4097)).IsEqualTo(1024);
        await Assert.That(DhGroupExchangeKeyExchange.ExponentBits(8192)).IsEqualTo(1024);

        using var a = new DhGroupExchangeKeyExchange(2048);
        using var b = new DhGroupExchangeKeyExchange(2048);
        a.ProcessGroup(Group(P14, 2));
        b.ProcessGroup(Group(P14, 2));
        await Assert.That(Convert.ToHexString(a.CreateInit())).IsNotEqualTo(Convert.ToHexString(b.CreateInit()));
    }

    [Test]
    public async Task PreferredBits_FollowsOpenSshsEstimate()
    {
        SshAlgorithms.TryGetCipher("aes128-gcm@openssh.com", out var aes128Gcm);
        SshAlgorithms.TryGetCipher("aes256-gcm@openssh.com", out var aes256Gcm);
        SshAlgorithms.TryGetCipher("chacha20-poly1305@openssh.com", out var chacha);
        SshAlgorithms.TryGetCipher("aes128-ctr", out var aes128Ctr);
        SshAlgorithms.TryGetMac("hmac-sha2-256-etm@openssh.com", out var sha256);

        // AES-128-GCM: 16-byte key and block, 12-byte IV, no MAC: 128 bits.
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Gcm, aes128Gcm, sha256, sha256)).IsEqualTo(3072);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Gcm, aes128Gcm, null, null)).IsEqualTo(3072);

        // Either direction counts; ChaCha20-Poly1305's 64-byte key, and a 32-byte MAC key with a non-AEAD cipher, give 8192.
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Gcm, aes256Gcm, null, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes256Gcm, aes128Gcm, null, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", chacha, chacha, null, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Ctr, aes128Ctr, sha256, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Ctr, aes128Ctr, null, sha256)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH_9.6", aes128Ctr, aes128Ctr, null, null)).IsEqualTo(3072);

        // Every band of dh_estimate, with made-up ciphers: up to 112 bits, 128, 192, and more.
        CipherInfo Made(CipherKind kind, int key, int iv) => new("x", kind, key, iv, false);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.ChaCha20Poly1305, 14, 0), Made(CipherKind.ChaCha20Poly1305, 8, 14), null, null)).IsEqualTo(2048);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.ChaCha20Poly1305, 15, 0), Made(CipherKind.ChaCha20Poly1305, 8, 0), null, null)).IsEqualTo(3072);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.ChaCha20Poly1305, 4, 0), Made(CipherKind.ChaCha20Poly1305, 4, 0), null, null)).IsEqualTo(2048);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.AesGcm, 24, 12), Made(CipherKind.AesGcm, 16, 12), null, null)).IsEqualTo(7680);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.AesGcm, 16, 12), Made(CipherKind.AesGcm, 16, 25), null, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("x", Made(CipherKind.AesCtr, 16, 16), Made(CipherKind.AesCtr, 16, 16), new MacInfo("m", HashAlgorithmName.SHA256, 24, true, true), null)).IsEqualTo(7680);

        // Cisco 1.x servers get at most 4096 (OpenSSH's SSH_BUG_DHGEX_LARGE); smaller requests are unchanged.
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("Cisco-1.25", chacha, chacha, null, null)).IsEqualTo(4096);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("Cisco-1.25", aes128Gcm, aes128Gcm, null, null)).IsEqualTo(3072);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("Cisco-2.0", chacha, chacha, null, null)).IsEqualTo(8192);
        await Assert.That(DhGroupExchangeKeyExchange.PreferredBits("OpenSSH Cisco-1.25", chacha, chacha, null, null)).IsEqualTo(8192);
    }

    [Test]
    public async Task RejectsABadGroup_BeforeSendingAnything()
    {
        var even = P14 + 1;
        var tooSmall = (BigInteger.One << 1024) - (BigInteger.One << 960) - 1 + ((ModpGroup.ScaledPi(894) + 129093) << 64);
        var tooLarge = (ModpGroup.Group18.Prime << 1) + 1;
        (BigInteger P, BigInteger G, string Message)[] cases =
        [
            (tooSmall, 2, "1024 bits, outside the 2048 to 8192 requested"),
            (tooLarge, 2, "8193 bits, outside the 2048 to 8192 requested"),
            (even, 2, "is even"),
            (P14 * 3, 2, "is not 3 mod 4"),
            (P14, 1, "generator is out of range"),
            (P14, P14 - 1, "generator is out of range"),
        ];
        foreach (var (p, g, message) in cases)
        {
            using var client = new DhGroupExchangeKeyExchange(8192);
            var ex = Assert.Throws<SshException>(() => client.ProcessGroup(Group(p, g)));
            await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
            await Assert.That(ex.Message).Contains(message);
            await Assert.That(() => client.CreateInit()).Throws<InvalidOperationException>();
        }
    }

    [Test]
    public async Task RejectsFOutOfRange()
    {
        using var client = new DhGroupExchangeKeyExchange(2048);
        client.ProcessGroup(Group(P14, 2));
        var hostKey = HostKeyBlob();
        foreach (var bad in new[] { BigInteger.Zero, BigInteger.One, P14 - 1, P14, P14 + 1 })
        {
            var reply = Message(33, w => { w.WriteString(hostKey); w.WriteMpint(Unsigned(bad)); w.WriteString(SignatureBlob([1])); });
            var ex = Assert.Throws<SshException>(() => client.ProcessReply(reply, Context));
            await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
            await Assert.That(ex.Message).Contains("out of range");
        }

        // The edges just inside the range are accepted.
        foreach (var good in new[] { new BigInteger(2), P14 - 2 })
        {
            var reply = Message(33, w => { w.WriteString(hostKey); w.WriteMpint(Unsigned(good)); w.WriteString(SignatureBlob([1])); });
            using var result = client.ProcessReply(reply, Context);
            await Assert.That(result.ExchangeHash.Length).IsEqualTo(32);
        }
    }

    [Test]
    public async Task RejectsMalformedMessages_AndOutOfOrderUse()
    {
        using var client = new DhGroupExchangeKeyExchange(2048);
        var group = Group(P14, 2);
        const string notReceived = "The server's group has not been received.";
        await Assert.That(() => client.CreateInit()).Throws<InvalidOperationException>().WithMessage(notReceived);
        await Assert.That(() => client.ProcessReply(Message(33, _ => { }), Context)).Throws<InvalidOperationException>().WithMessage(notReceived);

        var wrongType = (byte[])group.Clone();
        wrongType[0] = 33;
        await Assert.That(() => client.ProcessGroup(wrongType)).Throws<SshProtocolException>().WithMessage("Expected the key exchange group (31), got message 33.");
        await Assert.That(() => client.ProcessGroup([.. group, 0])).Throws<SshProtocolException>().WithMessage("Trailing data in the key exchange group.");
        await Assert.That(() => client.ProcessGroup(group.AsSpan(0, group.Length - 1))).Throws<SshProtocolException>();

        client.ProcessGroup(group);
        var hostKey = HostKeyBlob();
        var reply = Message(33, w => { w.WriteString(hostKey); w.WriteMpint([2]); w.WriteString(SignatureBlob([1])); });
        var oldReply = (byte[])reply.Clone();
        oldReply[0] = 31;
        await Assert.That(() => client.ProcessReply(oldReply, Context)).Throws<SshProtocolException>().WithMessage("Expected the key exchange reply (33), got message 31.");
        await Assert.That(() => client.ProcessReply([.. reply, 0], Context)).Throws<SshProtocolException>().WithMessage("Trailing data in the key exchange reply.");

        // The fixed-group exchanges have no group step.
        using var fixedGroup = ClientKeyExchange.Create(SshAlgorithms.DhGroup14Sha256);
        await Assert.That(() => fixedGroup.ProcessGroup(group)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task OverTheTransport_TheClientAsksForASize_AndTheExchangeCompletes()
    {
        await using var server = new FakeSshServer(new FakeServerOptions { Kex = SshAlgorithms.DhGroupExchangeSha256, Cipher = "aes128-gcm@openssh.com" });
        await using var transport = new SshTransport(server.ClientStream, new SshTransportOptions
        {
            Preferences = new AlgorithmPreferences { Kex = [SshAlgorithms.DhGroupExchangeSha256] },
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
        });
        var token = Timeout();
        var serverTask = server.StartAsync(token);
        await transport.ConnectAsync(token);
        await serverTask;

        await Assert.That(transport.Algorithms!.Kex).IsEqualTo(SshAlgorithms.DhGroupExchangeSha256);
        await Assert.That(server.GexRequest).IsEqualTo(((uint)2048, (uint)3072, (uint)8192));
        await Assert.That(Convert.ToHexString(transport.SessionId!)).IsEqualTo(Convert.ToHexString(server.SessionId!));
    }

    [Test]
    public async Task OverTheTransport_ABadGroupOrFFailsTheConnection()
    {
        foreach (var options in new[]
        {
            new FakeServerOptions { Kex = SshAlgorithms.DhGroupExchangeSha256, GexGroup = (P14 + 1, 2) },
            new FakeServerOptions { Kex = SshAlgorithms.DhGroupExchangeSha256, GexServerValue = P14 - 1 },
        })
        {
            await using var server = new FakeSshServer(options);
            await using var transport = new SshTransport(server.ClientStream, new SshTransportOptions
            {
                Preferences = new AlgorithmPreferences { Kex = [SshAlgorithms.DhGroupExchangeSha256] },
                VerifyHostKey = (_, _) => ValueTask.FromResult(true),
            });
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            _ = server.StartAsync(cts.Token);
            var ex = await Assert.ThrowsAsync<SshException>(async () => await transport.ConnectAsync(cts.Token));
            await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
            await server.CloseAsync();
        }
    }

    [Test]
    [Arguments(SshAlgorithms.DhGroupExchangeSha256)]
    [Arguments(SshAlgorithms.DhGroup18Sha512)]
    public async Task ItHandshakes_RunsCommands_AndRekeys(string kex)
    {
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        await using var server = new FakeSessionServer(new FakeServerOptions { Kex = kex }) { Password = password };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            AlgorithmPreferences = new AlgorithmPreferences { Kex = [kex] },
            RekeyAfterBytes = 64 * 1024,
        }, leaveOpen: true, Timeout());

        await Assert.That(client.Algorithms!.KeyExchange).IsEqualTo(kex);
        await Assert.That(client.Algorithms.IsPostQuantum).IsFalse();
        server.OnExec = async script =>
        {
            await script.StdoutAsync(new byte[96 * 1024]);
            await script.FinishAsync(0);
        };
        for (var round = 0; round < 3; round++)
        {
            var result = await client.RunCommandAsync("cat big", Timeout());
            await Assert.That(result.StandardOutput.Length).IsEqualTo(96 * 1024);
        }

        // Each re-exchange asks for (group exchange) or uses (group 18) its group again.
        await Assert.That(server.Raw.KeyExchangeCount).IsGreaterThan(2);
    }

    [Test]
    public async Task BothAreOffered_InOpenSshsOrder_AndOnlyTheFixedGroupInFipsMode()
    {
        var defaults = new AlgorithmPreferences().Kex.ToList();
        var gex = defaults.IndexOf(SshAlgorithms.DhGroupExchangeSha256);
        await Assert.That(defaults[gex - 1]).IsEqualTo(SshAlgorithms.EcdhNistp521);
        await Assert.That(string.Join(",", defaults.Skip(gex))).IsEqualTo(
            "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256");

        var fips = AlgorithmPreferences.Fips().Kex;
        // SP 800-56A rev. 3 approves the fixed safe-prime groups (RFC 3526), not a group the server picks.
        await Assert.That(fips).DoesNotContain(SshAlgorithms.DhGroupExchangeSha256);
        await Assert.That(fips).Contains(SshAlgorithms.DhGroup18Sha512);
        await Assert.That(SshAlgorithms.IsPostQuantum(SshAlgorithms.DhGroupExchangeSha256)).IsFalse();
        await Assert.That(ClientKeyExchange.Create(SshAlgorithms.DhGroup18Sha512).Hash).IsEqualTo(HashAlgorithmName.SHA512);
    }
}
