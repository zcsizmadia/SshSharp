using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class KexNegotiationTests
{
    private static KexInitMessage Server(
        string[]? kex = null, string[]? hostKeys = null, string[]? ciphers = null, string[]? macs = null, bool firstFollows = false,
        string[]? macsServerToClient = null) => new()
    {
        Cookie = new byte[16],
        KexAlgorithms = kex ?? [SshAlgorithms.Curve25519Sha256, SshAlgorithms.EcdhNistp256, SshAlgorithms.ExtInfoServer, SshAlgorithms.StrictKexServer],
        ServerHostKeyAlgorithms = hostKeys ?? [SshAlgorithms.SshEd25519, SshAlgorithms.RsaSha2_512],
        EncryptionClientToServer = ciphers ?? ["aes256-ctr", "chacha20-poly1305@openssh.com"],
        EncryptionServerToClient = ciphers ?? ["aes256-ctr", "chacha20-poly1305@openssh.com"],
        MacClientToServer = macs ?? ["hmac-sha2-256-etm@openssh.com"],
        MacServerToClient = macsServerToClient ?? macs ?? ["hmac-sha2-256-etm@openssh.com"],
        CompressionClientToServer = ["none", "zlib@openssh.com"],
        CompressionServerToClient = ["none", "zlib@openssh.com"],
        FirstKexPacketFollows = firstFollows,
    };

    private static byte[] Serialize(KexInitMessage message)
    {
        var buffer = new ArrayBufferWriter<byte>();
        message.Write(buffer);
        return buffer.WrittenSpan.ToArray();
    }

    [Test]
    public async Task KexInit_RoundTrips()
    {
        var original = Server(firstFollows: true);
        var parsed = KexInitMessage.Parse(Serialize(original));

        await Assert.That(parsed.FirstKexPacketFollows).IsTrue();
        await Assert.That(string.Join(",", parsed.KexAlgorithms)).IsEqualTo(string.Join(",", original.KexAlgorithms));
        await Assert.That(string.Join(",", parsed.ServerHostKeyAlgorithms)).IsEqualTo("ssh-ed25519,rsa-sha2-512");
        await Assert.That(string.Join(",", parsed.CompressionServerToClient)).IsEqualTo("none,zlib@openssh.com");
        await Assert.That(parsed.LanguagesClientToServer.Count).IsEqualTo(0);
        await Assert.That(parsed.Cookie.Length).IsEqualTo(16);
    }

    [Test]
    public async Task KexInit_ParseRejectsBadMessages()
    {
        var good = Serialize(Server());
        var wrongType = (byte[])good.Clone();
        wrongType[0] = 21;
        await Assert.That(() => KexInitMessage.Parse(wrongType)).Throws<SshProtocolException>();
        await Assert.That(() => KexInitMessage.Parse(good.AsSpan(0, 30))).Throws<SshProtocolException>();
        await Assert.That(() => KexInitMessage.Parse([.. good, 0])).Throws<SshProtocolException>();
    }

    [Test]
    public async Task ForClient_AddsMarkersAndRandomCookie()
    {
        var a = KexInitMessage.ForClient(new AlgorithmPreferences());
        var b = KexInitMessage.ForClient(new AlgorithmPreferences());
        await Assert.That(a.KexAlgorithms.Contains(SshAlgorithms.StrictKexClient)).IsTrue();
        await Assert.That(a.KexAlgorithms.Contains(SshAlgorithms.ExtInfoClient)).IsTrue();
        await Assert.That(a.KexAlgorithms[0]).IsEqualTo(SshAlgorithms.DefaultKex[0]); // the ML-KEM hybrid where the platform has it
        await Assert.That(Convert.ToHexString(a.Cookie)).IsNotEqualTo(Convert.ToHexString(b.Cookie));
        await Assert.That(() => KexInitMessage.ForClient(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task Negotiate_PicksTheFirstClientPreferenceTheServerHas()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences());
        var result = AlgorithmNegotiator.Negotiate(client, Server());

        await Assert.That(result.Kex).IsEqualTo(SshAlgorithms.Curve25519Sha256);
        await Assert.That(result.HostKey).IsEqualTo(SshAlgorithms.SshEd25519);
        // The client prefers chacha over aes256-ctr even though the server lists aes256-ctr first.
        await Assert.That(result.CipherClientToServer).IsEqualTo("chacha20-poly1305@openssh.com");
        await Assert.That(result.CipherServerToClient).IsEqualTo("chacha20-poly1305@openssh.com");
        await Assert.That(result.MacClientToServer).IsEqualTo("hmac-sha2-256-etm@openssh.com");
        await Assert.That(result.CompressionClientToServer).IsEqualTo("none");
        await Assert.That(result.StrictKex).IsTrue();
        await Assert.That(result.ServerSupportsExtInfo).IsTrue();
        await Assert.That(result.ServerGuessedWrong).IsFalse();
    }

    [Test]
    public async Task Negotiate_StrictKexNeedsBothSides_ExtInfoOnlyFromTheServer()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences());
        var plain = AlgorithmNegotiator.Negotiate(client, Server(kex: [SshAlgorithms.Curve25519Sha256]));
        await Assert.That(plain.StrictKex).IsFalse();
        await Assert.That(plain.ServerSupportsExtInfo).IsFalse();

        var noStrictClient = KexInitMessage.ForClient(new AlgorithmPreferences());
        var withoutMarker = new KexInitMessage
        {
            Cookie = noStrictClient.Cookie,
            KexAlgorithms = [.. noStrictClient.KexAlgorithms.Where(k => k != SshAlgorithms.StrictKexClient)],
            ServerHostKeyAlgorithms = noStrictClient.ServerHostKeyAlgorithms,
            EncryptionClientToServer = noStrictClient.EncryptionClientToServer,
            EncryptionServerToClient = noStrictClient.EncryptionServerToClient,
            MacClientToServer = noStrictClient.MacClientToServer,
            MacServerToClient = noStrictClient.MacServerToClient,
            CompressionClientToServer = noStrictClient.CompressionClientToServer,
            CompressionServerToClient = noStrictClient.CompressionServerToClient,
        };
        await Assert.That(AlgorithmNegotiator.Negotiate(withoutMarker, Server()).StrictKex).IsFalse();
    }

    [Test]
    public async Task Negotiate_MarkerNamesAreNeverChosenAsTheKex()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences { Kex = [SshAlgorithms.ExtInfoClient] });
        await Assert.That(() => AlgorithmNegotiator.Negotiate(client, Server())).Throws<SshException>();
    }

    [Test]
    public async Task Negotiate_FailsWithAReasonAndBothLists()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences { Ciphers = ["aes128-ctr"] });
        var ex = Assert.Throws<SshException>(() => AlgorithmNegotiator.Negotiate(client, Server(ciphers: ["3des-cbc"])));
        await Assert.That(ex.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
        await Assert.That(ex.Message).Contains("encryption");
        await Assert.That(ex.Message).Contains("aes128-ctr");
        await Assert.That(ex.Message).Contains("3des-cbc");

        foreach (var server in new[]
        {
            Server(kex: ["diffie-hellman-group1-sha1"]),
            Server(hostKeys: ["ssh-dss"]),
            Server(ciphers: ["aes256-ctr"], macs: ["hmac-md5"]),
        })
        {
            await Assert.That(() => AlgorithmNegotiator.Negotiate(KexInitMessage.ForClient(new AlgorithmPreferences()), server)).Throws<SshException>();
        }

        // Each direction's MAC is named on its own.
        var macs = KexInitMessage.ForClient(new AlgorithmPreferences { Ciphers = ["aes256-ctr"] });
        var toServer = Assert.Throws<SshException>(() => AlgorithmNegotiator.Negotiate(macs, Server(macs: ["hmac-md5"])));
        await Assert.That(toServer.Message).Contains("No matching MAC (client to server) algorithm");
        var toClient = Assert.Throws<SshException>(() => AlgorithmNegotiator.Negotiate(macs, Server(macsServerToClient: ["hmac-md5"])));
        await Assert.That(toClient.Message).Contains("No matching MAC (server to client) algorithm");
    }

    [Test]
    public async Task Negotiate_AnAeadCipherDoesNotNeedAMatchingMac()
    {
        // Like OpenSSH: the MAC is unused with an AEAD cipher, so a MAC list without a match must not fail the connection.
        var client = KexInitMessage.ForClient(new AlgorithmPreferences { Ciphers = ["chacha20-poly1305@openssh.com"] });
        var negotiated = AlgorithmNegotiator.Negotiate(client, Server(macs: ["umac-128-etm@openssh.com"]));
        await Assert.That(negotiated.CipherClientToServer).IsEqualTo("chacha20-poly1305@openssh.com");
        await Assert.That(negotiated.MacClientToServer).IsEqualTo(string.Empty);
        await Assert.That(negotiated.MacServerToClient).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Negotiate_DetectsAWrongFirstKexGuess()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences());
        // Server guessed ecdh-nistp256 first but the negotiated kex is curve25519-sha256.
        var wrongKex = Server(kex: [SshAlgorithms.EcdhNistp256, SshAlgorithms.Curve25519Sha256], firstFollows: true);
        await Assert.That(AlgorithmNegotiator.Negotiate(client, wrongKex).ServerGuessedWrong).IsTrue();

        var wrongHostKey = Server(hostKeys: [SshAlgorithms.RsaSha2_512, SshAlgorithms.SshEd25519], firstFollows: true);
        await Assert.That(AlgorithmNegotiator.Negotiate(client, wrongHostKey).ServerGuessedWrong).IsTrue();

        var right = Server(firstFollows: true);
        await Assert.That(AlgorithmNegotiator.Negotiate(client, right).ServerGuessedWrong).IsFalse();
        await Assert.That(() => AlgorithmNegotiator.Negotiate(null!, right)).Throws<ArgumentNullException>();
        await Assert.That(() => AlgorithmNegotiator.Negotiate(client, null!)).Throws<ArgumentNullException>();
    }

    private static SshHostConfig Config(string text) => SshConfig.Parse(text).Resolve("h", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = "/h" });

    [Test]
    public async Task FromConfig_AppliesSpecsToDefaults_AndDropsUnknownNames()
    {
        var prefs = AlgorithmPreferences.FromConfig(Config("Ciphers +aes128-ctr,3des-cbc\nKexAlgorithms -ecdh-sha2-nistp*\nMACs hmac-sha2-256-etm@openssh.com,hmac-md5\nHostKeyAlgorithms ^rsa-sha2-256,ssh-dss\n"));

        await Assert.That(prefs.Ciphers.Contains("3des-cbc")).IsFalse();
        await Assert.That(prefs.Ciphers[^1]).IsEqualTo("aes128-ctr");
        await Assert.That(prefs.Kex.Any(k => k.StartsWith("ecdh-", StringComparison.Ordinal))).IsFalse();
        await Assert.That(prefs.Kex[0]).IsEqualTo(SshAlgorithms.DefaultKex[0]);
        await Assert.That(string.Join(",", prefs.Macs)).IsEqualTo("hmac-sha2-256-etm@openssh.com");
        await Assert.That(prefs.HostKeys[0]).IsEqualTo(SshAlgorithms.RsaSha2_256);
        await Assert.That(prefs.HostKeys.Contains("ssh-dss")).IsFalse();
        await Assert.That(() => AlgorithmPreferences.FromConfig(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task FromConfig_AcceptsGroupExchangeAndGroup18_InEveryForm()
    {
        const string gex = SshAlgorithms.DhGroupExchangeSha256;
        const string group18 = SshAlgorithms.DhGroup18Sha512;

        var exact = AlgorithmPreferences.FromConfig(Config($"KexAlgorithms {group18},{gex}\n"));
        await Assert.That(string.Join(",", exact.Kex)).IsEqualTo($"{group18},{gex}");

        var first = AlgorithmPreferences.FromConfig(Config($"KexAlgorithms ^{gex}\n"));
        await Assert.That(first.Kex[0]).IsEqualTo(gex);
        await Assert.That(first.Kex.Count(k => k == gex)).IsEqualTo(1);

        var removed = AlgorithmPreferences.FromConfig(Config($"KexAlgorithms -{gex},{group18}\n"));
        await Assert.That(removed.Kex.Contains(gex)).IsFalse();
        await Assert.That(removed.Kex.Contains(group18)).IsFalse();
        await Assert.That(removed.Kex.Contains(SshAlgorithms.DhGroup16Sha512)).IsTrue();

        // Already a default: as in ssh, + leaves it where it is.
        var added = AlgorithmPreferences.FromConfig(Config($"KexAlgorithms +{group18}\n"));
        await Assert.That(string.Join(",", added.Kex)).IsEqualTo(string.Join(",", SshAlgorithms.DefaultKex));
    }

    [Test]
    public async Task FromConfig_DefaultsWhenNothingIsConfigured()
    {
        var prefs = AlgorithmPreferences.FromConfig(Config("User x\n"));
        await Assert.That(string.Join(",", prefs.Kex)).IsEqualTo(string.Join(",", SshAlgorithms.DefaultKex));
        await Assert.That(string.Join(",", prefs.Ciphers)).IsEqualTo(string.Join(",", SshAlgorithms.DefaultCiphers));
    }

    [Test]
    public async Task FipsMode_KeepsOnlyApprovedAlgorithms()
    {
        var prefs = AlgorithmPreferences.FromConfig(Config("User x\n"), fipsMode: true);

        await Assert.That(prefs.Kex.Any(k => k.StartsWith("curve25519", StringComparison.Ordinal))).IsFalse();
        await Assert.That(prefs.Kex.Count).IsGreaterThan(0);
        await Assert.That(prefs.HostKeys.Contains(SshAlgorithms.SshEd25519)).IsFalse();
        await Assert.That(prefs.HostKeys.Contains(SshAlgorithms.RsaSha2_512)).IsTrue();
        await Assert.That(prefs.Ciphers.Contains("chacha20-poly1305@openssh.com")).IsFalse();
        await Assert.That(prefs.Ciphers.Contains("aes256-gcm@openssh.com")).IsTrue();
        await Assert.That(string.Join(",", prefs.Macs))
            .IsEqualTo("hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512");
        await Assert.That(SshAlgorithms.FilterFips(["none"], AlgorithmKind.Compression).Count).IsEqualTo(1);
    }

    [Test]
    public async Task FipsMode_KeepsThePlainHmacSha2_AndDropsUnknownMacs()
    {
        var prefs = AlgorithmPreferences.FromConfig(Config("MACs hmac-sha2-256,umac-64@openssh.com,hmac-sha1,hmac-sha2-512\n"), fipsMode: true);
        await Assert.That(string.Join(",", prefs.Macs)).IsEqualTo("hmac-sha2-256,hmac-sha2-512");
        await Assert.That(string.Join(",", AlgorithmPreferences.Fips().Macs)).IsEqualTo(string.Join(",", SshAlgorithms.DefaultMacs));
    }

    [Test]
    public async Task DefaultMacs_PreferEncryptThenMac_ThenThePlainOnesInOpenSshOrder()
    {
        await Assert.That(string.Join(",", SshAlgorithms.DefaultMacs))
            .IsEqualTo("hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512");
        await Assert.That(string.Join(",", KexInitMessage.ForClient(new AlgorithmPreferences()).MacClientToServer))
            .IsEqualTo(string.Join(",", SshAlgorithms.DefaultMacs));
    }

    [Test]
    [Arguments("MACs hmac-sha2-256", "hmac-sha2-256")]
    [Arguments("MACs hmac-sha2-512,hmac-sha2-256-etm@openssh.com", "hmac-sha2-512,hmac-sha2-256-etm@openssh.com")]
    [Arguments("MACs -hmac-sha2-*-etm@openssh.com", "hmac-sha2-256,hmac-sha2-512")]
    [Arguments("MACs -hmac-sha2-256,hmac-sha2-512", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com")]
    [Arguments("MACs ^hmac-sha2-512", "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256")]
    [Arguments("MACs +hmac-sha2-256", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512")] // already there: unchanged
    public async Task FromConfig_MacsSpecsAcceptThePlainHmacSha2(string line, string expected)
    {
        var prefs = AlgorithmPreferences.FromConfig(Config(line + "\n"));
        await Assert.That(string.Join(",", prefs.Macs)).IsEqualTo(expected);
    }

    [Test]
    public async Task Negotiate_PicksAPlainHmacSha2_WhenTheServerOffersOnlyThat()
    {
        // Network equipment often offers only aes*-ctr with hmac-sha2-256 or hmac-sha2-512.
        var client = KexInitMessage.ForClient(new AlgorithmPreferences());
        foreach (var mac in new[] { "hmac-sha2-256", "hmac-sha2-512" })
        {
            var negotiated = AlgorithmNegotiator.Negotiate(client, Server(ciphers: ["aes128-ctr"], macs: ["hmac-sha1", mac]));
            await Assert.That(negotiated.CipherClientToServer).IsEqualTo("aes128-ctr");
            await Assert.That(negotiated.MacClientToServer).IsEqualTo(mac);
            await Assert.That(negotiated.MacServerToClient).IsEqualTo(mac);
        }

        // The client's order decides: encrypt-then-MAC wins when the server has both, whatever the server's order.
        var both = AlgorithmNegotiator.Negotiate(client, Server(ciphers: ["aes128-ctr"], macs: ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com"]));
        await Assert.That(both.MacClientToServer).IsEqualTo("hmac-sha2-256-etm@openssh.com");
        var plain = AlgorithmNegotiator.Negotiate(client, Server(ciphers: ["aes128-ctr"], macs: ["hmac-sha2-512", "hmac-sha2-256"]));
        await Assert.That(plain.MacClientToServer).IsEqualTo("hmac-sha2-256");
    }

    [Test]
    public async Task Negotiate_AnAeadCipherIgnoresAPlainMac()
    {
        var client = KexInitMessage.ForClient(new AlgorithmPreferences { Ciphers = ["aes256-gcm@openssh.com"] });
        var negotiated = AlgorithmNegotiator.Negotiate(client, Server(ciphers: ["aes256-gcm@openssh.com"], macs: ["hmac-sha2-256"]));
        await Assert.That(negotiated.CipherClientToServer).IsEqualTo("aes256-gcm@openssh.com");

        // Negotiated (both sides list it) but unused: the AEAD cipher gets no integrity key and builds no HMAC.
        SshAlgorithms.TryGetCipher(negotiated.CipherClientToServer, out var gcm);
        SshAlgorithms.TryGetMac(negotiated.MacClientToServer, out var mac);
        using var keys = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [1], new byte[32], new byte[32], gcm, gcm, mac, mac);
        await Assert.That(keys.IntegrityKeyClientToServer.Length).IsEqualTo(0);
        using var protector = PacketProtectorFactory.Create(gcm, mac, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
        await Assert.That(protector).IsTypeOf<AesGcmProtector>();
    }

    [Test]
    public async Task Registry_DescribesCiphersAndMacs()
    {
        await Assert.That(SshAlgorithms.TryGetCipher("aes256-gcm@openssh.com", out var gcm)).IsTrue();
        await Assert.That(gcm.IsAead).IsTrue();
        await Assert.That(gcm.KeyLength).IsEqualTo(32);
        await Assert.That(SshAlgorithms.TryGetCipher("aes192-ctr", out var ctr)).IsTrue();
        await Assert.That(ctr.IsAead).IsFalse();
        await Assert.That(ctr.KeyLength).IsEqualTo(24);
        await Assert.That(SshAlgorithms.TryGetCipher("rot13", out _)).IsFalse();
        await Assert.That(SshAlgorithms.TryGetMac("hmac-sha2-512-etm@openssh.com", out var mac)).IsTrue();
        await Assert.That(mac.KeyLength).IsEqualTo(64);
        await Assert.That(mac.EncryptThenMac).IsTrue();
        await Assert.That(SshAlgorithms.TryGetMac("hmac-md5", out _)).IsFalse();

        await Assert.That(SshAlgorithms.TryGetMac("hmac-sha2-256", out var plain256)).IsTrue();
        await Assert.That(plain256).IsEqualTo(new MacInfo("hmac-sha2-256", HashAlgorithmName.SHA256, 32, false, true));
        await Assert.That(SshAlgorithms.TryGetMac("hmac-sha2-512", out var plain512)).IsTrue();
        await Assert.That(plain512).IsEqualTo(new MacInfo("hmac-sha2-512", HashAlgorithmName.SHA512, 64, false, true));
        await Assert.That(SshAlgorithms.IsKnownMac("hmac-sha2-256")).IsTrue();
        await Assert.That(SshAlgorithms.IsKnownMac("hmac-sha1")).IsFalse();
    }

    // ---- key derivation and exchange hash, checked against independent re-computations ----

    private static byte[] Mpint(ReadOnlySpan<byte> magnitude)
    {
        var buffer = new ArrayBufferWriter<byte>();
        new SshWriter(buffer).WriteMpint(magnitude);
        return buffer.WrittenSpan.ToArray();
    }

    [Test]
    public async Task KeyDerivation_MatchesTheRfc4253Formula_IncludingExtension()
    {
        var k = Convert.FromHexString("80112233445566778899aabbccddeeff"); // high bit set: needs the mpint zero pad
        var h = SHA256.HashData("exchange"u8);
        var sessionId = SHA256.HashData("session"u8);

        // 80 bytes needs two SHA-256 blocks: K1 = HASH(K||H||"A"||sid), K2 = HASH(K||H||K1).
        var kh = new List<byte>(Mpint(k));
        kh.AddRange(h);
        var k1 = SHA256.HashData([.. kh, (byte)'A', .. sessionId]);
        var k2 = SHA256.HashData([.. kh, .. k1]);
        var k3 = SHA256.HashData([.. kh, .. k1, .. k2]);
        byte[] expected = [.. k1, .. k2, .. k3];

        var derived = KeyDerivation.Derive(HashAlgorithmName.SHA256, k, h, 'A', sessionId, 80);
        await Assert.That(Convert.ToHexString(derived)).IsEqualTo(Convert.ToHexString(expected.AsSpan(0, 80)));

        var shortKey = KeyDerivation.Derive(HashAlgorithmName.SHA256, k, h, 'A', sessionId, 16);
        await Assert.That(Convert.ToHexString(shortKey)).IsEqualTo(Convert.ToHexString(k1.AsSpan(0, 16)));
        await Assert.That(KeyDerivation.Derive(HashAlgorithmName.SHA256, k, h, 'A', sessionId, 0).Length).IsEqualTo(0);
        await Assert.That(() => KeyDerivation.Derive(HashAlgorithmName.SHA256, k, h, 'A', sessionId, -1)).Throws<ArgumentOutOfRangeException>();

        // Different letters give independent keys.
        var other = KeyDerivation.Derive(HashAlgorithmName.SHA256, k, h, 'B', sessionId, 16);
        await Assert.That(Convert.ToHexString(other)).IsNotEqualTo(Convert.ToHexString(shortKey));
    }

    [Test]
    public async Task DeriveAll_UsesTheNegotiatedKeyAndIvLengths()
    {
        SshAlgorithms.TryGetCipher("aes256-gcm@openssh.com", out var gcm);
        SshAlgorithms.TryGetCipher("aes128-ctr", out var ctr);
        SshAlgorithms.TryGetMac("hmac-sha2-256-etm@openssh.com", out var mac);
        var h = SHA256.HashData("h"u8);

        using var keys = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [1, 2, 3], h, h, gcm, ctr, mac, mac);
        await Assert.That(keys.IvClientToServer.Length).IsEqualTo(12);
        await Assert.That(keys.EncryptionKeyClientToServer.Length).IsEqualTo(32);
        await Assert.That(keys.IntegrityKeyClientToServer.Length).IsEqualTo(0); // AEAD: no MAC key
        await Assert.That(keys.IvServerToClient.Length).IsEqualTo(16);
        await Assert.That(keys.EncryptionKeyServerToClient.Length).IsEqualTo(16);
        await Assert.That(keys.IntegrityKeyServerToClient.Length).IsEqualTo(32);

        using var noMac = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [1], h, h, ctr, ctr, null, null);
        await Assert.That(noMac.IntegrityKeyClientToServer.Length).IsEqualTo(0);
    }

    [Test]
    public async Task SessionKeys_AreZeroedOnDispose()
    {
        SshAlgorithms.TryGetCipher("aes128-ctr", out var ctr);
        SshAlgorithms.TryGetMac("hmac-sha2-256-etm@openssh.com", out var mac);
        var h = SHA256.HashData("h"u8);
        var keys = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [9], h, h, ctr, ctr, mac, mac);
        var key = keys.EncryptionKeyClientToServer;
        await Assert.That(key.Any(b => b != 0)).IsTrue();
        keys.Dispose();
        await Assert.That(key.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task ExchangeHash_HasTheDocumentedLayout()
    {
        var hostKey = new byte[] { 1, 2, 3 };
        var secret = new byte[] { 0xAA, 0xBB };
        var clientInit = new byte[] { 20, 1 };
        var serverInit = new byte[] { 20, 2, 2 };

        var expectedInput = new ArrayBufferWriter<byte>();
        var w = new SshWriter(expectedInput);
        w.WriteString("SSH-2.0-client");
        w.WriteString("SSH-2.0-server");
        w.WriteString(clientInit);
        w.WriteString(serverInit);
        w.WriteString(hostKey);
        w.WriteString(new byte[] { 7, 7 }); // Q_C
        w.WriteString(new byte[] { 8, 8, 8 }); // Q_S
        w.WriteMpint(secret);

        var h = ExchangeHash.Compute(HashAlgorithmName.SHA256, "SSH-2.0-client", "SSH-2.0-server", clientInit, serverInit, hostKey,
            writer =>
            {
                writer.WriteString(new byte[] { 7, 7 });
                writer.WriteString(new byte[] { 8, 8, 8 });
            },
            secret);
        await Assert.That(Convert.ToHexString(h)).IsEqualTo(Convert.ToHexString(SHA256.HashData(expectedInput.WrittenSpan)));
        await Assert.That(() => ExchangeHash.Compute(HashAlgorithmName.SHA256, "a", "b", [], [], [], null!, [])).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task ExchangeHash_SupportsSha384AndSha512_AndRejectsOthers()
    {
        await Assert.That(ExchangeHash.HashSize(HashAlgorithmName.SHA256)).IsEqualTo(32);
        await Assert.That(ExchangeHash.HashSize(HashAlgorithmName.SHA384)).IsEqualTo(48);
        await Assert.That(ExchangeHash.HashSize(HashAlgorithmName.SHA512)).IsEqualTo(64);
        await Assert.That(() => ExchangeHash.HashSize(HashAlgorithmName.MD5)).Throws<ArgumentException>();
        var h = ExchangeHash.Compute(HashAlgorithmName.SHA512, "a", "b", [1], [2], [3], _ => { }, [4]);
        await Assert.That(h.Length).IsEqualTo(64);
    }

    [Test]
    public async Task Factory_BuildsWorkingProtectorsForEveryCipher()
    {
        var h = SHA256.HashData("h"u8);
        SshAlgorithms.TryGetMac("hmac-sha2-512-etm@openssh.com", out var mac);
        foreach (var name in SshAlgorithms.DefaultCiphers)
        {
            SshAlgorithms.TryGetCipher(name, out var cipher);
            using var keys = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [5, 6, 7], h, h, cipher, cipher, mac, mac);
            using var sender = PacketProtectorFactory.Create(cipher, mac, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
            using var receiver = PacketProtectorFactory.Create(cipher, mac, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);

            var wire = new ArrayBufferWriter<byte>();
            PacketCodec.Encode(wire, "hello"u8, sender, 0);
            var ok = PacketCodec.TryDecode(new ReadOnlySequence<byte>(wire.WrittenMemory), receiver, 0, out var packet, out _);
            using (packet)
            {
                await Assert.That(ok).IsTrue();
                await Assert.That(Convert.ToHexString(packet!.Payload.Span)).IsEqualTo(Convert.ToHexString("hello"u8));
            }
        }
    }

    /// <summary>
    /// Every MAC with every AES-CTR cipher, from derived keys: the -etm MACs get the encrypt-then-MAC protector, the plain ones
    /// encrypt-and-MAC, and several packets in a row decode (the counter and sequence number carry over).
    /// </summary>
    [Test]
    public async Task Factory_BuildsWorkingProtectorsForEveryMac()
    {
        var h = SHA256.HashData("h"u8);
        foreach (var cipherName in new[] { "aes128-ctr", "aes192-ctr", "aes256-ctr" })
        {
            foreach (var macName in SshAlgorithms.DefaultMacs)
            {
                SshAlgorithms.TryGetCipher(cipherName, out var cipher);
                SshAlgorithms.TryGetMac(macName, out var mac);
                using var keys = KeyDerivation.DeriveAll(HashAlgorithmName.SHA256, [5, 6, 7], h, h, cipher, cipher, mac, mac);
                await Assert.That(keys.IntegrityKeyClientToServer.Length).IsEqualTo(mac.KeyLength);
                using var sender = PacketProtectorFactory.Create(cipher, mac, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
                using var receiver = PacketProtectorFactory.Create(cipher, mac, keys.EncryptionKeyClientToServer, keys.IvClientToServer, keys.IntegrityKeyClientToServer);
                await Assert.That(sender.GetType()).IsEqualTo(mac.EncryptThenMac ? typeof(AesCtrEtmProtector) : typeof(AesCtrHmacProtector));
                await Assert.That(sender.TagSize).IsEqualTo(mac.KeyLength);

                for (uint sequence = 0; sequence < 3; sequence++)
                {
                    var wire = new ArrayBufferWriter<byte>();
                    PacketCodec.Encode(wire, "hello"u8, sender, sequence);
                    var ok = PacketCodec.TryDecode(new ReadOnlySequence<byte>(wire.WrittenMemory), receiver, sequence, out var packet, out _);
                    using (packet)
                    {
                        await Assert.That(ok).IsTrue();
                        await Assert.That(Convert.ToHexString(packet!.Payload.Span)).IsEqualTo(Convert.ToHexString("hello"u8));
                    }
                }
            }
        }
    }

    [Test]
    public async Task Factory_ChecksKeySizes()
    {
        SshAlgorithms.TryGetCipher("aes128-ctr", out var ctr);
        SshAlgorithms.TryGetMac("hmac-sha2-512", out var plain);
        await Assert.That(() => PacketProtectorFactory.Create(ctr, plain, new byte[16], new byte[16], new byte[32])).Throws<ArgumentException>();
        SshAlgorithms.TryGetMac("hmac-sha2-256-etm@openssh.com", out var mac);
        await Assert.That(() => PacketProtectorFactory.Create(ctr, mac, new byte[15], new byte[16], new byte[32])).Throws<ArgumentException>();
        await Assert.That(() => PacketProtectorFactory.Create(ctr, mac, new byte[16], new byte[16], new byte[31])).Throws<ArgumentException>();
        await Assert.That(() => PacketProtectorFactory.Create(ctr, null, new byte[16], new byte[16], new byte[32])).Throws<ArgumentNullException>();
        await Assert.That(() => PacketProtectorFactory.Create(null!, mac, new byte[16], new byte[16], new byte[32])).Throws<ArgumentNullException>();
        await Assert.That(() => PacketProtectorFactory.Create(new CipherInfo("x", (CipherKind)99, 1, 1, false), mac, new byte[1], new byte[1], new byte[1])).Throws<ArgumentOutOfRangeException>();
    }
}