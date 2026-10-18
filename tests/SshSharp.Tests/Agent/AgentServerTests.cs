using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;

namespace SshSharp.Tests.Agent;

/// <summary>
/// The agent protocol as the in-process agent and the forwarded-agent filter serve it (#275): each request, the RSA flags, the session
/// binding, what the filter sees, and malformed or hostile input.
/// </summary>
public class AgentServerTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    private static readonly byte[] SessionId = RandomNumberGenerator.GetBytes(32);

    private static AgentServer Server(Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? filter, params SshPrivateKey[] keys) =>
        new(new AgentKeyring(keys), filter, NullLogger.Instance);

    private static AgentServer Server(params SshPrivateKey[] keys) => Server(null, keys);

    private static async Task<byte[]> HandleAsync(AgentServer server, byte[] message) => await server.HandleAsync(message, Timeout());

    private static byte[] Sign(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> data, uint flags = 0)
    {
        var b = blob.ToArray();
        var d = data.ToArray();
        return TestKeys.Blob(w =>
        {
            w.WriteByte(13);
            w.WriteString(b);
            w.WriteString(d);
            w.WriteUInt32(flags);
        });
    }

    /// <summary>A public key login request, as ssh signs it (RFC 4252 section 7), host-bound when <paramref name="hostKey"/> is given.</summary>
    internal static byte[] Login(SshPrivateKey key, string algorithm, byte[]? sessionId = null, byte[]? hostKey = null, string user = "deploy") => TestKeys.Blob(w =>
    {
        w.WriteString(sessionId ?? SessionId);
        w.WriteByte(50);
        w.WriteString(user);
        w.WriteString("ssh-connection");
        w.WriteString(hostKey is null ? "publickey" : "publickey-hostbound-v00@openssh.com");
        w.WriteBoolean(true);
        w.WriteString(algorithm);
        w.WriteString(key.PublicKey.Span);
        if (hostKey is not null)
        {
            w.WriteString(hostKey);
        }
    });

    /// <summary>What ssh-keygen -Y sign asks an agent to sign: the SSHSIG preamble, the namespace, and the message's hash.</summary>
    internal static byte[] SshSig(string @namespace) =>
    [
        .. "SSHSIG"u8,
        .. TestKeys.Blob(w =>
        {
            w.WriteString(@namespace);
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteString("sha512");
            w.WriteString(SHA512.HashData("hello"u8));
        }),
    ];

    /// <summary>A session-bind@openssh.com request: <paramref name="hostKey"/> signs the session id, as the server's host key did in its key exchange.</summary>
    internal static byte[] Bind(SshPrivateKey hostKey, byte[] sessionId, bool forwarding, byte[]? signature = null) => TestKeys.Blob(w =>
    {
        w.WriteByte(27);
        w.WriteString("session-bind@openssh.com");
        w.WriteString(hostKey.PublicKey.Span);
        w.WriteString(sessionId);
        w.WriteString(signature ?? hostKey.Sign(hostKey.SignatureAlgorithms[0], sessionId));
        w.WriteBoolean(forwarding);
    });

    private static (string Algorithm, byte[] Blob) Signature(byte[] reply)
    {
        var reader = new SshReader(reply);
        if (reader.ReadByte() != 14)
        {
            throw new InvalidOperationException($"Expected SSH_AGENT_SIGN_RESPONSE, got {reply[0]}.");
        }

        var blob = reader.ReadString().ToArray();
        return (new SshReader(blob).ReadUtf8String(), blob);
    }

    private static List<(byte[] Blob, string Comment)> Identities(byte[] reply)
    {
        var reader = new SshReader(reply);
        if (reader.ReadByte() != 12)
        {
            throw new InvalidOperationException($"Expected SSH_AGENT_IDENTITIES_ANSWER, got {reply[0]}.");
        }

        var list = new List<(byte[], string)>();
        for (var count = reader.ReadUInt32(); count > 0; count--)
        {
            list.Add((reader.ReadString().ToArray(), reader.ReadUtf8String()));
        }

        return reader.IsEmpty ? list : throw new InvalidOperationException("Data after the identities.");
    }

    [Test]
    public async Task RequestIdentities_ListsEachKeyOnce_WithItsComment_AndACertifiedKeyAsKeyThenCertificate()
    {
        using var ed25519 = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var edBlob, comment: "laptop"));
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var ecdsa = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256, "build");
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(ca, ecdsa.PublicKey.ToArray(), SshCertificateType.User, ["deploy"]));
        var certified = ecdsa.WithCertificate(certificate);

        var listed = Identities(await HandleAsync(Server(ed25519, certified, ed25519), [11]));

        await Assert.That(listed.Count).IsEqualTo(3);
        await Assert.That(listed[0].Blob).IsEquivalentTo(edBlob);
        await Assert.That(listed[0].Comment).IsEqualTo("laptop");
        await Assert.That(listed[1].Blob).IsEquivalentTo(ecdsa.PublicKey.ToArray());
        await Assert.That(listed[1].Comment).IsEqualTo("build");
        await Assert.That(listed[2].Blob).IsEquivalentTo(certificate.Blob.ToArray());
    }

    [Test]
    public async Task AnAgentWithoutKeys_ListsNone()
    {
        await Assert.That(await HandleAsync(Server(), [11])).IsEquivalentTo(new byte[] { 12, 0, 0, 0, 0 });
    }

    [Test]
    [Arguments(SshKeyType.Ed25519, "ssh-ed25519")]
    [Arguments(SshKeyType.EcdsaNistp256, "ecdsa-sha2-nistp256")]
    [Arguments(SshKeyType.EcdsaNistp384, "ecdsa-sha2-nistp384")]
    [Arguments(SshKeyType.EcdsaNistp521, "ecdsa-sha2-nistp521")]
    public async Task SignRequest_SignsALoginRequest_WithTheKeysAlgorithm(SshKeyType type, string algorithm)
    {
        using var key = SshPrivateKey.Generate(type);
        var data = Login(key, algorithm);

        // Flags are for RSA only; another key ignores them, as ssh-agent does.
        var (signed, blob) = Signature(await HandleAsync(Server(key), Sign(key.PublicKey.Span, data, flags: 4)));

        await Assert.That(signed).IsEqualTo(algorithm);
        await Assert.That(key.GetPublicKey().VerifySignature(data, blob)).IsTrue();
    }

    [Test]
    [Arguments(2u, "rsa-sha2-256")]
    [Arguments(4u, "rsa-sha2-512")]
    [Arguments(6u, "rsa-sha2-256")] // both: SHA-256 first, as ssh-agent decides
    [Arguments(0xFFFFFFF6u, "rsa-sha2-256")] // unknown flag bits are ignored
    public async Task AnRsaKey_SignsWithTheHashTheFlagsAskFor(uint flags, string algorithm)
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        var data = Login(key, algorithm);

        var (signed, blob) = Signature(await HandleAsync(Server(key), Sign(key.PublicKey.Span, data, flags)));

        await Assert.That(signed).IsEqualTo(algorithm);
        await Assert.That(key.GetPublicKey().VerifySignature(data, blob)).IsTrue();
    }

    [Test]
    [Arguments(0u)]
    [Arguments(1u)]
    [Arguments(8u)]
    public async Task AnRsaKey_NeverSignsWithSha1(uint flags)
    {
        // Without a SHA-2 flag, ssh-agent would sign ssh-rsa (SHA-1); this agent refuses.
        using var key = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        await Assert.That(await HandleAsync(Server(key), Sign(key.PublicKey.Span, Login(key, "ssh-rsa"), flags))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task AnRsaCertificate_SignsWithTheHashTheFlagsAskFor_AndNeverSha1()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(ca, rsa.PublicKey.ToArray(), SshCertificateType.User, ["deploy"]));
        var server = Server(rsa.WithCertificate(certificate));
        var data = Login(rsa, "rsa-sha2-512-cert-v01@openssh.com");

        var (signed, blob) = Signature(await HandleAsync(server, Sign(certificate.Blob.Span, data, flags: 4)));
        await Assert.That(signed).IsEqualTo("rsa-sha2-512"); // a certificate's signature is its key's
        await Assert.That(rsa.GetPublicKey().VerifySignature(data, blob)).IsTrue();
        await Assert.That(await HandleAsync(server, Sign(certificate.Blob.Span, data))).IsEquivalentTo(new byte[] { 5 });

        // The plain key listed beside the certificate signs too.
        await Assert.That(Signature(await HandleAsync(server, Sign(rsa.PublicKey.Span, data, flags: 2))).Algorithm).IsEqualTo("rsa-sha2-256");
    }

    [Test]
    public async Task ASignerThatOffersOneHash_RefusesTheOther()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var key = SshPrivateKey.FromSigner(new KeySigner(inner) { Algorithms = ["rsa-sha2-512"] });
        var server = Server(key);

        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "rsa-sha2-256"), flags: 2))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(Signature(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "rsa-sha2-512"), flags: 4))).Algorithm)
            .IsEqualTo("rsa-sha2-512");
    }

    [Test]
    public async Task AKeyTheAgentDoesNotHold_IsRefused()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await Assert.That(await HandleAsync(Server(key), Sign(other.PublicKey.Span, Login(other, "ssh-ed25519")))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task TheSigner_GetsWhatTheSignatureIsFor()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var signer = new KeySigner(inner);
        using var key = SshPrivateKey.FromSigner(signer);
        var server = Server(key);
        var certificateBody = TestKeys.Certificate(ca, inner.PublicKey.ToArray(), SshCertificateType.User, ["deploy"]);

        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")))).IsNotEquivalentTo(new byte[] { 5 });
        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, SshSig("git")))).IsNotEquivalentTo(new byte[] { 5 });
        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, certificateBody))).IsNotEquivalentTo(new byte[] { 5 });

        await Assert.That(signer.Requests.Select(r => r.Purpose)).IsEquivalentTo(
            new[] { SshSignaturePurpose.Authentication, SshSignaturePurpose.FileSignature, SshSignaturePurpose.Certificate });
        await Assert.That(signer.Requests[1].Namespace).IsEqualTo("git");
        await Assert.That(signer.Requests[0].Namespace).IsNull();
    }

    [Test]
    public async Task ASignerThatThrows_IsARefusal()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.FromSigner(new KeySigner(inner) { Refuse = true });
        await Assert.That(await HandleAsync(Server(key), Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")))).IsEquivalentTo(new byte[] { 5 });
    }

    public static IEnumerable<Func<byte[]>> UnsignableData() =>
    [
        () => [],
        () => RandomNumberGenerator.GetBytes(64),
        () => "SSHSIG"u8.ToArray(),
        () => [.. "SSHSIG"u8, .. TestKeys.Blob(w => { w.WriteString(string.Empty); w.WriteString(string.Empty); w.WriteString("sha512"); w.WriteString(new byte[64]); })],
        () => [.. SshSig("file"), 0],
        () => TestKeys.Blob(w => w.WriteString("ssh-ed25519")), // a key, not a certificate
        () => TestKeys.Blob(w => { w.WriteString(new byte[32]); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("password"); w.WriteBoolean(false); }),
        () => TestKeys.Blob(w => { w.WriteString(new byte[32]); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey"); w.WriteBoolean(false); w.WriteString("a"); w.WriteString("k"); }),
        () => TestKeys.Blob(w => { w.WriteString(new byte[32]); w.WriteByte(51); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey"); w.WriteBoolean(true); w.WriteString("a"); w.WriteString("k"); }),
        () => TestKeys.Blob(w => { w.WriteString(new byte[129]); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey"); w.WriteBoolean(true); w.WriteString("a"); w.WriteString("k"); }),
        () => TestKeys.Blob(w => { w.WriteString(ReadOnlySpan<byte>.Empty); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey"); w.WriteBoolean(true); w.WriteString("a"); w.WriteString("k"); }),
        () => TestKeys.Blob(w => { w.WriteString(new byte[32]); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey"); w.WriteBoolean(true); w.WriteString("a"); w.WriteString("k"); w.WriteByte(0); }),
        () => TestKeys.Blob(w => { w.WriteString(new byte[32]); w.WriteByte(50); w.WriteString("u"); w.WriteString("s"); w.WriteString("publickey-hostbound-v00@openssh.com"); w.WriteBoolean(true); w.WriteString("a"); w.WriteString("k"); }),
    ];

    [Test]
    [MethodDataSource(nameof(UnsignableData))]
    public async Task DataThatIsNotALoginRequestAnSshSignatureOrACertificate_IsNotSigned(byte[] data)
    {
        // The agent signs what SSH signs, not whatever a program on the server hands it.
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await Assert.That(await HandleAsync(Server(key), Sign(key.PublicKey.Span, data))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    [Arguments(new byte[] { 17 })] // SSH_AGENTC_ADD_IDENTITY
    [Arguments(new byte[] { 18, 0, 0, 0, 0 })] // SSH_AGENTC_REMOVE_IDENTITY
    [Arguments(new byte[] { 19 })] // SSH_AGENTC_REMOVE_ALL_IDENTITIES
    [Arguments(new byte[] { 20 })] // SSH_AGENTC_ADD_SMARTCARD_KEY
    [Arguments(new byte[] { 22, 0, 0, 0, 1, 0x61 })] // SSH_AGENTC_LOCK
    [Arguments(new byte[] { 23, 0, 0, 0, 1, 0x61 })] // SSH_AGENTC_UNLOCK
    [Arguments(new byte[] { 25 })] // SSH_AGENTC_ADD_ID_CONSTRAINED
    [Arguments(new byte[] { 1 })] // SSH1 requests
    [Arguments(new byte[] { 0 })]
    [Arguments(new byte[] { 255 })]
    public async Task ChangingTheAgent_AndUnknownRequests_AreRefused(byte[] message)
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var server = Server(key);
        await Assert.That(await HandleAsync(server, message)).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(Identities(await HandleAsync(server, [11])).Count).IsEqualTo(1); // nothing changed
    }

    public static IEnumerable<Func<byte[]>> MalformedRequests() =>
    [
        () => [],
        () => [13],
        () => [13, 0, 0, 0, 9, 1],
        () => [13, 0xFF, 0xFF, 0xFF, 0xFF],
        () => TestKeys.Blob(w => { w.WriteByte(13); w.WriteString("x"); }),
        () => TestKeys.Blob(w => { w.WriteByte(13); w.WriteString("x"); w.WriteString("y"); }), // no flags
        () => TestKeys.Blob(w => { w.WriteByte(13); w.WriteString("x"); w.WriteString("y"); w.WriteUInt32(0); w.WriteByte(1); }),
        () => TestKeys.Blob(w => { w.WriteByte(13); w.WriteString(new byte[] { 0xC3 }); w.WriteString("y"); w.WriteUInt32(0); }), // a key type that is not UTF-8
        () => [27],
        () => TestKeys.Blob(w => { w.WriteByte(27); w.WriteString("unknown@example.com"); }),
        () => TestKeys.Blob(w => { w.WriteByte(27); w.WriteString("session-bind@openssh.com"); }),
        () => TestKeys.Blob(w => { w.WriteByte(27); w.WriteString("session-bind@openssh.com"); w.WriteString("k"); w.WriteString("s"); w.WriteString("g"); }),
    ];

    [Test]
    [MethodDataSource(nameof(MalformedRequests))]
    public async Task AMalformedRequest_IsAnsweredWithFailure(byte[] message)
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await Assert.That(await HandleAsync(Server(key), message)).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task RandomRequests_AreAlwaysAnswered_NeverThrown()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var server = Server(key);
        var random = new Random(275);
        for (var i = 0; i < 2000; i++)
        {
            var message = new byte[random.Next(0, 96)];
            random.NextBytes(message);
            if (message.Length > 0)
            {
                message[0] = (byte)((i % 3) switch { 0 => 13, 1 => 27, _ => random.Next(0, 32) });
            }

            var reply = await HandleAsync(server, message);
            await Assert.That(reply.Length).IsGreaterThan(0);
        }
    }

    [Test]
    public async Task Query_ListsTheExtensionsServed()
    {
        var reply = await HandleAsync(Server(), TestKeys.Blob(w => { w.WriteByte(27); w.WriteString("query"); }));
        await Assert.That(reply[0]).IsEqualTo((byte)29); // SSH_AGENT_EXTENSION_RESPONSE
        await Assert.That(Strings(reply.AsSpan(1))).IsEquivalentTo(new[] { "query", "query", "session-bind@openssh.com" });

        static List<string> Strings(ReadOnlySpan<byte> body)
        {
            var reader = new SshReader(body);
            var names = new List<string>();
            while (!reader.IsEmpty)
            {
                names.Add(reader.ReadUtf8String());
            }

            return names;
        }
    }

    [Test]
    public async Task SessionBind_IsVerified_AndFollowsSshAgentsRules()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var otherHost = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        var server = Server();
        byte[] success = [6], failure = [5];

        // A signature by another key, or over another session id, does not bind.
        await Assert.That(await HandleAsync(server, Bind(hostKey, SessionId, forwarding: true, otherHost.Sign("ecdsa-sha2-nistp256", SessionId)))).IsEquivalentTo(failure);
        await Assert.That(await HandleAsync(server, Bind(hostKey, SessionId, forwarding: true, hostKey.Sign("ssh-ed25519", new byte[32])))).IsEquivalentTo(failure);
        await Assert.That(await HandleAsync(server, Bind(hostKey, new byte[129], forwarding: true))).IsEquivalentTo(failure);
        await Assert.That(await HandleAsync(server, Bind(hostKey, [], forwarding: true))).IsEquivalentTo(failure);
        await Assert.That(await HandleAsync(server, [.. Bind(hostKey, SessionId, forwarding: true), 0])).IsEquivalentTo(failure);

        // Forwarding hops bind; the same session again only with the same host key.
        await Assert.That(await HandleAsync(server, Bind(hostKey, SessionId, forwarding: true))).IsEquivalentTo(success);
        await Assert.That(await HandleAsync(server, Bind(hostKey, SessionId, forwarding: true))).IsEquivalentTo(success);
        await Assert.That(await HandleAsync(server, Bind(otherHost, SessionId, forwarding: true))).IsEquivalentTo(failure);

        // Bound for authentication, the connection takes no other binding.
        var sessionId = RandomNumberGenerator.GetBytes(64);
        await Assert.That(await HandleAsync(server, Bind(otherHost, sessionId, forwarding: false))).IsEquivalentTo(success);
        await Assert.That(await HandleAsync(server, Bind(otherHost, RandomNumberGenerator.GetBytes(32), forwarding: true))).IsEquivalentTo(failure);
        await Assert.That(await HandleAsync(server, Bind(otherHost, sessionId, forwarding: false))).IsEquivalentTo(failure);
    }

    [Test]
    public async Task SessionBind_KeepsAtMostSixteenSessions()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var server = Server();
        for (var i = 0; i < 16; i++)
        {
            await Assert.That(await HandleAsync(server, Bind(hostKey, RandomNumberGenerator.GetBytes(32), forwarding: true))).IsEquivalentTo(new byte[] { 6 });
        }

        await Assert.That(await HandleAsync(server, Bind(hostKey, RandomNumberGenerator.GetBytes(32), forwarding: true))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task SessionBind_WithAHostCertificate_VerifiesWithItsKey()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certificate = TestKeys.Certificate(ca, hostKey.PublicKey.ToArray(), SshCertificateType.Host, ["host.example.com"]);
        var request = TestKeys.Blob(w =>
        {
            w.WriteByte(27);
            w.WriteString("session-bind@openssh.com");
            w.WriteString(certificate);
            w.WriteString(SessionId);
            w.WriteString(hostKey.Sign("ssh-ed25519", SessionId));
            w.WriteBoolean(false);
        });
        await Assert.That(await HandleAsync(Server(), request)).IsEquivalentTo(new byte[] { 6 });
    }

    [Test]
    public async Task OnAConnectionBoundForAuthentication_OnlyThatSessionsLoginIsSigned()
    {
        // As ssh-agent checks for destination-constrained keys: the request must be for the bound session, and a host-bound one must
        // name the bound host key.
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var otherHost = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var server = Server(key);
        await Assert.That(await HandleAsync(server, Bind(hostKey, SessionId, forwarding: false))).IsEquivalentTo(new byte[] { 6 });

        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519", RandomNumberGenerator.GetBytes(32)))))
            .IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519", hostKey: otherHost.PublicKey.ToArray()))))
            .IsEquivalentTo(new byte[] { 5 });
        await Assert.That(Signature(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519", hostKey: hostKey.PublicKey.ToArray())))).Algorithm)
            .IsEqualTo("ssh-ed25519");
        await Assert.That(Signature(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")))).Algorithm).IsEqualTo("ssh-ed25519");

        // An SSH signature is not a login, so the session does not matter.
        await Assert.That(Signature(await HandleAsync(server, Sign(key.PublicKey.Span, SshSig("file")))).Algorithm).IsEqualTo("ssh-ed25519");
    }

    [Test]
    public async Task TheFilter_HidesTheKeysItRefusesToList_AndSeesEachKeyWithItsComment()
    {
        using var shown = SshPrivateKey.Generate(SshKeyType.Ed25519, "shown");
        using var hidden = SshPrivateKey.Generate(SshKeyType.Ed25519, "hidden");
        var seen = new List<SshAgentRequest>();
        var server = Server((request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult(request.Key.Comment == "shown");
        }, shown, hidden);

        var listed = Identities(await HandleAsync(server, [11]));

        await Assert.That(listed.Select(k => k.Comment)).IsEquivalentTo(new[] { "shown" });
        await Assert.That(seen.Select(r => r.Operation).Distinct()).IsEquivalentTo(new[] { SshAgentOperation.ListKeys });
        await Assert.That(seen.Select(r => r.Key)).IsEquivalentTo(new[] { shown.GetPublicKey(), hidden.GetPublicKey() });
        await Assert.That(seen[0].Purpose).IsNull();
        await Assert.That(seen[0].DestinationHostKey).IsNull();
        await Assert.That(seen[0].ForwardingHostKeys).IsEmpty();
    }

    [Test]
    public async Task TheFilter_DecidesEverySignature_WhetherOrNotTheKeyWasListed()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "laptop");
        var allow = true;
        var seen = new List<SshAgentRequest>();
        var server = Server((request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult(allow);
        }, key);
        var request = Sign(key.PublicKey.Span, Login(key, "ssh-ed25519", user: "build"));

        await Assert.That(Signature(await HandleAsync(server, request)).Algorithm).IsEqualTo("ssh-ed25519");
        allow = false;
        await Assert.That(await HandleAsync(server, request)).IsEquivalentTo(new byte[] { 5 });

        await Assert.That(seen.Count).IsEqualTo(2);
        await Assert.That(seen[0].Operation).IsEqualTo(SshAgentOperation.Sign);
        await Assert.That(seen[0].Key).IsEqualTo(key.GetPublicKey());
        await Assert.That(seen[0].Purpose).IsEqualTo(SshSignaturePurpose.Authentication);
        await Assert.That(seen[0].UserName).IsEqualTo("build");
        await Assert.That(seen[0].Namespace).IsNull();
        await Assert.That(seen[0].Certificate).IsNull();
        await Assert.That(seen[0].Key.Comment).IsNull(); // not listed on this connection: no comment known
    }

    [Test]
    public async Task TheFilter_SeesTheForwardingHops_TheDestination_AndAFileSignaturesNamespace()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "laptop");
        using var bastion = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var jump = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        using var destination = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var seen = new List<SshAgentRequest>();
        var server = Server((request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult(true);
        }, key);

        // This client's own session first (trusted, not verified again), then a hop that forwarded the agent on, then the login.
        var bastionSession = RandomNumberGenerator.GetBytes(32);
        server.AddForwardingHop(new AgentBinding(bastion.PublicKey, bastionSession, bastion.Sign("ssh-ed25519", bastionSession)));
        await Assert.That(await HandleAsync(server, Bind(jump, RandomNumberGenerator.GetBytes(32), forwarding: true))).IsEquivalentTo(new byte[] { 6 });
        await HandleAsync(server, [11]);
        await Assert.That(await HandleAsync(server, Bind(destination, SessionId, forwarding: false))).IsEquivalentTo(new byte[] { 6 });
        await HandleAsync(server, [11]);
        await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")));
        await HandleAsync(server, Sign(key.PublicKey.Span, SshSig("git")));

        await Assert.That(seen.Count).IsEqualTo(4);
        foreach (var request in seen)
        {
            await Assert.That(request.ForwardingHostKeys).IsEquivalentTo(new[] { bastion.GetPublicKey(), jump.GetPublicKey() });
        }

        await Assert.That(seen[0].DestinationHostKey).IsNull(); // listed before the login's session was bound
        await Assert.That(seen[1].DestinationHostKey).IsEqualTo(destination.GetPublicKey());
        await Assert.That(seen[2].DestinationHostKey).IsEqualTo(destination.GetPublicKey());
        await Assert.That(seen[2].Key.Comment).IsEqualTo("laptop"); // from the listing on this connection
        await Assert.That(seen[3].Purpose).IsEqualTo(SshSignaturePurpose.FileSignature);
        await Assert.That(seen[3].Namespace).IsEqualTo("git");
        await Assert.That(seen[3].DestinationHostKey).IsNull();
        await Assert.That(seen[3].UserName).IsNull();
    }

    [Test]
    public async Task TheFilter_SeesACertificate_AsItsKeyAndTheCertificate()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(ca, key.PublicKey.ToArray(), SshCertificateType.User, ["deploy"]));
        var seen = new List<SshAgentRequest>();
        var server = Server((request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult(request.Certificate is not null);
        }, key.WithCertificate(certificate));

        var listed = Identities(await HandleAsync(server, [11]));

        await Assert.That(listed.Single().Blob).IsEquivalentTo(certificate.Blob.ToArray());
        await Assert.That(seen.Count).IsEqualTo(2);
        await Assert.That(seen[1].Key).IsEqualTo(key.GetPublicKey());
        await Assert.That(seen[1].Certificate!.Blob.ToArray()).IsEquivalentTo(certificate.Blob.ToArray());
    }

    [Test]
    public async Task AFilterThatThrows_Refuses()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var server = Server((_, _) => throw new InvalidOperationException("the prompt failed"), key);
        await Assert.That(await HandleAsync(server, [11])).IsEquivalentTo(new byte[] { 12, 0, 0, 0, 0 });
        await Assert.That(await HandleAsync(server, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task AnAsynchronousFilter_IsAwaited()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Server(async (request, ct) => request.Operation == SshAgentOperation.ListKeys || await answer.Task.WaitAsync(ct), key);

        var signing = server.HandleAsync(Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")), Timeout()).AsTask();
        await Task.Delay(50);
        await Assert.That(signing.IsCompleted).IsFalse(); // waiting for the user
        answer.SetResult(true);
        await Assert.That(Signature(await signing).Algorithm).IsEqualTo("ssh-ed25519");
    }

    [Test]
    public async Task UnderAFilter_AKeyItCannotShow_IsHidden_AndRefused()
    {
        // A DSA key from a real agent: SshPublicKey does not read it, so the filter could not judge it.
        var dsa = TestKeys.Blob(w => { w.WriteString("ssh-dss"); w.WriteMpint([1]); w.WriteMpint([2]); w.WriteMpint([3]); w.WriteMpint([4]); });
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var backend = new ListOnly([new AgentIdentity(dsa, "old"), new AgentIdentity(key.PublicKey.ToArray(), "new")]);
        var asked = 0;
        var server = new AgentServer(backend, (_, _) =>
        {
            asked++;
            return ValueTask.FromResult(true);
        }, NullLogger.Instance);

        var listed = Identities(await HandleAsync(server, [11]));
        await Assert.That(listed.Select(k => k.Comment)).IsEquivalentTo(new[] { "new" });
        await Assert.That(await HandleAsync(server, Sign(dsa, Login(key, "ssh-dss")))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(asked).IsEqualTo(1);
        await Assert.That(backend.Signed).IsEqualTo(0);

        // Without a filter, it is listed as it is.
        await Assert.That(Identities(await HandleAsync(new AgentServer(backend, null, NullLogger.Instance), [11])).Count).IsEqualTo(2);
    }

    [Test]
    public async Task FromKeys_RefusesNull()
    {
        await Assert.That(() => SshAgent.FromKeys(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => SshAgent.FromKeys([null!])).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task RelayedIdentities_AreReadStrictly()
    {
        await Assert.That(RelayedAgent.ReadIdentities([5])).IsNull();
        await Assert.That(RelayedAgent.ReadIdentities([12, 0, 0, 0, 0])!.Count).IsEqualTo(0);
        await Assert.That(() => RelayedAgent.ReadIdentities([12, 0, 0, 0, 1])).Throws<SshProtocolException>();
        await Assert.That(() => RelayedAgent.ReadIdentities([12, 0, 0, 0x08, 0x01])).Throws<SshProtocolException>(); // 2049 keys
    }

    [Test]
    public async Task ARelayedAgent_NeverGetsAnRsaRequestWithoutASha2Flag()
    {
        // A real agent would sign it with SHA-1; behind the agent server, it never sees the request.
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        var backend = new ListOnly([]);
        var server = new AgentServer(backend, null, NullLogger.Instance);
        await Assert.That(await HandleAsync(server, Sign(rsa.PublicKey.Span, Login(rsa, "ssh-rsa")))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(backend.Signed).IsEqualTo(0);
        await HandleAsync(server, Sign(rsa.PublicKey.Span, Login(rsa, "rsa-sha2-512"), flags: 4));
        await Assert.That(backend.Signed).IsEqualTo(1);
    }

    [Test]
    public async Task ASignRequestWithDataAfterIt_IsRefused()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        byte[] request = [.. Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")), 0];
        await Assert.That(await HandleAsync(Server(key), request)).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    public async Task SessionBind_WithAnUnreadableHostKeyOrSignature_IsRefused()
    {
        using var hostKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var badKey = TestKeys.Blob(w =>
        {
            w.WriteByte(27);
            w.WriteString("session-bind@openssh.com");
            w.WriteString(TestKeys.Blob(k => { k.WriteString("ssh-ed25519"); k.WriteString(new byte[3]); }));
            w.WriteString(SessionId);
            w.WriteString(hostKey.Sign("ssh-ed25519", SessionId));
            w.WriteBoolean(false);
        });
        await Assert.That(await HandleAsync(Server(), badKey)).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await HandleAsync(Server(), Bind(hostKey, SessionId, forwarding: false, signature: [0xFF, 0xFF, 0xFF, 0xFF]))).IsEquivalentTo(new byte[] { 5 });
        await Assert.That(await HandleAsync(Server(), Bind(hostKey, SessionId, forwarding: false, signature: [0, 0, 0, 1, 0xC3]))).IsEquivalentTo(new byte[] { 5 });
    }

    [Test]
    [Arguments("\nlaptop")]
    [Arguments("lap\rtop")]
    [Arguments("")]
    public async Task ACommentWithALineBreak_OrEmpty_IsLeftOut(string comment)
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var described = AgentServer.Describe(key.PublicKey.ToArray(), comment);
        await Assert.That(described!.Value.Key.Comment).IsNull();
        await Assert.That(AgentServer.Describe(key.PublicKey.ToArray(), "laptop")!.Value.Key.Comment).IsEqualTo("laptop");
    }

    [Test]
    public async Task TheKeyring_PicksTheRsaHashFromTheFlags_AndNoneWithoutOne()
    {
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var ed25519 = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await Assert.That(AgentKeyring.Algorithm(rsa, 0)).IsNull();
        await Assert.That(AgentKeyring.Algorithm(rsa, 1)).IsNull();
        await Assert.That(AgentKeyring.Algorithm(rsa, 2)).IsEqualTo("rsa-sha2-256");
        await Assert.That(AgentKeyring.Algorithm(rsa, 4)).IsEqualTo("rsa-sha2-512");
        await Assert.That(AgentKeyring.Algorithm(ed25519, 0)).IsEqualTo("ssh-ed25519");
    }

    [Test]
    public async Task RelayedIdentities_AreLimitedTo2048()
    {
        static byte[] Answer(int count) => TestKeys.Blob(w =>
        {
            w.WriteByte(12);
            w.WriteUInt32((uint)count);
            for (var i = 0; i < count; i++)
            {
                w.WriteString(new byte[] { 1 });
                w.WriteString(string.Empty);
            }
        });

        await Assert.That(RelayedAgent.ReadIdentities(Answer(2048))!.Count).IsEqualTo(2048);
        await Assert.That(() => RelayedAgent.ReadIdentities(Answer(2049))).Throws<SshProtocolException>();
    }

    [Test]
    public async Task RefusalsAndFilterFailures_AreLogged_WithTheKeysFingerprint()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var logger = new ListLogger();
        var refusing = new AgentServer(new AgentKeyring([key]), (_, _) => ValueTask.FromResult(false), logger);
        await HandleAsync(refusing, Sign(key.PublicKey.Span, Login(key, "ssh-ed25519")));
        var throwing = new AgentServer(new AgentKeyring([key]), (_, _) => throw new InvalidOperationException("no prompt"), logger);
        await HandleAsync(throwing, [11]);

        await Assert.That(logger.Entries.Select(e => e.EventId)).IsEquivalentTo(new[] { 42, 43 });
        await Assert.That(logger.Entries[0].Message).Contains(key.Fingerprint);
        await Assert.That(logger.Entries[1].Exception).IsTypeOf<InvalidOperationException>();
    }

    private sealed class ListLogger : Microsoft.Extensions.Logging.ILogger
    {
        public List<(int EventId, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((eventId.Id, formatter(state, exception), exception));
    }

    /// <summary>A backend that lists what it is given and counts signatures, standing in for a real agent.</summary>
    private sealed class ListOnly(IReadOnlyList<AgentIdentity> identities) : AgentBackend
    {
        public int Signed { get; private set; }

        public override ValueTask<IReadOnlyList<AgentIdentity>?> ListAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<AgentIdentity>?>(identities);

        public override ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, byte[] blob, byte[] data, uint flags, SignedData signed, CancellationToken cancellationToken)
        {
            Signed++;
            return ValueTask.FromResult<byte[]>([5]);
        }

        public override ValueTask<byte[]> BindAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken) => ValueTask.FromResult<byte[]>([6]);
    }

    /// <summary>A signer backed by a generated key, standing in for a KMS: it records each request and can refuse, as a policy would.</summary>
    internal sealed class KeySigner(SshPrivateKey key) : SshKeySigner(key.PublicKey)
    {
        public IReadOnlyList<string>? Algorithms { get; init; }

        public bool Refuse { get; init; }

        public List<SshSignRequest> Requests { get; } = [];

        public override IReadOnlyList<string> SignatureAlgorithms => Algorithms ?? base.SignatureAlgorithms;

        public override async ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken)
        {
            lock (Requests)
            {
                Requests.Add(request);
            }

            if (Refuse)
            {
                throw new UnauthorizedAccessException("The key service's policy refuses this request.");
            }

            var blob = await key.SignAsync(request, null, cancellationToken);
            var reader = new SshReader(blob);
            reader.ReadString();
            return reader.ReadString().ToArray(); // Ed25519 and RSA: the raw signature as a key service returns it
        }
    }
}
