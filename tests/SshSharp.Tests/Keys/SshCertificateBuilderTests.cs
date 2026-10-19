using System.Diagnostics;
using System.Security.Cryptography;
using SshSharp.Protocol;
using SshSharp.Tests.Agent;

namespace SshSharp.Tests.Keys;

/// <summary>Issuing certificates with SshCertificateBuilder: the encoding (PROTOCOL.certkeys), the checks, the signers, and ssh-keygen reading them.</summary>
public sealed class SshCertificateBuilderTests
{
    private static readonly DateTimeOffset Start = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset End = Start.AddHours(1);

    // One key of each type for the whole class: RSA keys are slow to generate.
    private static readonly Dictionary<SshKeyType, SshPrivateKey> Keys = Enum.GetValues<SshKeyType>()
        .ToDictionary(type => type, type => SshPrivateKey.Generate(type, "key-" + type.ToString().ToLowerInvariant(), rsaBits: 2048));

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    public static IEnumerable<(SshKeyType Authority, SshKeyType Subject)> Pairs() =>
        from authority in Enum.GetValues<SshKeyType>()
        from subject in Enum.GetValues<SshKeyType>()
        select (authority, subject);

    private static SshCertificateBuilder User(SshKeyType subject = SshKeyType.Ed25519) =>
        new(Keys[subject].GetPublicKey(), SshCertificateType.User, "ci-build-42")
        {
            Serial = 42,
            Principals = { "deploy" },
            ValidAfter = Start,
            ValidBefore = End,
        };

    /// <summary>The signature algorithm the certificate's signature names.</summary>
    private static string SignatureAlgorithm(SshCertificate certificate) => new SshReader(Signature(certificate)).ReadUtf8String();

    private static byte[] Signature(SshCertificate certificate)
    {
        // Walk the fields (PROTOCOL.certkeys) to the signature, the last string: the type and the nonce, the key's fields (one for
        // Ed25519, two for ECDSA and RSA, whose mpints are strings too), serial and type, key id and principals, the validity, then
        // the options, extensions, reserved field and authority key.
        var reader = new SshReader(certificate.Blob.Span);
        var strings = 2 + (certificate.KeyType == "ssh-ed25519" ? 1 : 2);
        for (var i = 0; i < strings; i++)
        {
            reader.ReadString();
        }

        reader.ReadUInt64();
        reader.ReadUInt32();
        reader.ReadString();
        reader.ReadString();
        reader.ReadUInt64();
        reader.ReadUInt64();
        for (var i = 0; i < 4; i++)
        {
            reader.ReadString();
        }

        return reader.ReadString().ToArray();
    }

    [Test]
    [MethodDataSource(nameof(Pairs))]
    public async Task SignedCertificates_ParseBack_Verify_AndHoldEveryField(SshKeyType authorityType, SshKeyType subjectType)
    {
        var authority = Keys[authorityType];
        var subject = Keys[subjectType].GetPublicKey();
        var builder = User(subjectType);
        builder.Principals.Add("ci");
        builder.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.0/24,2001:db8::/32";
        builder.CriticalOptions[SshCertificateBuilder.ForceCommand] = "/usr/local/bin/deploy --env test";

        var certificate = await builder.SignAsync(authority, Timeout());

        await Assert.That(certificate.Algorithm).IsEqualTo(subject.KeyType + "-cert-v01@openssh.com");
        await Assert.That(certificate.GetPublicKey()).IsEqualTo(subject);
        await Assert.That(certificate.GetAuthorityKey()).IsEqualTo(authority.GetPublicKey());
        await Assert.That(certificate.Type).IsEqualTo(SshCertificateType.User);
        await Assert.That(certificate.KeyId).IsEqualTo("ci-build-42");
        await Assert.That(certificate.Serial).IsEqualTo(42ul);
        await Assert.That(string.Join(",", certificate.Principals)).IsEqualTo("deploy,ci");
        await Assert.That(certificate.ValidAfter).IsEqualTo(Start);
        await Assert.That(certificate.ValidBefore).IsEqualTo(End);
        await Assert.That(certificate.CriticalOptions.Count).IsEqualTo(2);
        await Assert.That(certificate.CriticalOptions[SshCertificateBuilder.ForceCommand]).IsEqualTo("/usr/local/bin/deploy --env test");
        await Assert.That(certificate.CriticalOptions[SshCertificateBuilder.SourceAddress]).IsEqualTo("192.0.2.0/24,2001:db8::/32");
        await Assert.That(string.Join(",", certificate.Extensions)) // in byte order, as ssh-keygen writes them
            .IsEqualTo("permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc");
        await Assert.That(certificate.Comment).IsEqualTo(subject.Comment);
        await Assert.That(certificate.VerifySignature()).IsTrue();
        await Assert.That(SignatureAlgorithm(certificate)).IsEqualTo(authorityType == SshKeyType.Rsa ? "rsa-sha2-512" : authority.KeyType);

        // Its line parses back to the same certificate, and it can be used with its key.
        var parsed = SshCertificate.Parse(certificate.ToAuthorizedKeysLine());
        await Assert.That(Convert.ToHexString(parsed.Blob.Span)).IsEqualTo(Convert.ToHexString(certificate.Blob.Span));
        await Assert.That(parsed.VerifySignature()).IsTrue();
        await Assert.That(Keys[subjectType].WithCertificate(parsed).KeyType).IsEqualTo(certificate.Algorithm);
    }

    [Test]
    public async Task TheEncoding_FollowsProtocolCertkeys()
    {
        var builder = User(SshKeyType.EcdsaNistp384);
        builder.Extensions.Clear();
        builder.Extensions["permit-pty"] = string.Empty;
        builder.Extensions["login@example.com"] = "deploy";
        builder.Extensions["no-touch-required"] = string.Empty;
        builder.CriticalOptions[SshCertificateBuilder.VerifyRequired] = string.Empty;
        builder.CriticalOptions[SshCertificateBuilder.ForceCommand] = "true";
        var authority = Keys[SshKeyType.Ed25519];
        var certificate = await builder.SignAsync(authority, Timeout());

        // The same certificate written field by field from PROTOCOL.certkeys, with the nonce and the signature it got.
        var (nonce, signature) = NonceAndSignature(certificate);
        var keyFields = Keys[SshKeyType.EcdsaNistp384].PublicKey.ToArray()[(4 + "ecdsa-sha2-nistp384".Length)..]; // the curve name and the point
        var expected = TestKeys.Blob(w =>
        {
            w.WriteString("ecdsa-sha2-nistp384-cert-v01@openssh.com");
            w.WriteString(nonce);
            w.WriteBytes(keyFields);
            w.WriteUInt64(42);
            w.WriteUInt32(1); // SSH_CERT_TYPE_USER
            w.WriteString("ci-build-42");
            w.WriteString(TestKeys.Blob(p => p.WriteString("deploy")));
            w.WriteUInt64((ulong)Start.ToUnixTimeSeconds());
            w.WriteUInt64((ulong)End.ToUnixTimeSeconds());

            // Sorted by name; a value is a string inside the data string, and a flag has empty data.
            w.WriteString(TestKeys.Blob(o =>
            {
                o.WriteString("force-command");
                o.WriteString(TestKeys.Blob(v => v.WriteString("true")));
                o.WriteString("verify-required");
                o.WriteString(ReadOnlySpan<byte>.Empty);
            }));
            w.WriteString(TestKeys.Blob(e =>
            {
                e.WriteString("login@example.com");
                e.WriteString(TestKeys.Blob(v => v.WriteString("deploy")));
                e.WriteString("no-touch-required");
                e.WriteString(ReadOnlySpan<byte>.Empty);
                e.WriteString("permit-pty");
                e.WriteString(ReadOnlySpan<byte>.Empty);
            }));
            w.WriteString(ReadOnlySpan<byte>.Empty); // reserved
            w.WriteString(authority.PublicKey.Span);
            w.WriteString(signature);
        });

        await Assert.That(nonce.Length).IsEqualTo(32);
        await Assert.That(Convert.ToHexString(certificate.Blob.Span)).IsEqualTo(Convert.ToHexString(expected)); // in order, byte for byte
        await Assert.That(SignatureAlgorithm(certificate)).IsEqualTo("ssh-ed25519");

        // The values read back, a vendor extension's included, as the builder took them.
        var parsed = SshCertificate.Parse(certificate.ToAuthorizedKeysLine());
        await Assert.That(parsed.ExtensionValues).IsEquivalentTo(builder.Extensions);
        await Assert.That(parsed.ExtensionValues["login@example.com"]).IsEqualTo("deploy");
        await Assert.That(parsed.ExtensionValues["permit-pty"]).IsEqualTo(string.Empty);
        await Assert.That(string.Join(",", parsed.Extensions)).IsEqualTo(string.Join(",", parsed.ExtensionValues.Keys));
    }

    /// <summary>The nonce (the second field) and the signature (the last).</summary>
    private static (byte[] Nonce, byte[] Signature) NonceAndSignature(SshCertificate certificate)
    {
        var reader = new SshReader(certificate.Blob.Span);
        reader.ReadString();
        return (reader.ReadString().ToArray(), Signature(certificate));
    }

    [Test]
    public async Task EachSignature_HasAFreshNonce()
    {
        var builder = User();
        var first = NonceAndSignature(await builder.SignAsync(Keys[SshKeyType.Ed25519], Timeout())).Nonce;
        var second = NonceAndSignature(await builder.SignAsync(Keys[SshKeyType.Ed25519], Timeout())).Nonce;
        await Assert.That(Convert.ToHexString(first)).IsNotEqualTo(Convert.ToHexString(second));
    }

    [Test]
    public async Task HostCertificates_HaveNoExtensionsByDefault_AndVerifyForTheirHosts()
    {
        var authority = Keys[SshKeyType.EcdsaNistp256];
        var builder = new SshCertificateBuilder(Keys[SshKeyType.Ed25519].GetPublicKey(), SshCertificateType.Host, "web-1")
        {
            Principals = { "web1.example.com", "*.web.example.com" },
            ValidBefore = DateTimeOffset.UtcNow.AddDays(30),
        };
        await Assert.That(builder.Extensions).IsEmpty();
        var certificate = await builder.SignAsync(authority, Timeout());
        await Assert.That(certificate.Type).IsEqualTo(SshCertificateType.Host);
        await Assert.That(certificate.Extensions).IsEmpty();
        await Assert.That(certificate.IsValidFor(authority.GetPublicKey(), SshCertificateType.Host, "a.web.example.com", DateTimeOffset.UtcNow, out var reason))
            .IsTrue().Because(reason ?? string.Empty);
        await Assert.That(certificate.CheckForHost("web1.example.com", DateTimeOffset.UtcNow)).IsNull();

        builder.CriticalOptions[SshCertificateBuilder.ForceCommand] = "true";
        await Assert.That(async () => await builder.SignAsync(authority, Timeout())).Throws<InvalidOperationException>()
            .WithMessageContaining("Host certificates have no critical options");
    }

    [Test]
    public async Task UserCertificates_WithoutExtensions()
    {
        var builder = User();
        builder.Extensions.Clear();
        var certificate = await builder.SignAsync(Keys[SshKeyType.Ed25519], Timeout());
        await Assert.That(certificate.Extensions).IsEmpty();
        await Assert.That(certificate.IsValidFor(Keys[SshKeyType.Ed25519].GetPublicKey(), SshCertificateType.User, "deploy", Start, out _)).IsTrue();
    }

    [Test]
    public async Task Validity_HasNoDefaultEnd_StartsAMinuteBeforeSigning_AndCanBeForever()
    {
        var authority = Keys[SshKeyType.Ed25519];
        var builder = User();
        builder.ValidBefore = null;
        await Assert.That(async () => await builder.SignAsync(authority, Timeout())).Throws<InvalidOperationException>().WithMessageContaining("Set ValidBefore");

        builder.ValidAfter = null;
        builder.ValidBefore = DateTimeOffset.MaxValue;
        var before = DateTimeOffset.UtcNow;
        var certificate = await builder.SignAsync(authority, Timeout());
        var after = DateTimeOffset.UtcNow;
        await Assert.That(certificate.ValidAfter).IsGreaterThanOrEqualTo(before.AddMinutes(-1).AddSeconds(-1));
        await Assert.That(certificate.ValidAfter).IsLessThanOrEqualTo(after.AddMinutes(-1));
        await Assert.That(certificate.ValidBefore).IsEqualTo(DateTimeOffset.MaxValue);
        await Assert.That(certificate.ValidBeforeSeconds).IsEqualTo(ulong.MaxValue); // written as ssh-keygen's "forever"
        await Assert.That(certificate.IsValidAt(DateTimeOffset.UtcNow)).IsTrue();

        // Before the epoch is "always".
        builder.ValidAfter = DateTimeOffset.MinValue;
        await Assert.That((await builder.SignAsync(authority, Timeout())).ValidAfter).IsEqualTo(DateTimeOffset.UnixEpoch);

        // An empty window, and one that ends before it starts, are refused; whole seconds count.
        builder.ValidAfter = Start;
        builder.ValidBefore = Start.AddMilliseconds(500);
        await Assert.That(async () => await builder.SignAsync(authority, Timeout())).Throws<InvalidOperationException>().WithMessageContaining("validity window is empty");
        builder.ValidBefore = Start.AddSeconds(-1);
        await Assert.That(async () => await builder.SignAsync(authority, Timeout())).Throws<InvalidOperationException>();
        builder.ValidBefore = Start.AddSeconds(1);
        await Assert.That((await builder.SignAsync(authority, Timeout())).ValidBefore).IsEqualTo(Start.AddSeconds(1));
    }

    public static IEnumerable<(string Case, Action<SshCertificateBuilder> Change, string Message)> InvalidCertificates() =>
    [
        ("no principals", b => b.Principals.Clear(), "at least one principal"),
        ("empty principal", b => b.Principals.Add(string.Empty), "must not be empty"),
        ("control character", b => b.Principals.Add("de\nploy"), "control characters"),
        ("twice", b => b.Principals.Add("deploy"), "listed twice"),
        ("unknown option", b => b.CriticalOptions["force-comand"] = "x", "Unknown critical option 'force-comand': the standard ones are force-command, source-address, verify-required"),
        ("bad option name", b => b.CriticalOptions["a b"] = "x", "The critical option name 'a b'"),
        ("bare @", b => b.CriticalOptions["@example.com"] = "x", "Unknown critical option"),
        ("trailing @", b => b.CriticalOptions["option@"] = "x", "Unknown critical option"),
        ("unknown extension", b => b.Extensions["permit-tty"] = string.Empty, "Unknown extension 'permit-tty': the standard ones are no-touch-required, permit-X11-forwarding"),
        ("standard with value", b => b.Extensions["permit-pty"] = "yes", "takes no value"),
        ("empty force-command", b => b.CriticalOptions[SshCertificateBuilder.ForceCommand] = string.Empty, "needs the command"),
        ("verify-required value", b => b.CriticalOptions[SshCertificateBuilder.VerifyRequired] = "yes", "takes no value"),
        ("empty source-address", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = string.Empty, "needs a comma-separated list"),
        ("host name source", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "example.com", "'example.com' is not an address"),
        ("short IPv4", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2/24", "'192.0.2/24'"),
        ("IPv4 prefix", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.0/33", "'192.0.2.0/33'"),
        ("IPv6 prefix", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "2001:db8::/129", "'2001:db8::/129'"),
        ("signed prefix", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.0/+8", "'192.0.2.0/+8'"),
        ("empty entry", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.1,", "'' is not"),
        ("scope id", b => b.CriticalOptions[SshCertificateBuilder.SourceAddress] = "fe80::1%2", "'fe80::1%2'"),
        ("name with space", b => b.Extensions["a b@example.com"] = string.Empty, "not a valid name"),
        ("name with comma", b => b.Extensions["a,b@example.com"] = string.Empty, "not a valid name"),
        ("non-ASCII name", b => b.Extensions["é@example.com"] = string.Empty, "not a valid name"),
        ("empty name", b => b.Extensions[string.Empty] = string.Empty, "not a valid name"),
        ("null value", b => b.Extensions["x@example.com"] = null!, "null value"),
        ("NUL in value", b => b.Extensions["x@example.com"] = "a\0b", "NUL character"),
    ];

    [Test]
    [MethodDataSource(nameof(InvalidCertificates))]
    public async Task InvalidContent_IsRefusedBeforeSigning(string @case, Action<SshCertificateBuilder> change, string message)
    {
        var signer = new ExternalKeyTests.TestSigner(Keys[SshKeyType.Ed25519]);
        using var authority = SshPrivateKey.FromSigner(signer);
        var builder = User();
        change(builder);
        await Assert.That(async () => await builder.SignAsync(authority, Timeout())).Throws<InvalidOperationException>().WithMessageContaining(message)
            .Because(@case);
        await Assert.That(signer.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task ValidOptionsAndExtensions_AreAccepted()
    {
        var builder = User();
        builder.CriticalOptions[SshCertificateBuilder.SourceAddress] =
            "192.0.2.7,198.51.100.0/24,192.0.2.8/32,2001:db8::1,2001:db8:1::/48,2001:db8::2/128,0.0.0.0/0";
        builder.CriticalOptions[SshCertificateBuilder.VerifyRequired] = string.Empty;
        builder.CriticalOptions["tenant@example.com"] = "blue";
        builder.Extensions["no-touch-required"] = string.Empty;
        builder.Extensions["permissions@example.com"] = string.Empty;
        builder.Extensions["x~y@example.com"] = string.Empty;
        var certificate = await builder.SignAsync(Keys[SshKeyType.Ed25519], Timeout());
        await Assert.That(string.Join(",", certificate.CriticalOptions.Keys)).IsEqualTo("source-address,tenant@example.com,verify-required");
        await Assert.That(certificate.Extensions).Contains("x~y@example.com"); // '~' is the last printable character
        await Assert.That(certificate.CriticalOptions["tenant@example.com"]).IsEqualTo("blue");
        await Assert.That(certificate.Extensions).Contains("permissions@example.com");
    }

    [Test]
    public async Task TheConstructor_ChecksTheKeyAndTheKeyId()
    {
        var key = Keys[SshKeyType.Ed25519].GetPublicKey();
        await Assert.That(() => new SshCertificateBuilder(null!, SshCertificateType.User, "id")).Throws<ArgumentNullException>();
        await Assert.That(() => new SshCertificateBuilder(key, SshCertificateType.User, null!)).Throws<ArgumentNullException>();
        await Assert.That(() => new SshCertificateBuilder(key, SshCertificateType.User, string.Empty)).Throws<ArgumentException>();
        await Assert.That(() => new SshCertificateBuilder(key, SshCertificateType.User, "id\r\nforged log line")).Throws<ArgumentException>()
            .WithMessageContaining("control characters");
        await Assert.That(() => new SshCertificateBuilder(key, (SshCertificateType)3, "id")).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshCertificateBuilder(key, 0, "id")).Throws<ArgumentOutOfRangeException>();

        // FIDO security keys are not certified here (SshCertificate does not read their certificates); small RSA keys are refused.
        var sk = SshPublicKey.FromBlob(TestKeys.Blob(w =>
        {
            w.WriteString("sk-ssh-ed25519@openssh.com");
            w.WriteString(Keys[SshKeyType.Ed25519].GetPublicKey().Blob.Span[^32..]);
            w.WriteString("ssh:");
        }));
        await Assert.That(() => new SshCertificateBuilder(sk, SshCertificateType.User, "id")).Throws<ArgumentException>().WithMessageContaining("sk-ssh-ed25519");

        using var small = RSA.Create(1024);
        var smallKey = SshPublicKey.FromBlob(TestKeys.RsaPublicBlob(small));
        await Assert.That(() => new SshCertificateBuilder(smallKey, SshCertificateType.User, "id")).Throws<ArgumentException>().WithMessageContaining("2048");
        using var ok = RSA.Create(2048);
        await Assert.That(new SshCertificateBuilder(SshPublicKey.FromBlob(TestKeys.RsaPublicBlob(ok)), SshCertificateType.Host, "id").Type)
            .IsEqualTo(SshCertificateType.Host);
    }

    [Test]
    public async Task TheAuthority_CannotBeACertifiedKey()
    {
        var authority = Keys[SshKeyType.Ed25519];
        var ownCertificate = await User().SignAsync(Keys[SshKeyType.EcdsaNistp256], Timeout());
        var certified = authority.WithCertificate(ownCertificate);
        await Assert.That(async () => await User().SignAsync(certified, Timeout())).Throws<ArgumentException>().WithMessageContaining("cannot itself be a certificate");
        await Assert.That(async () => await User().SignAsync(null!, Timeout())).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task ASigner_IsAskedForACertificateSignature_WithSha2ForRsa()
    {
        var signer = new ExternalKeyTests.TestSigner(Keys[SshKeyType.Rsa]);
        using var authority = SshPrivateKey.FromSigner(signer);
        var certificate = await User().SignAsync(authority, Timeout());
        await Assert.That(signer.Requests.Single().Purpose).IsEqualTo(SshSignaturePurpose.Certificate);
        await Assert.That(signer.Requests.Single().Algorithm).IsEqualTo("rsa-sha2-512");
        await Assert.That(certificate.VerifySignature()).IsTrue();

        // A signer that signs only with SHA-256 gets rsa-sha2-256.
        var sha256 = new ExternalKeyTests.TestSigner(Keys[SshKeyType.Rsa]) { Algorithms = ["rsa-sha2-256"] };
        using var sha256Authority = SshPrivateKey.FromSigner(sha256);
        var signed = await User().SignAsync(sha256Authority, Timeout());
        await Assert.That(SignatureAlgorithm(signed)).IsEqualTo("rsa-sha2-256");
        await Assert.That(signed.VerifySignature()).IsTrue();
    }

    [Test]
    public async Task ASignerThatRefuses_StopsTheCertificate()
    {
        using var authority = SshPrivateKey.FromSigner(new LoginOnlySigner(Keys[SshKeyType.Ed25519]));
        await Assert.That(async () => await User().SignAsync(authority, Timeout())).Throws<UnauthorizedAccessException>();
    }

    [Test]
    public async Task AnAgentKey_CanBeTheAuthority_ButNotOneThatSignsWithSha1()
    {
        await using var agent = new FakeAgent();
        agent.Keys.Add((Keys[SshKeyType.Rsa], "ca"));
        var authority = (await new SshAgent(agent.Path).GetKeysAsync(Timeout())).Single();
        var certificate = await User().SignAsync(authority, Timeout());
        await Assert.That(certificate.VerifySignature()).IsTrue();
        await Assert.That(SignatureAlgorithm(certificate)).IsEqualTo("rsa-sha2-512");
        await Assert.That(agent.SignFlags.Single()).IsEqualTo(4u); // SSH_AGENT_RSA_SHA2_512

        agent.ClaimAlgorithm = "ssh-rsa";
        var error = await Assert.ThrowsAsync<SshException>(async () => await User().SignAsync(authority, Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AgentFailed);
    }

    [Test]
    public async Task ASecurityKeyInTheAgent_CannotBeTheAuthority()
    {
        // SshSharp cannot check a FIDO key's signatures, so it does not issue certificates with one.
        await using var agent = new FakeAgent();
        agent.RawIdentities.Add(TestKeys.Blob(w =>
        {
            w.WriteString("sk-ssh-ed25519@openssh.com");
            w.WriteString(Keys[SshKeyType.Ed25519].GetPublicKey().Blob.Span[^32..]);
            w.WriteString("ssh:");
        }));
        var authority = (await new SshAgent(agent.Path).GetKeysAsync(Timeout())).Single();
        await Assert.That(async () => await User().SignAsync(authority, Timeout())).Throws<ArgumentException>()
            .WithMessageContaining("sk-ssh-ed25519@openssh.com key cannot be a certificate authority");
    }

    [Test]
    public async Task ABrokenSigningPath_IsCaughtBeforeTheCertificateIsReturned()
    {
        // A key whose signatures do not verify (here: one that signs with another key) never yields a certificate.
        using var authority = new MismatchedKey(Keys[SshKeyType.Ed25519], Keys[SshKeyType.EcdsaNistp256]);
        await Assert.That(async () => await User().SignAsync(authority, Timeout())).Throws<CryptographicException>().WithMessageContaining("does not verify");
    }

    [Test]
    public async Task Cancellation_ReachesTheSigner()
    {
        await using var agent = new FakeAgent();
        agent.Keys.Add((Keys[SshKeyType.Ed25519], "ca"));
        var authority = (await new SshAgent(agent.Path).GetKeysAsync(Timeout())).Single();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.That(async () => await User().SignAsync(authority, cancelled.Token)).Throws<OperationCanceledException>();
    }

    // ---- ssh-keygen reads what the builder writes ----

    public static IEnumerable<(SshKeyType Authority, SshKeyType Subject, SshCertificateType Type)> KeygenCases() =>
    [
        (SshKeyType.Ed25519, SshKeyType.Ed25519, SshCertificateType.User),
        (SshKeyType.Rsa, SshKeyType.EcdsaNistp256, SshCertificateType.User),
        (SshKeyType.EcdsaNistp384, SshKeyType.Rsa, SshCertificateType.User),
        (SshKeyType.EcdsaNistp521, SshKeyType.EcdsaNistp521, SshCertificateType.Host),
        (SshKeyType.EcdsaNistp256, SshKeyType.EcdsaNistp384, SshCertificateType.Host),
    ];

    [Test]
    [MethodDataSource(nameof(KeygenCases))]
    public async Task SshKeygen_ListsTheCertificate(SshKeyType authorityType, SshKeyType subjectType, SshCertificateType type)
    {
        if (FindSshKeygen() is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        var builder = new SshCertificateBuilder(Keys[subjectType].GetPublicKey(), type, "interop-cert")
        {
            Serial = 1234567890123,
            Principals = { type == SshCertificateType.User ? "deploy" : "web1.example.com", type == SshCertificateType.User ? "ci" : "*.example.com" },
            ValidAfter = Start,
            ValidBefore = End,
        };
        if (type == SshCertificateType.User)
        {
            builder.CriticalOptions[SshCertificateBuilder.ForceCommand] = "/usr/bin/true";
            builder.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.0/24";
            builder.Extensions.Remove("permit-X11-forwarding");
            builder.Extensions["login@example.com"] = "deploy";
        }

        var certificate = await builder.SignAsync(Keys[authorityType], Timeout());
        var (exitCode, output) = await ListAsync(sshKeygen, certificate.ToAuthorizedKeysLine());
        await Assert.That(exitCode).IsEqualTo(0).Because(output);

        // ssh-keygen checks the authority's signature when it reads a certificate, so listing it proves the signature too.
        var authority = Keys[authorityType];
        var signatureAlgorithm = authorityType == SshKeyType.Rsa ? "rsa-sha2-512" : authority.KeyType;
        await Assert.That(output).Contains($"{certificate.Algorithm} {(type == SshCertificateType.User ? "user" : "host")} certificate");
        await Assert.That(output).Contains($"Signing CA: ").And.Contains($"{authority.Fingerprint} (using {signatureAlgorithm})");
        await Assert.That(output).Contains("Key ID: \"interop-cert\"");
        await Assert.That(output).Contains("Serial: 1234567890123");
        await Assert.That(output).Contains("Valid: from 20"); // in local time
        foreach (var principal in certificate.Principals)
        {
            await Assert.That(output).Contains("                " + principal);
        }

        if (type == SshCertificateType.User)
        {
            await Assert.That(output).Contains("force-command /usr/bin/true").And.Contains("source-address 192.0.2.0/24");
            await Assert.That(output).Contains("permit-pty").And.Contains("login@example.com UNKNOWN OPTION");
            await Assert.That(output).DoesNotContain("permit-X11-forwarding");
        }

        // A changed byte makes ssh-keygen refuse it: it does verify.
        var tampered = certificate.Blob.ToArray();
        tampered[tampered.AsSpan().IndexOf("interop-cert"u8)] ^= 1;
        var (tamperedExit, _) = await ListAsync(sshKeygen, $"{certificate.Algorithm} {Convert.ToBase64String(tampered)}");
        await Assert.That(tamperedExit).IsNotEqualTo(0);
    }

    private static async Task<(int ExitCode, string Output)> ListAsync(string sshKeygen, string line)
    {
        var directory = Directory.CreateTempSubdirectory("sshsharp-cert-");
        try
        {
            var path = Path.Combine(directory.FullName, "id-cert.pub");
            await File.WriteAllTextAsync(path, line + "\n");
            var start = new ProcessStartInfo(sshKeygen) { RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { "-L", "-f", path })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            return (process.ExitCode, await output + await error);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static string? FindSshKeygen()
    {
        var name = OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen";
        return (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, name))
            .FirstOrDefault(File.Exists);
    }

    /// <summary>A signer with a policy: it signs for logging in only, and refuses to issue certificates.</summary>
    private sealed class LoginOnlySigner(SshPrivateKey key) : SshKeySigner(key.PublicKey)
    {
        public override async ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken)
        {
            if (request.Purpose != SshSignaturePurpose.Authentication)
            {
                throw new UnauthorizedAccessException("This key signs for logging in only.");
            }

            var blob = await key.SignAsync(request, null, cancellationToken);
            var reader = new SshReader(blob);
            reader.ReadString();
            return reader.ReadString().ToArray();
        }
    }

    /// <summary>A key that claims one public key and signs with another: what a misconfigured agent or HSM slot looks like.</summary>
    private sealed class MismatchedKey(SshPrivateKey claimed, SshPrivateKey actual) : SshPrivateKey(claimed.KeyType, claimed.PublicKey.ToArray(), null)
    {
        internal override IReadOnlyList<string> SignatureAlgorithms => claimed.SignatureAlgorithms;

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) => actual.Sign(actual.SignatureAlgorithms[0], data);

        private protected override void DisposeCore()
        {
        }
    }
}
