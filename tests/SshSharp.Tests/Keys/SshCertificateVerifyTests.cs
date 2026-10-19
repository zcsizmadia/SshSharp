using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>
/// Checking certificates: the authority's signature, the validity window, and the combined check, against certificates the real
/// <c>ssh-keygen -s</c> made (Fixtures/certificates, see make.sh there) and ones the tests make.
/// </summary>
public sealed class SshCertificateVerifyTests
{
    // The fixtures' validity windows: user_ed25519 2026-01-01 to 2099-01-01, host_ecdsa 2026-01-01 to forever, user_rsa 2020-01-01 to
    // 2021-01-01, user_ecdsa521 always to forever.
    private static readonly DateTimeOffset InWindow = new(2030, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static SshCertificate Fixture(string name) =>
        SshCertificate.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "certificates", name)));

    private static SshPublicKey Authority(string name) =>
        SshPublicKey.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "certificates", name)));

    [Test]
    [Arguments("user_ed25519-cert.pub", "ca_ed25519.pub")]
    [Arguments("host_ecdsa-cert.pub", "ca_rsa.pub")]
    [Arguments("user_rsa-cert.pub", "ca_ecdsa.pub")]
    [Arguments("user_ecdsa521-cert.pub", "ca_rsa.pub")]
    public async Task SshKeygenCertificates_Verify(string certificate, string authority)
    {
        var parsed = Fixture(certificate);
        await Assert.That(parsed.VerifySignature()).IsTrue();
        await Assert.That(parsed.GetAuthorityKey()).IsEqualTo(Authority(authority));
        await Assert.That(parsed.GetAuthorityKey()).IsNotEqualTo(Authority("other_ca.pub"));
    }

    [Test]
    public async Task TheFixturesFields_AreWhatSshKeygenWasAskedFor()
    {
        var user = Fixture("user_ed25519-cert.pub");
        await Assert.That(user.Type).IsEqualTo(SshCertificateType.User);
        await Assert.That(user.KeyId).IsEqualTo("deploy-ci");
        await Assert.That(user.Serial).IsEqualTo(1001ul);
        await Assert.That(string.Join(",", user.Principals)).IsEqualTo("deploy,ci");
        await Assert.That(user.ValidAfter).IsEqualTo(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        await Assert.That(user.ValidBefore).IsEqualTo(new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero));
        await Assert.That(user.CriticalOptions[SshCertificateBuilder.ForceCommand]).IsEqualTo("/usr/bin/true");
        await Assert.That(user.CriticalOptions[SshCertificateBuilder.SourceAddress]).IsEqualTo("192.0.2.0/24");
        await Assert.That(string.Join(",", user.Extensions))
            .IsEqualTo("permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc");
        await Assert.That(user.Comment).IsEqualTo("user-ed25519");

        var host = Fixture("host_ecdsa-cert.pub");
        await Assert.That(host.Type).IsEqualTo(SshCertificateType.Host);
        await Assert.That(host.ValidBefore).IsEqualTo(DateTimeOffset.MaxValue);
        await Assert.That(host.Extensions).IsEmpty();

        var always = Fixture("user_ecdsa521-cert.pub");
        await Assert.That(always.ValidAfter).IsEqualTo(DateTimeOffset.UnixEpoch);
        await Assert.That(always.IsValidAt(DateTimeOffset.MinValue)).IsTrue();
        await Assert.That(always.IsValidAt(DateTimeOffset.MaxValue)).IsTrue();
    }

    [Test]
    public async Task ExtensionValues_ReadAVendorExtensionsValue_AsSshKeygenWroteIt()
    {
        // ssh-keygen -O extension:login@example.com=deploy (make-krl.sh); ssh-keygen -L lists the extensions in this order.
        var certificate = Fixture("not_revoked-cert.pub");
        await Assert.That(string.Join(",", certificate.Extensions)).IsEqualTo(
            "login@example.com,permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc");
        await Assert.That(certificate.ExtensionValues.Keys).IsEquivalentTo(certificate.Extensions);
        await Assert.That(certificate.ExtensionValues["login@example.com"]).IsEqualTo("deploy");
        await Assert.That(certificate.ExtensionValues.Where(e => e.Key != "login@example.com").All(e => e.Value.Length == 0)).IsTrue();
        await Assert.That(certificate.ExtensionValues.ContainsKey("LOGIN@example.com")).IsFalse(); // names are exact

        await Assert.That(Fixture("host_ecdsa-cert.pub").ExtensionValues).IsEmpty();
    }

    [Test]
    public async Task ToAuthorizedKeysLine_WritesTheLineBack()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "certificates", "user_ed25519-cert.pub");
        var certificate = SshCertificate.Parse(File.ReadAllText(path));
        await Assert.That(certificate.ToAuthorizedKeysLine()).IsEqualTo(File.ReadAllText(path).Trim());
        await Assert.That(certificate.ToString()).IsEqualTo(certificate.ToAuthorizedKeysLine());

        // Without a comment there is no trailing space; a comment that runs onto another line is left out.
        var fields = certificate.ToAuthorizedKeysLine().Split(' ');
        var bare = SshCertificate.Parse($"{fields[0]} {fields[1]}");
        await Assert.That(bare.Comment).IsNull();
        await Assert.That(bare.ToAuthorizedKeysLine()).IsEqualTo($"{fields[0]} {fields[1]}");
        await Assert.That(SshCertificate.Parse($"{fields[0]} {fields[1]} two\nlines").Comment).IsNull();
        await Assert.That(SshCertificate.Parse($"{fields[0]}\t{fields[1]}  spaced  comment ").Comment).IsEqualTo("spaced  comment");
    }

    [Test]
    public async Task WeakSignatures_AreRefused()
    {
        // ssh-keygen still signs with SHA-1 when asked (-t ssh-rsa), and with a 1024-bit RSA key; neither is accepted.
        await Assert.That(Fixture("weak_sha1-cert.pub").VerifySignature()).IsFalse();
        await Assert.That(Fixture("weak_rsa1024-cert.pub").VerifySignature()).IsFalse();
        await Assert.That(Fixture("weak_sha1-cert.pub").IsValidFor(Authority("ca_rsa.pub"), SshCertificateType.User, "deploy", InWindow, out var reason))
            .IsFalse();
        await Assert.That(reason).Contains("signature is invalid");
    }

    [Test]
    public async Task ATamperedBodyOrSignature_FailsToVerify()
    {
        var blob = Fixture("user_ed25519-cert.pub").Blob.ToArray();

        // The key id "deploy-ci" is in the signed body; the signature's last byte is the end of the blob.
        var body = (byte[])blob.Clone();
        var keyId = body.AsSpan().IndexOf("deploy-ci"u8);
        body[keyId] ^= 0x20;
        await Assert.That(SshCertificate.FromBlob(body).VerifySignature()).IsFalse();
        await Assert.That(SshCertificate.FromBlob(body).KeyId).IsEqualTo("Deploy-ci");

        var signature = (byte[])blob.Clone();
        signature[^1] ^= 1;
        await Assert.That(SshCertificate.FromBlob(signature).VerifySignature()).IsFalse();

        await Assert.That(SshCertificate.FromBlob(blob).VerifySignature()).IsTrue();
    }

    [Test]
    public async Task ASignatureFromAnotherKey_OrInAnotherAlgorithm_FailsToVerify()
    {
        // Swap the authority key for another one: the signature no longer matches the key it names.
        var original = Fixture("user_ed25519-cert.pub");
        var other = Authority("other_ca.pub").Blob.ToArray();
        var blob = original.Blob.ToArray();
        var authority = blob.AsSpan().IndexOf(original.AuthorityKey.Span);
        other.CopyTo(blob, authority); // the same length: both are Ed25519 keys
        await Assert.That(SshCertificate.FromBlob(blob).VerifySignature()).IsFalse();

        // The signature's algorithm name must be one the authority's key type signs with.
        var renamed = Fixture("host_ecdsa-cert.pub").Blob.ToArray();
        var name = renamed.AsSpan().LastIndexOf("rsa-sha2-512"u8);
        "rsa-sha2-256"u8.CopyTo(renamed.AsSpan(name));
        await Assert.That(SshCertificate.FromBlob(renamed).VerifySignature()).IsFalse();
    }

    [Test]
    public async Task IsValidAt_IsValidAfterInclusive_ValidBeforeExclusive()
    {
        var certificate = Fixture("user_ed25519-cert.pub");
        var start = certificate.ValidAfter;
        var end = certificate.ValidBefore;
        await Assert.That(certificate.IsValidAt(start)).IsTrue();
        await Assert.That(certificate.IsValidAt(start.AddSeconds(-1))).IsFalse();
        await Assert.That(certificate.IsValidAt(end.AddSeconds(-1))).IsTrue();
        await Assert.That(certificate.IsValidAt(end)).IsFalse();
        await Assert.That(certificate.IsValidAt(end.AddMilliseconds(-1))).IsTrue(); // whole seconds, as OpenSSH
        await Assert.That(certificate.IsValidAt(DateTimeOffset.MinValue)).IsFalse();

        var expired = Fixture("user_rsa-cert.pub");
        await Assert.That(expired.IsValidAt(InWindow)).IsFalse();
        await Assert.That(expired.IsValidAt(new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero))).IsTrue();
    }

    [Test]
    public async Task IsValidFor_UserCertificates()
    {
        var certificate = Fixture("user_ed25519-cert.pub");
        var ca = Authority("ca_ed25519.pub");

        // It carries force-command and source-address, which this check cannot enforce: refused, with the reason.
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.User, "deploy", InWindow, out var reason)).IsFalse();
        await Assert.That(reason).Contains("critical options").And.Contains("force-command");

        var plain = Fixture("user_rsa-cert.pub");
        var expiredAt = new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var rsaCa = Authority("ca_ecdsa.pub");
        await Assert.That(plain.IsValidFor(rsaCa, SshCertificateType.User, "deploy", expiredAt, out reason)).IsTrue();
        await Assert.That(reason).IsNull();

        await Assert.That(plain.IsValidFor(rsaCa, SshCertificateType.User, "deploy", InWindow, out reason)).IsFalse();
        await Assert.That(reason).Contains("valid only from 2020-01-01");
        await Assert.That(plain.IsValidFor(rsaCa, SshCertificateType.User, "Deploy", expiredAt, out reason)).IsFalse(); // user names are exact
        await Assert.That(reason).IsEqualTo("it is not issued for Deploy");
        await Assert.That(plain.IsValidFor(rsaCa, SshCertificateType.User, "deplo*", expiredAt, out _)).IsFalse();
        await Assert.That(plain.IsValidFor(rsaCa, SshCertificateType.Host, "deploy", expiredAt, out reason)).IsFalse();
        await Assert.That(reason).Contains("user certificate, not a host certificate");
        await Assert.That(plain.IsValidFor(ca, SshCertificateType.User, "deploy", expiredAt, out reason)).IsFalse();
        await Assert.That(reason).Contains("another authority").And.Contains(plain.AuthorityFingerprint);
    }

    [Test]
    public async Task IsValidFor_HostCertificates()
    {
        var certificate = Fixture("host_ecdsa-cert.pub");
        var ca = Authority("ca_rsa.pub");
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.Host, "web1.example.com", InWindow, out _)).IsTrue();
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.Host, "WEB2.Example.COM", InWindow, out _)).IsTrue(); // *.example.com
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.Host, "example.org", InWindow, out var reason)).IsFalse();
        await Assert.That(reason).IsEqualTo("it is not issued for example.org");
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.User, "web1.example.com", InWindow, out reason)).IsFalse();
        await Assert.That(reason).Contains("host certificate, not a user certificate");
        await Assert.That(certificate.IsValidFor(ca, SshCertificateType.Host, "web1.example.com", new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), out reason))
            .IsFalse();
        await Assert.That(reason).Contains("valid only");
    }

    [Test]
    public async Task IsValidFor_RefusesACertificateWithoutPrincipals()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var subject = SshPrivateKey.Generate(SshKeyType.Ed25519);
        foreach (var type in new[] { SshCertificateType.User, SshCertificateType.Host })
        {
            var certificate = SshCertificate.FromBlob(TestKeys.Certificate(ca, subject.PublicKey.ToArray(), type, principals: []));
            await Assert.That(certificate.VerifySignature()).IsTrue();
            await Assert.That(certificate.IsValidFor(ca.GetPublicKey(), type, "anyone", DateTimeOffset.UtcNow, out var reason)).IsFalse();
            await Assert.That(reason).IsEqualTo(type == SshCertificateType.User
                ? "it lists no principals, so it is no user's"
                : "it lists no principals, so it is no host's");
        }
    }

    [Test]
    public async Task AnOptionListedTwice_IsMalformed()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var subject = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var blob = TestKeys.Certificate(ca, subject.PublicKey.ToArray(), SshCertificateType.User, ["deploy"],
            criticalOptions: [("force-command", "a"), ("force-command", "b")]);
        await Assert.That(() => SshCertificate.FromBlob(blob)).Throws<SshProtocolException>().WithMessageContaining("'force-command' appears twice");
    }

    [Test]
    public async Task IsValidFor_ChecksItsArguments()
    {
        var certificate = Fixture("host_ecdsa-cert.pub");
        await Assert.That(() => certificate.IsValidFor(null!, SshCertificateType.Host, "h", InWindow, out _)).Throws<ArgumentNullException>();
        await Assert.That(() => certificate.IsValidFor(Authority("ca_rsa.pub"), SshCertificateType.Host, null!, InWindow, out _))
            .Throws<ArgumentNullException>();
    }

    [Test]
    public async Task AnAuthorityKeyThatCannotVerify_GivesFalse()
    {
        // Replace the authority key with a FIDO security key, which SshSharp does not verify: false, not an exception.
        using var subject = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var skKey = TestKeys.Blob(w =>
        {
            w.WriteString("sk-ssh-ed25519@openssh.com");
            w.WriteString(new byte[32]);
            w.WriteString("ssh:");
        });
        var body = TestKeys.Blob(w =>
        {
            var reader = new SshReader(subject.PublicKey.Span);
            reader.ReadUtf8String();
            w.WriteString("ssh-ed25519-cert-v01@openssh.com");
            w.WriteString(new byte[32]);
            w.WriteBytes(reader.Remaining);
            w.WriteUInt64(1);
            w.WriteUInt32(1);
            w.WriteString("id");
            w.WriteString(TestKeys.Blob(p => p.WriteString("deploy")));
            w.WriteUInt64(0);
            w.WriteUInt64(ulong.MaxValue);
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteString(skKey);
            w.WriteString(TestKeys.Blob(s => { s.WriteString("sk-ssh-ed25519@openssh.com"); s.WriteString(new byte[64]); }));
        });
        await Assert.That(SshCertificate.FromBlob(body).VerifySignature()).IsFalse();
    }
}
