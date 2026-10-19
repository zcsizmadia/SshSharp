using System.Text;

namespace SshSharp.Tests.Keys;

/// <summary>
/// The public KRL reader: user keys and certificates checked against a KRL that the real <c>ssh-keygen -k</c> wrote
/// (Fixtures/certificates/users.krl, see make-krl.sh there, whose verdicts <c>ssh-keygen -Q</c> confirmed), and against text key lists.
/// </summary>
public sealed class SshKeyRevocationListTests
{
    private static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", "certificates", name);

    private static SshCertificate Certificate(string name) => SshCertificate.Parse(File.ReadAllText(FixturePath(name)));

    private static SshPublicKey Key(string name) => SshPublicKey.Parse(File.ReadAllText(FixturePath(name)));

    private static SshKeyRevocationList Krl() => SshKeyRevocationList.Parse(File.ReadAllBytes(FixturePath("users.krl")));

    [Test]
    [Arguments("revoked_serial-cert.pub", true)] // serial 1001, in the KRL's range 1000-1005 for krl_ca
    [Arguments("revoked_id-cert.pub", true)]     // key id revoked-id
    [Arguments("revoked_key-cert.pub", true)]    // its certified key is revoked explicitly
    [Arguments("not_revoked-cert.pub", false)]
    [Arguments("user_ed25519-cert.pub", false)]  // serial 1001 too, but from another authority
    public async Task Certificates_AreCheckedAsSshKeygenChecksThem(string certificate, bool revoked)
    {
        var krl = Krl();
        await Assert.That(krl.IsKrl).IsTrue();
        await Assert.That(krl.IsRevoked(Certificate(certificate))).IsEqualTo(revoked);
    }

    [Test]
    public async Task PlainKeys_AreRevokedExplicitly_OrByFingerprint()
    {
        var krl = Krl();
        await Assert.That(krl.IsRevoked(Key("revoked_key.pub"))).IsTrue();
        await Assert.That(krl.IsRevoked(Key("revoked_hash.pub"))).IsTrue(); // by its SHA-256 fingerprint
        await Assert.That(krl.IsRevoked(Key("krl_ca.pub"))).IsFalse();

        // A revoked serial or key id revokes the certificate, not the key it certifies.
        await Assert.That(krl.IsRevoked(Certificate("revoked_serial-cert.pub").GetPublicKey())).IsFalse();
        await Assert.That(krl.IsRevoked(Certificate("revoked_id-cert.pub").GetPublicKey())).IsFalse();
        await Assert.That(krl.IsRevoked(Certificate("revoked_key-cert.pub").GetPublicKey())).IsTrue();
    }

    [Test]
    public async Task LoadAsync_ReadsTheFile_AsParseReadsItsBytes()
    {
        var krl = await SshKeyRevocationList.LoadAsync(FixturePath("users.krl"));
        await Assert.That(krl.IsKrl).IsTrue();
        await Assert.That(krl.IsRevoked(Certificate("revoked_id-cert.pub"))).IsTrue();
        await Assert.That(krl.IsRevoked(Certificate("not_revoked-cert.pub"))).IsFalse();

        await Assert.That(async () => await SshKeyRevocationList.LoadAsync(FixturePath("missing.krl"))).Throws<FileNotFoundException>();
        await Assert.That(async () => await SshKeyRevocationList.LoadAsync(" ")).Throws<ArgumentException>();
    }

    [Test]
    public async Task AKeyList_RevokesKeys_TheKeysOfCertificatesInIt_AndCertificatesFromARevokedAuthority()
    {
        // As sshd's RevokedKeys reads a text file: one key per line; comments and lines that do not parse are skipped.
        var text = $"""
            # revoked user keys
            {File.ReadAllText(FixturePath("revoked_hash.pub")).Trim()}
            not a key line

            {File.ReadAllText(FixturePath("revoked_id-cert.pub")).Trim()}
            """;
        var list = SshKeyRevocationList.Parse(Encoding.UTF8.GetBytes(text));
        await Assert.That(list.IsKrl).IsFalse();
        await Assert.That(list.IsRevoked(Key("revoked_hash.pub"))).IsTrue();
        await Assert.That(list.IsRevoked(Key("revoked_key.pub"))).IsFalse();

        // The certificate line revokes the key it certifies, and so every certificate for that key.
        await Assert.That(list.IsRevoked(Certificate("revoked_id-cert.pub").GetPublicKey())).IsTrue();
        await Assert.That(list.IsRevoked(Certificate("revoked_id-cert.pub"))).IsTrue();
        await Assert.That(list.IsRevoked(Certificate("not_revoked-cert.pub"))).IsFalse();

        // Revoking the authority's key revokes every certificate it issued.
        var authority = SshKeyRevocationList.Parse(File.ReadAllBytes(FixturePath("krl_ca.pub")));
        await Assert.That(authority.IsRevoked(Certificate("not_revoked-cert.pub"))).IsTrue();
        await Assert.That(authority.IsRevoked(Certificate("user_ed25519-cert.pub"))).IsFalse();

        await Assert.That(SshKeyRevocationList.Parse([]).IsRevoked(Key("revoked_key.pub"))).IsFalse();
    }

    [Test]
    public async Task AMalformedKrl_IsRefused_RatherThanReadInPart()
    {
        var krl = File.ReadAllBytes(FixturePath("users.krl"));
        await Assert.That(() => SshKeyRevocationList.Parse(krl.AsSpan(0, krl.Length - 1))).Throws<FormatException>();

        // A section type this library does not know: a KRL could revoke keys in it.
        byte[] unknownSection = [.. krl, 9, 0, 0, 0, 0];
        await Assert.That(() => SshKeyRevocationList.Parse(unknownSection)).Throws<FormatException>().WithMessageContaining("section type 9");

        var krlList = Krl();
        await Assert.That(() => krlList.IsRevoked((SshPublicKey)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => krlList.IsRevoked((SshCertificate)null!)).Throws<ArgumentNullException>();
    }
}
