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
    public async Task AKeyList_RevokesTheSecurityKeys_ItsFidoCertificatesCertify()
    {
        // ssh-keygen signed these sk certificates (make-sk.sh); a text RevokedKeys list of them revokes both security keys, as in sshd.
        var text = File.ReadAllText(FixturePath("sk_ed25519-cert.pub")) + File.ReadAllText(FixturePath("sk_ecdsa-cert.pub"));
        var list = SshKeyRevocationList.Parse(Encoding.UTF8.GetBytes(text));
        await Assert.That(list.IsRevoked(Key("sk_ed25519.pub"))).IsTrue();
        await Assert.That(list.IsRevoked(Key("sk_ecdsa.pub"))).IsTrue();
        await Assert.That(list.IsRevoked(Key("revoked_key.pub"))).IsFalse();

        // Only the line for one key revokes only that key.
        var one = SshKeyRevocationList.Parse(File.ReadAllBytes(FixturePath("sk_ecdsa-cert.pub")));
        await Assert.That(one.IsRevoked(Key("sk_ecdsa.pub"))).IsTrue();
        await Assert.That(one.IsRevoked(Key("sk_ed25519.pub"))).IsFalse();
    }

    [Test]
    [Arguments("sk_ed25519-cert.pub")]
    [Arguments("sk_ecdsa-cert.pub")]
    [Arguments("revoked_id-cert.pub")]
    public async Task AKeyList_WithACertificateLineThatCannotBeRead_IsRefused_RatherThanSkipped(string certificate)
    {
        // Skipping the line would leave the key it revokes accepted.
        var fields = File.ReadAllText(FixturePath(certificate)).Split(' ');
        var blob = Convert.FromBase64String(fields[1]);
        foreach (var bad in new[] { blob[..^1], [.. blob, 0] })
        {
            var line = $"{fields[0]} {Convert.ToBase64String(bad)}\n{File.ReadAllText(FixturePath("revoked_hash.pub"))}";
            await Assert.That(() => SshKeyRevocationList.Parse(Encoding.UTF8.GetBytes(line))).Throws<FormatException>();
        }
    }

    [Test]
    public async Task AFidoCertificate_RevokesExactlyItsKey_AndOnlyAWellFormedOne()
    {
        // An sk-ssh-ed25519 certificate laid out as PROTOCOL.certkeys does, around a chosen key and application.
        static byte[] Certificate(byte[] key, string application) => SshPrivateKey.Encode(w =>
        {
            w.WriteString("sk-ssh-ed25519-cert-v01@openssh.com");
            w.WriteString(new byte[32]); // nonce
            w.WriteString(key);
            w.WriteString(application);
            w.WriteUInt64(7); // serial
            w.WriteUInt32(1); // user
            w.WriteString("id");
            w.WriteString(SshPrivateKey.Encode(p => p.WriteString("deploy")));
            w.WriteUInt64(0);
            w.WriteUInt64(ulong.MaxValue);
            w.WriteString([]); // critical options
            w.WriteString([]); // extensions
            w.WriteString([]); // reserved
            w.WriteString(SshPrivateKey.Encode(p => { p.WriteString("ssh-ed25519"); p.WriteString(new byte[32]); }));
            w.WriteString(SshPrivateKey.Encode(p => { p.WriteString("ssh-ed25519"); p.WriteString(new byte[64]); }));
        });
        static byte[] List(byte[] certificate) =>
            Encoding.UTF8.GetBytes($"sk-ssh-ed25519-cert-v01@openssh.com {Convert.ToBase64String(certificate)}\n");
        static SshPublicKey Key(byte[] key, string application) => SshPublicKey.FromBlob(SshPrivateKey.Encode(w =>
        {
            w.WriteString("sk-ssh-ed25519@openssh.com");
            w.WriteString(key);
            w.WriteString(application);
        }));

        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var list = SshKeyRevocationList.Parse(List(Certificate(key, "ssh:")));
        await Assert.That(list.IsRevoked(Key(key, "ssh:"))).IsTrue();
        await Assert.That(list.IsRevoked(Key(key, "ssh:other"))).IsFalse(); // the application is part of the key
        await Assert.That(list.IsRevoked(Key([.. key[..^1], 0], "ssh:"))).IsFalse();

        // An Ed25519 key that is not 32 bytes is no key: the list is refused rather than read without it.
        await Assert.That(() => SshKeyRevocationList.Parse(List(Certificate(key[..^1], "ssh:")))).Throws<FormatException>();
    }

    [Test]
    public async Task AKeyList_WithACertificateOfATypeThisLibraryDoesNotKnow_IsRefused()
    {
        const string Type = "ssh-future-cert-v01@openssh.com";
        var type = Encoding.ASCII.GetBytes(Type);
        byte[] blob = [0, 0, 0, (byte)type.Length, .. type, 0, 0, 0, 1, 7];
        var line = $"{Type} {Convert.ToBase64String(blob)} future\n";
        await Assert.That(() => SshKeyRevocationList.Parse(Encoding.UTF8.GetBytes(line))).Throws<FormatException>();
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
