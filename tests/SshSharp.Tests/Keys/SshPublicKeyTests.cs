using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>
/// The public <see cref="SshPublicKey"/>: parsing lines and blobs, fingerprints against what OpenSSH's ssh-keygen printed for the keys in
/// fixtures/hostkeys_openssh.txt, equality, signature verification, hostile input, and the accessors on the types that hold key blobs.
/// </summary>
public class SshPublicKeyTests
{
    private static readonly byte[] Message = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "hostkey_message.txt"));

    public static IEnumerable<string> KeyNames() => ["ed25519", "rsa", "ecdsa256", "ecdsa384", "ecdsa521"];

    public static IEnumerable<Func<(SshKeyType Type, int Bits)>> Types()
    {
        yield return () => (SshKeyType.Ed25519, 0);
        yield return () => (SshKeyType.EcdsaNistp256, 0);
        yield return () => (SshKeyType.EcdsaNistp384, 0);
        yield return () => (SshKeyType.EcdsaNistp521, 0);
        yield return () => (SshKeyType.Rsa, 2048);
    }

    // What `ssh-keygen -l -E md5 -f` printed for each fixture key.
    private static string Md5Fingerprint(string name) => name switch
    {
        "ed25519" => "MD5:ae:e4:1d:af:48:a7:35:9e:08:9c:54:7c:e2:5e:22:4a",
        "rsa" => "MD5:de:d8:4a:f7:c1:78:80:36:16:b0:75:f5:3c:7a:3e:01",
        "ecdsa256" => "MD5:1e:8c:4e:e1:f2:5c:37:2a:46:18:a6:9e:b2:a4:d9:0a",
        "ecdsa384" => "MD5:f9:90:7f:15:d7:b0:eb:e7:6b:fa:a1:5f:0e:41:3c:bd",
        _ => "MD5:64:16:81:7b:55:e4:36:a0:b2:0a:35:43:55:90:98:a9",
    };

    private sealed record Fixture(string Pub, string Fingerprint, string Armor);

    private static Fixture Load(string name)
    {
        var lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "hostkeys_openssh.txt"));
        var start = Array.IndexOf(lines, $"[{name}]");
        var armor = new StringBuilder();
        for (var i = start + 4; lines[i] != ">>"; i++)
        {
            armor.Append(lines[i]);
        }

        return new Fixture(lines[start + 1]["pub=".Length..], lines[start + 2]["fp=".Length..], armor.ToString());
    }

    // The SSHSIG fixture: the signature blob and the data it signs (PROTOCOL.sshsig).
    private static (byte[] Signature, byte[] SignedData) SshSig(Fixture fixture)
    {
        var body = fixture.Armor.Replace("-----BEGIN SSH SIGNATURE-----", string.Empty).Replace("-----END SSH SIGNATURE-----", string.Empty);
        var reader = new SshReader(Convert.FromBase64String(body));
        reader.ReadBytes(6);
        reader.ReadUInt32();
        reader.ReadString();
        var ns = reader.ReadUtf8String();
        reader.ReadString();
        var hash = reader.ReadUtf8String();
        var signature = reader.ReadString().ToArray();

        var buffer = new ArrayBufferWriter<byte>();
        buffer.Write("SSHSIG"u8);
        var writer = new SshWriter(buffer);
        writer.WriteString(ns);
        writer.WriteString(string.Empty);
        writer.WriteString(hash);
        writer.WriteString(hash == "sha512" ? SHA512.HashData(Message) : SHA256.HashData(Message));
        return (signature, buffer.WrittenSpan.ToArray());
    }

    private static byte[] Blob(Action<SshWriter> write) => TestKeys.Blob(write);

    private static string Line(byte[] blob, string? comment = null) =>
        $"{new SshReader(blob).ReadUtf8String()} {Convert.ToBase64String(blob)}{(comment is null ? string.Empty : " " + comment)}";

    private static SshPrivateKey Generate(SshKeyType type, int bits) => SshPrivateKey.Generate(type, "user@example.com", bits == 0 ? 3072 : bits);

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task Parse_ReadsWhatSshKeygenWrote_AndMatchesItsFingerprints(string name)
    {
        var fixture = Load(name);
        var key = SshPublicKey.Parse(fixture.Pub);

        await Assert.That(key.KeyType).IsEqualTo(fixture.Pub.Split(' ')[0]);
        await Assert.That(key.KeySizeBits).IsEqualTo(name switch { "ed25519" => 256, "rsa" => 2048, "ecdsa256" => 256, "ecdsa384" => 384, _ => 521 });
        await Assert.That(key.Comment).IsNull();
        await Assert.That(Convert.ToBase64String(key.Blob.Span)).IsEqualTo(fixture.Pub.Split(' ')[1]);
        await Assert.That(key.Fingerprint).IsEqualTo(fixture.Fingerprint);
        await Assert.That(key.GetFingerprint(HashAlgorithmName.SHA256)).IsEqualTo(fixture.Fingerprint);
        await Assert.That(key.GetFingerprint(HashAlgorithmName.MD5)).IsEqualTo(Md5Fingerprint(name));
        await Assert.That(key.ToAuthorizedKeysLine()).IsEqualTo(fixture.Pub);
        await Assert.That(key.ToString()).IsEqualTo(fixture.Pub);
    }

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task ALine_RoundTripsWithItsComment_AndTheBlobReadsTheSame(string name)
    {
        var fixture = Load(name);
        var line = fixture.Pub + " deploy@example.com  key 1";
        var key = SshPublicKey.Parse(line);
        await Assert.That(key.Comment).IsEqualTo("deploy@example.com  key 1");
        await Assert.That(key.ToAuthorizedKeysLine()).IsEqualTo(line);
        await Assert.That(SshPublicKey.Parse(key.ToAuthorizedKeysLine()).Comment).IsEqualTo(key.Comment);

        var fromBlob = SshPublicKey.FromBlob(key.Blob.ToArray());
        await Assert.That(fromBlob).IsEqualTo(key);
        await Assert.That(fromBlob.Comment).IsNull();
        await Assert.That(SshPublicKey.FromBlob(key.Blob, "other").Comment).IsEqualTo("other");
        await Assert.That(SshPublicKey.FromBlob(key.Blob, string.Empty).Comment).IsNull();
        await Assert.That(SshPublicKey.TryParse(line, out var parsed)).IsTrue();
        await Assert.That(parsed).IsEqualTo(key);
    }

    [Test]
    public async Task Parse_TakesTheWhiteSpaceOpenSshDoes()
    {
        var fixture = Load("ed25519");
        var fields = fixture.Pub.Split(' ');
        var key = SshPublicKey.Parse($"  \t{fields[0]}\t \t{fields[1]} \t comment \r\n");
        await Assert.That(key.Fingerprint).IsEqualTo(fixture.Fingerprint);
        await Assert.That(key.Comment).IsEqualTo("comment");
        await Assert.That(SshPublicKey.Parse(fixture.Pub + "\n").Comment).IsNull();
        await Assert.That(SshPublicKey.Parse(fixture.Pub + "   ").Comment).IsNull();
    }

    [Test]
    [MethodDataSource(nameof(Types))]
    public async Task GeneratedKeys_RoundTrip_AndVerifyTheirSignatures(SshKeyType type, int bits)
    {
        using var privateKey = Generate(type, bits);
        var key = privateKey.GetPublicKey();

        await Assert.That(key.KeyType).IsEqualTo(privateKey.KeyType);
        await Assert.That(key.Comment).IsEqualTo("user@example.com");
        await Assert.That(key.Blob.ToArray().SequenceEqual(privateKey.PublicKey.ToArray())).IsTrue();
        await Assert.That(key.Fingerprint).IsEqualTo(privateKey.Fingerprint);
        await Assert.That(key.ToAuthorizedKeysLine()).IsEqualTo(privateKey.ToAuthorizedKeysLine());
        await Assert.That(SshPublicKey.Parse(privateKey.ToAuthorizedKeysLine())).IsEqualTo(key);
        await Assert.That(privateKey.GetPublicKey()).IsSameReferenceAs(key);

        var data = "data to sign"u8.ToArray();
        foreach (var algorithm in privateKey.SignatureAlgorithms)
        {
            var signature = privateKey.Sign(algorithm, data);
            await Assert.That(key.VerifySignature(data, signature)).IsTrue();
            await Assert.That(key.VerifySignature([.. data, 0], signature)).IsFalse();
            await Assert.That(key.VerifySignature(data, signature.AsSpan(0, signature.Length - 1))).IsFalse();
            await Assert.That(key.VerifySignature(data, [.. signature, 0])).IsFalse();
            var flipped = (byte[])signature.Clone();
            flipped[^1] ^= 1;
            await Assert.That(key.VerifySignature(data, flipped)).IsFalse();
        }
    }

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task VerifySignature_AcceptsTheSignatureOpenSshMade_AndNoOtherKeys(string name)
    {
        var fixture = Load(name);
        var (signature, signed) = SshSig(fixture);
        await Assert.That(SshPublicKey.Parse(fixture.Pub).VerifySignature(signed, signature)).IsTrue();

        foreach (var other in KeyNames().Where(n => n != name))
        {
            await Assert.That(SshPublicKey.Parse(Load(other).Pub).VerifySignature(signed, signature)).IsFalse();
        }
    }

    [Test]
    public async Task VerifySignature_RefusesMalformedSignatures_AndRsaSha1()
    {
        var fixture = Load("rsa");
        var key = SshPublicKey.Parse(fixture.Pub);
        var (signature, signed) = SshSig(fixture);
        var (algorithm, raw) = Split(signature);
        await Assert.That(algorithm).IsEqualTo("rsa-sha2-512");

        // The same RSA signature bytes under another algorithm name: SHA-256 does not verify, and SHA-1 ssh-rsa is never accepted.
        await Assert.That(key.VerifySignature(signed, Blob(w => { w.WriteString("rsa-sha2-256"); w.WriteString(raw); }))).IsFalse();
        await Assert.That(key.VerifySignature(signed, Blob(w => { w.WriteString("ssh-rsa"); w.WriteString(raw); }))).IsFalse();
        await Assert.That(key.VerifySignature(signed, [])).IsFalse();
        await Assert.That(key.VerifySignature(signed, [0, 0, 0, 9, 1])).IsFalse();
        await Assert.That(key.VerifySignature(signed, Blob(w => w.WriteString([0xff, 0xfe])))).IsFalse();
    }

    private static (string Algorithm, byte[] Raw) Split(byte[] signature)
    {
        var reader = new SshReader(signature);
        return (reader.ReadUtf8String(), reader.ReadString().ToArray());
    }

    [Test]
    public async Task Equality_IsByKeyBytes_AndIgnoresTheComment()
    {
        var ed = Load("ed25519").Pub;
        var a = SshPublicKey.Parse(ed + " one");
        var b = SshPublicKey.Parse(ed + " two");
        var other = SshPublicKey.Parse(Load("ecdsa256").Pub);

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a == b).IsTrue();
        await Assert.That(a != b).IsFalse();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
        await Assert.That(a.Equals((object)b)).IsTrue();
        await Assert.That(a.Equals(other)).IsFalse();
        await Assert.That(a == other).IsFalse();
        await Assert.That(a != other).IsTrue();
        await Assert.That(a.Equals((object)ed)).IsFalse();
        await Assert.That(new HashSet<SshPublicKey> { a, b, other }.Count).IsEqualTo(2);
        await Assert.That(a.Equals(null)).IsFalse();
        await Assert.That(a == null).IsFalse();
        await Assert.That(null == b).IsFalse();
        await Assert.That((SshPublicKey?)null == null).IsTrue();
    }

    [Test]
    public async Task GetFingerprint_RefusesOtherHashes()
    {
        var key = SshPublicKey.Parse(Load("ed25519").Pub);
        await Assert.That(() => key.GetFingerprint(HashAlgorithmName.SHA1)).ThrowsExactly<ArgumentException>();
        await Assert.That(() => key.GetFingerprint(HashAlgorithmName.SHA512)).ThrowsExactly<ArgumentException>();
        await Assert.That(() => key.GetFingerprint(default)).ThrowsExactly<ArgumentException>();
    }

    public static IEnumerable<Func<string>> MalformedLines()
    {
        var ed = Load("ed25519").Pub;
        var fields = ed.Split(' ');
        var blob = Convert.FromBase64String(fields[1]);
        yield return () => string.Empty;
        yield return () => "   \t ";
        yield return () => "ssh-ed25519";
        yield return () => "ssh-ed25519 ";
        yield return () => "ssh-ed25519 !!!!";
        yield return () => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5";                               // valid base64, truncated blob
        yield return () => $"ssh-ed25519 {Convert.ToBase64String(blob[..^1])}";            // one byte short
        yield return () => $"ssh-ed25519 {Convert.ToBase64String([.. blob, 0])}";           // trailing data
        yield return () => $"ssh-rsa {fields[1]}";                                         // type field does not match the blob
        yield return () => $"ecdsa-sha2-nistp256 {fields[1]}";
        yield return () => $"ssh-dss {fields[1]}";                                         // unsupported type
        yield return () => $"restrict,command=\"uptime\" {ed}";                            // authorized_keys options
        yield return () => $"from=\"192.0.2.0/24\" {ed}";
        yield return () => $"{ed} one\n{ed} two";                                          // two lines
        yield return () => $"{ed} comment\rinjected";
        yield return () => $"ssh-ed25519-cert-v01@openssh.com {fields[1]}";                // a certificate
        yield return () => $"ssh-rsa {Convert.ToBase64String(new byte[SshPublicKey.MaxBlobLength + 1])}"; // oversized
        yield return () => $"ssh-ed25519 {fields[1][..^1]}";                               // broken padding
    }

    [Test]
    [MethodDataSource(nameof(MalformedLines))]
    public async Task Parse_RefusesMalformedLines_WithAFormatException(string line)
    {
        await Assert.That(() => SshPublicKey.Parse(line)).ThrowsExactly<FormatException>();
        await Assert.That(SshPublicKey.TryParse(line, out var key)).IsFalse();
        await Assert.That(key).IsNull();
    }

    [Test]
    public async Task Parse_RefusesNull()
    {
        await Assert.That(() => SshPublicKey.Parse(null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(SshPublicKey.TryParse(null, out var key)).IsFalse();
        await Assert.That(key).IsNull();
    }

    [Test]
    public async Task Parse_SaysWhatIsWrong_WithoutEchoingTheLine()
    {
        var ed = Load("ed25519").Pub;
        var options = await Assert.That(() => SshPublicKey.Parse($"command=\"secret-token\" {ed}")).ThrowsExactly<FormatException>();
        await Assert.That(options!.Message).Contains("options");
        await Assert.That(options.Message).DoesNotContain("secret-token");
        var certificate = await Assert.That(() => SshPublicKey.Parse($"ssh-ed25519-cert-v01@openssh.com {ed.Split(' ')[1]}")).ThrowsExactly<FormatException>();
        await Assert.That(certificate!.Message).Contains("SshCertificate.Parse");
    }

    public static IEnumerable<Func<byte[]>> MalformedBlobs()
    {
        var ed = Convert.FromBase64String(Load("ed25519").Pub.Split(' ')[1]);
        var ec = Convert.FromBase64String(Load("ecdsa256").Pub.Split(' ')[1]);
        yield return () => [];
        yield return () => [0, 0, 0];
        yield return () => [0, 0, 0, 200, 1];
        yield return () => ed[..^1];
        yield return () => [.. ed, 1];
        yield return () => Blob(w => w.WriteString("ssh-ed25519"));
        yield return () => Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(new byte[31]); });
        yield return () => Blob(w => { w.WriteString("ssh-dss"); w.WriteString(new byte[32]); });
        yield return () => Blob(w => { w.WriteString("ssh-ed25519-cert-v01@openssh.com"); w.WriteString(new byte[32]); });
        yield return () => Blob(w => { w.WriteString([0xff, 0xfe]); });
        yield return () => [.. ec[..^1], (byte)(ec[^1] ^ 1)];                              // off the curve
        yield return () => Blob(w => { w.WriteString("ecdsa-sha2-nistp256"); w.WriteString("nistp384"); w.WriteString(new byte[65]); });
        yield return () => Blob(w => { w.WriteString("ssh-rsa"); w.WriteString(new byte[SshPublicKey.MaxBlobLength]); });
    }

    [Test]
    [MethodDataSource(nameof(MalformedBlobs))]
    public async Task FromBlob_RefusesMalformedBlobs_WithAFormatException(byte[] blob)
    {
        await Assert.That(() => SshPublicKey.FromBlob(blob)).ThrowsExactly<FormatException>();
        await Assert.That(() => SshPublicKey.Parse($"ssh-ed25519 {Convert.ToBase64String(blob)}")).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task FromBlob_RefusesACommentThatWouldAddALine()
    {
        var blob = Convert.FromBase64String(Load("ed25519").Pub.Split(' ')[1]);
        await Assert.That(() => SshPublicKey.FromBlob(blob, "a\nssh-ed25519 AAAA")).ThrowsExactly<ArgumentException>();
        await Assert.That(() => SshPublicKey.FromBlob(blob, "a\r")).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task SecurityKeys_Parse_ButTheirSignaturesAreNotVerified()
    {
        var edPoint = RandomNumberGenerator.GetBytes(32);
        var skEd = Blob(w => { w.WriteString("sk-ssh-ed25519@openssh.com"); w.WriteString(edPoint); w.WriteString("ssh:"); });
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = ecdsa.ExportParameters(false).Q;
        byte[] point = [4, .. q.X!, .. q.Y!];
        var skEc = Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256@openssh.com"); w.WriteString("nistp256"); w.WriteString(point); w.WriteString("ssh:"); });

        foreach (var blob in new[] { skEd, skEc })
        {
            var line = Line(blob, "yubikey@example.com");
            var key = SshPublicKey.Parse(line);
            await Assert.That(key.KeyType).IsEqualTo(new SshReader(blob).ReadUtf8String());
            await Assert.That(key.KeySizeBits).IsEqualTo(256);
            await Assert.That(key.Fingerprint).IsEqualTo("SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='));
            await Assert.That(key.ToAuthorizedKeysLine()).IsEqualTo(line);
            await Assert.That(SshPublicKey.FromBlob(blob)).IsEqualTo(key);
            await Assert.That(() => key.VerifySignature(blob, blob)).ThrowsExactly<NotSupportedException>();
        }

        byte[] offCurve = [.. point[..^1], (byte)(point[^1] ^ 1)];
        byte[][] malformed =
        [
            Blob(w => { w.WriteString("sk-ssh-ed25519@openssh.com"); w.WriteString(edPoint); }),
            Blob(w => { w.WriteString("sk-ssh-ed25519@openssh.com"); w.WriteString(edPoint.AsSpan(0, 31)); w.WriteString("ssh:"); }),
            [.. skEd, 0],
            Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256@openssh.com"); w.WriteString("nistp256"); w.WriteString(offCurve); w.WriteString("ssh:"); }),
            Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256@openssh.com"); w.WriteString("nistp384"); w.WriteString(point); w.WriteString("ssh:"); }),
            Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256@openssh.com"); w.WriteString("nistp256"); w.WriteString(point.AsSpan(0, point.Length - 1)); w.WriteString("ssh:"); }),
        ];
        foreach (var blob in malformed)
        {
            await Assert.That(() => SshPublicKey.FromBlob(blob)).ThrowsExactly<FormatException>();
        }
    }

    [Test]
    public async Task ACertifiedPrivateKey_GivesTheCertifiedKey_AndTheCertificateBothKeys()
    {
        using var authority = Generate(SshKeyType.Ed25519, 0);
        using var key = Generate(SshKeyType.EcdsaNistp256, 0);
        var certificate = SshCertificate.Parse(TestKeys.CertificateLine(TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User)));
        using var certified = key.WithCertificate(certificate);

        await Assert.That(certified.KeyType).IsEqualTo("ecdsa-sha2-nistp256-cert-v01@openssh.com");
        await Assert.That(certified.GetPublicKey()).IsEqualTo(key.GetPublicKey());
        await Assert.That(certified.GetPublicKey().KeyType).IsEqualTo("ecdsa-sha2-nistp256");
        await Assert.That(certificate.GetPublicKey()).IsEqualTo(key.GetPublicKey());
        await Assert.That(certificate.GetPublicKey().Fingerprint).IsEqualTo(certificate.Fingerprint);
        await Assert.That(certificate.GetAuthorityKey()).IsEqualTo(authority.GetPublicKey());
        await Assert.That(certificate.GetAuthorityKey().Fingerprint).IsEqualTo(certificate.AuthorityFingerprint);
    }

    [Test]
    public async Task AnOpenSshPrivateKeysCommentWithALineBreak_IsLeftOut()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob, comment: "a\nb"));
        await Assert.That(key.GetPublicKey().Comment).IsNull();
        await Assert.That(key.GetPublicKey().Blob.ToArray().SequenceEqual(blob)).IsTrue();
    }

    [Test]
    public async Task Signatures_GiveTheSignersKey()
    {
        using var key = Generate(SshKeyType.Ed25519, 0);
        var signature = SshSignature.Parse((await SshSignature.SignAsync(key, Message, "file")).ToString());
        await Assert.That(signature.GetPublicKey()).IsEqualTo(key.GetPublicKey());

        using var authority = Generate(SshKeyType.Ed25519, 0);
        var certificate = SshCertificate.Parse(TestKeys.CertificateLine(TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User)));
        using var certified = key.WithCertificate(certificate);
        var certifiedSignature = SshSignature.Parse((await SshSignature.SignAsync(certified, Message, "file")).ToString());
        await Assert.That(certifiedSignature.Certificate).IsNotNull();
        await Assert.That(certifiedSignature.GetPublicKey()).IsEqualTo(key.GetPublicKey());
    }

    [Test]
    public async Task HostAndAgentKeys_GiveTheKeyTheirBlobHolds()
    {
        var fixture = Load("ecdsa384");
        var expected = SshPublicKey.Parse(fixture.Pub);
        var hostKey = new SshHostKey("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384", fixture.Fingerprint, expected.Blob.ToArray(), 384);
        await Assert.That(hostKey.GetPublicKey()).IsEqualTo(expected);
        await Assert.That(hostKey.GetPublicKey().Fingerprint).IsEqualTo(hostKey.Fingerprint);
        await Assert.That(new SshAgentHostKey(expected.Blob).GetPublicKey()).IsEqualTo(expected);

        // A host key made by hand with bytes that are not a key.
        await Assert.That(() => (hostKey with { PublicKey = new byte[] { 1, 2, 3 } }).GetPublicKey()).ThrowsExactly<FormatException>();
        await Assert.That(() => new SshAgentHostKey(new byte[] { 1, 2, 3 }).GetPublicKey()).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task KnownHostsEntries_GiveTheirKey_AndTakeOne()
    {
        var ed = SshPublicKey.Parse(Load("ed25519").Pub);
        var ec = SshPublicKey.Parse(Load("ecdsa256").Pub);
        var file = KnownHostsFile.Parse($"host.example.com {ed.ToAuthorizedKeysLine()} a comment\n");

        var entry = file.Entries[0];
        await Assert.That(entry.GetPublicKey()).IsEqualTo(ed);
        await Assert.That(entry.GetPublicKey().Comment).IsEqualTo("a comment");
        await Assert.That(() => new KnownHostsEntry("h", "ssh-rsa", ed.Blob).GetPublicKey()).ThrowsExactly<FormatException>();
        await Assert.That(() => new KnownHostsEntry("h", "ssh-dss", new byte[] { 0, 0, 0, 7 }).GetPublicKey()).ThrowsExactly<FormatException>();

        await Assert.That(file.Check("host.example.com", ed)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("host.example.com", 22, ed)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("host.example.com", ec)).IsEqualTo(KnownHostsCheckResult.Unknown);
        await Assert.That(file.Check("other.example.com", ed)).IsEqualTo(KnownHostsCheckResult.Unknown);

        var added = file.Add("192.0.2.10", 2222, ec, comment: "added");
        await Assert.That(added.HostPatterns).IsEqualTo("[192.0.2.10]:2222");
        await Assert.That(added.KeyType).IsEqualTo(ec.KeyType);
        await Assert.That(added.GetPublicKey()).IsEqualTo(ec);
        await Assert.That(file.Check("192.0.2.10", 2222, ec)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Check("192.0.2.10", 2222, ec.KeyType, ec.Blob.Span)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(file.Add("192.0.2.11", 22, ed, hash: true).IsHashed).IsTrue();
        await Assert.That(file.Check("192.0.2.11", ed)).IsEqualTo(KnownHostsCheckResult.Match);
        await Assert.That(() => file.Add("h", 22, (SshPublicKey)null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => file.Check("h", 22, (SshPublicKey)null!)).ThrowsExactly<ArgumentNullException>();
    }

    [Test]
    public async Task PinnedKeys_AcceptOnlyThoseKeys()
    {
        var ed = SshPublicKey.Parse(Load("ed25519").Pub);
        var ec = SshPublicKey.Parse(Load("ecdsa256").Pub);
        var hostKey = new SshHostKey("ssh-ed25519", "ssh-ed25519", ed.Fingerprint, ed.Blob.ToArray(), 256);
        var context = new SshHostKeyContext("host.example.com", 22, null, hostKey);

        await Assert.That((await SshHostKeyVerifier.Pinned(ec, ed).VerifyAsync(context, default)).IsAccepted).IsTrue();
        var refused = await SshHostKeyVerifier.Pinned(ec).VerifyAsync(context, default);
        await Assert.That(refused.IsAccepted).IsFalse();
        await Assert.That(refused.Reason).Contains("pinned keys");

        await Assert.That(() => SshHostKeyVerifier.Pinned(Array.Empty<SshPublicKey>())).ThrowsExactly<ArgumentException>();
        await Assert.That(() => SshHostKeyVerifier.Pinned((SshPublicKey[])null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => SshHostKeyVerifier.Pinned(ed, null!)).ThrowsExactly<ArgumentException>();
    }
}
