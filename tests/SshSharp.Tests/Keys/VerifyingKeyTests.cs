using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>
/// Checks key parsing, fingerprints and signature verification against keys, fingerprints and SSHSIG signatures that
/// OpenSSH's own ssh-keygen produced (fixtures/hostkeys_openssh.txt).
/// </summary>
public class VerifyingKeyTests
{
    public static IEnumerable<string> KeyNames() => ["ed25519", "rsa", "ecdsa256", "ecdsa384", "ecdsa521"];

    private static readonly byte[] Message = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "hostkey_message.txt"));

    private sealed record Fixture(string Pub, string Fingerprint, string Armor);

    private static Fixture Load(string name)
    {
        var lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", "hostkeys_openssh.txt"));
        var start = Array.IndexOf(lines, $"[{name}]");
        var pub = lines[start + 1]["pub=".Length..];
        var fp = lines[start + 2]["fp=".Length..];
        var armor = new StringBuilder();
        for (var i = start + 4; lines[i] != ">>"; i++)
        {
            armor.Append(lines[i]);
        }

        return new Fixture(pub, fp, armor.ToString());
    }

    private static byte[] PublicKeyBlob(string authorizedKeysLine) => Convert.FromBase64String(authorizedKeysLine.Split(' ')[1]);

    // SSHSIG: "SSHSIG" || u32 version || string publickey || string namespace || string reserved || string hash_alg || string signature
    private static (byte[] PublicKey, string Namespace, string HashAlgorithm, byte[] Signature) ParseSshSig(string armor)
    {
        var body = armor.Replace("-----BEGIN SSH SIGNATURE-----", string.Empty).Replace("-----END SSH SIGNATURE-----", string.Empty);
        var bytes = Convert.FromBase64String(body);
        var reader = new SshReader(bytes);
        reader.ReadBytes(6);
        reader.ReadUInt32();
        var publicKey = reader.ReadString().ToArray();
        var ns = reader.ReadUtf8String();
        reader.ReadString();
        var hash = reader.ReadUtf8String();
        var signature = reader.ReadString().ToArray();
        return (publicKey, ns, hash, signature);
    }

    private static byte[] SignedData(string ns, string hashAlgorithm, byte[] message)
    {
        var buffer = new ArrayBufferWriter<byte>();
        buffer.Write("SSHSIG"u8);
        var writer = new SshWriter(buffer);
        writer.WriteString(ns);
        writer.WriteString(string.Empty);
        writer.WriteString(hashAlgorithm);
        writer.WriteString(hashAlgorithm == "sha512" ? SHA512.HashData(message) : SHA256.HashData(message));
        return buffer.WrittenSpan.ToArray();
    }

    private static string InnerAlgorithm(byte[] signatureBlob) => new SshReader(signatureBlob).ReadUtf8String();

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task Parse_MatchesOpenSshFingerprint(string name)
    {
        var fixture = Load(name);
        var blob = PublicKeyBlob(fixture.Pub);
        var key = VerifyingKey.Parse(blob);

        await Assert.That(key.Fingerprint).IsEqualTo(fixture.Fingerprint);
        await Assert.That(key.KeyType).IsEqualTo(fixture.Pub.Split(' ')[0]);
        await Assert.That(Convert.ToHexString(key.Blob.Span)).IsEqualTo(Convert.ToHexString(blob));
        await Assert.That(key.KeySizeBits).IsEqualTo(name switch { "ed25519" => 256, "rsa" => 2048, "ecdsa256" => 256, "ecdsa384" => 384, _ => 521 });
    }

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task VerifiesTheSignatureOpenSshProduced(string name)
    {
        var fixture = Load(name);
        var key = VerifyingKey.Parse(PublicKeyBlob(fixture.Pub));
        var (sigKey, ns, hashAlgorithm, signature) = ParseSshSig(fixture.Armor);
        var data = SignedData(ns, hashAlgorithm, Message);
        var algorithm = InnerAlgorithm(signature);

        await Assert.That(Convert.ToHexString(sigKey)).IsEqualTo(Convert.ToHexString(key.Blob.Span));
        await Assert.That(key.VerifySignature(algorithm, signature, data)).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(KeyNames))]
    public async Task RejectsTamperedMessageSignatureAndTruncation(string name)
    {
        var fixture = Load(name);
        var key = VerifyingKey.Parse(PublicKeyBlob(fixture.Pub));
        var (_, ns, hashAlgorithm, signature) = ParseSshSig(fixture.Armor);
        var data = SignedData(ns, hashAlgorithm, Message);
        var algorithm = InnerAlgorithm(signature);

        var otherData = SignedData(ns, hashAlgorithm, [.. Message, (byte)'!']);
        await Assert.That(key.VerifySignature(algorithm, signature, otherData)).IsFalse();

        for (var i = signature.Length - 1; i > signature.Length - 40; i -= 7)
        {
            var bad = (byte[])signature.Clone();
            bad[i] ^= 1;
            await Assert.That(key.VerifySignature(algorithm, bad, data)).IsFalse();
        }

        await Assert.That(key.VerifySignature(algorithm, signature.AsSpan(0, signature.Length - 1), data)).IsFalse();
        await Assert.That(key.VerifySignature(algorithm, [.. signature, 0], data)).IsFalse();
        await Assert.That(key.VerifySignature(algorithm, [], data)).IsFalse();
        await Assert.That(key.VerifySignature("ssh-dss", signature, data)).IsFalse();
    }

    [Test]
    public async Task OneKeyNeverVerifiesAnotherKeysSignature()
    {
        var ed = Load("ed25519");
        var rsa = Load("rsa");
        var edKey = VerifyingKey.Parse(PublicKeyBlob(ed.Pub));
        var (_, ns, hash, rsaSignature) = ParseSshSig(rsa.Armor);
        await Assert.That(edKey.VerifySignature(InnerAlgorithm(rsaSignature), rsaSignature, SignedData(ns, hash, Message))).IsFalse();

        var e1 = VerifyingKey.Parse(PublicKeyBlob(Load("ecdsa256").Pub));
        var (_, ns2, hash2, sig384) = ParseSshSig(Load("ecdsa384").Armor);
        await Assert.That(e1.VerifySignature(InnerAlgorithm(sig384), sig384, SignedData(ns2, hash2, Message))).IsFalse();
        await Assert.That(e1.VerifySignature("ecdsa-sha2-nistp256", sig384, SignedData(ns2, hash2, Message))).IsFalse();
    }

    [Test]
    public async Task Rsa_AcceptsOnlyTheMatchingSha2Algorithm()
    {
        var fixture = Load("rsa");
        var key = VerifyingKey.Parse(PublicKeyBlob(fixture.Pub));
        var (_, ns, hash, signature) = ParseSshSig(fixture.Armor);
        var data = SignedData(ns, hash, Message);

        await Assert.That(InnerAlgorithm(signature)).IsEqualTo("rsa-sha2-512");
        await Assert.That(key.VerifySignature("rsa-sha2-512", signature, data)).IsTrue();
        await Assert.That(key.VerifySignature("rsa-sha2-256", signature, data)).IsFalse();
        await Assert.That(key.VerifySignature("ssh-rsa", signature, data)).IsFalse();
    }

    [Test]
    [Arguments(new byte[] { 1 })]
    [Arguments(new byte[] { 2 })]
    [Arguments(new byte[] { 0x01, 0x00, 0x00 })]
    [Arguments(new byte[0])]
    public async Task Rsa_RejectsUnsafePublicExponents(byte[] exponent)
    {
        using var rsa = RSA.Create(2048);
        var modulus = rsa.ExportParameters(false).Modulus!;
        var blob = Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint(exponent);
            w.WriteMpint(modulus);
        });
        await Assert.That(() => VerifyingKey.Parse(blob)).Throws<SshProtocolException>();
    }

    [Test]
    public async Task Rsa_AcceptsASignatureWithItsLeadingZeroBytesDropped()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var key = VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint(parameters.Exponent);
            w.WriteMpint(parameters.Modulus);
        }));

        // About one signature in 256 starts with a zero byte; some servers send it without, and OpenSSH pads it back.
        byte[] data, signature;
        var i = 0;
        do
        {
            data = BitConverter.GetBytes(i++);
            signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        while (signature[0] != 0);

        var trimmed = signature.AsSpan().TrimStart((byte)0).ToArray();
        await Assert.That(key.VerifySignature("rsa-sha2-256", SignatureBlob("rsa-sha2-256", w => w.WriteBytes(trimmed)), data)).IsTrue();
        await Assert.That(key.VerifySignature("rsa-sha2-256", SignatureBlob("rsa-sha2-256", w => w.WriteBytes(signature)), data)).IsTrue();

        // Longer than the modulus is never valid.
        byte[] longer = [0, .. signature];
        await Assert.That(key.VerifySignature("rsa-sha2-256", SignatureBlob("rsa-sha2-256", w => w.WriteBytes(longer)), data)).IsFalse();
    }

    private static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] SignatureBlob(string type, Action<SshWriter> writeSignature)
    {
        var inner = Blob(writeSignature);
        return Blob(w =>
        {
            w.WriteString(type);
            w.WriteString(inner);
        });
    }

    [Test]
    public async Task Ed25519_SignaturesFromThisLibraryVerify()
    {
        var seed = new byte[32];
        new Random(51).NextBytes(seed);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        var key = VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(pub);
        }));

        var data = "data"u8.ToArray();
        var sig = new byte[64];
        Ed25519.Sign(seed, data, sig);
        var blob = SignatureBlob("ssh-ed25519", w => w.WriteBytes(sig));
        await Assert.That(key.VerifySignature("ssh-ed25519", blob, data)).IsTrue();

        // A signature of the wrong length is rejected before verification.
        var shortBlob = Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(sig.AsSpan(0, 63));
        });
        await Assert.That(key.VerifySignature("ssh-ed25519", shortBlob, data)).IsFalse();
    }

    [Test]
    [Arguments(256)]
    [Arguments(384)]
    [Arguments(521)]
    public async Task Ecdsa_ManySignatures_CoverMpintEdgeCases(int bits)
    {
        var (curve, name, size, hash) = bits switch
        {
            256 => (ECCurve.NamedCurves.nistP256, "nistp256", 32, HashAlgorithmName.SHA256),
            384 => (ECCurve.NamedCurves.nistP384, "nistp384", 48, HashAlgorithmName.SHA384),
            _ => (ECCurve.NamedCurves.nistP521, "nistp521", 66, HashAlgorithmName.SHA512),
        };
        using var ecdsa = ECDsa.Create(curve);
        var parameters = ecdsa.ExportParameters(false);
        var point = new byte[1 + (2 * size)];
        point[0] = 4;
        parameters.Q.X!.CopyTo(point, 1 + size - parameters.Q.X.Length);
        parameters.Q.Y!.CopyTo(point, 1 + (2 * size) - parameters.Q.Y.Length);
        var type = "ecdsa-sha2-" + name;
        var key = VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString(type);
            w.WriteString(name);
            w.WriteString(point);
        }));

        var sawHighBit = false;
        for (var i = 0; i < 60; i++)
        {
            var data = BitConverter.GetBytes(i);
            var raw = ecdsa.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            sawHighBit |= (raw[0] & 0x80) != 0 || (raw[size] & 0x80) != 0;
            var blob = SignatureBlob(type, w =>
            {
                w.WriteMpint(raw.AsSpan(0, size));
                w.WriteMpint(raw.AsSpan(size));
            });
            await Assert.That(key.VerifySignature(type, blob, data)).IsTrue();
        }

        if (bits != 521)
        {
            // (P-521 values occupy 521 of 528 bits, so their first byte never has the top bit set.)
            await Assert.That(sawHighBit).IsTrue();
        }

        // r or s longer than the field is rejected.
        var oversized = SignatureBlob(type, w =>
        {
            w.WriteMpint(new byte[size + 1].Select((_, idx) => (byte)(idx == 0 ? 1 : 2)).ToArray());
            w.WriteMpint([1]);
        });
        await Assert.That(key.VerifySignature(type, oversized, [1])).IsFalse();
    }

    [Test]
    public async Task Rsa_SignaturesFromTheFrameworkVerify()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var key = VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint(p.Exponent!);
            w.WriteMpint(p.Modulus!);
        }));
        var data = "payload"u8.ToArray();

        foreach (var (algorithm, hash) in new[] { ("rsa-sha2-256", HashAlgorithmName.SHA256), ("rsa-sha2-512", HashAlgorithmName.SHA512) })
        {
            var signature = rsa.SignData(data, hash, RSASignaturePadding.Pkcs1);
            var blob = SignatureBlob(algorithm, w => w.WriteBytes(signature));
            await Assert.That(key.VerifySignature(algorithm, blob, data)).IsTrue();
        }
    }

    [Test]
    public async Task Parse_RejectsMalformedKeys()
    {
        await Assert.That(() => VerifyingKey.Parse([])).Throws<SshProtocolException>();
        await Assert.That(() => VerifyingKey.Parse(Blob(w => w.WriteString("ssh-dss")))).Throws<SshProtocolException>();
        await Assert.That(() => VerifyingKey.Parse(Blob(w => w.WriteString("ssh-ed25519")))).Throws<SshProtocolException>();

        await Assert.That(() => VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(new byte[31]);
        }))).Throws<SshProtocolException>();

        var good = PublicKeyBlob(Load("ed25519").Pub);
        await Assert.That(() => VerifyingKey.Parse([.. good, 0])).Throws<SshProtocolException>();
    }

    [Test]
    public async Task Parse_RejectsBadEcdsaKeys()
    {
        var good = PublicKeyBlob(Load("ecdsa256").Pub);

        // Curve name that does not match the key type.
        var mismatch = Blob(w =>
        {
            w.WriteString("ecdsa-sha2-nistp256");
            w.WriteString("nistp384");
            w.WriteString(new byte[65]);
        });
        await Assert.That(() => VerifyingKey.Parse(mismatch)).Throws<SshProtocolException>();

        // Compressed point marker.
        var compressed = Blob(w =>
        {
            w.WriteString("ecdsa-sha2-nistp256");
            w.WriteString("nistp256");
            var point = new byte[65];
            point[0] = 2;
            w.WriteString(point);
        });
        await Assert.That(() => VerifyingKey.Parse(compressed)).Throws<SshProtocolException>();

        // A point that is not on the curve.
        var offCurve = Blob(w =>
        {
            w.WriteString("ecdsa-sha2-nistp256");
            w.WriteString("nistp256");
            var point = new byte[65];
            point[0] = 4;
            point[32] = 1;
            point[64] = 1;
            w.WriteString(point);
        });
        await Assert.That(() => VerifyingKey.Parse(offCurve)).Throws<SshProtocolException>();
        await Assert.That(VerifyingKey.Parse(good).KeyType).IsEqualTo("ecdsa-sha2-nistp256");
    }

    [Test]
    public async Task Parse_RejectsTinyRsaKeys()
    {
        var tiny = Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint([1, 0, 1]);
            w.WriteMpint(new byte[] { 0x80, 1, 2, 3 });
        });
        await Assert.That(() => VerifyingKey.Parse(tiny)).Throws<SshProtocolException>();

        var noExponent = Blob(w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint([]);
            w.WriteMpint(Enumerable.Repeat((byte)0x81, 256).ToArray());
        });
        await Assert.That(() => VerifyingKey.Parse(noExponent)).Throws<SshProtocolException>();
    }

    [Test]
    public async Task AnRsaSignatureNotReducedModuloN_IsRefused()
    {
        // s + n verifies like s (RFC 8017's RSAVP1 refuses it: s must be below n). .NET on macOS accepted it where Linux and Windows
        // did not (Wycheproof's "signature is not reduced"), so SshSharp checks it itself.
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var key = VerifyingKey.Parse(Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent); w.WriteMpint(p.Modulus); }));
        var n = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        for (var attempt = 0; attempt < 500; attempt++)
        {
            var data = RandomNumberGenerator.GetBytes(32);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var unreduced = (new BigInteger(signature, isUnsigned: true, isBigEndian: true) + n).ToByteArray(isUnsigned: true, isBigEndian: true);
            if (unreduced.Length > p.Modulus!.Length)
            {
                continue; // s + n needs a longer encoding, which the length check refuses anyway: try another signature
            }

            await Assert.That(key.VerifySignature("rsa-sha2-256", Blob(w => { w.WriteString("rsa-sha2-256"); w.WriteString(signature); }), data)).IsTrue();
            await Assert.That(key.VerifySignature("rsa-sha2-256", Blob(w => { w.WriteString("rsa-sha2-256"); w.WriteString(unreduced); }), data)).IsFalse();
            return;
        }

        Skip.Test("No signature of this key had s + n within the modulus's length (n is too close to 2^2048).");
    }
}
