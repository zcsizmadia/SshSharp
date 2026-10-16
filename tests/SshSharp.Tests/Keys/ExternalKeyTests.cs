using System.Security.Cryptography;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>Keys whose private half SshSharp never holds: SshPrivateKey.FromRsa, FromECDsa and FromSigner (#93).</summary>
public class ExternalKeyTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    private static readonly byte[] Data = Encoding.ASCII.GetBytes("data to sign");

    /// <summary>A signer backed by a key SshSharp generated, standing in for a key vault: it signs with that key's private half.</summary>
    internal sealed class TestSigner(SshPrivateKey key, Func<byte[], byte[]>? reshape = null) : SshKeySigner(key.PublicKey)
    {
        public IReadOnlyList<string>? Algorithms { get; init; }

        /// <summary>The format the signature is returned in.</summary>
        public DSASignatureFormat Format { get; init; } = DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

        /// <summary>The format the signer says it returns, when it differs from <see cref="Format"/> (a misconfigured signer).</summary>
        public DSASignatureFormat? Declared { get; init; }

        public int Calls { get; private set; }

        public override IReadOnlyList<string> SignatureAlgorithms => Algorithms ?? base.SignatureAlgorithms;

        public override DSASignatureFormat EcdsaSignatureFormat => Declared ?? Format;

        public override async ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            Calls++;

            // The raw signature out of SshSharp's own SSH blob: string algorithm, then string signature (for ECDSA, two mpints).
            var blob = await key.SignAsync(algorithm, data, null, cancellationToken);
            var reader = new SshSharp.Protocol.SshReader(blob);
            reader.ReadString();
            var signature = reader.ReadString().ToArray();
            if (KeyType.StartsWith("ecdsa-", StringComparison.Ordinal))
            {
                var inner = new SshSharp.Protocol.SshReader(signature);
                var size = KeyType.EndsWith("521", StringComparison.Ordinal) ? 66 : KeyType.EndsWith("384", StringComparison.Ordinal) ? 48 : 32;
                byte[] rs = [.. Fixed(inner.ReadMpint().ToArray(), size), .. Fixed(inner.ReadMpint().ToArray(), size)];
                signature = Format == DSASignatureFormat.Rfc3279DerSequence ? ToDer(rs) : rs;
            }

            return reshape is null ? signature : reshape(signature);
        }

        private static byte[] Fixed(byte[] value, int size)
        {
            var trimmed = value.AsSpan().TrimStart((byte)0);
            var result = new byte[size];
            trimmed.CopyTo(result.AsSpan(size - trimmed.Length));
            return result;
        }

        private static byte[] ToDer(byte[] rs)
        {
            using var ecdsa = ECDsa.Create();
            var half = rs.Length / 2;
            static byte[] Integer(ReadOnlySpan<byte> value)
            {
                var v = value.TrimStart((byte)0).ToArray();
                byte[] body = v.Length > 0 && (v[0] & 0x80) != 0 ? [0, .. v] : v.Length == 0 ? [0] : v;
                return [0x02, (byte)body.Length, .. body];
            }

            byte[] content = [.. Integer(rs.AsSpan(0, half)), .. Integer(rs.AsSpan(half))];
            return content.Length < 0x80 ? [0x30, (byte)content.Length, .. content] : [0x30, 0x81, (byte)content.Length, .. content];
        }
    }

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshPrivateKey key)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            PrivateKeys = [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    private static async Task AssertAuthenticatesAsync(SshPrivateKey key)
    {
        await using var server = new FakeSessionServer { AuthorizedKeys = [key.PublicKey.ToArray()], AdvertisedMethods = ["publickey"] };
        await using var client = await ConnectAsync(server, key);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task FromRsa_AuthenticatesWithoutExportingTheKey_AndLeavesItToTheCaller()
    {
        using var rsa = RSA.Create(2048);
        using (var key = SshPrivateKey.FromRsa(rsa, "vault"))
        {
            await Assert.That(key.KeyType).IsEqualTo("ssh-rsa");
            await Assert.That(key.Comment).IsEqualTo("vault");
            await AssertAuthenticatesAsync(key);
        }

        // Disposing the SSH key left the caller's RSA alone.
        await Assert.That(rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Length).IsEqualTo(256);
    }

    [Test]
    [Arguments(256, "ecdsa-sha2-nistp256")]
    [Arguments(384, "ecdsa-sha2-nistp384")]
    [Arguments(521, "ecdsa-sha2-nistp521")]
    public async Task FromECDsa_AuthenticatesOnEachNistCurve(int bits, string type)
    {
        using var ecdsa = ECDsa.Create(bits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        });
        using var key = SshPrivateKey.FromECDsa(ecdsa);
        await Assert.That(key.KeyType).IsEqualTo(type);
        await AssertAuthenticatesAsync(key);
    }

    [Test]
    public async Task FromECDsa_RefusesACurveSshDoesNotUse()
    {
        ECDsa ecdsa;
        try
        {
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or CryptographicException)
        {
            Skip.Test("This platform has no brainpool curves.");
            return;
        }

        using (ecdsa)
        {
            await Assert.That(() => SshPrivateKey.FromECDsa(ecdsa)).Throws<ArgumentException>();
        }
    }

    [Test]
    [Arguments(SshKeyType.Ed25519, false)]
    [Arguments(SshKeyType.EcdsaNistp384, false)]
    [Arguments(SshKeyType.EcdsaNistp256, true)]
    [Arguments(SshKeyType.Rsa, false)]
    public async Task FromSigner_Authenticates_WithEachKeyType_AndEcdsaInDer(SshKeyType type, bool der)
    {
        using var inner = SshPrivateKey.Generate(type, rsaBits: 2048);
        var signer = new TestSigner(inner) { Format = der ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation };
        using var key = SshPrivateKey.FromSigner(signer);
        await AssertAuthenticatesAsync(key);
        await Assert.That(signer.Calls).IsGreaterThanOrEqualTo(1);
    }

    [Test]
    public async Task FromSigner_WorksWithACertificate_AndForSshSignatures()
    {
        using var ca = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var inner = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.FromSigner(new TestSigner(inner));

        var signature = await SshSignature.SignAsync(key, Data, "file", cancellationToken: Timeout());
        await Assert.That(signature.Verify(Data, "file")).IsTrue();

        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(ca, key.PublicKey.ToArray(), SshCertificateType.User, ["tester"]));
        var certified = key.WithCertificate(certificate);
        await Assert.That(certified.KeyType).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
        var blob = await certified.SignAsync("ssh-ed25519-cert-v01@openssh.com", Data, null, Timeout());
        await Assert.That(blob.Length).IsGreaterThan(64);
        await Assert.That(certified.HasLocalPrivateMaterial).IsFalse();
    }

    [Test]
    public async Task ASignatureInTheWrongFormat_OrFromAnotherKey_FailsBeforeUse()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        using var other = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);

        // DER returned where r || s was declared.
        using var wrongFormat = SshPrivateKey.FromSigner(new TestSigner(inner)
        {
            Format = DSASignatureFormat.Rfc3279DerSequence,
            Declared = DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
        });
        await Assert.That(async () => await wrongFormat.SignAsync("ecdsa-sha2-nistp256", Data, null, Timeout())).Throws<CryptographicException>();

        // Signed by another key than the one the signer claims.
        using var wrongKey = SshPrivateKey.FromSigner(new SwappedSigner(inner, other));
        var error = await Assert.That(async () => await wrongKey.SignAsync("ecdsa-sha2-nistp256", Data, null, Timeout())).Throws<CryptographicException>();
        await Assert.That(error!.Message).Contains("does not verify against its public key");
    }

    [Test]
    public async Task SignatureAlgorithms_CanBeRestricted_ButNotWidened()
    {
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var sha256Only = SshPrivateKey.FromSigner(new TestSigner(rsa) { Algorithms = ["rsa-sha2-256"] });
        await Assert.That(sha256Only.SignatureAlgorithms).IsEquivalentTo(new[] { "rsa-sha2-256" });
        await Assert.That(async () => await sha256Only.SignAsync("rsa-sha2-512", Data, null, Timeout())).Throws<ArgumentException>();

        await Assert.That(() => SshPrivateKey.FromSigner(new TestSigner(rsa) { Algorithms = ["ssh-rsa"] })).Throws<ArgumentException>();
        await Assert.That(() => SshPrivateKey.FromSigner(new TestSigner(rsa) { Algorithms = [] })).Throws<ArgumentException>();
    }

    [Test]
    public async Task AnExternalKey_CannotBeExported_SignedSynchronously_OrAddedToAnAgent()
    {
        using var rsa = RSA.Create(2048);
        using var key = SshPrivateKey.FromRsa(rsa);
        await Assert.That(() => key.ToOpenSshPrivateKey()).Throws<NotSupportedException>();
        await Assert.That(() => key.Sign("rsa-sha2-256", Data)).Throws<NotSupportedException>();
        await Assert.That(key.HasLocalPrivateMaterial).IsFalse();
    }

    [Test]
    public async Task ASignerNeedsASupportedPublicKey()
    {
        using var small = RSA.Create(1024);
        await Assert.That(() => SshPrivateKey.FromRsa(small)).Throws<FormatException>();
        await Assert.That(() => new RawSigner([0, 0, 0, 3, (byte)'a', (byte)'b', (byte)'c'])).Throws<FormatException>();
    }

    /// <summary>A signer for whatever public key bytes it is given; never asked to sign.</summary>
    private sealed class RawSigner(byte[] publicKey) : SshKeySigner(publicKey)
    {
        public override ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
    }

    /// <summary>Claims <paramref name="claimed"/>'s public key but signs with <paramref name="actual"/>.</summary>
    private sealed class SwappedSigner(SshPrivateKey claimed, SshPrivateKey actual) : SshKeySigner(claimed.PublicKey)
    {
        private readonly TestSigner _actual = new(actual);

        public override ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
            _actual.SignAsync(algorithm, data, cancellationToken);
    }
}
