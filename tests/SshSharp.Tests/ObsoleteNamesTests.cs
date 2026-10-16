using SshSharp.Config;
using SshSharp.Scp;
using SshSharp.Tests.Keys;

namespace SshSharp.Tests;

/// <summary>The names renamed before 1.0 (#88) still work, through obsolete forwarders, so code written for 0.6.0 compiles with a warning.</summary>
public class ObsoleteNamesTests
{
#pragma warning disable CS0618 // the obsolete names are what is tested
    [Test]
    public async Task KnownHostsVerifierAsk_IsAskHostKey()
    {
        Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>> ask = (_, _) => ValueTask.FromResult(true);
        var verifier = new KnownHostsVerifier([]) { Ask = ask };
        await Assert.That(ReferenceEquals(verifier.AskHostKey, ask)).IsTrue();
        await Assert.That(ReferenceEquals(verifier.Ask, ask)).IsTrue();
    }

    [Test]
    public async Task ScpPreserveTimes_IsPreserve()
    {
        var options = new SshScpOptions { PreserveTimes = true };
        await Assert.That(options.Preserve).IsTrue();
        await Assert.That(options.PreserveTimes).IsTrue();
    }

    [Test]
    public async Task CertificateType_IsAlgorithm()
    {
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var certificate = SshCertificate.FromBlob(TestKeys.Certificate(authority, key.PublicKey.ToArray(), SshCertificateType.User, ["tester"]));
        await Assert.That(certificate.CertificateType).IsEqualTo(certificate.Algorithm);
        await Assert.That(certificate.Algorithm).IsEqualTo("ssh-ed25519-cert-v01@openssh.com");
    }
#pragma warning restore CS0618
}
