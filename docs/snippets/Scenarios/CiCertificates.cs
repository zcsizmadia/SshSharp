using SshSharp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/ci-certificates.md.</summary>
internal static class CiCertificates
{
    // <issue>
    /// <summary>
    /// Issues a certificate for one CI job's key, for the deploy user, for as long as the job may run. The CA key is the caller's: from
    /// an agent, or a key service through SshKeySigner.
    /// </summary>
    public static async Task<SshCertificate> IssueAsync(SshPrivateKey ca, SshPublicKey jobKey, string jobId, ulong jobNumber,
        TimeSpan jobTimeout, CancellationToken cancellationToken)
    {
        var builder = new SshCertificateBuilder(jobKey, SshCertificateType.User, keyId: $"ci-{jobId}")
        {
            Serial = jobNumber,
            Principals = { "deploy" },
            ValidBefore = DateTimeOffset.UtcNow + jobTimeout,
        };

        // Commands only, from the build network, as nothing but the deploy script.
        builder.Extensions.Clear();
        builder.CriticalOptions[SshCertificateBuilder.SourceAddress] = "192.0.2.0/24";
        builder.CriticalOptions[SshCertificateBuilder.ForceCommand] = "/usr/local/bin/deploy";

        var certificate = await builder.SignAsync(ca, cancellationToken);
        Console.WriteLine($"Issued {certificate.KeyId} (serial {certificate.Serial}) until {certificate.ValidBefore:u}");
        return certificate;
    }
    // </issue>

    // <use>
    public static async Task DeployAsync(SshPrivateKey ca, string jobId, ulong jobNumber, CancellationToken cancellationToken)
    {
        // A key for this job only: it lives in memory and is gone when the job ends.
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, $"ci-{jobId}");
        var certificate = await IssueAsync(ca, key.GetPublicKey(), jobId, jobNumber, TimeSpan.FromMinutes(20), cancellationToken);

        // The servers trust the CA (TrustedUserCAKeys) and prove themselves with host certificates from it (@cert-authority).
        await using var client = await SshClient.ConnectAsync("app1.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key.WithCertificate(certificate)],
            HostKeyVerifier = new KnownHostsVerifier(["/etc/ci/ssh_known_hosts"]),
        }, cancellationToken);

        // force-command runs the deploy script whatever is asked; what was asked reaches it as SSH_ORIGINAL_COMMAND.
        var result = await client.RunCommandAsync(jobId, cancellationToken);
        result.EnsureSuccess();
    }
    // </use>
}
