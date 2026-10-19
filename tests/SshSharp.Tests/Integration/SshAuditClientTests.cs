namespace SshSharp.Tests.Integration;

/// <summary>
/// The client side of the ssh-audit job in CI (#218). <c>ssh-audit -c</c> listens as a server, records the algorithms SshSharp offers
/// in its KEXINIT, and closes the connection; tests/ssh-audit/check_client_audit.py then judges its report. Runs only when the job
/// sets SSHSHARP_TEST_SSHAUDIT (the port for the default options) or SSHSHARP_TEST_SSHAUDIT_FIPS (the port for FIPS mode).
/// </summary>
[Category("Integration")]
[Category("SshAudit")] // needs ssh-audit listening (the audit job), not an SSH server: the interop jobs leave it out
public class SshAuditClientTests
{
    [Test]
    [Arguments("SSHSHARP_TEST_SSHAUDIT", false)]
    [Arguments("SSHSHARP_TEST_SSHAUDIT_FIPS", true)]
    public async Task OffersItsAlgorithmsToSshAudit(string variable, bool fips)
    {
        if (!int.TryParse(Environment.GetEnvironmentVariable(variable), out var port))
        {
            Skip.Test($"{variable} is not set (the ssh-audit job in CI sets it).");
        }

        // ssh-audit closes the connection once it has our KEXINIT, so the handshake cannot finish. That it was ssh-audit that closed it,
        // and not a refused connection, shows the report has our algorithms.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ex = await Assert.That(async () => await SshClient.ConnectAsync("127.0.0.1", port, new SshClientOptions
        {
            UserName = "audit",
            FipsMode = fips,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, timeout.Token)).Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
    }
}
