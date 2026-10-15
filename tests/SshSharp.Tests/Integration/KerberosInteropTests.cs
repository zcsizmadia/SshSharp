namespace SshSharp.Tests.Integration;

/// <summary>
/// gssapi-with-mic against OpenSSH with a real Kerberos realm. Needs SSHSHARP_TEST_GSSAPI=1, SSHSHARP_TEST_GSSAPI_SSHD (an sshd with
/// GSSAPIAuthentication yes whose keytab holds host/localhost), SSHSHARP_TEST_USER, and a ticket for that user in the credential cache
/// (KRB5CCNAME); CI sets up a throwaway MIT realm for it.
/// </summary>
public class KerberosInteropTests
{
    [Test]
    public async Task OpenSsh_AcceptsAKerberosTicket_WithNoPasswordOrKey()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var endpoint = Environment.GetEnvironmentVariable("SSHSHARP_TEST_GSSAPI_SSHD");
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_GSSAPI") != "1" || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(endpoint))
        {
            Skip.Test("SSHSHARP_TEST_GSSAPI=1, SSHSHARP_TEST_GSSAPI_SSHD and SSHSHARP_TEST_USER (with a Kerberos ticket) are needed.");
            return;
        }

        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        var colon = endpoint.LastIndexOf(':');
        var token = new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;
        await using var client = await SshClient.ConnectAsync(endpoint[..colon], int.Parse(endpoint[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture),
            new SshClientOptions
            {
                UserName = user,
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),

                // Kerberos names the service by host name: the keytab holds host/localhost, though the connection goes to 127.0.0.1.
                Gssapi = new SshGssapiOptions { TargetHost = "localhost" },
            }, token);

        var result = await client.RunCommandAsync("echo kerberos-ok", token);
        await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("kerberos-ok");
    }
}
