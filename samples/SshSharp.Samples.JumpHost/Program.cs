using System.Globalization;
using SshSharp;
using SshSharp.Config;

// Reaches a server through a jump host, configured in code (no ssh_config), logging in to both with a short-lived OpenSSH user
// certificate that this program issues itself from a certificate authority (CA) key:
//
//   dotnet run --project samples/SshSharp.Samples.JumpHost -- <ca-key> <user@jump-host[:port]> <user@destination[:port]> [command]
//
// The first run with a <ca-key> path that does not exist creates the CA key there and prints the line both servers need in the file
// their sshd_config's TrustedUserCAKeys names. Later runs generate a new Ed25519 key in memory, certify it for five minutes for both
// user names, and connect. The CA key's passphrase, if it has one, comes from SSHSHARP_CA_PASSPHRASE. Host keys are checked against
// ~/.ssh/known_hosts, for the jump host and the destination alike.
if (args.Length is < 3 or > 4)
{
    Console.Error.WriteLine("usage: <ca-key> <user@jump-host[:port]> <user@destination[:port]> [command]");
    return 2;
}

using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(2));
var caPath = args[0];
var passphrase = Environment.GetEnvironmentVariable("SSHSHARP_CA_PASSPHRASE");

if (!File.Exists(caPath))
{
    // In production the CA key lives in a secret store, an agent or a KMS (see docs/how-to/certificates.md), not next to the tool.
    using var newCa = SshPrivateKey.Generate(SshKeyType.Ed25519, "sshsharp-sample-ca");
    await newCa.SaveAsync(caPath, passphrase, stop.Token);
    Console.WriteLine($"Created the CA key {caPath}. Add this line to the TrustedUserCAKeys file of both servers, then run again:");
    Console.WriteLine(newCa.ToAuthorizedKeysLine());
    return 0;
}

var jump = Endpoint.Parse(args[1]);
var destination = Endpoint.Parse(args[2]);
var command = args.Length == 4 ? args[3] : "id && hostname";

using var ca = await SshPrivateKey.LoadAsync(caPath, passphrase, stop.Token);

// A key for this run only. It never touches the disk, and its certificate expires in five minutes, so nothing long-lived can leak.
using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "sshsharp-sample");
var builder = new SshCertificateBuilder(key.GetPublicKey(), SshCertificateType.User, keyId: $"sshsharp-sample-{Guid.NewGuid():N}")
{
    ValidAfter = DateTimeOffset.UtcNow.AddMinutes(-1), // a little slack for a server clock that runs behind
    ValidBefore = DateTimeOffset.UtcNow.AddMinutes(5),
};
foreach (var principal in new[] { jump.User, destination.User }.Distinct(StringComparer.Ordinal))
{
    builder.Principals.Add(principal);
}

var certificate = await builder.SignAsync(ca, stop.Token);
using var certified = key.WithCertificate(certificate);
Console.WriteLine($"Issued {certificate.KeyId} for {string.Join(", ", certificate.Principals)}, valid until {certificate.ValidBefore:u}.");

// Each hop has its own options: its own user, credentials and host key check. The destination's options are never offered to the hop.
try
{
    return await RunAsync();
}
catch (SshException ex)
{
    // The message says which hop failed and why (an unknown host key, a CA the server does not trust, ...).
    Console.Error.WriteLine($"{ex.Reason}: {ex.Message}");
    return 1;
}

async Task<int> RunAsync()
{
    await using var client = await SshClient.ConnectAsync(destination.Host, destination.Port, new SshClientOptions
    {
        UserName = destination.User,
        PrivateKeys = [certified],
        HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
        JumpHosts =
        [
            new SshJumpHost(jump.Host, jump.Port, new SshClientOptions
            {
                UserName = jump.User,
                PrivateKeys = [certified],
                HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            }),
        ],
        ConnectTimeout = TimeSpan.FromSeconds(30), // the whole chain: both connections, handshakes and logins
    }, stop.Token);

    var result = await client.RunCommandAsync(command, stop.Token);
    Console.Write(result.StandardOutputText);
    Console.Error.Write(result.StandardErrorText);
    return result.ExitStatus ?? 255;
}

/// <summary>A <c>user@host[:port]</c> argument; an IPv6 address goes in brackets when a port follows (<c>user@[2001:db8::1]:2222</c>).</summary>
internal sealed record Endpoint(string User, string Host, int Port)
{
    public static Endpoint Parse(string value)
    {
        var at = value.LastIndexOf('@');
        if (at <= 0 || at == value.Length - 1)
        {
            throw new ArgumentException($"'{value}' is not user@host[:port].", nameof(value));
        }

        var user = value[..at];
        var rest = value[(at + 1)..];
        if (rest.StartsWith('['))
        {
            var close = rest.IndexOf(']', StringComparison.Ordinal);
            var host = rest[1..close];
            return new(user, host, close + 1 < rest.Length ? ParsePort(rest[(close + 2)..]) : 22);
        }

        var colon = rest.LastIndexOf(':');
        return colon > 0 && rest.IndexOf(':', StringComparison.Ordinal) == colon
            ? new(user, rest[..colon], ParsePort(rest[(colon + 1)..]))
            : new(user, rest, 22);
    }

    private static int ParsePort(string text) => int.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
}
