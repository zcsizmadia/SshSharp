using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/verify-host-keys.md.</summary>
internal static class HostKeys
{
    public static SshHostKeyVerifier Strict()
    {
        // <strict>
        // ~/.ssh/known_hosts and the system file; an unknown or changed key fails the connection.
        var verifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes);
        // </strict>
        return verifier;
    }

    public static SshHostKeyVerifier AppFile()
    {
        // <app-file>
        // A known_hosts file the application owns, filled on first contact (trust on first use) and checked from then on.
        var verifier = new KnownHostsVerifier(["/var/lib/myapp/known_hosts"])
        {
            Policy = StrictHostKeyChecking.AcceptNew,
            HashNewEntries = true,       // HashKnownHosts yes: host names are not readable in the file
            UpdateHostKeys = true,       // follow the server's key rotation (UpdateHostKeys yes)
        };
        // </app-file>
        return verifier;
    }

    public static SshHostKeyVerifier Pinned()
    {
        // <pinned>
        // The fingerprints as ssh-keygen -lf prints them; any one of them is accepted (for example during a key rotation).
        var verifier = SshHostKeyVerifier.Pinned(
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            "SHA256:kKiu2Km+4JVJ4V3VzRUknvNqDe4cM1Kwu884+5BThkA");
        // </pinned>
        return verifier;
    }

    public static SshHostKeyVerifier Inventory(IHostInventory inventory)
    {
        // <delegate>
        // Your own source of truth: a CMDB, a vault, a database of provisioned machines.
        var verifier = SshHostKeyVerifier.FromDelegate(async (context, ct) =>
            await inventory.IsTrustedAsync(context.HostKeyAlias ?? context.Host ?? "", context.HostKey.Fingerprint, ct));
        // </delegate>
        return verifier;
    }

    /// <summary>A source of trusted fingerprints.</summary>
    internal interface IHostInventory
    {
        Task<bool> IsTrustedAsync(string host, string fingerprint, CancellationToken cancellationToken);
    }

    // <custom>
    /// <summary>Accepts only host certificates signed by one authority, with the host's name among their principals.</summary>
    internal sealed class HostCertificateVerifier(string authorityFingerprint) : SshHostKeyVerifier
    {
        public override ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken)
        {
            var host = context.HostKeyAlias ?? context.Host;
            var verdict = context.HostKey.Certificate switch
            {
                null => SshHostKeyVerdict.Reject("The server presented no host certificate."),
                { Type: not SshCertificateType.Host } => SshHostKeyVerdict.Reject("Not a host certificate."),
                var c when c.AuthorityFingerprint != authorityFingerprint => SshHostKeyVerdict.Reject("Signed by an unknown authority."),
                var c when DateTimeOffset.UtcNow < c.ValidAfter || DateTimeOffset.UtcNow >= c.ValidBefore => SshHostKeyVerdict.Reject("Expired or not yet valid."),
                var c when host is null || !c.Principals.Contains(host) => SshHostKeyVerdict.Reject("Not issued for this host."),
                _ => SshHostKeyVerdict.Accept(),
            };
            return ValueTask.FromResult(verdict);
        }
    }
    // </custom>

    public static async Task ScanAsync(CancellationToken cancellationToken)
    {
        // <scan>
        // ssh-keyscan: the server's host keys, without logging in. Compare them with fingerprints you got another way
        // (the provisioning output, the cloud console) before trusting them.
        var keys = await SshClient.ScanHostKeysAsync("new-host.example.com", cancellationToken: cancellationToken);
        foreach (var key in keys)
        {
            Console.WriteLine($"{key.KeyType} {key.Fingerprint}");
        }
        // </scan>
    }

    public static async Task HandleRejectionAsync(SshClientOptions options, CancellationToken cancellationToken)
    {
        // <rejected>
        try
        {
            await using var client = await SshClient.ConnectAsync("example.com", 22, options, cancellationToken);
        }
        catch (SshHostKeyException ex)
        {
            // Never retry with a looser policy here: a changed key is exactly what an interception looks like.
            Console.Error.WriteLine($"Host key {ex.HostKey?.KeyType} {ex.HostKey?.Fingerprint} not trusted: {ex.Message}");
            throw;
        }
        // </rejected>
    }
}
