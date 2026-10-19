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

    public static async Task<SshHostKeyVerifier> PinnedKeysAsync(CancellationToken cancellationToken)
    {
        // <pinned-keys>
        // The server's own public keys (its /etc/ssh/ssh_host_*_key.pub files), shipped with the application or taken from the
        // provisioning output. Any one of them is accepted.
        var verifier = SshHostKeyVerifier.Pinned(
            SshPublicKey.Parse(await File.ReadAllTextAsync("trusted/ssh_host_ed25519_key.pub", cancellationToken)),
            SshPublicKey.Parse(await File.ReadAllTextAsync("trusted/ssh_host_ecdsa_key.pub", cancellationToken)));
        // </pinned-keys>
        return verifier;
    }

    public static async Task CompareAfterConnectingAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <compare-key>
        // The verified key as an SshPublicKey: compare it with a key you hold, print it as a known_hosts or .pub line, or
        // print the MD5 fingerprint an older inventory lists.
        var expected = SshPublicKey.Parse(await File.ReadAllTextAsync("trusted/ssh_host_ed25519_key.pub", cancellationToken));
        var hostKey = client.HostKey.GetPublicKey();
        Console.WriteLine(hostKey == expected ? "the expected server" : "another key");
        Console.WriteLine(hostKey.ToAuthorizedKeysLine());
        Console.WriteLine(hostKey.GetFingerprint(System.Security.Cryptography.HashAlgorithmName.MD5));
        // </compare-key>
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

    public static async Task RecordKeyAsync(KnownHostsFile knownHosts, SshPublicKey key, string knownHostsPath, CancellationToken cancellationToken)
    {
        // <record-key>
        // A key you trust, for example one read with SshPublicKey.Parse from the server's .pub file.
        knownHosts.Add("new-host.example.com", 22, key, hash: true);
        var result = knownHosts.Check("new-host.example.com", key);   // KnownHostsCheckResult.Match

        // Or straight into the file, as ssh records a new key: one line appended, nothing else rewritten.
        await KnownHostsFile.AppendAsync(knownHostsPath, "new-host.example.com", 22, key, hash: true, cancellationToken: cancellationToken);
        // </record-key>
        _ = result;
    }

    public static void Entries(SshPublicKey hostKey, SshPublicKey hostCa)
    {
        // <known-hosts-entry>
        // One line, without a file: the host as ssh writes it ([host]:port off port 22), hashed as HashKnownHosts does ...
        var line = KnownHostsEntry.ForHost("db.example.com", 2222, hostKey, hash: true).ToLine();

        // ... or any host patterns, with a marker: "@cert-authority *.example.com ssh-ed25519 AAAA... corp CA".
        var caLine = new KnownHostsEntry("*.example.com", hostCa, KnownHostsMarker.CertAuthority, comment: "corp CA").ToLine();
        // </known-hosts-entry>
        _ = (line, caLine);
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
