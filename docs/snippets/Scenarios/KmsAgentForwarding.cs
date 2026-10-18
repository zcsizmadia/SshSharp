using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/kms-agent-forwarding.md.</summary>
internal static class KmsAgentForwarding
{
    // <agent>
    /// <summary>
    /// An agent in this process whose one key is in the KMS: the bastion's programs can ask it to sign, and every request reaches
    /// <see cref="AllowAsync"/> first.
    /// </summary>
    public static SshAgent CreateAgent(Keys.IKeyService kms, ReadOnlyMemory<byte> publicKeyBlob) =>
        SshAgent.FromKeys(SshPrivateKey.FromSigner(new Keys.KmsSigner(kms, "ssh-deploy", publicKeyBlob), comment: "kms:ssh-deploy"));
    // </agent>

    // <filter>
    /// <summary>
    /// What the bastion may do with the forwarded key: list it, and log in with it as deploy to the application servers, recognised by
    /// their host keys. Everything else (another user, another server, an unknown destination, a file signature) is refused and logged.
    /// </summary>
    public static ValueTask<bool> AllowAsync(SshAgentRequest request, IReadOnlySet<SshPublicKey> appServers)
    {
        var allowed = request switch
        {
            { Operation: SshAgentOperation.ListKeys } => true,
            { Purpose: SshSignaturePurpose.Authentication, UserName: "deploy", DestinationHostKey: { } destination } => appServers.Contains(destination),
            _ => false,
        };

        Console.WriteLine($"{(allowed ? "allowed" : "refused")}: {request.Operation} {request.Purpose} {request.Key.Fingerprint} " +
            $"to {request.DestinationHostKey?.Fingerprint ?? "an unknown server"}");
        return ValueTask.FromResult(allowed);
    }
    // </filter>

    // <deploy>
    public static async Task DeployAsync(Keys.IKeyService kms, ReadOnlyMemory<byte> publicKeyBlob, CancellationToken cancellationToken)
    {
        string[] servers = ["app1.example.com", "app2.example.com"];
        var knownHosts = await KnownHostsFile.LoadAsync("/etc/deploy/known_hosts", cancellationToken);
        var appServers = servers.SelectMany(s => knownHosts.Find(s)).Where(e => e.Marker == KnownHostsMarker.None).Select(e => e.GetPublicKey()).ToHashSet();

        var agent = CreateAgent(kms, publicKeyBlob);
        await using var bastion = await SshClient.ConnectAsync("bastion.example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = await agent.GetKeysAsync(cancellationToken),   // the KMS key logs in to the bastion too
            HostKeyVerifier = new KnownHostsVerifier(["/etc/deploy/known_hosts"]),
            ForwardAgent = agent,
            ForwardAgentFilter = (request, _) => AllowAsync(request, appServers),
        }, cancellationToken);

        // ssh on the bastion logs in to each application server with the forwarded key; the key never leaves the KMS.
        foreach (var server in servers)
        {
            var result = await bastion.RunCommandAsync($"ssh -o BatchMode=yes deploy@{server} /usr/local/bin/deploy", cancellationToken);
            result.EnsureSuccess();
        }
    }
    // </deploy>
}
