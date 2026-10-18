using System.Collections.Concurrent;
using System.Text;

namespace SshSharp.Tests.Integration;

/// <summary>
/// An in-process agent (SshAgent.FromKeys) forwarded to a real OpenSSH server, where ssh-add, ssh-keygen and ssh use it, with and
/// without ForwardAgentFilter (#275). Needs what AgentInteropTests needs (SSHSHARP_TEST_AGENT=1, SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER),
/// and SSHSHARP_TEST_KEYDIR with the ed25519 key in the user's authorized_keys; no agent process is used.
/// </summary>
public class InProcessAgentInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    private static string? KeyFile =>
        Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir && File.Exists(Path.Combine(dir, "ed25519")) ? Path.Combine(dir, "ed25519") : null;

    /// <summary>The port sshd listens on as seen from the server itself (a container maps it), for logging in onward from there.</summary>
    private static int ServerSidePort => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD_INNER_PORT") is { } inner
        ? int.Parse(inner, System.Globalization.CultureInfo.InvariantCulture)
        : RealServer.Endpoint!.Value.Port;

    private static bool Configured(out string user, out string keyFile)
    {
        user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER") ?? string.Empty;
        keyFile = KeyFile ?? string.Empty;
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || !RealServer.IsAvailable || user.Length == 0 || keyFile.Length == 0
            || !RealServer.IsOpenSsh || RealServer.IsWindows)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1, SSHSHARP_TEST_SSHD (OpenSSH on Unix), SSHSHARP_TEST_USER and SSHSHARP_TEST_KEYDIR are needed.");
            return false;
        }

        return true;
    }

    private static async Task<SshClient> ConnectAsync(string user, SshAgent agent, Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? filter = null)
    {
        var (host, port) = RealServer.Endpoint!.Value;
        return await SshClient.ConnectAsync(host, port, new SshClientOptions
        {
            UserName = user,
            PrivateKeys = await agent.GetKeysAsync(Timeout()), // authentication through the in-process agent too
            ForwardAgent = agent,
            ForwardAgentFilter = filter,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, Timeout());
    }

    private static async Task<(int Status, string Output)> RunAsync(SshClient client, string command)
    {
        var result = await client.RunCommandAsync(command, options: null, standardInput: null, Timeout());
        return ((int)(result.ExitStatus ?? -1), result.StandardOutputText);
    }

    [Test]
    public async Task SshAddOnTheServer_ListsTheInProcessAgentsKeys()
    {
        if (!Configured(out var user, out var keyFile))
        {
            return;
        }

        using var key = await SshPrivateKey.LoadAsync(keyFile);
        using var extra = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256, "generated");
        await using var client = await ConnectAsync(user, SshAgent.FromKeys(key, extra));

        var (status, listed) = await RunAsync(client, "ssh-add -l");

        await Assert.That(status).IsEqualTo(0);
        await Assert.That(listed).Contains(key.Fingerprint);
        await Assert.That(listed).Contains(extra.Fingerprint);
    }

    [Test]
    public async Task TheFilter_DecidesWhatTheServersProgramsGet()
    {
        if (!Configured(out var user, out var keyFile))
        {
            return;
        }

        using var key = await SshPrivateKey.LoadAsync(keyFile);
        using var hidden = SshPrivateKey.Generate(SshKeyType.Ed25519, "hidden");
        var asked = new ConcurrentQueue<SshAgentRequest>();
        await using var client = await ConnectAsync(user, SshAgent.FromKeys(key, hidden), (request, _) =>
        {
            asked.Enqueue(request);
            return ValueTask.FromResult(request.Key != hidden.GetPublicKey() && request.Namespace != "git");
        });

        // ssh-add sees only what the filter lets through.
        var (status, listed) = await RunAsync(client, "ssh-add -l");
        await Assert.That(status).IsEqualTo(0);
        await Assert.That(listed).Contains(key.Fingerprint);
        await Assert.That(listed).DoesNotContain(hidden.Fingerprint);

        // ssh-keygen -Y signs through the forwarded agent: allowed in the "file" namespace, refused in "git".
        var publicKey = key.GetPublicKey().ToAuthorizedKeysLine();
        string Sign(string @namespace) =>
            $"f=$(mktemp) && printf '%s\\n' '{publicKey}' > \"$f\" && printf hello | ssh-keygen -q -Y sign -n {@namespace} -f \"$f\"; s=$?; rm -f \"$f\"; exit $s";
        var (signed, armored) = await RunAsync(client, Sign("file"));
        await Assert.That(signed).IsEqualTo(0);
        var signature = SshSignature.Parse(armored);
        await Assert.That(signature.Verify(Encoding.ASCII.GetBytes("hello"), "file")).IsTrue();
        await Assert.That((await RunAsync(client, Sign("git"))).Status).IsNotEqualTo(0);

        var signs = asked.Where(r => r.Operation == SshAgentOperation.Sign).ToArray();
        await Assert.That(signs.Select(r => r.Namespace ?? string.Empty)).IsEquivalentTo(new[] { "file", "git" });
        await Assert.That(signs.All(r => r.Purpose == SshSignaturePurpose.FileSignature)).IsTrue();
        await Assert.That(signs[0].ForwardingHostKeys[0]).IsEqualTo(client.HostKey.GetPublicKey());
    }

    [Test]
    public async Task SshOnTheServer_LogsInOnward_AndTheFilterSeesTheDestination()
    {
        if (!Configured(out var user, out var keyFile))
        {
            return;
        }

        using var key = await SshPrivateKey.LoadAsync(keyFile);
        var asked = new ConcurrentQueue<SshAgentRequest>();
        await using var client = await ConnectAsync(user, SshAgent.FromKeys(key), (request, _) =>
        {
            asked.Enqueue(request);
            return ValueTask.FromResult(true);
        });

        // ssh on the server logs in to the same server again with the forwarded key, as a hop to the next host would.
        var (status, output) = await RunAsync(client,
            $"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p {ServerSidePort} {user}@127.0.0.1 echo onward");
        await Assert.That(status).IsEqualTo(0);
        await Assert.That(output.Trim()).IsEqualTo("onward");

        var login = asked.Last(r => r.Operation == SshAgentOperation.Sign);
        await Assert.That(login.Purpose).IsEqualTo(SshSignaturePurpose.Authentication);
        await Assert.That(login.UserName).IsEqualTo(user);
        await Assert.That(login.Key).IsEqualTo(key.GetPublicKey());

        // OpenSSH 8.9 and later bind the agent connection to the session they log in to: the filter learns that server's host key.
        var version = System.Text.RegularExpressions.Regex.Match((await RunAsync(client, "ssh -V 2>&1")).Output, @"OpenSSH_(\d+)\.(\d+)");
        var binds = version.Success && (int.Parse(version.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) * 100)
            + int.Parse(version.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture) >= 809;
        var (host, port) = RealServer.Endpoint!.Value;
        var serverKeys = await SshClient.ScanHostKeysAsync(host, port, cancellationToken: Timeout());
        if (binds)
        {
            await Assert.That(login.DestinationHostKey).IsNotNull();
        }

        if (login.DestinationHostKey is { } destination)
        {
            await Assert.That(serverKeys.Select(k => k.GetPublicKey())).Contains(destination);
        }
    }
}
