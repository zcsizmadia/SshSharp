namespace SshSharp.Tests.Integration;

/// <summary>
/// Keys held by OpenSSH's ssh-agent, signing for a real server. Needs SSHSHARP_TEST_AGENT=1 (so a developer's own agent is used only on
/// purpose), SSH_AUTH_SOCK, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER, with the agent's keys in the user's authorized_keys.
/// </summary>
public class AgentInteropTests
{
    [Test]
    public async Task OpenSshsAgent_AnswersTheQueryExtension()
    {
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1 and SSH_AUTH_SOCK are needed.");
            return;
        }

        // OpenSSH's agent has supported query and session-bind@openssh.com since 8.9; whichever reply form it uses, it must parse.
        var extensions = await agent.QueryExtensionsAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        await Assert.That(extensions).Contains("session-bind@openssh.com");
    }

    [Test]
    public async Task TheForwardedAgent_IsUsableOnTheServer()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || RealServer.Endpoint is not var (host, port)
            || string.IsNullOrEmpty(user) || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1, SSH_AUTH_SOCK, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return;
        }

        var keys = await agent.GetKeysAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        await using var client = await SshClient.ConnectAsync(host, port, new SshClientOptions
        {
            UserName = user,
            PrivateKeys = keys,
            ForwardAgent = agent,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);

        // ssh-add on the server lists the keys through the forwarded agent: the same fingerprints as here.
        var result = await client.RunCommandAsync("true", new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await using var session = await client.StartCommandAsync("ssh-add -l", cancellationToken: new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        using var reader = new StreamReader(session.StandardOutput);
        var listed = await reader.ReadToEndAsync();
        await session.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        await Assert.That(session.ExitStatus).IsEqualTo(0);
        foreach (var key in keys)
        {
            await Assert.That(listed).Contains(key.Fingerprint);
        }
    }

    [Test]
    [Arguments("ssh-ed25519")]
    [Arguments("ssh-rsa")]
    public async Task EachAgentKey_Authenticates(string keyType)
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || RealServer.Endpoint is not var (host, port)
            || string.IsNullOrEmpty(user) || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1, SSH_AUTH_SOCK, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER are needed.");
            return;
        }

        var keys = await agent.GetKeysAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        var key = keys.FirstOrDefault(k => k.KeyType == keyType);
        if (key is null)
        {
            Skip.Test($"The agent holds no {keyType} key.");
            return;
        }

        var options = new SshClientOptions
        {
            UserName = user,
            PrivateKeys = [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        await using var client = await SshClient.ConnectAsync(host, port, options, new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        var result = await client.RunCommandAsync("echo agent", new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("agent");
    }
}
