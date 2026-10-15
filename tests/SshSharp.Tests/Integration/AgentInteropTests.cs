namespace SshSharp.Tests.Integration;

/// <summary>
/// Keys held by OpenSSH's ssh-agent, signing for a real server. Needs SSHSHARP_TEST_AGENT=1 (so a developer's own agent is used only on
/// purpose), SSH_AUTH_SOCK, SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER, with the agent's keys in the user's authorized_keys.
/// </summary>
[NotInParallel("ssh-agent")] // one agent for all of them, and one test adds constrained keys to it
public class AgentInteropTests
{
    [Test]
    public async Task OpenSshsAgent_AnswersTheQuery_OrDeclinesIt()
    {
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1 and SSH_AUTH_SOCK are needed.");
            return;
        }

        // An agent without the query extension (OpenSSH 9.6, for one) declines it, which is an empty list, not an error. One that
        // answers lists session-bind@openssh.com, which OpenSSH's agent has had since 8.9.
        var extensions = await agent.QueryExtensionsAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        if (extensions.Count > 0)
        {
            await Assert.That(extensions).Contains("session-bind@openssh.com");
        }
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

    [Test]
    public async Task ADestinationConstrainedKey_WorksForItsHost_AndNotForAnother()
    {
        // ssh-add -h: the agent signs with such a key only on a connection bound to a session with an allowed host key
        // (session-bind@openssh.com), for a host-bound authentication request naming that host key.
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var keyDir = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR");
        var sshAdd = FindOnPath(OperatingSystem.IsWindows() ? "ssh-add.exe" : "ssh-add");
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || RealServer.Endpoint is not var (host, port)
            || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(keyDir) || sshAdd is null || SshAgent.FromEnvironment() is not { } agent
            || !File.Exists(Path.Combine(keyDir, "ecdsa256")) || !File.Exists(Path.Combine(keyDir, "ecdsa384")))
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1, SSH_AUTH_SOCK, ssh-add, SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_KEYDIR are needed.");
            return;
        }

        var token = new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

        // A known_hosts file for ssh-add -H: this server's keys under one name, and an unrelated key under another.
        var serverKeys = await SshClient.ScanHostKeysAsync(host, port, cancellationToken: token);
        using var unrelated = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var knownHosts = Path.Combine(Path.GetTempPath(), "sshsharp-constrained-" + Guid.NewGuid().ToString("N"));
        await File.WriteAllLinesAsync(knownHosts,
        [
            .. serverKeys.Select(k => $"sshsharp-destination {k.KeyType} {Convert.ToBase64String(k.PublicKey.Span)}"),
            $"sshsharp-elsewhere {unrelated.KeyType} {Convert.ToBase64String(unrelated.PublicKey.Span)}",
        ], token);

        // Both keys are in the server's authorized_keys; only the agent's constraints tell them apart.
        var allowedFile = Path.Combine(keyDir, "ecdsa256");
        var otherFile = Path.Combine(keyDir, "ecdsa384");
        using var allowedKey = await SshPrivateKey.LoadFileAsync(allowedFile, cancellationToken: token);
        using var otherKey = await SshPrivateKey.LoadFileAsync(otherFile, cancellationToken: token);
        try
        {
            await RunAsync(sshAdd, ["-q", "-H", knownHosts, "-h", "sshsharp-destination", allowedFile], token);
            await RunAsync(sshAdd, ["-q", "-H", knownHosts, "-h", "sshsharp-elsewhere", otherFile], token);
            var held = await agent.GetKeysAsync(token);

            SshClientOptions With(string fingerprint) => new()
            {
                UserName = user,
                PrivateKeys = [held.Single(k => k.Fingerprint == fingerprint)],
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            };

            await using (var client = await SshClient.ConnectAsync(host, port, With(allowedKey.Fingerprint), token))
            {
                var result = await client.RunCommandAsync("echo constrained", token);
                await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("constrained");
            }

            await Assert.That(async () => await SshClient.ConnectAsync(host, port, With(otherKey.Fingerprint), token)).Throws<SshAuthenticationException>();
        }
        finally
        {
            await RunAsync(sshAdd, ["-q", "-d", allowedFile, otherFile], CancellationToken.None, check: false);
            File.Delete(knownHosts);
        }
    }

    private static string? FindOnPath(string name) =>
        (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, name))
            .FirstOrDefault(File.Exists);

    private static async Task RunAsync(string program, string[] arguments, CancellationToken cancellationToken, bool check = true)
    {
        var start = new System.Diagnostics.ProcessStartInfo(program) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = System.Diagnostics.Process.Start(start)!;
        var error = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        if (check && process.ExitCode != 0)
        {
            throw new InvalidOperationException($"{Path.GetFileName(program)} failed ({process.ExitCode}): {error}");
        }
    }

    [Test]
    public async Task KeysAreAdded_Used_AndRemoved()
    {
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1 and SSH_AUTH_SOCK are needed.");
            return;
        }

        var token = new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;
        using var key = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256, "added-by-sshsharp");
        using var authority = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var rsa = SshPrivateKey.Generate(SshKeyType.Rsa, rsaBits: 2048);
        using var certified = rsa.WithCertificate(SshCertificate.Parse(SshSharp.Tests.Keys.TestKeys.CertificateLine(
            SshSharp.Tests.Keys.TestKeys.Certificate(authority, rsa.PublicKey.ToArray(), SshCertificateType.User, ["tester"]))));
        try
        {
            // A plain key with a lifetime, and an RSA key with its certificate, as ssh-add -t 600 and ssh-add with a -cert.pub do.
            await agent.AddKeyAsync(key, new SshAgentKeyConstraints { Lifetime = TimeSpan.FromMinutes(10) }, token);
            await agent.AddKeyAsync(certified, cancellationToken: token);

            var keys = await agent.GetKeysAsync(token);
            var held = keys.Single(k => k.PublicKey.Span.SequenceEqual(key.PublicKey.Span));
            await Assert.That(held.Comment).IsEqualTo("added-by-sshsharp");
            await Assert.That(keys.Any(k => k.PublicKey.Span.SequenceEqual(certified.PublicKey.Span))).IsTrue();

            var message = "signed by ssh-agent"u8.ToArray();
            var signature = await SshSignature.SignAsync(held, message, "file", cancellationToken: token);
            await Assert.That(signature.Verify(message, "file")).IsTrue();

            // Locking is left to the unit tests: a locked agent here would empty the key list of tests that authenticate with it in
            // parallel (they are not all in this class).
        }
        finally
        {
            await agent.RemoveKeyAsync(key, token);
            await agent.RemoveKeyAsync(certified, token);
        }

        await Assert.That((await agent.GetKeysAsync(token)).Any(k => k.PublicKey.Span.SequenceEqual(key.PublicKey.Span))).IsFalse();
    }

    [Test]
    public async Task ADestinationConstrainedKey_SignsInOnlyWhereItIsAllowed()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_AGENT") != "1" || RealServer.Endpoint is not var (host, port)
            || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password) || SshAgent.FromEnvironment() is not { } agent)
        {
            Skip.Test("SSHSHARP_TEST_AGENT=1, SSH_AUTH_SOCK, SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var token = new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;
        var trustAll = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true));
        var hostKeys = (await SshClient.ScanHostKeysAsync(host, port, cancellationToken: token)).Select(k => new SshAgentHostKey(k.PublicKey)).ToList();
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "restricted-by-sshsharp");
        var marker = "sshsharp-restricted-" + Guid.NewGuid().ToString("N");

        // The key may sign in to this server only; it goes into the account's authorized_keys for the test.
        await using var admin = await SshClient.ConnectAsync(host, port, new SshClientOptions { UserName = user, Password = password, HostKeyVerifier = trustAll }, token);
        var line = $"{key.KeyType} {Convert.ToBase64String(key.PublicKey.Span)} {marker}";
        await Assert.That((await admin.RunCommandAsync($"mkdir -p ~/.ssh && echo '{line}' >> ~/.ssh/authorized_keys", token)).ExitStatus).IsEqualTo(0);
        try
        {
            async Task<bool> SignsInAsync()
            {
                var held = (await agent.GetKeysAsync(token)).Single(k => k.PublicKey.Span.SequenceEqual(key.PublicKey.Span));
                try
                {
                    await using var client = await SshClient.ConnectAsync(host, port,
                        new SshClientOptions { UserName = user, PrivateKeys = [held], HostKeyVerifier = trustAll }, token);
                    return (await client.RunCommandAsync("echo restricted", token)).StandardOutputText.Trim() == "restricted";
                }
                catch (SshAuthenticationException)
                {
                    return false;
                }
            }

            await agent.AddKeyAsync(key, new SshAgentKeyConstraints
            {
                Destinations = [new SshAgentDestination { To = new SshAgentHost(host, hostKeys) }],
            }, token);

            // Outside a bound session (SshSignature uses a plain agent connection), OpenSSH's agent refuses a constrained key.
            var held = (await agent.GetKeysAsync(token)).Single(k => k.PublicKey.Span.SequenceEqual(key.PublicKey.Span));
            await Assert.That(async () => await SshSignature.SignAsync(held, "unbound"u8.ToArray(), "file", cancellationToken: token)).Throws<SshException>();

            // Bound to this server's session, it signs in.
            await Assert.That(await SignsInAsync()).IsTrue();

            // Restricted to another host instead, the agent refuses it here.
            await agent.RemoveKeyAsync(key, token);
            await agent.AddKeyAsync(key, new SshAgentKeyConstraints
            {
                Destinations = [new SshAgentDestination { To = new SshAgentHost("elsewhere.invalid", [new SshAgentHostKey(other.PublicKey)]) }],
            }, token);
            await Assert.That(await SignsInAsync()).IsFalse();
        }
        finally
        {
            try
            {
                await agent.RemoveKeyAsync(key, token);
            }
            catch (SshException)
            {
                // Not added (the test failed before that).
            }

            await admin.RunCommandAsync($"sed -i '/{marker}/d' ~/.ssh/authorized_keys", token);
        }
    }
}
