namespace SshSharp.Tests.Integration;

/// <summary>
/// Keyboard-interactive against a real server. sshd offers it through PAM (CI's runner sshd), which asks for the password with one hidden
/// prompt. Needs SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD; skipped where the server does not offer the method.
/// </summary>
public class KeyboardInteractiveInteropTests
{
    [Test]
    public async Task ThePasswordPrompt_IsAnsweredByTheHandler()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var rounds = new List<SshKeyboardInteractiveRequest>();
        var options = new SshClientOptions
        {
            UserName = user,
            KeyboardInteractive = (request, _) =>
            {
                rounds.Add(request);
                IReadOnlyList<string> answers = [.. request.Prompts.Select(p => p.Echo ? "" : password)];
                return ValueTask.FromResult<IReadOnlyList<string>?>(answers);
            },
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };

        SshClient client;
        try
        {
            client = await SshClient.ConnectAsync(host, port, options, new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        }
        catch (SshAuthenticationException) when (rounds.Count == 0)
        {
            // Not offered, or offered with nothing behind it (OpenSSH built without PAM lists the method but has no devices to ask).
            Skip.Test("The server does not ask anything over keyboard-interactive.");
            return;
        }

        await using (client)
        {
            var result = await client.RunCommandAsync("echo kbd", new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
            await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("kbd");
            await Assert.That(rounds.SelectMany(r => r.Prompts).Count(p => !p.Echo)).IsGreaterThanOrEqualTo(1);
        }
    }
}
