using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;
using Round = SshSharp.Tests.Protocol.FakeSessionServer.KeyboardRound;

namespace SshSharp.Tests;

/// <summary>Keyboard-interactive authentication (RFC 4256), the banner, and the order methods are tried in.</summary>
public class KeyboardInteractiveTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static readonly Round PasswordRound = new("", "", [("Password: ", false)], [TestSecrets.Password]);

    private static readonly Round CodeRound = new("Two-factor", "Enter the code from your app.", [("Code: ", true)], ["123456"]);

    private static async Task<SshClient> ConnectAsync(
        FakeSessionServer server,
        Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>>? respond = null,
        string? password = null,
        IReadOnlyList<SshPrivateKey>? keys = null,
        Func<string, CancellationToken, ValueTask>? banner = null)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = password,
            PrivateKeys = keys ?? [],
            KeyboardInteractive = respond,
            AuthenticationBanner = banner,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private static Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>> Answers(
        List<SshKeyboardInteractiveRequest> seen, params string[][] rounds)
    {
        var next = 0;
        return (request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult<IReadOnlyList<string>?>(next < rounds.Length ? rounds[next++] : null);
        };
    }

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }

    [Test]
    public async Task TheHandlerAnswersEachRound_AndSeesTheServersQuestions()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [PasswordRound, CodeRound] };
        var seen = new List<SshKeyboardInteractiveRequest>();
        await using var client = await ConnectAsync(server, Answers(seen, [TestSecrets.Password], ["123456"]));

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(seen.Count).IsEqualTo(2);
        await Assert.That(seen[0].Prompts.Single()).IsEqualTo(new SshAuthenticationPrompt("Password: ", false));
        await Assert.That(seen[1].Name).IsEqualTo("Two-factor");
        await Assert.That(seen[1].Instruction).IsEqualTo("Enter the code from your app.");
        await Assert.That(seen[1].Prompts.Single()).IsEqualTo(new SshAuthenticationPrompt("Code: ", true));
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "keyboard-interactive" });
    }

    [Test]
    public async Task ANullAnswer_IsSentAsAnEmptyOne()
    {
        // A handler that ignores the nullability of its answers must not break the message: a null answer is an empty one.
        var blank = new Round("", "", [("Optional note: ", true)], [""]);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [blank] };
        await using var client = await ConnectAsync(server, (_, _) => ValueTask.FromResult<IReadOnlyList<string>?>([null!]));
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.KeyboardInteractiveAnswers.Single()).IsEquivalentTo(new[] { "" });
    }

    [Test]
    public async Task ARoundWithoutQuestions_IsAnsweredWithNothing()
    {
        var notice = new Round("", "Your password expires in 3 days.", [], []);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [notice, PasswordRound] };
        var seen = new List<SshKeyboardInteractiveRequest>();
        await using var client = await ConnectAsync(server, Answers(seen, [], [TestSecrets.Password]));
        await Assert.That(seen[0].Prompts.Count).IsEqualTo(0);
        await Assert.That(server.KeyboardInteractiveAnswers[0].Length).IsEqualTo(0);
    }

    [Test]
    public async Task WrongAnswers_FailWithTheMethodsTheServerAccepts()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [PasswordRound] };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Answers([], [TestSecrets.New()])));
        await Assert.That(error!.AllowedMethods).IsEquivalentTo(new[] { "keyboard-interactive" });
    }

    [Test]
    public async Task APasswordAlone_AnswersAServerThatTakesItOnlyThroughKeyboardInteractive()
    {
        // sshd with PasswordAuthentication no and KbdInteractiveAuthentication yes (PAM) asks for the password this way.
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [PasswordRound] };
        await using var client = await ConnectAsync(server, password: TestSecrets.Password);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "keyboard-interactive" });
    }

    [Test]
    public async Task APasswordAlone_UsesThePasswordMethod_WhenTheServerOffersIt()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive", "password"], KeyboardInteractiveRounds = [PasswordRound] };
        await using var client = await ConnectAsync(server, password: TestSecrets.Password);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "password" });
    }

    [Test]
    public async Task APasswordAlone_IsNotSentToAVisibleQuestion_OrASecondRound()
    {
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [CodeRound] })
        {
            await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, password: TestSecrets.Password));
            await Assert.That(server.KeyboardInteractiveAnswers).IsEmpty();
        }

        // A second hidden question (a one-time code after the password) does not get the password again.
        var hiddenCode = CodeRound with { Prompts = [("Code: ", false)] };
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [PasswordRound, hiddenCode] })
        {
            await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, password: TestSecrets.Password));
            await Assert.That(server.KeyboardInteractiveAnswers.Count).IsEqualTo(1);
        }
    }

    [Test]
    public async Task AHandlerThatGivesUp_FallsThroughToThePassword()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive", "password"], KeyboardInteractiveRounds = [PasswordRound] };
        var seen = new List<SshKeyboardInteractiveRequest>();
        await using var client = await ConnectAsync(server, Answers(seen), password: TestSecrets.Password);
        await Assert.That(seen.Count).IsEqualTo(1);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "keyboard-interactive", "password" });
    }

    [Test]
    public async Task AHandlerReturningTheWrongNumberOfAnswers_IsABug()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [PasswordRound] };
        await Assert.ThrowsAsync<InvalidOperationException>(() => ConnectAsync(server, Answers([], ["a", "b"])));
    }

    [Test]
    public async Task AServerThatNeverStopsAsking_IsCutOff()
    {
        await using var server = new FakeSessionServer
        {
            AdvertisedMethods = ["keyboard-interactive"],
            KeyboardInteractiveRounds = [PasswordRound],
            EndlessKeyboardInteractive = true,
        };
        var rounds = 0;
        var error = await Assert.ThrowsAsync<SshException>(() => ConnectAsync(server, (_, _) =>
        {
            rounds++;
            return ValueTask.FromResult<IReadOnlyList<string>?>([TestSecrets.Password]);
        }));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(rounds).IsEqualTo(SshUserAuth.MaxRounds);
    }

    [Test]
    public async Task TooManyPrompts_AreAProtocolError()
    {
        var flood = new Round("", "", [.. Enumerable.Range(0, SshUserAuth.MaxPrompts + 1).Select(i => ($"Q{i}: ", true))], []);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [flood] };
        var called = false;
        await Assert.ThrowsAsync<SshProtocolException>(() => ConnectAsync(server, (_, _) =>
        {
            called = true;
            return ValueTask.FromResult<IReadOnlyList<string>?>([]);
        }));
        await Assert.That(called).IsFalse();
    }

    [Test]
    public async Task PublicKeyThenKeyboardInteractive_AsSshdsAuthenticationMethodsRequires()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer
        {
            AuthorizedKeys = [blob],
            AuthenticationChain = ["publickey", "keyboard-interactive"],
            KeyboardInteractiveRounds = [CodeRound],
        };
        await using var client = await ConnectAsync(server, Answers([], ["123456"]), keys: [key]);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "publickey", "publickey-signed:ssh-ed25519", "keyboard-interactive" });
    }

    [Test]
    public async Task APartialSuccessThatAsksForAnEarlierMethod_WalksTheOrderAgain()
    {
        // AuthenticationMethods password,publickey: the key comes first in the client's order, but the server takes it only after the password.
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer { AuthorizedKeys = [blob], AuthenticationChain = ["password", "publickey"] };
        await using var client = await ConnectAsync(server, password: TestSecrets.Password, keys: [key]);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "password", "publickey", "publickey-signed:ssh-ed25519" });
    }

    [Test]
    public async Task TheBanner_ReachesTheCallback()
    {
        await using var server = new FakeSessionServer { AuthenticationBanner = "Authorized use only.\n" };
        var banners = new List<string>();
        await using var client = await ConnectAsync(server, password: TestSecrets.Password, banner: (text, _) =>
        {
            banners.Add(text);
            return ValueTask.CompletedTask;
        });
        await Assert.That(banners).IsEquivalentTo(new[] { "Authorized use only.\n" });

        // Without a callback it is skipped.
        await using var quiet = new FakeSessionServer { AuthenticationBanner = "Authorized use only.\n" };
        await using var other = await ConnectAsync(quiet, password: TestSecrets.Password);
        await Assert.That(other.IsConnected).IsTrue();
    }

    [Test]
    [Arguments("", "publickey,keyboard-interactive,password")]
    [Arguments("PreferredAuthentications password,gssapi-with-mic,publickey,password\n", "password,publickey")]
    [Arguments("KbdInteractiveAuthentication no\n", "publickey,password")]
    [Arguments("ChallengeResponseAuthentication no\nPasswordAuthentication no\n", "publickey")]
    [Arguments("PubkeyAuthentication no\nPreferredAuthentications keyboard-interactive,publickey\n", "keyboard-interactive")]
    public async Task TheConfiguredOrder_FollowsPreferredAuthenticationsAndTheMethodSwitches(string config, string expected)
    {
        var resolve = new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = Path.GetTempPath() };
        var hostConfig = SshConfig.Parse(config).Resolve("h", resolve);
        await Assert.That(string.Join(",", SshClient.AuthenticationOrder(hostConfig))).IsEqualTo(expected);
    }
}
