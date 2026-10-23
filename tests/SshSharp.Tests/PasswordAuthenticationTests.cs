using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;
using Round = SshSharp.Tests.Protocol.FakeSessionServer.KeyboardRound;

namespace SshSharp.Tests;

/// <summary>
/// PasswordProvider and NumberOfPasswordPrompts, password change requests (RFC 4252 section 8), and the per-attempt detail of
/// SshAuthenticationException.
/// </summary>
public class PasswordAuthenticationTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A password made up for one test, never a literal.</summary>
    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions options, CancellationToken cancellationToken = default)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, cancellationToken == default ? Timeout() : cancellationToken);
    }

    private static SshClientOptions Options(
        string? password = null,
        Func<SshPasswordPrompt, CancellationToken, ValueTask<string?>>? provider = null,
        int prompts = 3,
        Func<SshPasswordChangeRequest, CancellationToken, ValueTask<string?>>? changePassword = null,
        IReadOnlyList<SshPrivateKey>? keys = null) =>
        new()
        {
            UserName = "tester",
            Password = password,
            PasswordProvider = provider,
            NumberOfPasswordPrompts = prompts,
            ChangePassword = changePassword,
            PrivateKeys = keys ?? [],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };

    /// <summary>A provider that answers from a list (null once it runs out) and records each prompt.</summary>
    private static Func<SshPasswordPrompt, CancellationToken, ValueTask<string?>> Provider(List<SshPasswordPrompt> seen, params string[] answers)
    {
        var next = 0;
        return (prompt, _) =>
        {
            seen.Add(prompt);
            return ValueTask.FromResult(next < answers.Length ? answers[next++] : null);
        };
    }

    private static Func<SshPasswordChangeRequest, CancellationToken, ValueTask<string?>> Changer(List<SshPasswordChangeRequest> seen, params string[] answers)
    {
        var next = 0;
        return (request, _) =>
        {
            seen.Add(request);
            return ValueTask.FromResult(next < answers.Length ? answers[next++] : null);
        };
    }

    // PasswordProvider and NumberOfPasswordPrompts.

    [Test]
    public async Task TheProvider_IsNotAsked_WhenAKeyLogsIn()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), AuthorizedKeys = [blob], AdvertisedMethods = ["publickey", "password"] };
        var seen = new List<SshPasswordPrompt>();
        await using var client = await ConnectAsync(server, Options(provider: Provider(seen, server.Password), keys: [key]));

        await Assert.That(seen).IsEmpty();
        await Assert.That(server.PasswordsReceived).IsEmpty();
    }

    [Test]
    public async Task TheProvider_IsAskedOnceTheKeysAreRefused_WithWhatAPromptShows()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), AdvertisedMethods = ["publickey", "password"] };
        var seen = new List<SshPasswordPrompt>();
        await using var client = await ConnectAsync(server, Options(provider: Provider(seen, server.Password), keys: [key]));

        var prompt = seen.Single();
        await Assert.That(prompt.UserName).IsEqualTo("tester");
        await Assert.That(prompt.Host).IsNull(); // connected over a stream
        await Assert.That(prompt.Method).IsEqualTo("password");
        await Assert.That(prompt.Attempt).IsEqualTo(1);
        await Assert.That(prompt.IsRetry).IsFalse();
    }

    [Test]
    public async Task ARefusedPassword_IsAskedForAgain_UntilOneWorks()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        await using var client = await ConnectAsync(server, Options(provider: Provider(seen, TestSecrets.New(), TestSecrets.New(), server.Password)));

        await Assert.That(seen.Select(p => p.Attempt)).IsEquivalentTo(new[] { 1, 2, 3 });
        await Assert.That(seen.Select(p => p.IsRetry)).IsEquivalentTo(new[] { false, true, true });
        await Assert.That(server.PasswordsReceived.Count).IsEqualTo(3);
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task NumberOfPasswordPrompts_BoundsTheProvider_AndEachRefusalIsListed(int prompts)
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        var wrong = Enumerable.Range(0, 10).Select(_ => TestSecrets.New()).ToArray();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(provider: Provider(seen, wrong), prompts: prompts)));

        await Assert.That(seen.Count).IsEqualTo(prompts);
        await Assert.That(error!.Attempts).IsEquivalentTo(Enumerable.Repeat(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Rejected), prompts));
        foreach (var password in wrong)
        {
            await Assert.That(error.Message).DoesNotContain(password);
        }
    }

    [Test]
    public async Task TheDefault_IsThreePrompts_AsInSsh()
    {
        await Assert.That(new SshClientOptions { UserName = "u", HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)) }.NumberOfPasswordPrompts).IsEqualTo(3);
        await Assert.That(() => new SshClientOptions { UserName = "u", HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)), NumberOfPasswordPrompts = -1 })
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task ZeroPrompts_NeverAsks()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(provider: Provider(seen, server.Password), prompts: 0)));
        await Assert.That(seen).IsEmpty();
        await Assert.That(server.PasswordsReceived).IsEmpty();
    }

    [Test]
    public async Task AProviderThatReturnsNull_StopsAsking_AndIsListedAsDeclined()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(provider: Provider(seen))));

        await Assert.That(seen.Count).IsEqualTo(1);
        await Assert.That(server.PasswordsReceived).IsEmpty();
        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Declined));
    }

    [Test]
    public async Task TheGivenPassword_IsTriedFirst_AndTheProviderOnlyAfterItIsRefused()
    {
        var stale = TestSecrets.New();
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        await using var client = await ConnectAsync(server, Options(password: stale, provider: Provider(seen, server.Password), prompts: 1));

        await Assert.That(server.PasswordsReceived).IsEquivalentTo(new[] { stale, server.Password });
        await Assert.That(seen.Single().Attempt).IsEqualTo(1); // the given password is not a prompt
        await Assert.That(seen.Single().IsRetry).IsTrue();
    }

    [Test]
    public async Task TheGivenPassword_WhenRight_NeverAsks()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        var seen = new List<SshPasswordPrompt>();
        await using var client = await ConnectAsync(server, Options(password: server.Password, provider: Provider(seen)));
        await Assert.That(seen).IsEmpty();
    }

    [Test]
    public async Task CancellingInTheProvider_CancelsTheConnect()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New() };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var options = Options(provider: async (_, ct) =>
        {
            await cts.CancelAsync();
            ct.ThrowIfCancellationRequested();
            return null;
        });
        await Assert.ThrowsAsync<OperationCanceledException>(() => ConnectAsync(server, options, cts.Token));
        await Assert.That(server.PasswordsReceived).IsEmpty();
    }

    [Test]
    public async Task TheProvider_AnswersAServerThatAsksForThePasswordThroughKeyboardInteractive()
    {
        // sshd with PAM and PasswordAuthentication no: each try is a keyboard-interactive exchange with one hidden question.
        var password = TestSecrets.New();
        var round = new Round("", "", [("Password: ", false)], [password]);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [round] };
        var seen = new List<SshPasswordPrompt>();
        var wrong = TestSecrets.New();
        await using var client = await ConnectAsync(server, Options(provider: Provider(seen, wrong, password)));

        await Assert.That(seen.Select(p => p.Method)).IsEquivalentTo(new[] { "keyboard-interactive", "keyboard-interactive" });
        await Assert.That(seen[1].IsRetry).IsTrue();
        await Assert.That(server.KeyboardInteractiveAnswers.Select(a => a.Single())).IsEquivalentTo(new[] { wrong, password });
    }

    [Test]
    public async Task TheProvider_IsNotAskedForAKeyboardInteractiveQuestionThatIsNotAPassword()
    {
        var code = new Round("", "", [("Verification code: ", true)], ["000000"]);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [code] };
        var seen = new List<SshPasswordPrompt>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(provider: Provider(seen, TestSecrets.New()))));

        await Assert.That(seen).IsEmpty();
        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("keyboard-interactive", SshAuthenticationOutcome.Declined));
    }

    [Test]
    public async Task AKeyboardInteractiveHandler_AnswersKeyboardInteractive_AndTheProviderThePasswordMethod()
    {
        var password = TestSecrets.New();
        var round = new Round("", "", [("Password: ", false)], [TestSecrets.New()]);
        await using var server = new FakeSessionServer
        {
            Password = password,
            AdvertisedMethods = ["keyboard-interactive", "password"],
            KeyboardInteractiveRounds = [round],
        };
        var handled = 0;
        var seen = new List<SshPasswordPrompt>();
        var options = new SshClientOptions
        {
            UserName = "tester",
            PasswordProvider = Provider(seen, password),
            KeyboardInteractive = (_, _) =>
            {
                handled++;
                return ValueTask.FromResult<IReadOnlyList<string>?>(null);
            },
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        await using var client = await ConnectAsync(server, options);

        await Assert.That(handled).IsEqualTo(1);
        await Assert.That(seen.Single().Method).IsEqualTo("password");
    }

    // Password change requests (RFC 4252 section 8).

    [Test]
    public async Task AnExpiredPassword_IsChanged_AndTheConnectSucceeds()
    {
        var replacement = TestSecrets.New();
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true };
        var seen = new List<SshPasswordChangeRequest>();
        await using var client = await ConnectAsync(server, Options(password: server.Password, changePassword: Changer(seen, replacement)));

        var request = seen.Single();
        await Assert.That(request.Prompt).IsEqualTo("Your password has expired.");
        await Assert.That(request.Language).IsEqualTo("en");
        await Assert.That(request.UserName).IsEqualTo("tester");
        await Assert.That(request.Attempt).IsEqualTo(1);

        // The change request repeats the old password, with the new one.
        await Assert.That(server.PasswordsReceived).IsEquivalentTo(new[] { server.Password, server.Password });
        await Assert.That(server.ChangedPassword).IsEqualTo(replacement);
    }

    [Test]
    public async Task ARefusedNewPassword_IsAskedForAgain_WithTheServersReason()
    {
        var replacement = TestSecrets.New();
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true, NewPasswordsRefused = 1 };
        var seen = new List<SshPasswordChangeRequest>();
        await using var client = await ConnectAsync(server, Options(password: server.Password, changePassword: Changer(seen, "short", replacement)));

        await Assert.That(seen.Select(r => r.Attempt)).IsEquivalentTo(new[] { 1, 2 });
        await Assert.That(seen[1].Prompt).IsEqualTo("Password too short.");
        await Assert.That(server.ChangedPassword).IsEqualTo(replacement);
    }

    [Test]
    public async Task AServerThatRefusesEveryNewPassword_IsAskedABoundedNumberOfTimes()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true, NewPasswordsRefused = 100 };
        var asked = 0;
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(password: server.Password, changePassword: (_, _) =>
        {
            asked++;
            return ValueTask.FromResult<string?>(TestSecrets.New());
        })));

        await Assert.That(asked).IsEqualTo(SshClient.MaxPasswordChangeRequests);
        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.PasswordChangeRequired));
    }

    [Test]
    public async Task WithoutAHandler_AnExpiredPassword_FailsAsAnAuthenticationFailure_AndIsNotAskedForAgain()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true };
        var seen = new List<SshPasswordPrompt>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(provider: Provider(seen, server.Password, server.Password))));

        await Assert.That(seen.Count).IsEqualTo(1); // the password was right; another one would not help
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(error.Attempts.Single().Outcome).IsEqualTo(SshAuthenticationOutcome.PasswordChangeRequired);
        await Assert.That(error.Message).Contains("PasswordChangeRequired");
    }

    [Test]
    public async Task DecliningTheChange_SendsNoNewPassword()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true };
        var seen = new List<SshPasswordChangeRequest>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(password: server.Password, changePassword: Changer(seen))));

        await Assert.That(seen.Count).IsEqualTo(1);
        await Assert.That(server.NewPasswordsReceived).IsEmpty();
        await Assert.That(error!.Attempts.Single().Outcome).IsEqualTo(SshAuthenticationOutcome.PasswordChangeRequired);
    }

    [Test]
    public async Task AChangeTheServerRefuses_IsListedAsRejected()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true, NewPasswordsRefused = -1 };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server,
            Options(password: server.Password, changePassword: Changer([], TestSecrets.New()))));

        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Rejected));
        await Assert.That(server.ChangedPassword).IsNull();
    }

    [Test]
    public async Task AChangeWithPartialSuccess_GoesOnToTheNextMethod()
    {
        using var key = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out var blob));
        var replacement = TestSecrets.New();
        await using var server = new FakeSessionServer
        {
            Password = TestSecrets.New(),
            PasswordExpired = true,
            AuthorizedKeys = [blob],
            AuthenticationChain = ["password", "publickey"],
        };
        await using var client = await ConnectAsync(server, Options(password: server.Password, changePassword: Changer([], replacement), keys: [key]));

        await Assert.That(server.ChangedPassword).IsEqualTo(replacement);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task CancellingInTheChangeHandler_CancelsTheConnect()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), PasswordExpired = true };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var options = Options(password: server.Password, changePassword: async (_, ct) =>
        {
            await cts.CancelAsync();
            ct.ThrowIfCancellationRequested();
            return null;
        });
        await Assert.ThrowsAsync<OperationCanceledException>(() => ConnectAsync(server, options, cts.Token));
        await Assert.That(server.NewPasswordsReceived).IsEmpty();
    }

    // What SshAuthenticationException.Attempts lists.

    [Test]
    public async Task EachRefusedKey_IsListedByFingerprint_AndTheMessageNamesNoUser()
    {
        using var first = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var second = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], UserName = "someone-specific" };
        var options = new SshClientOptions
        {
            UserName = "someone-specific",
            PrivateKeys = [first, second],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, options));

        await Assert.That(error!.Attempts).IsEquivalentTo(new[]
        {
            new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.Rejected, first.Fingerprint),
            new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.Rejected, second.Fingerprint),
        });
        await Assert.That(error.Message).Contains(first.Fingerprint);
        await Assert.That(error.Message).DoesNotContain("someone-specific");
    }

    [Test]
    public async Task CredentialsForAMethodTheServerDoesNotOffer_AreListedAsNotOffered()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), AdvertisedMethods = ["password"] };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(password: TestSecrets.New(), keys: [key])));

        await Assert.That(error!.Attempts).IsEquivalentTo(new[]
        {
            new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.NotOffered),
            new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Rejected),
        });
    }

    [Test]
    public async Task AKeyWithNoAlgorithmTheServerAccepts_IsListedAsSuch()
    {
        using var ecdsa = SshPrivateKey.Generate(SshKeyType.EcdsaNistp256);
        await using var server = new FakeSessionServer(new FakeServerOptions { ServerSigAlgs = "ssh-ed25519" }) { AdvertisedMethods = ["publickey"] };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(keys: [ecdsa])));

        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.NoAcceptedAlgorithm, ecdsa.Fingerprint));
    }

    [Test]
    public async Task AKeyWhoseSignerDeclines_IsListedAsSigningFailed()
    {
        using var inner = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var key = SshPrivateKey.FromSigner(new DecliningSigner(inner.PublicKey));
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey"], AuthorizedKeys = [inner.PublicKey.ToArray()] };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options(keys: [key])));

        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.SigningFailed, key.Fingerprint));
    }

    [Test]
    public async Task AKeyboardInteractiveHandlerThatGivesUp_IsListedAsDeclined()
    {
        var round = new Round("", "", [("Code: ", true)], ["000000"]);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["keyboard-interactive"], KeyboardInteractiveRounds = [round] };
        var options = new SshClientOptions
        {
            UserName = "tester",
            KeyboardInteractive = (_, _) => ValueTask.FromResult<IReadOnlyList<string>?>(null),
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, options));
        await Assert.That(error!.Attempts.Single()).IsEqualTo(new SshAuthenticationAttempt("keyboard-interactive", SshAuthenticationOutcome.Declined));
    }

    [Test]
    public async Task KerberosThatCannotRunHere_IsListedAsUnavailable()
    {
        await using var server = new FakeSessionServer { Password = TestSecrets.New(), AdvertisedMethods = ["gssapi-with-mic", "password"] };
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.New(),
            Gssapi = new SshGssapiOptions { TargetHost = "kdc-test.example", ContextFactory = (_, _, _) => throw new PlatformNotSupportedException() },
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, options));

        await Assert.That(error!.Attempts).IsEquivalentTo(new[]
        {
            new SshAuthenticationAttempt("gssapi-with-mic", SshAuthenticationOutcome.Unavailable),
            new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Rejected),
        });
    }

    [Test]
    public async Task WithNoCredentials_TheMessageSaysSo()
    {
        await using var server = new FakeSessionServer();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(server, Options()));
        await Assert.That(error!.Attempts).IsEmpty();
        await Assert.That(error.Message).Contains("No method was tried");
    }

    [Test]
    public async Task TheOldConstructor_HasNoAttempts()
    {
        var error = new SshAuthenticationException("failed", ["publickey"]);
        await Assert.That(error.Attempts).IsEmpty();
        await Assert.That(new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.Rejected, "SHA256:abc").ToString())
            .IsEqualTo("publickey SHA256:abc (Rejected)");
    }

    /// <summary>A signer that refuses, as an agent does when the user declines an <c>ssh-add -c</c> confirmation.</summary>
    private sealed class DecliningSigner(ReadOnlyMemory<byte> publicKey) : SshKeySigner(publicKey)
    {
        public override ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken) =>
            throw new SshException(SshFailureReason.AgentFailed, "The user declined.");
    }
}
