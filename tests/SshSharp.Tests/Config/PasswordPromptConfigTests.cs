using System.Security.Cryptography;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Config;

/// <summary>NumberOfPasswordPrompts, PasswordProvider and ChangePassword when connecting by ssh_config alias.</summary>
public class PasswordPromptConfigTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static string NewPassword() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private static readonly SshConfigResolveOptions Resolve = new() { LocalUser = "local", HomeDirectory = Path.GetTempPath(), LocalHostName = "box" };

    private static Func<string, int, SshAddressFamily, CancellationToken, ValueTask<(Stream, IAsyncDisposable?)>> Network(params (string Host, FakeSessionServer Server)[] servers) =>
        (host, _, _, _) =>
        {
            var server = servers.FirstOrDefault(s => s.Host == host).Server ?? throw new SshException(SshFailureReason.ConnectFailed, "No route.");
            _ = server.StartAsync();
            return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
        };

    private static SshConfig Config(string extra = "") =>
        SshConfig.Parse($"Host t\n HostName target.example.com\n{extra}Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n");

    [Test]
    [Arguments("", 3)]
    [Arguments(" NumberOfPasswordPrompts 1\n", 1)]
    [Arguments(" NumberOfPasswordPrompts 0\n", 0)]
    [Arguments(" NumberOfPasswordPrompts many\n", 3)]
    [Arguments(" NumberOfPasswordPrompts -2\n", 3)]
    public async Task NumberOfPasswordPrompts_IsRead(string line, int expected) =>
        await Assert.That(Config(line).Resolve("t", Resolve).NumberOfPasswordPrompts).IsEqualTo(expected);

    [Test]
    public async Task TheProvider_IsAskedUpToTheConfiguredNumberOfTimes_WithTheHostName()
    {
        await using var server = new FakeSessionServer { Password = NewPassword() };
        var seen = new List<SshPasswordPrompt>();
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(async () => await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = Config(" NumberOfPasswordPrompts 2\n"),
            ResolveOptions = Resolve,
            PasswordProvider = (prompt, _) =>
            {
                seen.Add(prompt);
                return ValueTask.FromResult<string?>(NewPassword());
            },
            TcpConnector = Network(("target.example.com", server)),
        }, Timeout()));

        await Assert.That(seen.Count).IsEqualTo(2);
        await Assert.That(seen[0].Host).IsEqualTo("target.example.com");
        await Assert.That(seen[0].Port).IsEqualTo(22);
        await Assert.That(seen[0].UserName).IsEqualTo("tester");
        await Assert.That(error!.Attempts.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(" BatchMode yes\n")]
    [Arguments(" PasswordAuthentication no\n KbdInteractiveAuthentication no\n")]
    public async Task TheProvider_IsNotAsked_InBatchMode_OrWithPasswordsOff(string line)
    {
        await using var server = new FakeSessionServer { Password = NewPassword() };
        var asked = 0;
        await Assert.ThrowsAsync<SshAuthenticationException>(async () => await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = Config(line),
            ResolveOptions = Resolve,
            PasswordProvider = (_, _) =>
            {
                asked++;
                return ValueTask.FromResult<string?>(server.Password);
            },
            TcpConnector = Network(("target.example.com", server)),
        }, Timeout()));

        await Assert.That(asked).IsEqualTo(0);
    }

    [Test]
    public async Task AJumpHost_IsNeverAskedForThroughTheProvider()
    {
        // A jump host that takes passwords only: the provider is the destination's, so the chain fails at the hop without asking.
        await using var jump = new FakeSessionServer { Password = NewPassword(), AdvertisedMethods = ["password"] };
        var asked = 0;
        var error = await Assert.ThrowsAsync<SshAuthenticationException>(async () => await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = Config(" ProxyJump j\n"),
            ResolveOptions = Resolve,
            PasswordProvider = (_, _) =>
            {
                asked++;
                return ValueTask.FromResult<string?>(jump.Password);
            },
            TcpConnector = Network(("j", jump)),
        }, Timeout()));

        await Assert.That(asked).IsEqualTo(0);
        await Assert.That(jump.PasswordsReceived).IsEmpty();
    }

    [Test]
    public async Task AnExpiredPassword_IsChangedThroughTheConfigPath()
    {
        var replacement = NewPassword();
        await using var server = new FakeSessionServer { Password = NewPassword(), PasswordExpired = true };
        await using var client = await SshClient.ConnectAsync("t", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = Config(),
            ResolveOptions = Resolve,
            Password = server.Password,
            ChangePassword = (_, _) => ValueTask.FromResult<string?>(replacement),
            TcpConnector = Network(("target.example.com", server)),
        }, Timeout());

        await Assert.That(server.ChangedPassword).IsEqualTo(replacement);
    }
}
