using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>gssapi-with-mic (RFC 4462 section 3) against the fake server, with a fake GSS-API mechanism.</summary>
public sealed class GssapiTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-gssapi-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, FakeGssapi? gss, string? password = null, string? targetHost = "kdc-test.example")
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Gssapi = gss is null ? null : new SshGssapiOptions { TargetHost = targetHost, DelegateCredentials = true, ContextFactory = gss.Factory },
        }, leaveOpen: true, Timeout());
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task Kerberos_Authenticates_WithTheMicOverThisSession(int rounds)
    {
        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        var gss = new FakeGssapi(rounds);
        await using var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic"], Gssapi = new FakeGssapiServer { Rounds = rounds } };
        await using var client = await ConnectAsync(server, gss);

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.GssapiMicValid).IsTrue();

        // RFC 4462 section 3.2: the krb5 mechanism, DER-encoded.
        await Assert.That(server.GssapiMechanismsOffered.Single().SequenceEqual(new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 })).IsTrue();
        await Assert.That(server.GssapiTokensReceived).IsEquivalentTo(Enumerable.Range(0, rounds + 1).Select(i => $"C{i}"));
        await Assert.That(gss.Host).IsEqualTo("kdc-test.example");
        await Assert.That(gss.Delegate).IsTrue();
        await Assert.That(gss.Disposed).IsTrue();
    }

    [Test]
    public async Task AStatusMessageFromTheServer_IsSkipped()
    {
        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        await using var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic"], Gssapi = new FakeGssapiServer { SendStatusMessage = true } };
        await using var client = await ConnectAsync(server, new FakeGssapi());
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments("refused")]
    [Arguments("no-ticket")]
    [Arguments("error-token")]
    [Arguments("last-token-rejected")]
    [Arguments("mic-rejected")]
    [Arguments("ticket-fails-later")]
    public async Task WhenKerberosFails_TheNextMethodIsTried(string failure)
    {
        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        var gss = failure switch
        {
            "no-ticket" => new FakeGssapi { FailAtStep = 0 },
            "ticket-fails-later" => new FakeGssapi(2) { FailAtStep = 1 },
            _ => new FakeGssapi(),
        };
        await using var server = new FakeSessionServer
        {
            AdvertisedMethods = ["gssapi-with-mic", "password"],
            Gssapi = failure switch
            {
                "refused" => null,
                "error-token" => new FakeGssapiServer { FailWithErrorToken = true },
                "last-token-rejected" => new FakeGssapiServer { FailLastTokenWithErrorToken = true },
                "mic-rejected" => new FakeGssapiServer { RejectMic = true },
                "ticket-fails-later" => new FakeGssapiServer { Rounds = 2 },
                _ => new FakeGssapiServer(),
            },
        };
        await using var client = await ConnectAsync(server, gss, password: TestSecrets.Password);

        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(server.AuthAttempts).Contains("gssapi-with-mic");
        await Assert.That(server.AuthAttempts[^1]).IsEqualTo("password");
        await Assert.That(gss.Disposed).IsTrue();
    }

    [Test]
    public async Task AServerThatChoosesAnotherMechanism_IsAProtocolError()
    {
        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        await using var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic"], Gssapi = new FakeGssapiServer { ChooseWrongMechanism = true } };
        await Assert.That(async () => await ConnectAsync(server, new FakeGssapi())).Throws<SshProtocolException>();
    }

    [Test]
    public async Task Kerberos_IsTriedOnlyWhenAskedFor_AndWithATargetHost()
    {
        // Off by default, as in ssh.
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic", "password"], Gssapi = new FakeGssapiServer() })
        await using (var client = await ConnectAsync(server, gss: null, password: TestSecrets.Password))
        {
            await Assert.That(server.AuthAttempts).DoesNotContain("gssapi-with-mic");
        }

        // Over a plain stream there is no host name to name the service after, unless TargetHost gives one.
        var gss = new FakeGssapi();
        await using (var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic", "password"], Gssapi = new FakeGssapiServer() })
        await using (var client = await ConnectAsync(server, gss, password: TestSecrets.Password, targetHost: null))
        {
            await Assert.That(server.AuthAttempts).DoesNotContain("gssapi-with-mic");
            await Assert.That(gss.Host).IsNull();
        }
    }

    [Test]
    public async Task ThePlatformContext_FailsAsAnAuthenticationFailure_ForAnUnknownService()
    {
        if (!SshGssapiOptions.IsSupported)
        {
            Skip.Test("gssapi-with-mic needs .NET 10.");
            return;
        }

        // No KDC knows host/nonexistent.invalid: the platform's context fails, and the client sees an SshException it can fall back from
        // (or, where there is no GSS-API library at all, creating the context fails with one of the exceptions the client catches).
        IGssapiContext context;
        try
        {
            context = Gssapi.Create("nonexistent.invalid", credential: null, delegateCredentials: false);
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException or InvalidOperationException
            or System.ComponentModel.Win32Exception)
        {
            return;
        }

        using (context)
        {
            await Assert.That(() => context.Step([], out _)).Throws<SshException>();
        }
    }

    [Test]
    public async Task OnDotNet8_TheMethodIsNotOffered()
    {
        if (SshGssapiOptions.IsSupported)
        {
            Skip.Test("This build has gssapi-with-mic.");
            return;
        }

        var gss = new FakeGssapi();
        await using var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic", "password"], Gssapi = new FakeGssapiServer() };
        await using var client = await ConnectAsync(server, gss, password: TestSecrets.Password);
        await Assert.That(server.AuthAttempts).DoesNotContain("gssapi-with-mic");
        await Assert.That(gss.Host).IsNull();
    }

    [Test]
    [Arguments("GSSAPIAuthentication yes\n GSSAPIDelegateCredentials yes\n", true, true)]
    [Arguments("GSSAPIAuthentication yes\n", true, false)]
    [Arguments("GSSAPIAuthentication no\n", false, false)]
    [Arguments("", false, false)]
    public async Task SshConfig_TurnsKerberosOn(string settings, bool tried, bool delegated)
    {
        var gss = new FakeGssapi();
        var server = new FakeSessionServer { AdvertisedMethods = ["gssapi-with-mic", "password"], Gssapi = new FakeGssapiServer() };
        await using (server)
        {
            var config = $"Host target\n HostName build.example.com\n User tester\n {settings} StrictHostKeyChecking no\n UserKnownHostsFile none\n";
            await using var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
            {
                Config = SshConfig.Parse(config),
                ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
                Password = TestSecrets.Password,
                UseAgent = false,
                GssapiContextFactory = gss.Factory,
                TcpConnector = (_, _, _, _) =>
                {
                    _ = server.StartAsync();
                    return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                },
            }, Timeout());

            var expectTried = tried && SshGssapiOptions.IsSupported;
            await Assert.That(server.AuthAttempts.Contains("gssapi-with-mic")).IsEqualTo(expectTried);
            if (expectTried)
            {
                await Assert.That(server.AuthAttempts[^1]).IsEqualTo("gssapi-with-mic"); // it succeeded; the password was not needed
                await Assert.That(gss.Host).IsEqualTo("build.example.com");
                await Assert.That(gss.Delegate).IsEqualTo(delegated);
            }
        }
    }
}
