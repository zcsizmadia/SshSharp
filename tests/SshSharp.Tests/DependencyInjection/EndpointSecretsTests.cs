using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshSharp.Extensions.DependencyInjection;

namespace SshSharp.Tests.DependencyInjection;

/// <summary>
/// SshEndpointOptions for containers: private keys given as values (<see cref="SshEndpointOptions.PrivateKeys"/>), pinned host key
/// fingerprints, a proxy URI, their validation, and that no key or passphrase reaches a message, a log or <c>ToString</c>.
/// </summary>
public sealed class EndpointSecretsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-di-secrets").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A throwaway secret for a test (never a fixed password in the source).</summary>
    private static string NewSecret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>The lines of a key's text that hold key material (everything but the BEGIN and END lines).</summary>
    private static string[] KeyMaterial(string keyText) =>
        [.. keyText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(l => !l.StartsWith("-----", StringComparison.Ordinal))];

    private static async Task AssertHoldsNoSecret(string text, string keyText, params string?[] secrets)
    {
        foreach (var line in KeyMaterial(keyText))
        {
            await Assert.That(text).DoesNotContain(line);
        }

        foreach (var secret in secrets)
        {
            if (!string.IsNullOrEmpty(secret))
            {
                await Assert.That(text).DoesNotContain(secret);
            }
        }
    }

    /// <summary>
    /// Configuration as environment variables give it (<c>Ssh__Endpoints__deploy__PrivateKeys__0__Key</c>): the environment provider turns
    /// each <c>__</c> into the <c>:</c> separator, which is done here, so the test does not change the process's environment.
    /// </summary>
    private static IConfiguration FromEnvironmentStyle(Dictionary<string, string?> variables) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(variables.Select(v => KeyValuePair.Create(v.Key.Replace("__", ":", StringComparison.Ordinal), v.Value)))
            .Build();

    [Test]
    public async Task KeysAndFingerprints_BindFromEnvironmentStyleConfiguration_AndConnect()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var passphrase = NewSecret();
        var keyText = key.ToOpenSshPrivateKey(passphrase);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pemText = ecdsa.ExportPkcs8PrivateKeyPem(); // a PEM key, unencrypted
        using var pemKey = SshPrivateKey.Parse(pemText);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [pemKey.PublicKey.ToArray()] };
        var configuration = FromEnvironmentStyle(new()
        {
            ["Ssh__Endpoints__deploy__Host"] = "127.0.0.1",
            ["Ssh__Endpoints__deploy__Port"] = server.Port.ToString(CultureInfo.InvariantCulture),
            ["Ssh__Endpoints__deploy__UserName"] = "tester",
            ["Ssh__Endpoints__deploy__PrivateKeys__0__Key"] = keyText,
            ["Ssh__Endpoints__deploy__PrivateKeys__0__Passphrase"] = passphrase,
            ["Ssh__Endpoints__deploy__PrivateKeys__1__Key"] = pemText,
            ["Ssh__Endpoints__deploy__HostKeyFingerprints__0"] = key.Fingerprint, // another key's: one match is enough
            ["Ssh__Endpoints__deploy__HostKeyFingerprints__1"] = server.HostKeyFingerprint + "\n", // as a mounted secret file ends
        });
        IReadOnlyList<string>? offered = null;
        var services = new ServiceCollection();
        services.AddSingleton(configuration);
        services.AddSshClient("deploy").BindConfiguration("Ssh:Endpoints:deploy").Configure(o => o.ConfigureClientOptions = (_, built) =>
        {
            offered = [.. built.PrivateKeys.Select(k => k.Fingerprint)];
            return built;
        });
        await using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("deploy");
        await Assert.That(options.PrivateKeys.Count).IsEqualTo(2);
        await Assert.That(options.PrivateKeys[0].Passphrase).IsEqualTo(passphrase);
        await Assert.That(options.HostKeyFingerprints.Count).IsEqualTo(2);

        // No password and no known_hosts: the PEM key (the second) authenticates, and the pinned fingerprint verifies the host.
        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("deploy", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.HostKey.Fingerprint).IsEqualTo(server.HostKeyFingerprint);
        await Assert.That(offered!.SequenceEqual([key.Fingerprint, pemKey.Fingerprint])).IsTrue();
    }

    [Test]
    public async Task KeyFiles_AreOfferedBeforeKeysGivenAsValues()
    {
        using var fileKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var valueKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var file = Path.Combine(_dir, "id_ed25519");
        await fileKey.SaveAsync(file);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [valueKey.PublicKey.ToArray()] };
        IReadOnlyList<string>? offered = null;
        var services = new ServiceCollection();
        services.AddSshClient("deploy", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = valueKey.ToOpenSshPrivateKey() });
            o.PrivateKeyFiles.Add(file);
            o.HostKeyFingerprints.Add(server.HostKeyFingerprint);
            o.ConfigureClientOptions = (_, built) =>
            {
                offered = [.. built.PrivateKeys.Select(k => k.Fingerprint)];
                return built;
            };
        });
        await using var provider = services.BuildServiceProvider();

        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("deploy", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(offered!.SequenceEqual([fileKey.Fingerprint, valueKey.Fingerprint])).IsTrue();
    }

    [Test]
    public async Task AFingerprintThatDoesNotMatch_FailsWithAHostKeyException()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [key.PublicKey.ToArray()] };
        var services = new ServiceCollection();
        services.AddSshClient("deploy", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = key.ToOpenSshPrivateKey() });
            o.HostKeyFingerprints.Add(other.Fingerprint);
        });
        await using var provider = services.BuildServiceProvider();

        var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("deploy", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(ex.Message).Contains("pinned");
        await Assert.That(ex.HostKey!.Fingerprint).IsEqualTo(server.HostKeyFingerprint);
    }

    [Test]
    public async Task KeysAndPassphrases_StayOutOfLogs_ToString_AndErrors()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var passphrase = NewSecret();
        var keyText = key.ToOpenSshPrivateKey(passphrase);
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [key.PublicKey.ToArray()] };
        var logs = new CapturingLoggerFactory();
        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(logs);
        services.AddSshClient("good", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = keyText, Passphrase = passphrase });
            o.HostKeyFingerprints.Add(server.HostKeyFingerprint);
        });
        services.AddSshClient("pinned-elsewhere", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = keyText, Passphrase = passphrase });
            o.HostKeyFingerprints.Add(other.Fingerprint);
        });
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<ISshClientFactory>();

        await using (var client = await factory.ConnectAsync("good", Timeout()))
        {
            await Assert.That(client.IsConnected).IsTrue();
        }

        var rejected = await Assert.ThrowsAsync<SshHostKeyException>(async () => await factory.ConnectAsync("pinned-elsewhere", Timeout()));
        await Assert.That(logs.Text.Length).IsGreaterThan(0); // the client did log
        await AssertHoldsNoSecret(logs.Text, keyText, passphrase);
        await AssertHoldsNoSecret(rejected!.ToString(), keyText, passphrase);

        var options = provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("good");
        await AssertHoldsNoSecret(options.ToString()!, keyText, passphrase);
        await AssertHoldsNoSecret(options.PrivateKeys[0].ToString(), keyText, passphrase);
        await Assert.That(options.PrivateKeys[0].ToString()).Contains("redacted");
        await Assert.That(new SshEndpointPrivateKey().ToString()).Contains("not set");
    }

    private static string ValidationError(Action<SshEndpointOptions> configure)
    {
        var services = new ServiceCollection();
        services.AddSshClient("deploy", o =>
        {
            o.Host = "ssh.example.com";
            o.UserName = "deploy";
            configure(o);
        });
        using var provider = services.BuildServiceProvider();
        try
        {
            provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("deploy");
        }
        catch (OptionsValidationException ex)
        {
            return ex.Message;
        }

        throw new InvalidOperationException("The settings were expected to fail validation.");
    }

    [Test]
    [Arguments("MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48")]
    [Arguments("sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")]
    [Arguments("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    [Arguments("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF")]
    [Arguments("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFV")]
    [Arguments("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")]
    [Arguments("")]
    public async Task AFingerprintNotInOpenSshFormat_FailsValidation(string fingerprint)
    {
        var message = ValidationError(o => o.HostKeyFingerprints = ["SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", fingerprint]);
        await Assert.That(message).Contains("HostKeyFingerprints[1] is not an OpenSSH SHA-256 fingerprint");
        await Assert.That(message).DoesNotContain("HostKeyFingerprints[0]");
    }

    [Test]
    public async Task FingerprintsWithKnownHostsFiles_OrAcceptNewHostKeys_FailValidation()
    {
        string[] pinned = ["SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"];
        await Assert.That(ValidationError(o =>
        {
            o.HostKeyFingerprints = pinned;
            o.KnownHostsFiles = ["/etc/myapp/known_hosts"];
        })).Contains("HostKeyFingerprints or KnownHostsFiles, not both");
        await Assert.That(ValidationError(o =>
        {
            o.HostKeyFingerprints = pinned;
            o.AcceptNewHostKeys = true;
        })).Contains("AcceptNewHostKeys cannot be combined with HostKeyFingerprints");
    }

    [Test]
    public async Task TimesTheClientCannotUse_FailValidation()
    {
        // Above SshClientOptions.ConnectTimeout's bound every connection would fail; a negative keep-alive interval would only after
        // authenticating.
        await Assert.That(ValidationError(o => o.ConnectTimeout = TimeSpan.FromDays(30))).Contains("ConnectTimeout must be positive, and at most");
        await Assert.That(ValidationError(o => o.ConnectTimeout = TimeSpan.Zero)).Contains("ConnectTimeout must be positive");
        await Assert.That(ValidationError(o => o.KeepAliveInterval = TimeSpan.FromSeconds(-1))).Contains("KeepAliveInterval must not be negative");

        // The longest allowed, and a zero keep-alive interval (none), are fine.
        var services = new ServiceCollection();
        services.AddSshClient("deploy", o =>
        {
            o.Host = "ssh.example.com";
            o.UserName = "deploy";
            o.ConnectTimeout = TimeSpan.FromMilliseconds(int.MaxValue);
            o.KeepAliveInterval = TimeSpan.Zero;
        });
        using var provider = services.BuildServiceProvider();
        await Assert.That(provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("deploy").KeepAliveInterval).IsEqualTo(TimeSpan.Zero);
    }

    [Test]
    public async Task UseAgentWithConfigAlias_IsTheRegisteredAgent_ElseTheEnvironments()
    {
        var registered = SshAgent.FromKeys();
        var environment = SshAgent.FromKeys();
        Task<SshAgent?> FromEnvironment(CancellationToken _) => Task.FromResult<SshAgent?>(environment);
        Task<SshAgent?> NoAgent(CancellationToken _) => Task.FromResult<SshAgent?>(null);
        Task<SshAgent?> NotAsked(CancellationToken _) => throw new InvalidOperationException("The environment was asked.");

        await Assert.That(await SshClientFactory.AliasAgentAsync(true, registered, NotAsked, CancellationToken.None)).IsSameReferenceAs(registered);
        await Assert.That(await SshClientFactory.AliasAgentAsync(true, null, FromEnvironment, CancellationToken.None)).IsSameReferenceAs(environment);

        // No agent anywhere: ssh_config's IdentityAgent decides. Null or false: ssh_config decides, or the agent is off.
        await Assert.That(await SshClientFactory.AliasAgentAsync(true, null, NoAgent, CancellationToken.None)).IsNull();
        await Assert.That(await SshClientFactory.AliasAgentAsync(null, registered, NotAsked, CancellationToken.None)).IsNull();
        await Assert.That(await SshClientFactory.AliasAgentAsync(false, registered, NotAsked, CancellationToken.None)).IsNull();
    }

    [Test]
    public async Task ValuesThatSshConfigDecides_FailValidationWithConfigAlias()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var keyText = key.ToOpenSshPrivateKey();
        var message = ValidationError(o =>
        {
            o.ConfigAlias = "deploy-host";
            o.HostKeyFingerprints = [key.Fingerprint];
            o.PrivateKeys = [new SshEndpointPrivateKey { Key = keyText }];
            o.Proxy = "http://proxy.example.com:3128";
        });
        await Assert.That(message).Contains("HostKeyFingerprints, PrivateKeys, Proxy cannot be combined with ConfigAlias");
        await AssertHoldsNoSecret(message, keyText);
    }

    [Test]
    public async Task AKeyThatIsNotAKey_FailsValidation_WithoutShowingIt()
    {
        var garbage = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(120)) + "\n-----END OPENSSH PRIVATE KEY-----\n";
        var message = ValidationError(o => o.PrivateKeys = [new SshEndpointPrivateKey { Key = garbage }]);
        await Assert.That(message).Contains("PrivateKeys[0] could not be read");
        await AssertHoldsNoSecret(message, garbage);

        var notPem = NewSecret();
        await AssertHoldsNoSecret(ValidationError(o => o.PrivateKeys = [new SshEndpointPrivateKey { Key = notPem }]), notPem);

        await Assert.That(ValidationError(o => o.PrivateKeys = [new SshEndpointPrivateKey { Passphrase = NewSecret() }]))
            .Contains("PrivateKeys[0] has no Key");
    }

    [Test]
    public async Task AWrongOrMissingPassphrase_FailsValidation_WithoutShowingTheKeyOrPassphrase()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var passphrase = NewSecret();
        var wrong = NewSecret();
        var keyText = key.ToOpenSshPrivateKey(passphrase);

        var message = ValidationError(o => o.PrivateKeys = [new SshEndpointPrivateKey { Key = keyText, Passphrase = wrong }]);
        await Assert.That(message).Contains("PrivateKeys[0] could not be read");
        await Assert.That(message).Contains("passphrase");
        await AssertHoldsNoSecret(message, keyText, passphrase, wrong);

        var missing = ValidationError(o => o.PrivateKeys = [new SshEndpointPrivateKey { Key = keyText }]);
        await Assert.That(missing).Contains("passphrase");
        await AssertHoldsNoSecret(missing, keyText, passphrase);
    }

    [Test]
    public async Task AProxyUri_BindsAndIsUsed_AndABadOneFailsValidation_WithoutShowingIt()
    {
        var password = NewSecret();
        var configuration = FromEnvironmentStyle(new()
        {
            ["Ssh__Endpoints__deploy__Host"] = "ssh.example.com",
            ["Ssh__Endpoints__deploy__UserName"] = "deploy",
            ["Ssh__Endpoints__deploy__HostKeyFingerprints__0"] = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            ["Ssh__Endpoints__deploy__Proxy"] = $"socks5://proxyuser:{password}@proxy.example.com:1080",
        });
        SshProxy? used = null;
        var services = new ServiceCollection();
        services.AddSingleton(configuration);
        services.AddSshClient("deploy").BindConfiguration("Ssh:Endpoints:deploy").Configure(o => o.ConfigureClientOptions = (_, built) =>
        {
            used = built.Proxy;
            throw new OperationCanceledException("Stopped before connecting: only the built options are checked.");
        });
        await using var provider = services.BuildServiceProvider();

        await Assert.That(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("deploy", Timeout())).Throws<OperationCanceledException>();
        await Assert.That(used!.Type).IsEqualTo(SshProxyType.Socks5);
        await Assert.That(used.Host).IsEqualTo("proxy.example.com");
        await Assert.That(used.Port).IsEqualTo(1080);
        await Assert.That(used.Credentials!.Password).IsEqualTo(password);

        var bad = ValidationError(o => o.Proxy = $"ftp://proxyuser:{password}@proxy.example.com");
        await Assert.That(bad).Contains("Proxy is not a proxy URI");
        await Assert.That(bad).DoesNotContain(password);
        await Assert.That(ValidationError(o => o.Proxy = "proxy.example.com:3128")).Contains("Proxy is not a proxy URI");
    }

    /// <summary>Collects every message and exception logged through it, at every level.</summary>
    private sealed class CapturingLoggerFactory : ILoggerFactory, ILogger
    {
        private readonly List<string> _entries = [];

        public string Text
        {
            get
            {
                lock (_entries)
                {
                    return string.Join('\n', _entries);
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => this;

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_entries)
            {
                _entries.Add($"{formatter(state, exception)} {state} {exception}");
            }
        }
    }
}
