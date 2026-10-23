using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SshSharp.Extensions.DependencyInjection;

namespace SshSharp.Tests.DependencyInjection;

/// <summary>
/// SshEndpointOptions settings beyond one server: <see cref="SshEndpointOptions.JumpHosts"/>, <see cref="SshEndpointOptions.UseAgent"/>,
/// and host keys pinned by public key or known_hosts lines as well as by fingerprint.
/// </summary>
public sealed class EndpointJumpHostTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-di-jump").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static string NewSecret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>A bastion whose direct-tcpip channels all lead to <paramref name="destination"/>, recording what was asked for.</summary>
    private static TcpFakeSshServer Bastion(TcpFakeSshServer destination, string password, List<string> requested) => new()
    {
        Password = password,
        Configure = s => s.DirectTcpIp = (host, port) =>
        {
            lock (requested)
            {
                requested.Add($"{host}:{port}");
            }

            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(IPAddress.Loopback, destination.Port);
            return new NetworkStream(socket, ownsSocket: true);
        },
    };

    private static IConfiguration Configuration(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Test]
    public async Task JumpHosts_BindFromConfiguration_AndEachHopUsesOnlyItsOwnCredentialsAndPins()
    {
        using var destinationKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var destination = new TcpFakeSshServer { AuthorizedKeys = [destinationKey.PublicKey.ToArray()] };
        var bastionPassword = NewSecret();
        var requested = new List<string>();
        await using var bastion = Bastion(destination, bastionPassword, requested);
        var configuration = Configuration(new()
        {
            ["Ssh:App:Host"] = "app1.internal.example.com", // resolved by the bastion
            ["Ssh:App:Port"] = "2222",
            ["Ssh:App:UserName"] = "tester",
            ["Ssh:App:PrivateKeys:0:Key"] = destinationKey.ToOpenSshPrivateKey(),
            ["Ssh:App:HostKeyFingerprints:0"] = destination.HostKeyLine, // a .pub line
            ["Ssh:App:JumpHosts:0:Host"] = "127.0.0.1",
            ["Ssh:App:JumpHosts:0:Port"] = bastion.Port.ToString(CultureInfo.InvariantCulture),
            ["Ssh:App:JumpHosts:0:UserName"] = "tester",
            ["Ssh:App:JumpHosts:0:Password"] = bastionPassword,
            ["Ssh:App:JumpHosts:0:HostKeyFingerprints:0"] = bastion.HostKeyFingerprint,
        });
        SshClientOptions? built = null;
        var services = new ServiceCollection();
        services.AddSingleton(configuration);
        services.AddSshClient("app").BindConfiguration("Ssh:App").ValidateOnStart().Configure(o => o.ConfigureClientOptions = (_, options) =>
        {
            built = options;
            return options;
        });
        await using var provider = services.BuildServiceProvider();

        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("app", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.HostKey.Fingerprint).IsEqualTo(destination.HostKeyFingerprint);
        await Assert.That(requested).IsEquivalentTo(["app1.internal.example.com:2222"]);
        await Assert.That(bastion.Connections).IsEqualTo(1);

        // The hop has its own user and password; the destination's key and the hop's password stay apart.
        var hop = built!.JumpHosts.Single();
        await Assert.That(hop.Host).IsEqualTo("127.0.0.1");
        await Assert.That(hop.Port).IsEqualTo(bastion.Port);
        await Assert.That(hop.Options.Password).IsEqualTo(bastionPassword);
        await Assert.That(hop.Options.PrivateKeys.Count).IsEqualTo(0);
        await Assert.That(built.Password).IsNull();
        await Assert.That(built.PrivateKeys.Single().Fingerprint).IsEqualTo(destinationKey.Fingerprint);
    }

    [Test]
    public async Task AJumpHostWithoutHostKeySettings_IsCheckedAgainstTheEndpointsKnownHosts()
    {
        var password = NewSecret();
        await using var destination = new TcpFakeSshServer { Password = password };
        var requested = new List<string>();
        await using var bastion = Bastion(destination, password, requested);
        var knownHosts = Path.Combine(_dir, "known_hosts");
        var services = new ServiceCollection();
        services.AddSshClient("app", o =>
        {
            o.Host = "app1.internal.example.com";
            o.UserName = "tester";
            o.Password = password;
            o.KnownHostsFiles = [knownHosts];
            o.AcceptNewHostKeys = true;
            o.JumpHosts.Add(new SshEndpointJumpHost { Host = "127.0.0.1", Port = bastion.Port, UserName = "tester", Password = password });
        });
        await using var provider = services.BuildServiceProvider();

        await using (var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("app", Timeout()))
        {
            await Assert.That(client.IsConnected).IsTrue();
        }

        // Both keys were recorded in the endpoint's file (accept-new applies to the hop too), and are trusted from then on.
        var recorded = await File.ReadAllTextAsync(knownHosts);
        await Assert.That(recorded).Contains($"[127.0.0.1]:{bastion.Port} ssh-ed25519 ");
        await Assert.That(recorded).Contains("app1.internal.example.com ssh-ed25519 ");

        var strict = new ServiceCollection();
        strict.AddSshClient("app", o =>
        {
            o.Host = "app1.internal.example.com";
            o.UserName = "tester";
            o.Password = password;
            o.KnownHostsFiles = [knownHosts];
            o.JumpHosts.Add(new SshEndpointJumpHost { Host = "127.0.0.1", Port = bastion.Port, UserName = "tester", Password = password });
        });
        await using var strictProvider = strict.BuildServiceProvider();
        await using var again = await strictProvider.GetRequiredService<ISshClientFactory>().ConnectAsync("app", Timeout());
        await Assert.That(again.IsConnected).IsTrue();
    }

    [Test]
    public async Task AJumpHostsPin_IsCheckedAgainstTheJumpHost()
    {
        var password = NewSecret();
        await using var destination = new TcpFakeSshServer { Password = password };
        await using var bastion = Bastion(destination, password, []);
        var services = new ServiceCollection();
        services.AddSshClient("app", o =>
        {
            o.Host = "app1.internal.example.com";
            o.UserName = "tester";
            o.Password = password;
            o.HostKeyFingerprints = [destination.HostKeyFingerprint];
            o.JumpHosts.Add(new SshEndpointJumpHost
            {
                Host = "127.0.0.1",
                Port = bastion.Port,
                UserName = "tester",
                Password = password,
                HostKeyFingerprints = [destination.HostKeyFingerprint], // the destination's, not the bastion's
            });
        });
        await using var provider = services.BuildServiceProvider();

        var ex = await Assert.ThrowsAsync<SshException>(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("app", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(destination.Connections).IsEqualTo(0);
    }

    [Test]
    public async Task JumpHostSettings_AreValidated()
    {
        var services = new ServiceCollection();
        services.AddSshClient("pinned", o =>
        {
            o.Host = "app1.internal.example.com";
            o.UserName = "tester";
            o.HostKeyFingerprints = ["SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"];
            o.JumpHosts.Add(new SshEndpointJumpHost { Host = "bastion.example.com", UserName = "jump" }); // no pin of its own
            o.JumpHosts.Add(new SshEndpointJumpHost
            {
                Port = 0,
                KnownHostsFiles = ["/etc/myapp/known_hosts"],
                HostKeyFingerprints = ["not a fingerprint"],
                PrivateKeys = [new SshEndpointPrivateKey()],
            });
        });
        services.AddSshClient("alias", o =>
        {
            o.ConfigAlias = "prod";
            o.JumpHosts.Add(new SshEndpointJumpHost { Host = "bastion.example.com", UserName = "jump" });
        });
        await using var provider = services.BuildServiceProvider();
        var endpoints = provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>();

        var pinned = Assert.Throws<OptionsValidationException>(() => endpoints.Get("pinned"));
        await Assert.That(pinned.Failures).Contains(f => f.Contains("JumpHosts[0]: set HostKeyFingerprints or KnownHostsFiles for the jump host", StringComparison.Ordinal));
        await Assert.That(pinned.Failures).Contains("SSH endpoint 'pinned': JumpHosts[1]: set Host.");
        await Assert.That(pinned.Failures).Contains("SSH endpoint 'pinned': JumpHosts[1]: set UserName.");
        await Assert.That(pinned.Failures).Contains("SSH endpoint 'pinned': JumpHosts[1]: Port must be between 1 and 65535.");
        await Assert.That(pinned.Failures).Contains(f => f.StartsWith("SSH endpoint 'pinned': JumpHosts[1]: HostKeyFingerprints[0] is not", StringComparison.Ordinal));
        await Assert.That(pinned.Failures).Contains(f => f.Contains("JumpHosts[1]: set HostKeyFingerprints or KnownHostsFiles, not both", StringComparison.Ordinal));
        await Assert.That(pinned.Failures).Contains(f => f.Contains("JumpHosts[1]: PrivateKeys[0] has no Key", StringComparison.Ordinal));
        await Assert.That(pinned.Failures.Count()).IsEqualTo(7);

        var alias = Assert.Throws<OptionsValidationException>(() => endpoints.Get("alias"));
        await Assert.That(alias.Failures).Contains(f => f.Contains("JumpHosts cannot be combined with ConfigAlias", StringComparison.Ordinal));
    }

    [Test]
    public async Task HostKeyFingerprints_AcceptPublicKeyAndKnownHostsLines()
    {
        var password = NewSecret();
        await using var server = new TcpFakeSshServer { Password = password };
        var keyText = server.HostKeyLine.Split(' ', 3);
        string[] accepted =
        [
            server.HostKeyLine,                                                       // a .pub file's line
            "  " + server.HostKeyLine + "\n",                                         // with the white space a mounted file adds
            $"{keyText[0]} {keyText[1]}",                                            // without a comment
            $"[127.0.0.1]:{server.Port} {keyText[0]} {keyText[1]}",                    // a known_hosts line
            $"{(global::SshSharp.Config.KnownHostsEntry.HashHost("127.0.0.1", server.Port))} {keyText[0]} {keyText[1]}", // hashed
            $"some.other.example.com {keyText[0]} {keyText[1]}",                       // its host field is not checked
        ];
        foreach (var pin in accepted)
        {
            var services = new ServiceCollection();
            services.AddSshClient("box", o =>
            {
                o.Host = "127.0.0.1";
                o.Port = server.Port;
                o.UserName = "tester";
                o.Password = password;
                o.HostKeyFingerprints = [pin];
            });
            await using var provider = services.BuildServiceProvider();
            await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout());
            await Assert.That(client.HostKey.Fingerprint).IsEqualTo(server.HostKeyFingerprint);
        }

        // Another key's line is a pin like any other: it does not match.
        using var other = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var mismatch = new ServiceCollection();
        mismatch.AddSshClient("box", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.Password = password;
            o.HostKeyFingerprints = [other.GetPublicKey().ToAuthorizedKeysLine()];
        });
        await using var mismatchProvider = mismatch.BuildServiceProvider();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await mismatchProvider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
    }

    [Test]
    public async Task HostKeyFingerprints_RejectMarkedLines_SeveralLines_AndUnreadableKeys_WithoutEchoingThem()
    {
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var line = key.GetPublicKey().ToAuthorizedKeysLine(); // ends with the key's comment, which can be a user and host name
        var fields = line.Split(' ');
        var services = new ServiceCollection();
        services.AddSshClient("box", o =>
        {
            o.Host = "box.example.com";
            o.UserName = "tester";
            o.HostKeyFingerprints =
            [
                $"@cert-authority *.example.com {fields[0]} {fields[1]}",
                $"@revoked * {fields[0]} {fields[1]}",
                line + "\n" + line,
                $"{fields[0]} {fields[1][..20]}",
                "",
            ];
        });
        await using var provider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("box"));
        var failures = ex.Failures.ToArray();
        await Assert.That(failures[0]).Contains("HostKeyFingerprints[0] is a marked known_hosts line");
        await Assert.That(failures[1]).Contains("HostKeyFingerprints[1] is a marked known_hosts line");
        await Assert.That(failures[2]).Contains("HostKeyFingerprints[2] holds more than one line");
        await Assert.That(failures[3]).Contains("HostKeyFingerprints[3] is not an OpenSSH SHA-256 fingerprint");
        await Assert.That(failures[4]).Contains("HostKeyFingerprints[4] is not an OpenSSH SHA-256 fingerprint");
        foreach (var failure in failures)
        {
            await Assert.That(failure).DoesNotContain(fields[1][^20..]);
        }
    }

    [Test]
    public async Task UseAgent_OffersTheRegisteredAgentsKeys_AfterTheEndpointsOwn()
    {
        using var agentKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        using var ownKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [agentKey.PublicKey.ToArray()] };
        IReadOnlyList<string>? offered = null;
        var services = new ServiceCollection();
        services.AddSingleton(SshAgent.FromKeys(agentKey));
        services.AddSshClient("box", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.HostKeyFingerprints = [server.HostKeyFingerprint];
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = ownKey.ToOpenSshPrivateKey() });
            o.UseAgent = true;
            o.ConfigureClientOptions = (_, built) =>
            {
                offered = [.. built.PrivateKeys.Select(k => k.Fingerprint)];
                return built;
            };
        });
        await using var provider = services.BuildServiceProvider();

        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(offered!.SequenceEqual([ownKey.Fingerprint, agentKey.Fingerprint])).IsTrue();

        // Without UseAgent, the agent registered in the container is not used.
        var without = new ServiceCollection();
        without.AddSingleton(SshAgent.FromKeys(agentKey));
        without.AddSshClient("box", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.HostKeyFingerprints = [server.HostKeyFingerprint];
            o.PrivateKeys.Add(new SshEndpointPrivateKey { Key = ownKey.ToOpenSshPrivateKey() });
        });
        await using var withoutProvider = without.BuildServiceProvider();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await withoutProvider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    [Arguments(null)]
    public async Task UseAgent_WithConfigAlias_TrueUsesTheRegisteredAgent_InPlaceOfIdentityAgent(bool? useAgent)
    {
        // The alias says IdentityAgent none, and the server accepts only the agent's key: UseAgent = true must still offer the agent the
        // application registered (as without ConfigAlias); unset leaves the choice to ssh_config, and false turns the agent off.
        using var agentKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        await using var server = new TcpFakeSshServer { AuthorizedKeys = [agentKey.PublicKey.ToArray()] };
        var knownHosts = Path.Combine(_dir, "known_hosts");
        await File.WriteAllTextAsync(knownHosts, $"[127.0.0.1]:{server.Port.ToString(CultureInfo.InvariantCulture)} {server.HostKeyLine}\n");
        var config = SshSharp.Config.SshConfig.Parse(
            $"Host agent-box\n HostName 127.0.0.1\n Port {server.Port.ToString(CultureInfo.InvariantCulture)}\n User tester\n"
            + $" UserKnownHostsFile \"{knownHosts.Replace('\\', '/')}\"\n StrictHostKeyChecking yes\n IdentityAgent none\n");

        var services = new ServiceCollection();
        services.AddSingleton(SshAgent.FromKeys(agentKey));
        services.AddSingleton(new SshAliasConfiguration(config, new SshSharp.Config.SshConfigResolveOptions { HomeDirectory = _dir }));
        services.AddSshClient("box", o =>
        {
            o.ConfigAlias = "agent-box";
            o.UseAgent = useAgent;
        });
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<ISshClientFactory>();

        if (useAgent == true)
        {
            await using var client = await factory.ConnectAsync("box", Timeout());
            await Assert.That(client.IsConnected).IsTrue();
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SshException>(async () => await factory.ConnectAsync("box", Timeout()));
            await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        }
    }

    [Test]
    public async Task UseAgent_OnAJumpHost_OffersTheAgentToThatHopOnly()
    {
        using var agentKey = SshPrivateKey.Generate(SshKeyType.Ed25519);
        var password = NewSecret();
        await using var destination = new TcpFakeSshServer { Password = password };
        await using var bastion = new TcpFakeSshServer
        {
            AuthorizedKeys = [agentKey.PublicKey.ToArray()],
            Configure = s => s.DirectTcpIp = (_, _) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Connect(IPAddress.Loopback, destination.Port);
                return new NetworkStream(socket, ownsSocket: true);
            },
        };
        SshClientOptions? built = null;
        var services = new ServiceCollection();
        services.AddSingleton(SshAgent.FromKeys(agentKey));
        services.AddSshClient("app", o =>
        {
            o.Host = "app1.internal.example.com";
            o.UserName = "tester";
            o.Password = password;
            o.HostKeyFingerprints = [destination.HostKeyFingerprint];
            o.JumpHosts.Add(new SshEndpointJumpHost
            {
                Host = "127.0.0.1",
                Port = bastion.Port,
                UserName = "tester",
                UseAgent = true,
                HostKeyFingerprints = [bastion.HostKeyLine],
            });
            o.ConfigureClientOptions = (_, options) =>
            {
                built = options;
                return options;
            };
        });
        await using var provider = services.BuildServiceProvider();

        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("app", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(built!.PrivateKeys.Count).IsEqualTo(0);
        await Assert.That(built.JumpHosts.Single().Options.PrivateKeys.Single().Fingerprint).IsEqualTo(agentKey.Fingerprint);
    }

    [Test]
    public async Task UseAgent_BindsFromConfiguration_AsANullableSwitch()
    {
        var configuration = Configuration(new()
        {
            ["Ssh:A:UseAgent"] = "true",
            ["Ssh:B:UseAgent"] = "false",
            ["Ssh:A:JumpHosts:0:UseAgent"] = "true",
        });
        await Assert.That(Bound("a").UseAgent).IsTrue();
        await Assert.That(Bound("a").JumpHosts.Single().UseAgent).IsTrue();
        await Assert.That(Bound("b").UseAgent).IsFalse();
        await Assert.That(Bound("c").UseAgent).IsNull();

        SshEndpointOptions Bound(string name)
        {
            var options = new SshEndpointOptions();
            configuration.GetSection("Ssh:" + name.ToUpperInvariant()).Bind(options);
            return options;
        }
    }
}
