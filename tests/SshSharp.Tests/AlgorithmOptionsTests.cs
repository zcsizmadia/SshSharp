using System.Security.Cryptography;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;
using Round = SshSharp.Tests.Protocol.FakeSessionServer.KeyboardRound;

namespace SshSharp.Tests;

/// <summary>
/// The typed algorithm, authentication-order and RSA-size options of <see cref="SshClientOptions"/> (#266): <see cref="SshAlgorithmList"/>,
/// <see cref="SshClientOptions.PreferredAuthentications"/> and <see cref="SshClientOptions.RequiredRsaSize"/>.
/// </summary>
public class AlgorithmOptionsTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    // Generated per run, as CI does: no password is written down.
    private static readonly string Password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static SshClientOptions Options(int requiredRsaSize = 2048) => new()
    {
        UserName = "tester",
        Password = Password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        RequiredRsaSize = requiredRsaSize,
    };

    private static FakeSessionServer Server(FakeServerOptions? options = null) => new(options) { Password = Password };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions options)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    private static string[] Attempts(FakeSessionServer server)
    {
        lock (server.AuthAttempts)
        {
            return [.. server.AuthAttempts];
        }
    }

    // SshAlgorithmList

    [Test]
    public async Task EachForm_AppliesToTheDefaults_AsSshConfigDoes()
    {
        IReadOnlyList<string> defaults = ["a", "b", "c"];
        await Assert.That(string.Join(",", SshAlgorithmList.Only("c", "a", "c").Apply(defaults))).IsEqualTo("c,a");
        await Assert.That(string.Join(",", SshAlgorithmList.Append("a", "d").Apply(defaults))).IsEqualTo("b,c,a,d");
        await Assert.That(string.Join(",", SshAlgorithmList.Prepend("c", "d").Apply(defaults))).IsEqualTo("c,d,a,b");
        await Assert.That(string.Join(",", SshAlgorithmList.Remove("b", "x*").Apply(defaults))).IsEqualTo("a,c");
    }

    [Test]
    [Arguments("aes128-ctr,aes256-ctr")]
    [Arguments("+aes128-ctr")]
    [Arguments("-aes*-ctr,chacha20-poly1305@openssh.com")]
    [Arguments("^aes128-ctr")]
    public async Task Parse_AndToString_RoundTrip(string specification)
    {
        await Assert.That(SshAlgorithmList.Parse(specification).ToString()).IsEqualTo(specification);
        await Assert.That(SshAlgorithmList.Parse($"  {specification.Replace(",", " , ", StringComparison.Ordinal)} ").ToString()).IsEqualTo(specification);
    }

    [Test]
    public async Task MalformedLists_AreRejected()
    {
        await Assert.That(() => SshAlgorithmList.Only()).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Only(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => SshAlgorithmList.Only("aes128-ctr", null!)).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Only("aes128-ctr,aes256-ctr")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Append("aes128 ctr")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Prepend(" ")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Parse("")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Parse("+")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Parse(null!)).Throws<ArgumentNullException>();

        // Wildcards only where ssh_config takes them: in a list that removes.
        await Assert.That(() => SshAlgorithmList.Only("aes*")).Throws<ArgumentException>();
        await Assert.That(() => SshAlgorithmList.Parse("^aes?28-ctr")).Throws<ArgumentException>();
        await Assert.That(SshAlgorithmList.Remove("aes*").ToString()).IsEqualTo("-aes*");
    }

    // Names are checked against the kind of list they are set as

    [Test]
    public async Task AnUnknownName_IsRejected_WhenTheOptionIsSet_WithTheSupportedOnesListed()
    {
        var error = await Assert.That(() => new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            Ciphers = SshAlgorithmList.Only("aes128-cbc"),
        }).Throws<ArgumentException>();
        await Assert.That(error!.Message).Contains("'aes128-cbc' is not a cipher");
        await Assert.That(error.Message).Contains("aes256-gcm@openssh.com");

        // A name of another kind is no better than an unknown one.
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"), Macs = SshAlgorithmList.Append("aes128-ctr") })
            .Throws<ArgumentException>();
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"), KexAlgorithms = SshAlgorithmList.Prepend("ssh-ed25519") })
            .Throws<ArgumentException>();
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"), HostKeyAlgorithms = SshAlgorithmList.Only("ssh-rsa") })
            .Throws<ArgumentException>();
        await Assert.That(() => new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"), Ciphers = SshAlgorithmList.Remove("aes128-cbc") })
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task KnownNames_AndRemovalPatterns_AreAccepted()
    {
        var options = new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            KexAlgorithms = SshAlgorithmList.Prepend(SshAlgorithms.MlKem768Nistp256Sha256), // known, even where the platform lacks ML-KEM
            HostKeyAlgorithms = SshAlgorithmList.Append("ssh-ed25519-cert-v01@openssh.com"),
            Ciphers = SshAlgorithmList.Remove("chacha20*", "aes192-ctr"),
            Macs = SshAlgorithmList.Only("hmac-sha2-512-etm@openssh.com", "hmac-sha2-512"),
        };
        await Assert.That(options.Ciphers!.ToString()).IsEqualTo("-chacha20*,aes192-ctr");
    }

    // Negotiation

    [Test]
    public async Task TheClientOffers_TheListsAsConfigured()
    {
        await using var server = Server(new FakeServerOptions { Cipher = "aes128-ctr", Mac = "hmac-sha2-512" });
        await using var client = await ConnectAsync(server, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KexAlgorithms = SshAlgorithmList.Remove("sntrup*", "mlkem*"),
            Ciphers = SshAlgorithmList.Prepend("aes128-ctr"),
            Macs = SshAlgorithmList.Only("hmac-sha2-512"),
        });

        var offered = server.Raw.ClientKexInit!;
        await Assert.That(offered.KexAlgorithms[0]).IsEqualTo(SshAlgorithms.Curve25519Sha256);
        await Assert.That(offered.KexAlgorithms.Any(k => k.StartsWith("sntrup", StringComparison.Ordinal) || k.StartsWith("mlkem", StringComparison.Ordinal)))
            .IsFalse();
        await Assert.That(offered.EncryptionClientToServer[0]).IsEqualTo("aes128-ctr");
        await Assert.That(offered.EncryptionClientToServer.Count).IsEqualTo(SshAlgorithms.DefaultCiphers.Count);
        await Assert.That(offered.MacClientToServer).IsEquivalentTo(new[] { "hmac-sha2-512" });

        await Assert.That(client.Algorithms.EncryptionClientToServer).IsEqualTo("aes128-ctr");
        await Assert.That(client.Algorithms.MacClientToServer).IsEqualTo("hmac-sha2-512");
        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task TheHostKeyAlgorithm_IsTheFirstOfTheListThatTheServerHas()
    {
        await using var server = Server(new FakeServerOptions { ExtraHostKeys = [FakeHostKey.Ecdsa(256)] });
        await using var client = await ConnectAsync(server, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            HostKeyAlgorithms = SshAlgorithmList.Only("ecdsa-sha2-nistp256"),
            KexAlgorithms = SshAlgorithmList.Only(SshAlgorithms.Curve25519Sha256),
        });
        await Assert.That(client.HostKey.KeyType).IsEqualTo("ecdsa-sha2-nistp256");
        await Assert.That(client.Algorithms.KeyExchange).IsEqualTo(SshAlgorithms.Curve25519Sha256);
    }

    [Test]
    public async Task AServerWithNoneOfTheListedAlgorithms_FailsTheKeyExchange()
    {
        await using var server = Server(new FakeServerOptions { Cipher = "chacha20-poly1305@openssh.com" });
        var options = new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Ciphers = SshAlgorithmList.Remove("chacha20-poly1305@openssh.com"),
        };
        var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectAsync(server, options));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.KeyExchangeFailed);
    }

    [Test]
    public async Task MlKem_WhereThePlatformLacksIt_IsDropped_AndAListOfOnlyThatSaysSo()
    {
        var options = new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            KexAlgorithms = SshAlgorithmList.Only(SshAlgorithms.MlKem768X25519Sha256),
        };
        if (SshAlgorithms.HasMlKem)
        {
            await Assert.That(AlgorithmPreferences.FromOptions(options).Kex).IsEquivalentTo(new[] { SshAlgorithms.MlKem768X25519Sha256 });
            return;
        }

        var error = await Assert.That(() => AlgorithmPreferences.FromOptions(options)).Throws<ArgumentException>();
        await Assert.That(error!.Message).Contains("KexAlgorithms");
    }

    // FIPS mode still restricts

    [Test]
    public async Task FipsMode_StillRemovesWhatItExcludes_FromAConfiguredList()
    {
        var preferences = AlgorithmPreferences.FromOptions(new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            FipsMode = true,
            KexAlgorithms = SshAlgorithmList.Prepend(SshAlgorithms.Curve25519Sha256),
            HostKeyAlgorithms = SshAlgorithmList.Prepend("ssh-ed25519"),
            Ciphers = SshAlgorithmList.Prepend("chacha20-poly1305@openssh.com", "aes128-ctr"),
        });
        await Assert.That(preferences.Kex.Contains(SshAlgorithms.Curve25519Sha256)).IsFalse();
        await Assert.That(preferences.HostKeys.Contains("ssh-ed25519")).IsFalse();
        await Assert.That(preferences.Ciphers[0]).IsEqualTo("aes128-ctr");
        await Assert.That(preferences.Ciphers.Contains("chacha20-poly1305@openssh.com")).IsFalse();
    }

    [Test]
    public async Task FipsMode_WithAListOfOnlyExcludedAlgorithms_FailsBeforeTheNetworkIsTouched()
    {
        var options = new SshClientOptions
        {
            UserName = "tester",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            FipsMode = true,
            Ciphers = SshAlgorithmList.Only("chacha20-poly1305@openssh.com"),
        };

        // A documentation address: reaching for it would time out or fail with an SshException, not an ArgumentException.
        var error = await Assert.That(async () => await SshClient.ConnectAsync("192.0.2.1", 22, options, Timeout())).Throws<ArgumentException>();
        await Assert.That(error!.Message).Contains("Ciphers");
        await Assert.That(error.Message).Contains("FIPS");

        // Over a stream, the same, and the stream is closed as on any failure to connect.
        await using var server = Server();
        await Assert.That(async () => await ConnectAsync(server, options)).Throws<ArgumentException>();
    }

    // PreferredAuthentications

    [Test]
    public async Task TheMethodsAreTried_InTheConfiguredOrder()
    {
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
        Round codeRound = new("", "", [("Code: ", true)], [code]);
        SshClientOptions OptionsWith(IReadOnlyList<string>? order) => new()
        {
            UserName = "tester",
            Password = Password,
            KeyboardInteractive = (_, _) => ValueTask.FromResult<IReadOnlyList<string>?>([code]),
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            PreferredAuthentications = order,
        };

        await using (var server = new FakeSessionServer { Password = Password, AdvertisedMethods = ["keyboard-interactive", "password"], KeyboardInteractiveRounds = [codeRound] })
        await using (await ConnectAsync(server, OptionsWith(null)))
        {
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "keyboard-interactive" });
        }

        await using (var server = new FakeSessionServer { Password = Password, AdvertisedMethods = ["keyboard-interactive", "password"], KeyboardInteractiveRounds = [codeRound] })
        await using (await ConnectAsync(server, OptionsWith(["password", "keyboard-interactive"])))
        {
            await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none", "password" });
        }
    }

    [Test]
    public async Task AMethodLeftOut_IsNotTried_EvenWithItsCredentials()
    {
        await using var server = Server();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            PreferredAuthentications = ["publickey"],
        };
        var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectAsync(server, options));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(Attempts(server)).IsEquivalentTo(new[] { "none" });
    }

    [Test]
    [Arguments("hostbased")]
    [Arguments("Password")]
    [Arguments("")]
    public async Task AnUnknownMethod_IsRejected(string method)
    {
        var error = await Assert.That(() => new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            PreferredAuthentications = ["publickey", method],
        }).Throws<ArgumentException>();
        await Assert.That(error!.Message).Contains("keyboard-interactive");
    }

    [Test]
    public async Task DuplicateMethods_AreTriedOnce()
    {
        var options = new SshClientOptions
        {
            UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused"),
            PreferredAuthentications = ["password", "publickey", "password"],
        };
        await Assert.That(options.PreferredAuthentications!).IsEquivalentTo(new[] { "password", "publickey" });
    }

    // RequiredRsaSize

    [Test]
    public async Task ASmallRsaHostKey_IsRefusedByDefault_AndAcceptedOnlyDownToTheConfiguredSize()
    {
        var weak = FakeHostKey.Rsa(1024);
        await using (var server = Server(new FakeServerOptions { HostKey = weak }))
        {
            var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectAsync(server, Options()));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
            await Assert.That(error.Message).Contains("minimum 2048");
        }

        await using (var server = Server(new FakeServerOptions { HostKey = weak }))
        await using (var client = await ConnectAsync(server, Options(requiredRsaSize: 1024)))
        {
            await Assert.That(client.HostKey.KeySizeBits).IsEqualTo(1024);
        }

        await using (var server = Server(new FakeServerOptions { HostKey = FakeHostKey.Rsa(2048) }))
        {
            var error = await Assert.ThrowsAsync<SshException>(async () => await ConnectAsync(server, Options(requiredRsaSize: 3072)));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
            await Assert.That(error.Message).Contains("minimum 3072");
        }
    }

    [Test]
    public async Task TheRequiredRsaSize_CannotGoBelow1024_AsInSsh()
    {
        await Assert.That(new SshClientOptions { UserName = "tester", HostKeyVerifier = SshHostKeyVerifier.Pinned("SHA256:unused") }.RequiredRsaSize).IsEqualTo(2048);
        await Assert.That(() => Options(requiredRsaSize: 1023)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(requiredRsaSize: 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(Options(requiredRsaSize: 4096).RequiredRsaSize).IsEqualTo(4096);
    }
}
