using System.Security.Cryptography;
using System.Text;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;
using SshSharp.Tests.Sftp;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="SshClientOptions.Compression"/>, ssh_config's <c>Compression</c> and <see cref="SshConfigConnectOptions.Compression"/>:
/// a whole connection with delayed compression against the fake server (a command, its input and output, and SFTP), and how each
/// setting reaches the key exchange.
/// </summary>
public sealed class CompressionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-compression-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    // Generated per run: no password is written down, as for CI's test servers.
    private static readonly string Password = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private static readonly string[] ServerOffers = ["none", SshAlgorithms.CompressionZlibOpenSsh];

    private static FakeSessionServer Server(IReadOnlyList<string>? compression = null) =>
        new(new FakeServerOptions { Compression = compression ?? ServerOffers }) { Password = Password };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, bool compression, bool fipsMode = false)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Compression = compression,
            FipsMode = fipsMode,
        }, leaveOpen: true, Timeout());
    }

    private static string ClientToServer => SshAlgorithms.CanCompressOutgoing ? SshAlgorithms.CompressionZlibOpenSsh : SshAlgorithms.CompressionNone;

    private static byte[] Listing(int size)
    {
        var builder = new StringBuilder(size);
        for (var i = 0; builder.Length < size; i++)
        {
            builder.Append(FormattableString.Invariant($"-rw-r--r-- 1 deploy staff {i * 37 % 100_000,6} Oct 19 12:{i % 60:00} file-{i}.log\n"));
        }

        return Encoding.ASCII.GetBytes(builder.ToString(0, size));
    }

    [Test]
    public async Task ACommand_RunsOverACompressedConnection()
    {
        await using var server = Server();
        var output = Listing(300_000);
        server.OnExec = async script =>
        {
            // Echo the input back on stderr, then a large listing on stdout.
            var input = new List<byte>();
            while (await script.ReadInputAsync() is { } chunk)
            {
                input.AddRange(chunk);
            }

            await script.StderrAsync([.. input]);
            await script.StdoutAsync(output);
            await script.FinishAsync(0);
        };

        await using var client = await ConnectAsync(server, compression: true);
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);
        await Assert.That(client.Algorithms.CompressionClientToServer).IsEqualTo(ClientToServer);

        var input = Listing(100_000);
        var result = await client.RunCommandAsync("ls -l", null, SshCommandInput.FromBytes(input), Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(result.StandardOutput.Span.SequenceEqual(output)).IsTrue();
        await Assert.That(result.StandardError.Span.SequenceEqual(input)).IsTrue();

        // Everything the server sent after the authentication went compressed; what the client sent too, where it compresses.
        await Assert.That(server.Raw.SentPackets.Count(p => p.Compressed)).IsGreaterThan(5);
        await Assert.That(server.Raw.ReceivedPackets.Any(p => p.Compressed)).IsEqualTo(SshAlgorithms.CanCompressOutgoing);
    }

    [Test]
    public async Task Sftp_RoundTripsAFileOverACompressedConnection()
    {
        await using var server = Server();
        var files = new FakeSftpServer();
        files.Install(server);
        await using var client = await ConnectAsync(server, compression: true);
        await using var sftp = await client.OpenSftpAsync(Timeout());

        var content = Listing(1_000_000);
        var path = FakeSftpServer.Home + "/listing.txt";
        await sftp.WriteAllBytesAsync(path, content, Timeout());
        var back = await sftp.ReadAllBytesAsync(path, Timeout());
        await Assert.That(back.AsSpan().SequenceEqual(content)).IsTrue();
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);
    }

    [Test]
    public async Task OffByDefault()
    {
        await using var server = Server();
        await using var client = await ConnectAsync(server, compression: false);
        await Assert.That(client.Algorithms.CompressionClientToServer).IsEqualTo(SshAlgorithms.CompressionNone);
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);
        await Assert.That(server.Raw.ClientKexInit!.CompressionServerToClient).IsEquivalentTo(new[] { "none" });
    }

    [Test]
    public async Task Offered_AsZlibAtOpenSshThenNone_AsSshDoesWithCompressionYes()
    {
        await using var server = Server(["none"]);
        await using var client = await ConnectAsync(server, compression: true);
        await Assert.That(string.Join(",", server.Raw.ClientKexInit!.CompressionServerToClient)).IsEqualTo("zlib@openssh.com,none");
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);
    }

    [Test]
    public async Task PlainZlib_IsNeverOffered()
    {
        // Plain zlib compresses from the first packet, before the server has authenticated the client: left out by design.
        await using var server = Server(["zlib", "none"]);
        await using var client = await ConnectAsync(server, compression: true);
        await Assert.That(server.Raw.ClientKexInit!.CompressionClientToServer.Contains("zlib")).IsFalse();
        await Assert.That(server.Raw.ClientKexInit.CompressionServerToClient.Contains("zlib")).IsFalse();
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionNone);
    }

    [Test]
    public async Task FipsMode_AllowsCompression()
    {
        await using var server = new FakeSessionServer(new FakeServerOptions
        {
            Compression = ServerOffers,
            Kex = SshAlgorithms.EcdhNistp256,
            Cipher = "aes256-gcm@openssh.com",
            HostKey = FakeHostKey.Ecdsa(256),
        }) { Password = Password };
        await using var client = await ConnectAsync(server, compression: true, fipsMode: true);
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);
    }

    [Test]
    public async Task Preferences_FollowTheOptionsAndTheConfiguration()
    {
        var trustAll = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true));
        await Assert.That(AlgorithmPreferences.FromOptions(new SshClientOptions { UserName = "u", HostKeyVerifier = trustAll }).Compression)
            .IsEquivalentTo(new[] { "none" });
        await Assert.That(AlgorithmPreferences.FromOptions(new SshClientOptions { UserName = "u", HostKeyVerifier = trustAll, Compression = true }).Compression)
            .IsEquivalentTo(new[] { "zlib@openssh.com", "none" });
        await Assert.That(AlgorithmPreferences.FromOptions(new SshClientOptions { UserName = "u", HostKeyVerifier = trustAll, Compression = true, FipsMode = true })
            .Compression).IsEquivalentTo(new[] { "zlib@openssh.com", "none" });

        var on = Resolve("Host box\n Compression yes\n");
        await Assert.That(AlgorithmPreferences.FromConfig(on).Compression).IsEquivalentTo(new[] { "zlib@openssh.com", "none" });
        await Assert.That(AlgorithmPreferences.FromConfig(on, compression: false).Compression).IsEquivalentTo(new[] { "none" });
        await Assert.That(AlgorithmPreferences.FromConfig(Resolve("Host box\n User deploy\n"), compression: true).Compression)
            .IsEquivalentTo(new[] { "zlib@openssh.com", "none" });
    }

    [Test]
    [Arguments("", false)]
    [Arguments(" Compression yes\n", true)]
    [Arguments(" Compression no\n", false)]
    [Arguments(" compression YES\n", true)]
    public async Task TheDirective_IsParsed(string line, bool expected) =>
        await Assert.That(Resolve("Host box\n" + line).Compression).IsEqualTo(expected);

    [Test]
    public async Task TheFirstValueWins_AsForEveryDirective() =>
        await Assert.That(Resolve("Host box\n Compression no\nHost *\n Compression yes\n").Compression).IsFalse();

    private SshHostConfig Resolve(string config) =>
        SshConfig.Parse(config).Resolve("box", new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir });

    private const string Trusting = " User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n";

    private async Task<SshClient> ConnectByConfigAsync(FakeSessionServer server, string config, bool? compression)
    {
        return await SshClient.ConnectAsync("box", new SshConfigConnectOptions
        {
            UseAgent = false,
            Config = SshConfig.Parse(config),
            ResolveOptions = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir },
            Password = Password,
            Compression = compression,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
    }

    [Test]
    [Arguments("", null, false)]
    [Arguments(" Compression yes\n", null, true)]
    [Arguments(" Compression yes\n", false, false)]
    [Arguments(" Compression no\n", true, true)]
    [Arguments("", true, true)]
    public async Task TheConfiguration_AndItsOverride_DecideWhatIsOffered(string line, bool? overrideValue, bool expected)
    {
        await using var server = Server();
        await using var client = await ConnectByConfigAsync(server, "Host box\n" + line + Trusting, overrideValue);
        await Assert.That(client.Algorithms.CompressionServerToClient)
            .IsEqualTo(expected ? SshAlgorithms.CompressionZlibOpenSsh : SshAlgorithms.CompressionNone);
        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }
}
