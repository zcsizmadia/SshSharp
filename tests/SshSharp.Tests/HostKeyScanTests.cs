using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary><see cref="SshClient.ScanHostKeysAsync(Func{CancellationToken, ValueTask{Stream}}, SshHostKeyScanOptions?, CancellationToken)"/> (#116).</summary>
public class HostKeyScanTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>The fake servers are in memory, but a busy CI runner can take longer than the 5 s per-connection default: give them room.</summary>
    private static readonly TimeSpan InMemoryTimeout = TimeSpan.FromSeconds(45);

    private static SshHostKeyScanOptions Patient() => new() { Timeout = InMemoryTimeout };

    /// <summary>Starts a fresh fake server per connection, as a real server would accept them, and counts the connections.</summary>
    private sealed class Servers(FakeServerOptions options) : IAsyncDisposable
    {
        private readonly List<FakeSshServer> _started = [];

        public int Count => _started.Count;

        public ValueTask<Stream> ConnectAsync(CancellationToken cancellationToken)
        {
            var server = new FakeSshServer(options);
            _started.Add(server);
            _ = server.StartAsync(cancellationToken);
            return ValueTask.FromResult(server.ClientStream);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var server in _started)
            {
                await server.DisposeAsync();
            }
        }
    }

    private static readonly FakeHostKey Ed25519Key = FakeHostKey.Ed25519();
    private static readonly FakeHostKey EcdsaKey = FakeHostKey.Ecdsa(256);
    private static readonly FakeHostKey RsaKey = FakeHostKey.Rsa(2048);

    [Test]
    public async Task EveryKeyTypeTheServerHas_IsFound_WithOneConnectionPerType()
    {
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key, ExtraHostKeys = [EcdsaKey, RsaKey] });

        var keys = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, Patient(), Timeout());

        // In SshSharp's preference order; RSA once, although the server offers it under two signature algorithms.
        await Assert.That(keys.Select(k => k.KeyType)).IsEquivalentTo(["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]);
        await Assert.That(keys.Select(k => k.Fingerprint)).IsEquivalentTo([Ed25519Key.Fingerprint, EcdsaKey.Fingerprint, RsaKey.Fingerprint]);
        await Assert.That(keys[0].PublicKey.ToArray()).IsEquivalentTo(Ed25519Key.Blob);
        await Assert.That(keys[2].Algorithm).IsEqualTo("rsa-sha2-512");
        await Assert.That(servers.Count).IsEqualTo(3);
    }

    [Test]
    public async Task AServerThatSaysNothing_TimesOut_AsSshKeyscanDoes()
    {
        // Accepts, then never sends its identification.
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var held = listener.AcceptSocketAsync();

        var started = System.Diagnostics.Stopwatch.StartNew();
        var ex = await Assert.That(async () => await SshClient.ScanHostKeysAsync("127.0.0.1", port,
            new SshHostKeyScanOptions { Timeout = TimeSpan.FromMilliseconds(500) }, Timeout())).Throws<SshException>();

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(started.Elapsed).IsLessThan(TimeSpan.FromSeconds(30));
        (await held).Dispose();
        await Assert.That(new SshHostKeyScanOptions().Timeout).IsEqualTo(TimeSpan.FromSeconds(5));
        await Assert.That(() => new SshHostKeyScanOptions { Timeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(new SshHostKeyScanOptions { Timeout = System.Threading.Timeout.InfiniteTimeSpan }.Timeout).IsEqualTo(System.Threading.Timeout.InfiniteTimeSpan);
    }

    [Test]
    public async Task OnlyTheRequestedAlgorithms_AreAskedFor()
    {
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key, ExtraHostKeys = [EcdsaKey, RsaKey] });

        var keys = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, new SshHostKeyScanOptions { Timeout = InMemoryTimeout, HostKeyAlgorithms = ["rsa-sha2-256", "ecdsa-sha2-nistp256"] }, Timeout());

        await Assert.That(keys.Select(k => k.Algorithm)).IsEquivalentTo(["rsa-sha2-256", "ecdsa-sha2-nistp256"]);
        await Assert.That(servers.Count).IsEqualTo(2);
    }

    [Test]
    public async Task AServerWithNoneOfTheRequestedTypes_GivesAnEmptyList_AfterOneConnection()
    {
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key });

        var keys = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, new SshHostKeyScanOptions { Timeout = InMemoryTimeout, HostKeyAlgorithms = ["rsa-sha2-512"] }, Timeout());

        await Assert.That(keys).IsEmpty();
        await Assert.That(servers.Count).IsEqualTo(1);
    }

    [Test]
    public async Task FipsMode_LeavesOutEd25519()
    {
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key, ExtraHostKeys = [EcdsaKey], Kex = global::SshSharp.Protocol.SshAlgorithms.EcdhNistp256, Cipher = "aes256-gcm@openssh.com" });

        var keys = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, new SshHostKeyScanOptions { Timeout = InMemoryTimeout, FipsMode = true }, Timeout());

        await Assert.That(keys.Select(k => k.KeyType)).IsEquivalentTo(["ecdsa-sha2-nistp256"]);
    }

    [Test]
    public async Task HostCertificates_AreFoundWhenAskedFor_NextToThePlainKey()
    {
        using var authority = SshPrivateKey.Parse(TestKeys.OpenSshEd25519(out _));
        var certificate = FakeHostKey.Certified(Ed25519Key, TestKeys.Certificate(authority, Ed25519Key.Blob, SshCertificateType.Host, ["host.example"]));
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key, HostCertificate = certificate });

        var withCertificates = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, new SshHostKeyScanOptions { Timeout = InMemoryTimeout, IncludeCertificates = true }, Timeout());
        var plainOnly = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, Patient(), Timeout());

        await Assert.That(withCertificates.Count).IsEqualTo(2);
        await Assert.That(withCertificates[0].Certificate).IsNotNull();
        await Assert.That(withCertificates[0].Certificate!.Principals).IsEquivalentTo(["host.example"]);
        await Assert.That(withCertificates[0].Fingerprint).IsEqualTo(Ed25519Key.Fingerprint); // the certified key
        await Assert.That(withCertificates[1].Certificate).IsNull();
        await Assert.That(plainOnly.Count).IsEqualTo(1);
        await Assert.That(plainOnly[0].Certificate).IsNull();
    }

    [Test]
    public async Task SmallRsaKeys_AreReportedWithTheirSize()
    {
        var small = FakeHostKey.Rsa(1024);
        await using var servers = new Servers(new FakeServerOptions { HostKey = small });

        var keys = await SshClient.ScanHostKeysAsync(servers.ConnectAsync, Patient(), Timeout());

        await Assert.That(keys.Single().KeySizeBits).IsEqualTo(1024);
    }

    [Test]
    public async Task AKeyWhoseSignatureFails_IsNotReported()
    {
        await using var servers = new Servers(new FakeServerOptions { HostKey = Ed25519Key, CorruptSignature = true });

        await Assert.That(async () => await SshClient.ScanHostKeysAsync(servers.ConnectAsync, Patient(), Timeout())).Throws<SshHostKeyException>();
    }

    [Test]
    public async Task AnUnsupportedAlgorithm_IsRejectedUpFront()
    {
        await Assert.That(async () => await SshClient.ScanHostKeysAsync(_ => throw new InvalidOperationException("not called"),
            new SshHostKeyScanOptions { HostKeyAlgorithms = ["ssh-dss"] })).Throws<ArgumentException>();
    }

    [Test]
    public async Task AnUnreachableHost_IsAConnectFailure()
    {
        // Port 1 on loopback: nothing listens there.
        var ex = await Assert.That(async () => await SshClient.ScanHostKeysAsync("127.0.0.1", 1, cancellationToken: Timeout())).Throws<SshException>();
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
    }
}
