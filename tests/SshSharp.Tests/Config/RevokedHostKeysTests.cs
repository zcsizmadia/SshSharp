using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Config;
using SshSharp.Protocol;
using SshSharp.Tests.Keys;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Config;

/// <summary>RevokedHostKeys: OpenSSH Key Revocation Lists (PROTOCOL.krl) and plain key lists, as ssh's verify_host_key checks them.</summary>
public sealed class RevokedHostKeysTests : IDisposable
{
    private const string Host = "srv.example.com";

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-revoked-").FullName;
    private readonly SshPrivateKey _authority = SshPrivateKey.Generate(SshKeyType.Ed25519, "ca");
    private readonly SshPrivateKey _otherAuthority = SshPrivateKey.Generate(SshKeyType.Ed25519, "other-ca");

    public void Dispose()
    {
        _authority.Dispose();
        _otherAuthority.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private string RevokedFile => Path.Combine(_dir, "revoked");

    private static string Line(byte[] blob) => $"{new SshReader(blob).ReadUtf8String()} {Convert.ToBase64String(blob)}";

    private async Task<SshClient> ConnectAsync(FakeServerOptions server, StrictHostKeyChecking policy = StrictHostKeyChecking.No, string? revoked = "")
    {
        var fake = new FakeSessionServer(server);
        _ = fake.StartAsync();
        return await SshClient.ConnectAsync(fake.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyAlias = Host,
            HostKeyVerifier = new KnownHostsVerifier([KnownHosts]) { Policy = policy, RevokedHostKeys = revoked == "" ? RevokedFile : revoked },
        }, leaveOpen: true, Timeout());
    }

    private async Task<string> RefusalAsync(FakeServerOptions server, StrictHostKeyChecking policy = StrictHostKeyChecking.No)
    {
        try
        {
            await using var client = await ConnectAsync(server, policy);
        }
        catch (SshHostKeyException ex)
        {
            return ex.Message;
        }

        throw new InvalidOperationException("The host key was accepted.");
    }

    private static FakeServerOptions WithCertificate(FakeHostKey key, SshPrivateKey authority, ulong serial = 7, string keyId = "host-id") => new()
    {
        HostKey = key,
        HostCertificate = FakeHostKey.Certified(key, TestKeys.Certificate(authority, key.Blob, SshCertificateType.Host, [Host], keyId: keyId, serial: serial)),
    };

    private SshCertificate Certificate(FakeHostKey key, ulong serial = 7, string keyId = "host-id", SshPrivateKey? authority = null) =>
        SshCertificate.FromBlob(TestKeys.Certificate(authority ?? _authority, key.Blob, SshCertificateType.Host, [Host], keyId: keyId, serial: serial));

    // ---- a KRL built by hand, section by section (PROTOCOL.krl) ----

    private sealed class Krl
    {
        private readonly ArrayBufferWriter<byte> _sections = new();

        public Krl Section(byte type, Action<SshWriter> data)
        {
            var w = new SshWriter(_sections);
            w.WriteByte(type);
            w.WriteString(TestKeys.Blob(data));
            return this;
        }

        /// <summary>A signature section, which ssh-keygen -s wrote unlike the others: byte 4, string signing key, string signature.</summary>
        public Krl Signature(byte[] key, byte[] signature)
        {
            var w = new SshWriter(_sections);
            w.WriteByte(4);
            w.WriteString(key);
            w.WriteString(signature);
            return this;
        }

        public Krl Certificates(byte[]? authority, params (byte Type, Action<SshWriter> Data)[] subsections) => Section(1, w =>
        {
            w.WriteString(authority ?? []);
            w.WriteString(ReadOnlySpan<byte>.Empty); // reserved
            foreach (var (type, data) in subsections)
            {
                w.WriteByte(type);
                w.WriteString(TestKeys.Blob(data));
            }
        });

        public byte[] Build(uint version = 1) => [.. "SSHKRL\n\0"u8.ToArray(), .. TestKeys.Blob(w =>
        {
            w.WriteUInt32(version);
            w.WriteUInt64(1);           // krl_version
            w.WriteUInt64(1700000000);  // generated_date
            w.WriteUInt64(0);           // flags
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteString("hand-built");
        }), .. _sections.WrittenSpan.ToArray()];
    }

    private static bool Revoked(byte[] krl, FakeHostKey key, SshCertificate? certificate = null) =>
        RevokedKeyList.Parse(krl).IsRevoked(key.Blob, certificate);

    [Test]
    public async Task AListedKey_IsRefused_EvenWhenKnownHostsTrustsIt()
    {
        var revoked = FakeHostKey.Ed25519();
        var fine = FakeHostKey.Ecdsa(256);
        File.WriteAllText(KnownHosts, $"{Host} {Line(revoked.Blob)}\n{Host} {Line(fine.Blob)}\n");
        File.WriteAllText(RevokedFile, $"# revoked host keys\n\nnot a key line\n{Line(revoked.Blob)} old-host\n");

        var message = await RefusalAsync(new FakeServerOptions { HostKey = revoked }, StrictHostKeyChecking.Yes);
        await Assert.That(message).Contains("revoked by file").And.Contains(revoked.Fingerprint);

        await using var client = await ConnectAsync(new FakeServerOptions { HostKey = fine }, StrictHostKeyChecking.Yes);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AKeyList_RevokesACertificatesKeyOrItsAuthority()
    {
        var key = FakeHostKey.Ed25519();
        File.WriteAllText(KnownHosts, $"@cert-authority * {_authority.ToAuthorizedKeysLine()}\n");

        // The authority's key on the list: every certificate it signed is refused.
        File.WriteAllText(RevokedFile, _authority.ToAuthorizedKeysLine() + "\n");
        await Assert.That(await RefusalAsync(WithCertificate(key, _authority), StrictHostKeyChecking.Yes)).Contains("revoked by file");

        // A certificate line revokes the key it certifies (ssh compares the keys).
        File.WriteAllText(RevokedFile, TestKeys.CertificateLine(TestKeys.Certificate(_otherAuthority, key.Blob, SshCertificateType.Host, [Host])) + "\n");
        await Assert.That(await RefusalAsync(WithCertificate(key, _authority), StrictHostKeyChecking.Yes)).Contains("revoked by file");

        File.WriteAllText(RevokedFile, Line(FakeHostKey.Ed25519().Blob) + "\n");
        await using var client = await ConnectAsync(WithCertificate(key, _authority), StrictHostKeyChecking.Yes);
        await Assert.That(client.HostKey.Certificate).IsNotNull();
    }

    [Test]
    public async Task AKrl_RevokesExplicitKeys_AndSha1AndSha256Fingerprints()
    {
        var explicitKey = FakeHostKey.Ed25519();
        var bySha1 = FakeHostKey.Ecdsa(384);
        var bySha256 = FakeHostKey.Rsa(2048);
        var fine = FakeHostKey.Ecdsa(256);
        var krl = new Krl()
            .Section(2, w => w.WriteString(explicitKey.Blob))
#pragma warning disable CA5350 // the KRL format lists keys by SHA-1
            .Section(3, w => w.WriteString(SHA1.HashData(bySha1.Blob)))
#pragma warning restore CA5350
            .Section(5, w => w.WriteString(SHA256.HashData(bySha256.Blob)))
            .Build();

        await Assert.That(Revoked(krl, explicitKey)).IsTrue();
        await Assert.That(Revoked(krl, bySha1)).IsTrue();
        await Assert.That(Revoked(krl, bySha256)).IsTrue();
        await Assert.That(Revoked(krl, fine)).IsFalse();
        await Assert.That(RevokedKeyList.Parse(krl).IsKrl).IsTrue();

        File.WriteAllBytes(RevokedFile, krl);
        await Assert.That(await RefusalAsync(new FakeServerOptions { HostKey = bySha256 })).Contains("revoked by file");
        await using var client = await ConnectAsync(new FakeServerOptions { HostKey = fine });
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AKrl_RevokesCertificatesBySerialRangeBitmapAndKeyId_ForTheirAuthority()
    {
        var key = FakeHostKey.Ed25519();
        var authority = _authority.PublicKey.ToArray();
        var krl = new Krl()
            .Certificates(authority,
                (0x20, w => { w.WriteUInt64(7); w.WriteUInt64(9); }),                 // serial list
                (0x21, w => { w.WriteUInt64(100); w.WriteUInt64(200); }),             // serial range
                (0x22, w => { w.WriteUInt64(1000); w.WriteMpint(new byte[] { 0x01, 0x05 }); }), // bitmap: bits 0, 2, 8 -> 1000, 1002, 1008
                (0x23, w => w.WriteString("bad-host")),                              // key id
                (0x39, w => { w.WriteString("future@example.com"); w.WriteBoolean(false); w.WriteString("x"); })) // non-critical extension
            .Certificates(null, (0x23, w => w.WriteString("any-ca-bad-id")))          // wildcard authority: key ids only
            .Build();

        foreach (var serial in new ulong[] { 7, 9, 100, 150, 200, 1000, 1002, 1008 })
        {
            await Assert.That(Revoked(krl, key, Certificate(key, serial))).IsTrue().Because($"serial {serial}");
        }

        foreach (var serial in new ulong[] { 8, 99, 201, 1001, 1009, 0 })
        {
            await Assert.That(Revoked(krl, key, Certificate(key, serial))).IsFalse().Because($"serial {serial}");
        }

        await Assert.That(Revoked(krl, key, Certificate(key, serial: 0, keyId: "bad-host"))).IsTrue();
        await Assert.That(Revoked(krl, key, Certificate(key, serial: 42, keyId: "any-ca-bad-id", authority: _otherAuthority))).IsTrue();

        // Serials and key ids under one authority do not revoke another authority's certificates.
        await Assert.That(Revoked(krl, key, Certificate(key, serial: 7, keyId: "bad-host", authority: _otherAuthority))).IsFalse();

        File.WriteAllBytes(RevokedFile, krl);
        File.WriteAllText(KnownHosts, $"@cert-authority * {_authority.ToAuthorizedKeysLine()}\n");
        await Assert.That(await RefusalAsync(WithCertificate(key, _authority, serial: 150), StrictHostKeyChecking.Yes)).Contains("revoked by file");
        await using var client = await ConnectAsync(WithCertificate(key, _authority, serial: 201), StrictHostKeyChecking.Yes);
        await Assert.That(client.HostKey.Certificate!.Serial).IsEqualTo(201ul);
    }

    [Test]
    public async Task ManySerials_AreLookedUpWithoutExpandingThem()
    {
        var key = FakeHostKey.Ed25519();
        var authority = _authority.PublicKey.ToArray();

        // A full 1 MiB bitmap (8 million serials) and overlapping, adjacent and out-of-order lists and ranges.
        var bitmap = new byte[1024 * 1024];
        Array.Fill(bitmap, (byte)0xff);
        bitmap[0] = 0x7f; // a positive mpint; the highest bit is 8 * 2^20 - 2
        var started = System.Diagnostics.Stopwatch.StartNew();
        var list = RevokedKeyList.Parse(new Krl()
            .Certificates(authority,
                (0x22, w => { w.WriteUInt64(1_000_000); w.WriteMpint(bitmap); }),
                (0x21, w => { w.WriteUInt64(50); w.WriteUInt64(60); }),
                (0x20, w => { w.WriteUInt64(61); w.WriteUInt64(10); w.WriteUInt64(55); }), // 61 joins 50..60; 55 is inside it
                (0x21, w => { w.WriteUInt64(5); w.WriteUInt64(9); }),                    // 5..9 then 10: adjacent
                (0x21, w => { w.WriteUInt64(ulong.MaxValue - 1); w.WriteUInt64(ulong.MaxValue); }))
            .Build());
        await Assert.That(started.Elapsed).IsLessThan(TimeSpan.FromSeconds(5));

        bool Revoked(ulong serial) => list.IsRevoked(key.Blob, Certificate(key, serial));
        foreach (var serial in new ulong[] { 5, 9, 10, 50, 55, 60, 61, 1_000_000, 1_000_000 + (8UL * 1024 * 1024) - 2, ulong.MaxValue - 1, ulong.MaxValue })
        {
            await Assert.That(Revoked(serial)).IsTrue().Because($"serial {serial}");
        }

        foreach (var serial in new ulong[] { 4, 11, 49, 62, 999_999, 1_000_000 + (8UL * 1024 * 1024) - 1, ulong.MaxValue - 2 })
        {
            await Assert.That(Revoked(serial)).IsFalse().Because($"serial {serial}");
        }
    }

    [Test]
    public async Task TheFile_IsParsedAgainOnlyWhenItChanges()
    {
        var first = FakeHostKey.Ed25519();
        var second = FakeHostKey.Ed25519();
        File.WriteAllText(RevokedFile, $"ssh-ed25519 {Convert.ToBase64String(first.Blob)}\n");

        var loaded = await RevokedKeyList.LoadAsync(RevokedFile, CancellationToken.None);
        await Assert.That(await RevokedKeyList.LoadAsync(RevokedFile, CancellationToken.None)).IsSameReferenceAs(loaded);

        // Same size, same timestamps: an edit still takes effect, since the cache compares the contents, not the file times.
        var times = File.GetLastWriteTimeUtc(RevokedFile);
        File.WriteAllText(RevokedFile, $"ssh-ed25519 {Convert.ToBase64String(second.Blob)}\n");
        File.SetLastWriteTimeUtc(RevokedFile, times);
        var reloaded = await RevokedKeyList.LoadAsync(RevokedFile, CancellationToken.None);
        await Assert.That(reloaded.IsRevoked(second.Blob, null)).IsTrue();
        await Assert.That(reloaded.IsRevoked(first.Blob, null)).IsFalse();
    }

    [Test]
    public async Task AKrlThatCannotBeChecked_RefusesEveryHostKey_AsSshDoes()
    {
        var key = FakeHostKey.Ed25519();
        var authority = _authority.PublicKey.ToArray();
        byte[][] unusable =
        [
            new Krl().Build(version: 2),
            new Krl().Section(9, _ => { }).Build(),                                               // an unknown section
            new Krl().Section(255, w => { w.WriteString("future"); w.WriteBoolean(true); w.WriteString(ReadOnlySpan<byte>.Empty); }).Build(), // critical extension
            new Krl().Certificates(authority, (0x40, _ => { })).Build(),                          // an unknown certificate section
            new Krl().Certificates(authority, (0x20, w => w.WriteUInt64(0))).Build(),              // serial 0
            new Krl().Certificates(authority, (0x21, w => { w.WriteUInt64(9); w.WriteUInt64(3); })).Build(), // an empty range
            new Krl().Certificates(authority, (0x22, w => { w.WriteUInt64(0); w.WriteMpint(new byte[] { 0x01 }); })).Build(), // bitmap: serial 0
            new Krl().Certificates(authority, (0x22, w => { w.WriteUInt64(ulong.MaxValue); w.WriteMpint(new byte[] { 0x02 }); })).Build(), // bitmap past 2^64 - 1
            new Krl().Section(3, w => w.WriteString(new byte[19])).Build(),                       // a SHA-1 of the wrong length
            new Krl().Signature(authority, new byte[64]).Section(2, w => w.WriteString(key.Blob)).Build(), // after a signature
            new Krl().Section(2, w => w.WriteString(key.Blob)).Build().Concat(new byte[] { 4, 0, 0, 0, 1, 0 }).ToArray(), // a signature without one
            new Krl().Build()[..20],                                                               // truncated
        ];

        foreach (var krl in unusable)
        {
            await Assert.That(() => RevokedKeyList.Parse(krl)).Throws<FormatException>();
        }

        File.WriteAllBytes(RevokedFile, unusable[1]);
        await Assert.That(await RefusalAsync(new FakeServerOptions { HostKey = key })).Contains("Error checking host key");

        File.Delete(RevokedFile);
        await Assert.That(await RefusalAsync(new FakeServerOptions { HostKey = key })).Contains("Error checking host key");

        // A non-critical extension and a trailing signature section (not verified) are fine.
        var usable = new Krl()
            .Section(255, w => { w.WriteString("future"); w.WriteBoolean(false); w.WriteString("data"); })
            .Signature(authority, new byte[64])
            .Signature(authority, new byte[64]) // ssh-keygen -s can sign with several keys
            .Build();
        await Assert.That(Revoked(usable, key)).IsFalse();
    }

    [Test]
    public async Task SshConfig_RevokedHostKeys_IsExpanded_AndRefusesTheConnection()
    {
        var key = FakeHostKey.Ed25519();
        File.WriteAllText(Path.Combine(_dir, "revoked-srv"), Line(key.Blob) + "\n");
        var resolve = new SshConfigResolveOptions { LocalUser = "local", HomeDirectory = _dir };

        await Assert.That(Path.GetFullPath(SshConfig.Parse("Host *\n RevokedHostKeys ~/revoked-%h\n").Resolve("srv", resolve).RevokedHostKeys!))
            .IsEqualTo(Path.GetFullPath(Path.Combine(_dir, "revoked-srv")));
        await Assert.That(SshConfig.Parse("Host *\n RevokedHostKeys none\n").Resolve("srv", resolve).RevokedHostKeys).IsNull();
        await Assert.That(SshConfig.Parse(string.Empty).Resolve("srv", resolve).RevokedHostKeys).IsNull();

        // StrictHostKeyChecking no accepts anything, except a revoked key.
        var server = new FakeSessionServer(new FakeServerOptions { HostKey = key });
        await using (server)
        {
            var error = await Assert.ThrowsAsync<SshHostKeyException>(async () =>
            {
                await using var client = await SshClient.ConnectAsync("srv", new SshConfigConnectOptions
                {
                    Config = SshConfig.Parse("Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n RevokedHostKeys ~/revoked-%h\n"),
                    ResolveOptions = resolve,
                    Password = "secret",
                    UseAgent = false,
                    TcpConnector = (_, _, _, _) =>
                    {
                        _ = server.StartAsync();
                        return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
                    },
                }, Timeout());
            });
            await Assert.That(error!.Message).Contains("revoked by file");
        }
    }

    [Test]
    public async Task UpdateHostKeys_NeverLearnsARevokedKey()
    {
        var revoked = FakeHostKey.Ed25519();
        var fine = FakeHostKey.Ecdsa(256);
        File.WriteAllText(RevokedFile, Line(revoked.Blob) + "\n");
        var verifier = new KnownHostsVerifier([KnownHosts]) { RevokedHostKeys = RevokedFile, UpdateHostKeys = true };

        var unknown = await verifier.UnknownHostKeysAsync(Host, 22, [revoked.Blob, fine.Blob], Timeout());

        await Assert.That(unknown.Count).IsEqualTo(1);
        await Assert.That(unknown[0].SequenceEqual(fine.Blob)).IsTrue();
    }

    // ---- KRLs written by the real ssh-keygen -k ----

    [Test]
    public async Task KrlsFromSshKeygen_RevokeWhatTheirSpecificationSays()
    {
        if (FindSshKeygen() is not { } sshKeygen)
        {
            Skip.Test("ssh-keygen is not installed.");
            return;
        }

        var explicitKey = FakeHostKey.Ed25519();
        var bySha1 = FakeHostKey.Ecdsa(256);
        var byHash = FakeHostKey.Ecdsa(384);
        var fine = FakeHostKey.Rsa(2048);
        var certified = FakeHostKey.Ed25519();
        File.WriteAllText(Path.Combine(_dir, "explicit.pub"), Line(explicitKey.Blob) + "\n");
        File.WriteAllText(Path.Combine(_dir, "ca.pub"), _authority.ToAuthorizedKeysLine() + "\n");

        // Odd serials 1001..1199 make ssh-keygen pick a bitmap section; a range and a list besides, and key ids.
        var spec = new StringBuilder()
            .AppendLine("serial: 7")
            .AppendLine("serial: 100-200")
            .AppendLine("id: bad-host");
        for (ulong s = 1001; s < 1200; s += 2)
        {
            spec.Append("serial: ").Append(s.ToString(System.Globalization.CultureInfo.InvariantCulture)).AppendLine();
        }

        File.WriteAllText(Path.Combine(_dir, "certs.spec"), spec.ToString());
        File.WriteAllText(Path.Combine(_dir, "keys.spec"),
            $"sha1: {Line(bySha1.Blob)}\nhash: {SshSharp.Keys.SshPublicKey.Parse(byHash.Blob).Fingerprint}\n");

        var krl = Path.Combine(_dir, "revoked.krl");
        await RunAsync(sshKeygen, "-k", "-f", krl, Path.Combine(_dir, "explicit.pub"), Path.Combine(_dir, "keys.spec"));
        await RunAsync(sshKeygen, "-k", "-u", "-f", krl, "-s", Path.Combine(_dir, "ca.pub"), Path.Combine(_dir, "certs.spec"));

        var list = await RevokedKeyList.LoadAsync(krl, Timeout());
        await Assert.That(list.IsKrl).IsTrue();
        await Assert.That(list.IsRevoked(explicitKey.Blob, null)).IsTrue();
        await Assert.That(list.IsRevoked(bySha1.Blob, null)).IsTrue();
        await Assert.That(list.IsRevoked(byHash.Blob, null)).IsTrue();
        await Assert.That(list.IsRevoked(fine.Blob, null)).IsFalse();
        foreach (var serial in new ulong[] { 7, 100, 150, 200, 1001, 1101, 1199 })
        {
            await Assert.That(list.IsRevoked(certified.Blob, Certificate(certified, serial))).IsTrue().Because($"serial {serial}");
        }

        foreach (var serial in new ulong[] { 8, 99, 201, 1000, 1002, 1200 })
        {
            await Assert.That(list.IsRevoked(certified.Blob, Certificate(certified, serial))).IsFalse().Because($"serial {serial}");
        }

        await Assert.That(list.IsRevoked(certified.Blob, Certificate(certified, serial: 5, keyId: "bad-host"))).IsTrue();
        await Assert.That(list.IsRevoked(certified.Blob, Certificate(certified, serial: 7, authority: _otherAuthority))).IsFalse();
    }

    private static async Task RunAsync(string program, params string[] arguments)
    {
        var start = new ProcessStartInfo(program) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var error = await process.StandardError.ReadToEndAsync();
        await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"ssh-keygen failed ({process.ExitCode}): {error}");
        }
    }

    private static string? FindSshKeygen()
    {
        var name = OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen";
        return (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, name))
            .FirstOrDefault(File.Exists);
    }
}
