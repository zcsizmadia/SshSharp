using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Integration;

/// <summary>Handshakes against a real OpenSSH server (see <see cref="RealServer"/>).</summary>
public class TransportInteropTests
{
    // Host key types the test server (ed25519, rsa, ecdsa-p256) offers, and key exchanges / ciphers it supports.
    public static IEnumerable<(string Kex, string Cipher, string HostKey)> Combinations()
    {
        string[] kex = [SshAlgorithms.Curve25519Sha256, SshAlgorithms.EcdhNistp256, SshAlgorithms.EcdhNistp384, SshAlgorithms.EcdhNistp521, SshAlgorithms.DhGroup14Sha256, SshAlgorithms.DhGroup16Sha512,
            SshAlgorithms.DhGroupExchangeSha256, SshAlgorithms.DhGroup18Sha512];
        string[] ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"];
        string[] hostKeys = [SshAlgorithms.SshEd25519, SshAlgorithms.EcdsaNistp256, SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256];

        // Every kex with the default cipher and host key; every cipher with the default kex; every host key with the default kex.
        foreach (var k in kex)
        {
            yield return (k, ciphers[0], hostKeys[0]);
        }

        foreach (var c in ciphers.Skip(1))
        {
            yield return (kex[0], c, hostKeys[0]);
        }

        foreach (var h in hostKeys.Skip(1))
        {
            yield return (kex[0], ciphers[0], h);
        }

        // The post-quantum hybrid (OpenSSH 9.9+), where this platform has ML-KEM; older servers skip it as not offered.
        if (SshAlgorithms.HasMlKem)
        {
            yield return (SshAlgorithms.MlKem768X25519Sha256, ciphers[0], hostKeys[0]);
        }

        // sntrup761 everywhere: under its RFC name (OpenSSH 9.9+) and its original one (OpenSSH 8.5+); Dropbear 2022.83+ has the latter.
        yield return (SshAlgorithms.Sntrup761X25519Sha512, ciphers[0], hostKeys[0]);
        yield return (SshAlgorithms.Sntrup761X25519Sha512OpenSsh, ciphers[0], hostKeys[0]);
    }

    private static SshTransportOptions Options(string kex, string cipher, string hostKey, List<HostKeyInfo> seen) => new()
    {
        Preferences = new AlgorithmPreferences { Kex = [kex], Ciphers = [cipher], HostKeys = [hostKey] },
        VerifyHostKey = (info, _) =>
        {
            seen.Add(info);
            return ValueTask.FromResult(true);
        },
    };

    /// <summary>
    /// Many key exchanges per host key type (SSHSHARP_TEST_HANDSHAKES, default off): a host key signature that fails once in a few
    /// thousand handshakes (#188, against AsyncSSH with rsa-sha2-512) shows how often, and whether only one key type is affected. Only
    /// the key exchange runs; each failure is reported with the signature's own description.
    /// </summary>
    [Test]
    public async Task ManyKeyExchanges_PerHostKey_AllVerify()
    {
        if (!RealServer.IsAvailable || !int.TryParse(Environment.GetEnvironmentVariable("SSHSHARP_TEST_HANDSHAKES"), out var count) || count <= 0)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_HANDSHAKES (handshakes per host key) are needed.");
            return;
        }

        string[] hostKeys = [SshAlgorithms.SshEd25519, SshAlgorithms.EcdsaNistp256, SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256];
        var report = new System.Text.StringBuilder();
        var failed = 0;
        foreach (var hostKey in hostKeys)
        {
            var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var done = 0;
            await Parallel.ForAsync(0, count, new ParallelOptions { MaxDegreeOfParallelism = 8 }, async (_, ct) =>
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try
                {
                    // The TCP connect too: one that fails is counted, not the end of the run (and of its report).
                    await using var stream = await RealServer.ConnectAsync().WaitAsync(timeout.Token);
                    await using var transport = new SshTransport(stream, Options(SshAlgorithms.Curve25519Sha256, "chacha20-poly1305@openssh.com", hostKey, []));
                    await transport.ConnectAsync(timeout.Token);
                    Interlocked.Increment(ref done);
                }
                catch (SshException ex) when (ex.Message.StartsWith("No matching", StringComparison.Ordinal))
                {
                    failures.Enqueue("not offered");
                }
                catch (Exception ex)
                {
                    failures.Enqueue($"{ex.GetType().Name}: {ex.Message}");
                }
            });

            if (failures.All(f => f == "not offered") && done == 0)
            {
                report.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"{hostKey}: not offered by {RealServer.Software}");
                continue;
            }

            failed += failures.Count;
            report.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"{hostKey}: {done} of {count} verified, {failures.Count} failed");
            foreach (var group in failures.GroupBy(f => f).Take(5))
            {
                report.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"  {group.Count()} x {group.Key}");
            }
        }

        Console.WriteLine(report);
        if (Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY") is { Length: > 0 } summary)
        {
            // Shown on the CI run's page whether the test passes or fails.
            await File.AppendAllTextAsync(summary, $"### Key exchanges per host key ({RealServer.Software}, {Environment.Version})\n```\n{report}```\n");
        }

        if (failed > 0)
        {
            Assert.Fail(report.ToString());
        }
    }

    [Test]
    [MethodDataSource(nameof(Combinations))]
    public async Task HandshakeAndEncryptedRoundTrip(string kex, string cipher, string hostKey)
    {
        if (!RealServer.IsAvailable)
        {
            Skip.Test("SSHSHARP_TEST_SSHD is not set.");
        }

        var seen = new List<HostKeyInfo>();

        // Finite-field DH up to 8192 bits is CPU-bound BigInteger work (the group exchange's primality round alone is about 0.65 s on a
        // fast machine). Under the parallel test load of a 4-core CI runner it took over 20 s once, so these get more time; a hang still
        // fails.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(kex.StartsWith("diffie-hellman", StringComparison.Ordinal) ? 90 : 20));
        var (stream, transport) = await ConnectOrSkipAsync(() =>
        {
            seen.Clear();
            return Options(kex, cipher, hostKey, seen);
        }, timeout.Token);
        await using var connectedStream = stream;
        await using var connected = transport;

        await Assert.That(transport.Algorithms!.Kex).IsEqualTo(kex);
        await Assert.That(transport.Algorithms.CipherClientToServer).IsEqualTo(cipher);
        await Assert.That(transport.Algorithms.HostKey).IsEqualTo(hostKey);
        await Assert.That(transport.Algorithms.StrictKex).IsEqualTo(RealServer.SupportsStrictKex);
        await Assert.That(transport.SessionId!.Length).IsGreaterThanOrEqualTo(32);
        await Assert.That(seen.Count).IsEqualTo(1);
        await Assert.That(seen[0].Fingerprint).StartsWith("SHA256:");

        // The first encrypted request and reply in each direction: if either direction's keys were wrong this would fail.
        await AssertServiceRequestIsAcceptedAsync(transport, timeout.Token);
    }

    /// <summary>
    /// The plain (encrypt-and-MAC) HMACs of RFC 4253 with AES-CTR (#268), the combination network equipment often offers alone. The
    /// client offers only that MAC and cipher, so the handshake and the round trip after it use them in both directions.
    /// </summary>
    [Test]
    [Arguments("aes128-ctr", "hmac-sha2-256")]
    [Arguments("aes128-ctr", "hmac-sha2-512")]
    public async Task PlainHmacSha2_HandshakeAndEncryptedRoundTrip(string cipher, string mac)
    {
        if (!RealServer.IsAvailable)
        {
            Skip.Test("SSHSHARP_TEST_SSHD is not set.");
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (stream, transport) = await ConnectOrSkipAsync(() => new SshTransportOptions
        {
            Preferences = new AlgorithmPreferences { Ciphers = [cipher], Macs = [mac] },
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
        }, timeout.Token);
        await using var connectedStream = stream;
        await using var connected = transport;

        await Assert.That(transport.Algorithms!.CipherClientToServer).IsEqualTo(cipher);
        await Assert.That(transport.Algorithms.CipherServerToClient).IsEqualTo(cipher);
        await Assert.That(transport.Algorithms.MacClientToServer).IsEqualTo(mac);
        await Assert.That(transport.Algorithms.MacServerToClient).IsEqualTo(mac);
        await AssertServiceRequestIsAcceptedAsync(transport, timeout.Token);
    }

    private static async Task AssertServiceRequestIsAcceptedAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        var request = new ArrayBufferWriter<byte>();
        var writer = new SshWriter(request);
        writer.WriteByte(SshMessage.ServiceRequest);
        writer.WriteString("ssh-userauth");
        await transport.SendAsync(request.WrittenMemory, cancellationToken);

        using var reply = await transport.ReceiveAsync(cancellationToken);
        await Assert.That(reply.Payload.Span[0]).IsEqualTo(SshMessage.ServiceAccept);
    }

    /// <summary>
    /// Connects a transport with fresh options per attempt. A server without the algorithms skips the test; the caller disposes the
    /// stream and transport.
    /// </summary>
    private static async Task<(Stream Stream, SshTransport Transport)> ConnectOrSkipAsync(Func<SshTransportOptions> options, CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            var stream = await RealServer.ConnectAsync();
            var transport = new SshTransport(stream, options());
            try
            {
                await transport.ConnectAsync(cancellationToken);
                return (stream, transport);
            }
            catch (SshException ex) when (ex.Reason == SshFailureReason.KeyExchangeFailed && ex.Message.StartsWith("No matching", StringComparison.Ordinal))
            {
                // Older OpenSSH and Dropbear lack some algorithms; only "the server does not offer it" is a skip, anything else fails.
                await transport.DisposeAsync();
                await stream.DisposeAsync();
                Skip.Test($"{RealServer.Software} does not offer this combination: {ex.Message}");
                throw new System.Diagnostics.UnreachableException(); // Skip.Test throws
            }
            catch (Exception ex) when (attempt == 1 && ex is IOException or SshException { Reason: SshFailureReason.ConnectionClosed })
            {
                // A server that finds nothing in common disconnects at once, and OpenSSH for Windows resets the connection; Windows may then
                // drop its KEXINIT before the client reads it, so the client sees the reset instead of "no matching". Once more decides:
                // that race is rare, and a real failure fails again.
                await transport.DisposeAsync();
                await stream.DisposeAsync();
            }
        }
    }

    [Test]
    public async Task ServerAnnouncesExtensions_AndIdentifiesItself()
    {
        if (!RealServer.IsAvailable)
        {
            Skip.Test("SSHSHARP_TEST_SSHD is not set.");
        }

        await using var stream = await RealServer.ConnectAsync();
        await using var transport = new SshTransport(stream, new SshTransportOptions { VerifyHostKey = (_, _) => ValueTask.FromResult(true) });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await transport.ConnectAsync(timeout.Token);

        await Assert.That(transport.ServerIdentification!.SoftwareVersion).StartsWith(RealServer.Software, StringComparison.OrdinalIgnoreCase);
        await Assert.That(transport.ServerIdentification.ProtocolVersion).IsEqualTo("2.0");

        // OpenSSH sends SSH_MSG_EXT_INFO with server-sig-algs right after NEWKEYS, before it answers anything: provoke the first read.
        var request = new ArrayBufferWriter<byte>();
        new SshWriter(request).WriteByte(SshMessage.ServiceRequest);
        var writer = new SshWriter(request);
        writer.WriteString("ssh-userauth");
        await transport.SendAsync(request.WrittenMemory, timeout.Token);
        using var reply = await transport.ReceiveAsync(timeout.Token);
        await Assert.That(transport.ServerExtensions.ContainsKey("server-sig-algs")).IsTrue();
    }

    [Test]
    public async Task RejectedHostKeyAbortsTheConnection()
    {
        if (!RealServer.IsAvailable)
        {
            Skip.Test("SSHSHARP_TEST_SSHD is not set.");
        }

        await using var stream = await RealServer.ConnectAsync();
        await using var transport = new SshTransport(stream, new SshTransportOptions { VerifyHostKey = (_, _) => ValueTask.FromResult(false) });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ex = await Assert.ThrowsAsync<SshException>(() => transport.ConnectAsync(timeout.Token));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
    }
}