using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Config;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Fuzz;

/// <summary>
/// Mutation fuzzing in the regular test run: every parser that reads untrusted input is fed thousands of corrupted variants of valid
/// inputs (fixed seeds, so failures reproduce). A parser may reject input only with its documented exception; anything else
/// (index out of range, overflow, argument exceptions, hangs) is a bug. This is the cheap, always-on part of fuzzing; coverage-guided
/// fuzzing (SharpFuzz) is planned for nightly runs.
/// </summary>
public class ParserRobustnessTests
{
    private const int Iterations = 3000;

    [Test]
    public async Task PacketDecoding_OnlyEverFailsWithAProtocolError()
    {
        var plain = Packets(PacketProtector.None);
        var key = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var sealedPackets = Packets(new AesGcmProtector(key, iv));

        var failures = Run(plain, input => Decode(input, PacketProtector.None), ProtocolErrors);
        failures.AddRange(Run(sealedPackets, input =>
        {
            using var protector = new AesGcmProtector(key, iv);
            Decode(input, protector);
        }, ProtocolErrors));
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task KexInitParsing_OnlyEverFailsWithAProtocolError()
    {
        var buffer = new ArrayBufferWriter<byte>();
        KexInitMessage.ForClient(new AlgorithmPreferences()).Write(buffer);
        var failures = Run([buffer.WrittenSpan.ToArray()], input => KexInitMessage.Parse(input), ProtocolErrors);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task CompressedPayloads_OnlyEverFailWithAProtocolError()
    {
        // zlib@openssh.com's inflater, fed one stream as consecutive packets (each framed by a 2-byte length here, as the fuzz target
        // does): corrupt zlib data, streams that end early or go on after their end, and bombs must all be clean rejections.
        var failures = Run(CompressedStreams(), InflatePackets, ProtocolErrors, iterations: 2000);
        await Assert.That(failures).IsEmpty();
    }

    /// <summary>Splits <paramref name="input"/> into packets (a 2-byte big-endian length, then that many bytes) and inflates them as one stream.</summary>
    private static void InflatePackets(byte[] input)
    {
        using var decompressor = new ZlibDecompressor(limit: 64 * 1024);
        var rest = input.AsMemory();
        while (!rest.IsEmpty)
        {
            ReadOnlyMemory<byte> payload;
            if (rest.Length < 2)
            {
                payload = rest;
                rest = default;
            }
            else
            {
                var length = Math.Min((rest.Span[0] << 8) | rest.Span[1], rest.Length - 2);
                payload = rest.Slice(2, length);
                rest = rest[(2 + length)..];
            }

            decompressor.Decompress(payload).Dispose();
        }
    }

    private static byte[][] CompressedStreams()
    {
        byte[] Stream(params byte[][] payloads)
        {
            var framed = new List<byte>();
            var output = new MemoryStream();
            using var zlib = new System.IO.Compression.ZLibStream(output, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true);
            foreach (var payload in payloads)
            {
                output.SetLength(0);
                zlib.Write(payload);
                zlib.Flush();
                var compressed = output.ToArray();
                framed.Add((byte)(compressed.Length >> 8));
                framed.Add((byte)compressed.Length);
                framed.AddRange(compressed);
            }

            return [.. framed];
        }

        var text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("drwxr-xr-x 2 deploy staff 4096 config\n", 40)));
        return
        [
            Stream(text),
            Stream([94, 0, 0, 0, 1], text, [96, 0, 0, 0, 1]),
            Stream(RandomNumberGenerator.GetBytes(300), text.AsSpan(0, 50).ToArray()),
            Stream(new byte[60_000]),
        ];
    }

    [Test]
    public async Task PublicKeyParsing_AndVerification_OnlyEverFailWithAProtocolError()
    {
        var failures = Run(PublicKeyBlobs(), input =>
        {
            var key = VerifyingKey.Parse(input);

            // Whatever parsed must also survive verifying garbage.
            key.VerifySignature(key.KeyType, input, input);
        }, ProtocolErrors);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task PublicSshPublicKey_OnlyEverFailsWithAFormatError()
    {
        // The public type over the same blobs and FIDO security keys, as a blob and as a .pub line: fingerprints, the line and
        // verifying garbage must survive whatever parsed.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = ecdsa.ExportParameters(false).Q;
        byte[][] blobs =
        [
            .. PublicKeyBlobs(),
            Blob(w => { w.WriteString("sk-ssh-ed25519@openssh.com"); w.WriteString(new byte[32]); w.WriteString("ssh:"); }),
            Blob(w => { w.WriteString("sk-ecdsa-sha2-nistp256@openssh.com"); w.WriteString("nistp256"); w.WriteString([4, .. q.X!, .. q.Y!]); w.WriteString("ssh:"); }),
        ];

        static void Use(SshPublicKey key, byte[] input)
        {
            _ = key.GetFingerprint(HashAlgorithmName.MD5);
            _ = key.ToAuthorizedKeysLine();
            if (!key.KeyType.StartsWith("sk-", StringComparison.Ordinal))
            {
                key.VerifySignature(input, input);
            }
        }

        var failures = Run(blobs, input => Use(SshPublicKey.FromBlob(input), input), FormatErrors);
        var lines = blobs.Select(b => Encoding.UTF8.GetBytes($"{new SshReader(b).ReadUtf8String()} {Convert.ToBase64String(b)} user@example")).ToArray();
        failures.AddRange(Run(lines, input => Use(SshPublicKey.Parse(Encoding.UTF8.GetString(input)), input), FormatErrors));
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task SignatureVerification_NeverThrows()
    {
        var seed = new byte[32];
        new Random(7).NextBytes(seed);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        var signature = new byte[64];
        Ed25519.Sign(seed, "m"u8, signature);
        var blob = Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(signature);
        });
        var key = VerifyingKey.Parse(Blob(w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(pub);
        }));

        var failures = Run([blob], input =>
        {
            // VerifySignature returns false for anything malformed; it never throws.
            key.VerifySignature("ssh-ed25519", input, "m"u8);
        }, allowed: null);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task IdentificationParsing_NeverThrows()
    {
        var seeds = new[] { "SSH-2.0-OpenSSH_9.9 comment", "SSH-1.99-Cisco-1.25", "SSH-2.0-x" }.Select(Encoding.ASCII.GetBytes).ToArray();
        var failures = Run(seeds, input => _ = SshIdentification.TryParse(Encoding.Latin1.GetString(input), out _), allowed: null);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task KnownHostsParsing_OnlyEverFailsWithAFormatError()
    {
        var seed = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "known_hosts_openssh_hashed"));
        var failures = Run([seed], input =>
        {
            var file = KnownHostsFile.Parse(Encoding.UTF8.GetString(input));
            foreach (var entry in file.Entries)
            {
                entry.Matches("example.com", 22);
            }
        }, FormatErrors, iterations: 1000);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task RevokedKeysParsing_OnlyEverFailsWithAFormatError()
    {
        // RevokedHostKeys: a KRL written by ssh-keygen -k (fingerprints, serials, a range, key ids), and a key list.
        var krl = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "revoked.krl"));
        var list = Encoding.UTF8.GetBytes(string.Join('\n', PublicKeyBlobs().Select(b => $"{new SshReader(b).ReadUtf8String()} {Convert.ToBase64String(b)}")));
        var probe = PublicKeyBlobs()[0];
        var failures = Run([krl, list], input => RevokedKeyList.Parse(input).IsRevoked(probe, null), FormatErrors, iterations: 2000);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task SshConfigParsingAndResolving_OnlyEverFailWithAFormatError()
    {
        var seed = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ssh_config_sample"));
        var options = new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = "/h", LocalHostName = "l", GetEnvironmentVariable = _ => "v" };
        var failures = Run([seed], input =>
        {
            var config = SshConfig.Parse(Encoding.UTF8.GetString(input), "/nonexistent");
            config.Resolve("web", options);
        }, FormatErrors, iterations: 1000);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task PrivateKeyParsing_OnlyEverFailsWithAFormatError()
    {
        // Mutate the decoded OpenSSH key and re-wrap it, so the binary parser is exercised rather than the base64 decoder.
        static byte[] Body(string pem) => Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal))));
        byte[][] seeds =
        [
            Body(Keys.TestKeys.OpenSshEd25519(out _)),
            Body(Keys.TestKeys.OpenSshEcdsa(ECCurve.NamedCurves.nistP256, "nistp256", out _)),
            Body(Keys.TestKeys.OpenSshRsa(2048, out _)),
        ];
        var failures = Run(seeds, input =>
        {
            var pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(input) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            using var key = SshPrivateKey.Parse(pem);
            key.Sign(key.SignatureAlgorithms[0], "m"u8);
        }, FormatErrors, iterations: 1500);

        // PEM: corrupt DER inside a valid PEM frame.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        failures.AddRange(Run([ecdsa.ExportPkcs8PrivateKey(), ecdsa.ExportECPrivateKey()], input =>
        {
            using var key = SshPrivateKey.Parse(PemEncoding.WriteString("PRIVATE KEY", input));
        }, FormatErrors, iterations: 500));
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task CertificateParsingAndChecking_OnlyEverFailWithAProtocolError()
    {
        // Host certificates come from the server: parsing and every check must reject garbage cleanly.
        using var authority = SshPrivateKey.Parse(Keys.TestKeys.OpenSshEd25519(out _));
        using var rsaAuthority = SshPrivateKey.Parse(Keys.TestKeys.OpenSshRsa(2048, out _));
        var seeds = PublicKeyBlobs()
            .Select(key => Keys.TestKeys.Certificate(authority, key, SshCertificateType.Host, ["a", "b"], criticalOptions: [("x", "y")]))
            .Append(Keys.TestKeys.Certificate(rsaAuthority, PublicKeyBlobs()[0], SshCertificateType.User))
            .ToArray();
        var failures = Run(seeds, input =>
        {
            var certificate = SshCertificate.FromBlob(input);
            certificate.CheckForHost("a", DateTimeOffset.UtcNow);
            _ = certificate.ValidBefore;
            _ = certificate.AuthorityFingerprint;
        }, ProtocolErrors, iterations: 2000);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task PuttyKeyParsing_OnlyEverFailsWithAFormatError()
    {
        byte[][] seeds =
        [
            Encoding.Latin1.GetBytes(Keys.TestKeys.Ppk(2, "ssh-ed25519", out _)),
            Encoding.Latin1.GetBytes(Keys.TestKeys.Ppk(3, "ecdsa-sha2-nistp256", out _)),
            Encoding.Latin1.GetBytes(Keys.TestKeys.Ppk(3, "ssh-ed25519", out _, passphrase: "pw")),
        ];
        var failures = Run(seeds, input =>
        {
            using var key = SshPrivateKey.Parse(Encoding.Latin1.GetString(input), "pw");
        }, FormatErrors, iterations: 1500);
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task SftpReplyParsing_OnlyEverFailsWithAnSshException()
    {
        // Every reply an SFTP server can send passes through one of the client's parsers; SftpException is an SshException too.
        var failures = Run(SftpReplySeeds(), global::SshSharp.Sftp.SftpClient.ParseAnyReply, ex => ex is SshException, iterations: 5000);
        await Assert.That(failures).IsEmpty();
    }

    /// <summary>One valid example of each SFTP reply type: version, status, handle, data, name, attributes, and the limits reply.</summary>
    internal static byte[][] SftpReplySeeds() =>
    [
        Reply(w => { w.WriteByte(2); w.WriteUInt32(3); w.WriteString("posix-rename@openssh.com"); w.WriteString("1"); w.WriteString("limits@openssh.com"); w.WriteString("1"); }),
        Reply(w => { w.WriteByte(101); w.WriteUInt32(7); w.WriteUInt32(2); w.WriteString("No such file"); w.WriteString("en"); }),
        Reply(w => { w.WriteByte(101); w.WriteUInt32(7); w.WriteUInt32(0); w.WriteString(""); w.WriteString(""); }),
        Reply(w => { w.WriteByte(102); w.WriteUInt32(7); w.WriteString("handle-1"); }),
        Reply(w => { w.WriteByte(103); w.WriteUInt32(7); w.WriteString("file contents"u8); }),
        Reply(w =>
        {
            w.WriteByte(104);
            w.WriteUInt32(7);
            w.WriteUInt32(2);
            foreach (var name in new[] { "a.txt", "dir" })
            {
                w.WriteString(name);
                w.WriteString("-rw-r--r-- 1 u g 5 Jan 1 2024 " + name);
                SftpAttributes(w);
            }
        }),
        Reply(w => { w.WriteByte(105); w.WriteUInt32(7); SftpAttributes(w); }),
        Reply(w => { w.WriteByte(201); w.WriteUInt32(7); w.WriteUInt64(262144); w.WriteUInt64(261120); w.WriteUInt64(261120); w.WriteUInt64(0); }),
        Reply(w => { w.WriteByte(201); w.WriteUInt32(7); w.WriteString("check-file"); w.WriteString("sha256"); w.WriteBytes(new byte[32]); }),
        Reply(w => { w.WriteByte(201); w.WriteUInt32(7); w.WriteString("check-file"); w.WriteString("vendor@example.com"); w.WriteBytes([1, 2, 3]); }),
        Reply(w => { w.WriteByte(201); w.WriteUInt32(7); w.WriteString("md5-hash"); w.WriteString(new byte[16]); }),
    ];

    private static void SftpAttributes(SshWriter w)
    {
        w.WriteUInt32(0x8000000F); // size, uid/gid, permissions, times, extended
        w.WriteUInt64(5);
        w.WriteUInt32(1000);
        w.WriteUInt32(1000);
        w.WriteUInt32(0x81A4);
        w.WriteUInt32(1_700_000_000);
        w.WriteUInt32(1_700_000_000);
        w.WriteUInt32(1);
        w.WriteString("vendor@example");
        w.WriteString("data");
    }

    private static byte[] Reply(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    [Test]
    public async Task TheHarness_ReportsUnexpectedExceptions_AndMutates()
    {
        // A harness that silently swallowed everything would make every test above pass.
        var failures = Run([[1, 2, 3]], _ => throw new InvalidOperationException("boom"), ProtocolErrors, iterations: 10);
        await Assert.That(failures).IsNotEmpty();
        await Assert.That(failures[0]).Contains("InvalidOperationException");
        await Assert.That(Run([[1, 2, 3]], _ => throw new SshProtocolException("ok"), ProtocolErrors, iterations: 10)).IsEmpty();

        var seen = new HashSet<string>();
        Run([[1, 2, 3, 4, 5, 6, 7, 8]], input => seen.Add(Convert.ToHexString(input)), allowed: null, iterations: 100);
        await Assert.That(seen.Count).IsGreaterThan(50);
    }

    // ---- harness ----

    private static readonly Func<Exception, bool> ProtocolErrors = ex => ex is SshProtocolException;

    private static readonly Func<Exception, bool> FormatErrors = ex => ex is FormatException;

    /// <summary>
    /// Runs mutations of the seeds through <paramref name="parse"/> and returns a description of each unexpected exception.
    /// <paramref name="allowed"/> says which exceptions are a clean rejection (null: none, the parser must never throw).
    /// </summary>
    private static List<string> Run(byte[][] seeds, Action<byte[]> parse, Func<Exception, bool>? allowed, int iterations = Iterations)
    {
        var random = new Random(20261013);
        var failures = new List<string>();
        foreach (var seed in seeds)
        {
            Check(seed);
        }

        for (var i = 0; i < iterations; i++)
        {
            Check(Mutate(seeds[random.Next(seeds.Length)], random));
        }

        return failures;

        void Check(byte[] input)
        {
            try
            {
                parse(input);
            }
            catch (Exception ex) when (allowed?.Invoke(ex) == true)
            {
                // A clean rejection.
            }
            catch (Exception ex) when (failures.Count < 5)
            {
                failures.Add($"{ex.GetType().Name}: {ex.Message} (input {Convert.ToHexString(input.AsSpan(0, Math.Min(input.Length, 48)))})");
            }
            catch (Exception)
            {
                // Enough examples collected.
            }
        }
    }

    private static readonly byte[] Interesting = [0x00, 0x01, 0x7f, 0x80, 0xff, (byte)'%', (byte)'\n', (byte)'"', (byte)' ', (byte)','];

    private static byte[] Mutate(byte[] seed, Random random)
    {
        var data = new List<byte>(seed);
        var operations = random.Next(1, 5);
        for (var op = 0; op < operations; op++)
        {
            var at = data.Count == 0 ? 0 : random.Next(data.Count);
            switch (random.Next(7))
            {
                case 0 when data.Count > 0:
                    data[at] ^= (byte)(1 << random.Next(8));
                    break;
                case 1 when data.Count > 0:
                    data[at] = Interesting[random.Next(Interesting.Length)];
                    break;
                case 2 when data.Count > 0:
                    data.RemoveRange(at, Math.Min(data.Count - at, random.Next(1, 16)));
                    break;
                case 3:
                    data.InsertRange(at, Enumerable.Range(0, random.Next(1, 8)).Select(_ => (byte)random.Next(256)));
                    break;
                case 4 when data.Count > 4:
                    // Length fields are where parsers break: overwrite four bytes with a big-endian edge value.
                    var value = random.Next(4) switch { 0 => 0u, 1 => uint.MaxValue, 2 => 0x7fffffffu, _ => (uint)random.Next() };
                    at = Math.Min(at, data.Count - 4);
                    data[at] = (byte)(value >> 24);
                    data[at + 1] = (byte)(value >> 16);
                    data[at + 2] = (byte)(value >> 8);
                    data[at + 3] = (byte)value;
                    break;
                case 5 when data.Count > 0:
                    data.RemoveRange(at, data.Count - at); // truncate
                    break;
                default:
                    if (data.Count > 0)
                    {
                        var length = Math.Min(data.Count - at, random.Next(1, 32));
                        data.InsertRange(at, data.GetRange(at, length)); // duplicate a chunk
                    }

                    break;
            }
        }

        return [.. data];
    }

    private static void Decode(byte[] input, PacketProtector protector)
    {
        var sequence = new ReadOnlySequence<byte>(input);
        while (PacketCodec.TryDecode(sequence, protector, 0, out var packet, out var consumed))
        {
            packet!.Dispose();
            sequence = sequence.Slice(consumed);
        }
    }

    private static byte[][] Packets(PacketProtector protector)
    {
        var result = new List<byte[]>();
        foreach (var size in new[] { 1, 17, 100, 1000 })
        {
            var buffer = new ArrayBufferWriter<byte>();
            var payload = new byte[size];
            new Random(size).NextBytes(payload);
            payload[0] = 94;
            PacketCodec.Encode(buffer, payload, protector, 0);
            result.Add(buffer.WrittenSpan.ToArray());
        }

        return [.. result];
    }

    private static byte[][] PublicKeyBlobs()
    {
        var seed = new byte[32];
        new Random(3).NextBytes(seed);
        var ed = new byte[32];
        Ed25519.GetPublicKey(seed, ed);

        using var rsa = RSA.Create(2048);
        var rsaParameters = rsa.ExportParameters(false);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ec = ecdsa.ExportParameters(false);

        return
        [
            Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(ed); }),
            Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(rsaParameters.Exponent); w.WriteMpint(rsaParameters.Modulus); }),
            Blob(w => { w.WriteString("ecdsa-sha2-nistp256"); w.WriteString("nistp256"); w.WriteString([4, .. ec.Q.X!, .. ec.Q.Y!]); }),
        ];
    }

    private static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }
}
