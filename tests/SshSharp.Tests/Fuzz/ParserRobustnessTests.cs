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
    public async Task PublicKeyParsing_AndVerification_OnlyEverFailWithAProtocolError()
    {
        var failures = Run(PublicKeyBlobs(), input =>
        {
            var key = SshPublicKey.Parse(input);

            // Whatever parsed must also survive verifying garbage.
            key.VerifySignature(key.KeyType, input, input);
        }, ProtocolErrors);
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
        var key = SshPublicKey.Parse(Blob(w =>
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
