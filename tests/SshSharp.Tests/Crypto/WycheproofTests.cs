using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Crypto;

/// <summary>
/// Project Wycheproof's test vectors (C2SP, Fixtures/wycheproof/README.md) against the primitives SshSharp implements itself (X25519,
/// Ed25519, ChaCha20 and Poly1305) and its SSH signature verification (ECDSA, RSA PKCS#1 v1.5), #218. Each vector is an edge case that
/// broke a real implementation. "valid" must verify, "invalid" must be refused, and "acceptable" may go either way, but when it is
/// accepted the result must be the right one. Every mismatch in a file is reported at once, with its id, comment and flags.
/// </summary>
public class WycheproofTests
{
    private static JsonElement Load(string file)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "wycheproof", file);
        return JsonDocument.Parse(File.ReadAllBytes(path)).RootElement;
    }

    private static byte[] Hex(JsonElement element, string name) => Convert.FromHexString(element.GetProperty(name).GetString()!);

    private static string Describe(JsonElement test) =>
        $"tcId {test.GetProperty("tcId").GetInt32()} ({test.GetProperty("comment").GetString()}; " +
        $"{string.Join(",", test.GetProperty("flags").EnumerateArray().Select(f => f.GetString()))})";

    private static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Fails with every mismatch (the first 40 in full), after checking the file was really read.</summary>
    private static async Task ReportAsync(string file, int tested, List<string> mismatches)
    {
        await Assert.That(tested).IsGreaterThan(0);
        if (mismatches.Count > 0)
        {
            Assert.Fail($"{file}: {mismatches.Count} of {tested} vectors gave the wrong answer:{Environment.NewLine}" +
                string.Join(Environment.NewLine, mismatches.Take(40)));
        }
    }

    [Test]
    public async Task X25519_AgreesOrRefusesAsWycheproofExpects()
    {
        var root = Load("x25519_test.json");
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var test in root.GetProperty("testGroups").EnumerateArray().SelectMany(g => g.GetProperty("tests").EnumerateArray()))
        {
            tested++;
            var expected = Hex(test, "shared");
            var shared = new byte[32];
            var agreed = X25519.TryAgree(Hex(test, "private"), Hex(test, "public"), shared);
            var result = test.GetProperty("result").GetString();

            // Refusing is right for an all-zero result (a low-order point; RFC 7748 section 6.1 lets a protocol abort), which Wycheproof
            // marks acceptable. Accepting with a different secret is wrong whatever the label.
            if (agreed && !shared.AsSpan().SequenceEqual(expected))
            {
                mismatches.Add($"{Describe(test)}: agreed on {Convert.ToHexString(shared)}, expected {Convert.ToHexString(expected)}");
            }
            else if (!agreed && result == "valid")
            {
                mismatches.Add($"{Describe(test)}: refused a valid exchange");
            }
        }

        await ReportAsync("x25519_test.json", tested, mismatches);
    }

    [Test]
    public async Task Ed25519_VerifiesExactlyTheValidSignatures()
    {
        var root = Load("ed25519_test.json");
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var publicKey = Hex(group.GetProperty("publicKey"), "pk");
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                var valid = test.GetProperty("result").GetString() == "valid";
                bool verified;
                try
                {
                    verified = Ed25519.Verify(publicKey, Hex(test, "msg"), Hex(test, "sig"));
                }
                catch (Exception ex)
                {
                    mismatches.Add($"{Describe(test)}: threw {ex.GetType().Name}: {ex.Message}");
                    continue;
                }

                if (verified != valid)
                {
                    mismatches.Add($"{Describe(test)}: {(verified ? "accepted an invalid" : "refused a valid")} signature");
                }
            }
        }

        await ReportAsync("ed25519_test.json", tested, mismatches);
    }

    /// <summary>
    /// RFC 8439's AEAD, built from SshSharp's ChaCha20 block function and Poly1305: SSH uses OpenSSH's construction of the same two
    /// primitives (chacha20-poly1305@openssh.com), so these vectors test the primitives, Poly1305's edge cases among them.
    /// </summary>
    [Test]
    public async Task ChaCha20AndPoly1305_MatchTheRfc8439Vectors()
    {
        var root = Load("chacha20_poly1305_test.json");
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            if (group.GetProperty("ivSize").GetInt32() != 96 || group.GetProperty("keySize").GetInt32() != 256)
            {
                continue; // other nonce and key sizes are tests of an API that takes them, which these primitives do not
            }

            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                var (ciphertext, tag) = Rfc8439Seal(Hex(test, "key"), Hex(test, "iv"), Hex(test, "aad"), Hex(test, "msg"));
                var matches = ciphertext.AsSpan().SequenceEqual(Hex(test, "ct")) && tag.AsSpan().SequenceEqual(Hex(test, "tag"));
                var valid = test.GetProperty("result").GetString() == "valid";
                if (matches != valid)
                {
                    mismatches.Add($"{Describe(test)}: {(matches ? "an invalid vector matched" : "a valid vector did not match")}");
                }
            }
        }

        await ReportAsync("chacha20_poly1305_test.json", tested, mismatches);
    }

    private static (byte[] Ciphertext, byte[] Tag) Rfc8439Seal(byte[] key, byte[] nonce, byte[] aad, byte[] message)
    {
        uint Word(int i) => BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4));

        // Block 0's first 32 bytes are the one-time Poly1305 key; the message is encrypted from block 1 on.
        var block = new byte[64];
        ChaCha20.Block(key, 0, Word(0), Word(1), Word(2), block);
        var oneTimeKey = block[..32];
        var ciphertext = new byte[message.Length];
        for (var offset = 0; offset < message.Length; offset += 64)
        {
            ChaCha20.Block(key, (uint)(offset / 64) + 1, Word(0), Word(1), Word(2), block);
            for (var i = 0; i < Math.Min(64, message.Length - offset); i++)
            {
                ciphertext[offset + i] = (byte)(message[offset + i] ^ block[i]);
            }
        }

        static int Pad(int length) => (16 - (length % 16)) % 16;
        var macInput = new byte[aad.Length + Pad(aad.Length) + ciphertext.Length + Pad(ciphertext.Length) + 16];
        aad.CopyTo(macInput, 0);
        ciphertext.CopyTo(macInput, aad.Length + Pad(aad.Length));
        BinaryPrimitives.WriteUInt64LittleEndian(macInput.AsSpan(macInput.Length - 16), (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(macInput.AsSpan(macInput.Length - 8), (ulong)ciphertext.Length);
        var tag = new byte[16];
        Poly1305.ComputeTag(oneTimeKey, macInput, tag);
        return (ciphertext, tag);
    }

    [Test]
    [Arguments("ecdsa_secp256r1_sha256_p1363_test.json", "ecdsa-sha2-nistp256", "nistp256")]
    [Arguments("ecdsa_secp384r1_sha384_p1363_test.json", "ecdsa-sha2-nistp384", "nistp384")]
    [Arguments("ecdsa_secp521r1_sha512_p1363_test.json", "ecdsa-sha2-nistp521", "nistp521")]
    public async Task Ecdsa_SshSignatures_VerifyExactlyTheValidOnes(string file, string algorithm, string curve)
    {
        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var point = Hex(group.GetProperty("publicKey"), "uncompressed");
            SshPublicKey? key;
            try
            {
                key = SshPublicKey.Parse(Blob(w =>
                {
                    w.WriteString(algorithm);
                    w.WriteString(curve);
                    w.WriteString(point);
                }));
            }
            catch (FormatException)
            {
                key = null; // a key the parser refuses: every signature under it must count as refused
            }

            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var p1363 = Hex(test, "sig");
                if (p1363.Length % 2 != 0 || test.GetProperty("flags").EnumerateArray().Any(f => f.GetString() == "SignatureSize"))
                {
                    // P1363 encodes r || s at a fixed width, and these vectors are wrong only in that width: their r and s are often the
                    // right numbers. SSH writes r and s as two mpints of any length, so the fault has no SSH form, and the halves are the
                    // right signature there.
                    continue;
                }

                tested++;
                var half = p1363.Length / 2;
                var signature = Blob(w =>
                {
                    w.WriteString(algorithm);
                    w.WriteString(Blob(inner =>
                    {
                        inner.WriteMpint(p1363.AsSpan(0, half));
                        inner.WriteMpint(p1363.AsSpan(half));
                    }));
                });
                Check(test, mismatches, () => key?.VerifySignature(algorithm, signature, Hex(test, "msg")) ?? false);
            }
        }

        await ReportAsync(file, tested, mismatches);
    }

    [Test]
    [Arguments("rsa_signature_2048_sha256_test.json", "rsa-sha2-256")]
    [Arguments("rsa_signature_2048_sha512_test.json", "rsa-sha2-512")]
    [Arguments("rsa_signature_4096_sha512_test.json", "rsa-sha2-512")]
    public async Task Rsa_SshSignatures_VerifyExactlyTheValidOnes(string file, string algorithm)
    {
        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var publicKey = group.GetProperty("publicKey");
            var key = SshPublicKey.Parse(Blob(w =>
            {
                w.WriteString("ssh-rsa");
                w.WriteMpint(Hex(publicKey, "publicExponent"));
                w.WriteMpint(Hex(publicKey, "modulus"));
            }));
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                var signature = Blob(w =>
                {
                    w.WriteString(algorithm);
                    w.WriteString(Hex(test, "sig"));
                });
                Check(test, mismatches, () => key.VerifySignature(algorithm, signature, Hex(test, "msg")));
            }
        }

        await ReportAsync(file, tested, mismatches);
    }

    /// <summary>valid must verify, invalid must not, acceptable may do either; an exception is a refusal.</summary>
    private static void Check(JsonElement test, List<string> mismatches, Func<bool> verify)
    {
        bool verified;
        try
        {
            verified = verify();
        }
        catch (Exception ex) when (ex is FormatException or SshProtocolException or CryptographicException or ArgumentException)
        {
            verified = false;
        }

        switch (test.GetProperty("result").GetString())
        {
            case "valid" when !verified:
                mismatches.Add($"{Describe(test)}: refused a valid signature");
                break;
            case "invalid" when verified:
                mismatches.Add($"{Describe(test)}: accepted an invalid signature");
                break;
        }
    }
}
