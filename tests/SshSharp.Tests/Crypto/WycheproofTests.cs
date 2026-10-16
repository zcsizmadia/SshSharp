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
/// Ed25519, ChaCha20 and Poly1305), its SSH signature verification (ECDSA, RSA PKCS#1 v1.5), its NIST ECDH point checks and the AES-GCM
/// parameters SSH uses, #218. Each vector is an edge case that
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
    [Arguments("rsa_signature_3072_sha256_test.json", "rsa-sha2-256")]
    [Arguments("rsa_signature_3072_sha512_test.json", "rsa-sha2-512")]
    [Arguments("rsa_signature_4096_sha256_test.json", "rsa-sha2-256")]
    [Arguments("rsa_signature_4096_sha512_test.json", "rsa-sha2-512")]
    [Arguments("rsa_signature_8192_sha256_test.json", "rsa-sha2-256")]
    [Arguments("rsa_signature_8192_sha512_test.json", "rsa-sha2-512")]
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

    /// <summary>
    /// ecdh-sha2-nistp256/384/521 and the ML-KEM/NIST hybrids: the server's point taken as the key exchange takes it (only the
    /// uncompressed SEC 1 form), then <see cref="NistCurve.TryDeriveSecret"/>, which checks the point itself before the platform agrees.
    /// Among the vectors are invalid-curve attacks and points on the wrong curve, which some platforms (Windows CNG) do not refuse.
    /// </summary>
    [Test]
    [Arguments("ecdh_secp256r1_ecpoint_test.json")]
    [Arguments("ecdh_secp384r1_ecpoint_test.json")]
    [Arguments("ecdh_secp521r1_ecpoint_test.json")]
    public async Task Ecdh_AgreesOrRefusesAsWycheproofExpects(string file)
    {
        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var curve = group.GetProperty("curve").GetString() switch
            {
                "secp256r1" => NistCurve.P256,
                "secp384r1" => NistCurve.P384,
                "secp521r1" => NistCurve.P521,
                var other => throw new InvalidOperationException($"{file}: unexpected curve {other}"),
            };
            var size = curve.FieldSize;
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                var point = Hex(test, "public");
                var expected = FixedWidth(Hex(test, "shared"), size);
                byte[]? shared = null;
                string? refusal = null;
                if (point.Length != 1 + (2 * size) || point[0] != 4)
                {
                    refusal = "not an uncompressed point";
                }
                else
                {
                    try
                    {
                        using var own = ECDiffieHellman.Create(new ECParameters { Curve = curve.Curve, D = FixedWidth(Hex(test, "private"), size) });
                        shared = curve.TryDeriveSecret(own, point.AsSpan(1, size), point.AsSpan(1 + size));
                        refusal = shared is null ? "not on the curve" : null;
                    }
                    catch (CryptographicException ex)
                    {
                        refusal = $"the platform refused it ({ex.Message})";
                    }
                }

                // Accepting with a different secret is wrong whatever the label; refusing is wrong only for a valid vector.
                if (shared is not null && !FixedWidth(shared, size).AsSpan().SequenceEqual(expected))
                {
                    mismatches.Add($"{Describe(test)}: agreed on {Convert.ToHexString(shared)}, expected {Convert.ToHexString(expected)}");
                }
                else if (shared is not null && test.GetProperty("result").GetString() == "invalid")
                {
                    mismatches.Add($"{Describe(test)}: agreed with an invalid point");
                }
                else if (shared is null && test.GetProperty("result").GetString() == "valid")
                {
                    mismatches.Add($"{Describe(test)}: refused a valid exchange: {refusal}");
                }
            }
        }

        await ReportAsync(file, tested, mismatches);
    }

    /// <summary>An unsigned big-endian number at exactly <paramref name="size"/> bytes (Wycheproof adds a sign byte or drops leading zeros).</summary>
    private static byte[] FixedWidth(byte[] value, int size)
    {
        var start = 0;
        while (value.Length - start > size && value[start] == 0)
        {
            start++;
        }

        var result = new byte[size];
        value.AsSpan(start).CopyTo(result.AsSpan(size - (value.Length - start)));
        return result;
    }

    /// <summary>
    /// aes128-gcm@openssh.com and aes256-gcm@openssh.com: the platform's AES-GCM with the parameters SSH uses (a 128- or 256-bit key, a
    /// 96-bit IV and a 128-bit tag). The other key, IV and tag sizes test an API that takes them, which SSH does not.
    /// </summary>
    [Test]
    public async Task AesGcm_WithSshParameters_MatchesAndRefusesAsWycheproofExpects()
    {
        var root = Load("aes_gcm_test.json");
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            if (group.GetProperty("ivSize").GetInt32() != 96 || group.GetProperty("tagSize").GetInt32() != 128 ||
                group.GetProperty("keySize").GetInt32() is not (128 or 256))
            {
                continue;
            }

            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                using var gcm = new AesGcm(Hex(test, "key"), 16);
                var (iv, aad, message, ciphertext, tag) = (Hex(test, "iv"), Hex(test, "aad"), Hex(test, "msg"), Hex(test, "ct"), Hex(test, "tag"));
                var valid = test.GetProperty("result").GetString() == "valid";

                var opened = new byte[ciphertext.Length];
                bool decrypted;
                try
                {
                    gcm.Decrypt(iv, ciphertext, tag, opened, aad);
                    decrypted = true;
                }
                catch (AuthenticationTagMismatchException)
                {
                    decrypted = false;
                }

                if (decrypted != valid)
                {
                    mismatches.Add($"{Describe(test)}: {(decrypted ? "opened an invalid" : "refused a valid")} ciphertext");
                }
                else if (valid)
                {
                    var sealedText = new byte[message.Length];
                    var sealedTag = new byte[16];
                    gcm.Encrypt(iv, message, sealedText, sealedTag, aad);
                    if (!opened.AsSpan().SequenceEqual(message) || !sealedText.AsSpan().SequenceEqual(ciphertext) || !sealedTag.AsSpan().SequenceEqual(tag))
                    {
                        mismatches.Add($"{Describe(test)}: the plaintext, ciphertext or tag differs from the vector");
                    }
                }
            }
        }

        await ReportAsync("aes_gcm_test.json", tested, mismatches);
    }

    /// <summary>
    /// rsa-sha2-256 and rsa-sha2-512 signing (public key authentication): PKCS#1 v1.5 signatures are deterministic, so the key, read
    /// from the vector's PKCS#1 PEM by <see cref="SshPrivateKey.Parse"/>, must give exactly the vector's signature. Only the SHA-256
    /// and SHA-512 groups have an SSH algorithm, and the 1024- and 1536-bit files are left out because SshSharp refuses keys under 2048
    /// bits. A key that cannot be read counts as refusing its vectors, which is allowed only for acceptable ones.
    /// </summary>
    [Test]
    [Arguments("rsa_pkcs1_2048_sig_gen_test.json")]
    [Arguments("rsa_pkcs1_3072_sig_gen_test.json")]
    [Arguments("rsa_pkcs1_4096_sig_gen_test.json")]
    public async Task Rsa_SshSigning_GivesTheVectorsSignatures(string file)
    {
        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var algorithm = group.GetProperty("sha").GetString() switch
            {
                "SHA-256" => "rsa-sha2-256",
                "SHA-512" => "rsa-sha2-512",
                _ => null,
            };
            if (algorithm is null)
            {
                continue;
            }

            // .NET cannot import a key whose primes are of unequal length (RSAParameters wants p, q and the CRT values at half the
            // modulus length). The vectors' keys with e = 3 are such keys, marked acceptable; ssh-keygen always makes balanced primes.
            SshPrivateKey? parsed;
            try
            {
                parsed = SshPrivateKey.Parse(group.GetProperty("privateKeyPem").GetString()!);
            }
            catch (FormatException)
            {
                parsed = null;
            }

            using var key = parsed;
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                if (key is null)
                {
                    if (test.GetProperty("result").GetString() == "valid")
                    {
                        mismatches.Add($"{Describe(test)}: the key of a valid vector could not be read");
                    }

                    continue;
                }

                var signature = SignatureBytes(key.Sign(algorithm, Hex(test, "msg")), algorithm);
                var expected = Hex(test, "sig");
                if (!signature.AsSpan().SequenceEqual(expected))
                {
                    mismatches.Add($"{Describe(test)}: signed {Convert.ToHexString(signature)}, expected {Convert.ToHexString(expected)}");
                }
            }
        }

        await ReportAsync(file, tested, mismatches);
    }

    /// <summary>The signature inside an SSH signature blob (<c>string algorithm || string signature</c>).</summary>
    private static byte[] SignatureBytes(byte[] blob, string algorithm)
    {
        var reader = new SshReader(blob);
        if (reader.ReadUtf8String() != algorithm)
        {
            throw new InvalidOperationException($"The signature blob is not {algorithm}.");
        }

        return reader.ReadString().ToArray();
    }

    /// <summary>
    /// mlkem768x25519-sha256, mlkem768nistp256-sha256 (ML-KEM-768) and mlkem1024nistp384-sha384 (ML-KEM-1024): the client's side, which
    /// is decapsulation. The server's ciphertext is taken as the key exchange takes it (exactly the parameter set's size, anything else is
    /// refused), then decapsulated by the platform's ML-KEM. The vectors' Strcmp and MalleableCiphertext cases check implicit rejection.
    /// The vectors with a seed of the wrong length are left out: SshSharp makes its own key and never imports one.
    /// </summary>
    [Test]
    [Arguments("mlkem_768_test.json")]
    [Arguments("mlkem_1024_test.json")]
    public async Task MlKem_DecapsulatesAsWycheproofExpects(string file)
    {
#if NET10_0_OR_GREATER
        if (!MLKem.IsSupported)
        {
            Skip.Test("This platform has no ML-KEM, so SshSharp does not offer the ML-KEM key exchanges.");
        }

        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            var parameters = group.GetProperty("parameterSet").GetString() switch
            {
                "ML-KEM-768" => MLKemAlgorithm.MLKem768,
                "ML-KEM-1024" => MLKemAlgorithm.MLKem1024,
                var other => throw new InvalidOperationException($"{file}: unexpected parameter set {other}"),
            };
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var seed = Hex(test, "seed");
                if (seed.Length != parameters.PrivateSeedSizeInBytes)
                {
                    continue;
                }

                tested++;
                using var kem = MLKem.ImportPrivateSeed(parameters, seed);
                var valid = test.GetProperty("result").GetString() == "valid";
                if (valid && !kem.ExportEncapsulationKey().AsSpan().SequenceEqual(Hex(test, "ek")))
                {
                    mismatches.Add($"{Describe(test)}: the encapsulation key from the seed differs from the vector");
                    continue;
                }

                var ciphertext = Hex(test, "c");
                byte[]? shared = null;
                if (ciphertext.Length == parameters.CiphertextSizeInBytes)
                {
                    shared = new byte[parameters.SharedSecretSizeInBytes];
                    try
                    {
                        kem.Decapsulate(ciphertext, shared);
                    }
                    catch (CryptographicException)
                    {
                        shared = null;
                    }
                }

                if (shared is null && valid)
                {
                    mismatches.Add($"{Describe(test)}: refused a valid ciphertext");
                }
                else if (shared is not null && !valid)
                {
                    mismatches.Add($"{Describe(test)}: decapsulated an invalid ciphertext");
                }
                else if (shared is not null && !shared.AsSpan().SequenceEqual(Hex(test, "K")))
                {
                    mismatches.Add($"{Describe(test)}: decapsulated to {Convert.ToHexString(shared)}, expected {test.GetProperty("K").GetString()}");
                }
            }
        }

        await ReportAsync(file, tested, mismatches);
#else
        Skip.Test($"ML-KEM needs .NET 10 ({file}).");
        await Task.CompletedTask;
#endif
    }

    /// <summary>
    /// hmac-sha2-256-etm@openssh.com and hmac-sha2-512-etm@openssh.com: the platform's HMAC, as the packet protector uses it. SSH sends
    /// the whole tag, so only the groups with a full-length tag apply.
    /// </summary>
    [Test]
    [Arguments("hmac_sha256_test.json", "SHA256", 256)]
    [Arguments("hmac_sha512_test.json", "SHA512", 512)]
    public async Task Hmac_WithFullTags_MatchesAndRefusesAsWycheproofExpects(string file, string hash, int tagBits)
    {
        var root = Load(file);
        var mismatches = new List<string>();
        var tested = 0;
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            if (group.GetProperty("tagSize").GetInt32() != tagBits)
            {
                continue;
            }

            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                tested++;
                using var mac = IncrementalHash.CreateHMAC(new HashAlgorithmName(hash), Hex(test, "key"));
                mac.AppendData(Hex(test, "msg"));
                var matches = CryptographicOperations.FixedTimeEquals(mac.GetHashAndReset(), Hex(test, "tag"));
                if (matches != (test.GetProperty("result").GetString() == "valid"))
                {
                    mismatches.Add($"{Describe(test)}: {(matches ? "an invalid tag matched" : "a valid tag did not match")}");
                }
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
