using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>sntrup761 against the official known-answer tests, and its behaviour on tampered input.</summary>
public class Sntrup761Tests
{
    public static IEnumerable<Func<KatRecord>> KnownAnswers()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "sntrup761.rsp");
        var fields = new Dictionary<string, string>();
        foreach (var line in File.ReadLines(path).Append(string.Empty))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                if (fields.Count == 6)
                {
                    var record = new KatRecord(int.Parse(fields["count"], System.Globalization.CultureInfo.InvariantCulture),
                        Convert.FromHexString(fields["seed"]), Convert.FromHexString(fields["pk"]), Convert.FromHexString(fields["sk"]),
                        Convert.FromHexString(fields["ct"]), Convert.FromHexString(fields["ss"]));
                    yield return () => record;
                }

                fields.Clear();
                continue;
            }

            var parts = line.Split(" = ", 2);
            fields[parts[0].Trim()] = parts[1].Trim();
        }
    }

    [Test]
    [MethodDataSource(nameof(KnownAnswers))]
    public async Task KnownAnswerTests(KatRecord kat)
    {
        var random = new NistDrbg(kat.Seed);
        var publicKey = new byte[Sntrup761.PublicKeySize];
        var secretKey = new byte[Sntrup761.SecretKeySize];
        Sntrup761.GenerateKeyPair(publicKey, secretKey, random);
        await Assert.That(Convert.ToHexString(publicKey)).IsEqualTo(Convert.ToHexString(kat.PublicKey));
        await Assert.That(Convert.ToHexString(secretKey)).IsEqualTo(Convert.ToHexString(kat.SecretKey));

        var ciphertext = new byte[Sntrup761.CiphertextSize];
        var sent = new byte[Sntrup761.SharedSecretSize];
        Sntrup761.Encapsulate(ciphertext, sent, publicKey, random);
        await Assert.That(Convert.ToHexString(ciphertext)).IsEqualTo(Convert.ToHexString(kat.Ciphertext));
        await Assert.That(Convert.ToHexString(sent)).IsEqualTo(Convert.ToHexString(kat.SharedSecret));

        var received = new byte[Sntrup761.SharedSecretSize];
        Sntrup761.Decapsulate(received, kat.Ciphertext, kat.SecretKey);
        await Assert.That(Convert.ToHexString(received)).IsEqualTo(Convert.ToHexString(kat.SharedSecret));
    }

    [Test]
    public async Task FreshKeys_AgreeOnTheSecret_AndATamperedCiphertextIsImplicitlyRejected()
    {
        var publicKey = new byte[Sntrup761.PublicKeySize];
        var secretKey = new byte[Sntrup761.SecretKeySize];
        Sntrup761.GenerateKeyPair(publicKey, secretKey);
        var ciphertext = new byte[Sntrup761.CiphertextSize];
        var sent = new byte[Sntrup761.SharedSecretSize];
        Sntrup761.Encapsulate(ciphertext, sent, publicKey);

        var received = new byte[Sntrup761.SharedSecretSize];
        Sntrup761.Decapsulate(received, ciphertext, secretKey);
        await Assert.That(received.SequenceEqual(sent)).IsTrue();

        // Any changed byte, in the rounded part or the confirmation hash, gives an unrelated secret rather than an error.
        foreach (var index in new[] { 0, 500, 1006, 1007, 1038 })
        {
            var tampered = (byte[])ciphertext.Clone();
            tampered[index] ^= 0x01;
            var other = new byte[Sntrup761.SharedSecretSize];
            Sntrup761.Decapsulate(other, tampered, secretKey);
            await Assert.That(other.SequenceEqual(sent)).IsFalse();
        }

        // Random bytes decapsulate without throwing.
        var garbage = RandomNumberGenerator.GetBytes(Sntrup761.CiphertextSize);
        Sntrup761.Decapsulate(received, garbage, secretKey);
        await Assert.That(received.SequenceEqual(sent)).IsFalse();
    }

    [Test]
    public async Task TheSortingNetwork_Sorts()
    {
        foreach (var n in new[] { 0, 1, 2, 3, 5, 16, 17, 100, 761 })
        {
            var values = Enumerable.Range(0, n).Select(_ => (uint)Random.Shared.NextInt64(0, 1L << 32)).ToArray();
            values[..Math.Min(n, 3)].AsSpan().Fill(uint.MaxValue);
            var sorted = values.Order().ToArray();
            Sntrup761.SortUInt32(values);
            await Assert.That(values.SequenceEqual(sorted)).IsTrue().Because($"n = {n}");
        }
    }

    public sealed record KatRecord(int Count, byte[] Seed, byte[] PublicKey, byte[] SecretKey, byte[] Ciphertext, byte[] SharedSecret)
    {
        public override string ToString() => $"count {Count}";
    }

    /// <summary>The NIST PQC KAT generator's AES-256 CTR DRBG (rng.c): randombytes_init(seed), then randombytes.</summary>
    private sealed class NistDrbg : Sntrup761.IRandom, IDisposable
    {
        private readonly byte[] _key = new byte[32];
        private readonly byte[] _v = new byte[16];
        private Aes _aes = Aes.Create();

        public NistDrbg(byte[] seed)
        {
            _aes.Key = _key; // all zero, as is V
            Update(seed);
        }

        public uint Next32()
        {
            Span<byte> c = stackalloc byte[4];
            Fill(c);
            return BinaryPrimitives.ReadUInt32LittleEndian(c);
        }

        public void Fill(Span<byte> buffer)
        {
            Span<byte> block = stackalloc byte[16];
            while (buffer.Length > 0)
            {
                Increment();
                Encrypt(_v, block);
                var n = Math.Min(16, buffer.Length);
                block[..n].CopyTo(buffer);
                buffer = buffer[n..];
            }

            Update(null);
        }

        public void Dispose() => _aes.Dispose();

        private void Update(byte[]? provided)
        {
            var temp = new byte[48];
            for (var i = 0; i < 3; i++)
            {
                Increment();
                Encrypt(_v, temp.AsSpan(16 * i, 16));
            }

            if (provided is not null)
            {
                for (var i = 0; i < 48; i++)
                {
                    temp[i] ^= provided[i];
                }
            }

            temp.AsSpan(0, 32).CopyTo(_key);
            temp.AsSpan(32, 16).CopyTo(_v);
            _aes.Dispose();
            _aes = Aes.Create();
            _aes.Key = _key;
        }

        private void Increment()
        {
            for (var j = 15; j >= 0; j--)
            {
                if (_v[j] == 0xff)
                {
                    _v[j] = 0;
                }
                else
                {
                    _v[j]++;
                    break;
                }
            }
        }

        private void Encrypt(ReadOnlySpan<byte> input, Span<byte> output) => _aes.EncryptEcb(input, output, PaddingMode.None);
    }
}
