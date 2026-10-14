using System.Diagnostics;
using System.Security.Cryptography;
using SshSharp.Crypto;

/// <summary>
/// A dudect-style check ("Dude, is my code constant time?", Reparaz et al. 2017) for the managed secret-key operations: time an
/// operation on one fixed secret and on fresh random secrets, interleaved at random, and compare the two timing distributions with
/// Welch's t-test. |t| above 4.5 suggests the time depends on the secret; above 10, a leak is very likely. Run on an idle 64-bit
/// machine: dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --timing [samples]
/// It is not part of CI: shared runners are too noisy for a statistical timing test.
/// </summary>
internal static class TimingLeakCheck
{
    public static void Run(int samples)
    {
        Console.WriteLine($"{samples:N0} samples per class; |t| < 4.5 means no evidence of secret-dependent timing.");

        // Ed25519 signing: an all-zero seed against random seeds.
        var message = RandomNumberGenerator.GetBytes(64);
        var signature = new byte[64];
        Check("Ed25519.Sign", samples, new byte[32], secret => Ed25519.Sign(secret, message, signature));

        // X25519: a minimal clamped scalar (only bit 254 set, the case a naive double-and-add would speed up) against random scalars.
        var peer = new byte[32];
        X25519.GetPublicKey(RandomNumberGenerator.GetBytes(32), peer);
        var shared = new byte[32];
        var lowScalar = new byte[32];
        lowScalar[31] = 0x40;
        Check("X25519", samples, lowScalar, secret => X25519.TryAgree(secret, peer, shared));

        // sntrup761 decapsulation is about a millisecond, so it gets a tenth of the samples. First a fixed secret key against fresh ones
        // (each with a valid ciphertext of its own), then the implicit-rejection path: one key, a valid ciphertext against random bytes.
        var kemSamples = Math.Max(1000, samples / 10);
        var pool = Enumerable.Range(0, 32).Select(_ => KemCase()).ToArray();
        var next = 0;
        var kemSecret = new byte[Sntrup761.SharedSecretSize];
        var (fixedKey, fixedCiphertext) = KemCase();
        Check("sntrup761 key", kemSamples, [.. fixedKey, .. fixedCiphertext], input =>
            Sntrup761.Decapsulate(kemSecret, input.AsSpan(Sntrup761.SecretKeySize), input.AsSpan(0, Sntrup761.SecretKeySize)),
            () => { var (k, c) = pool[next++ % pool.Length]; return [.. k, .. c]; });
        Check("sntrup761 rej", kemSamples, fixedCiphertext, ciphertext => Sntrup761.Decapsulate(kemSecret, ciphertext, fixedKey),
            () => RandomNumberGenerator.GetBytes(Sntrup761.CiphertextSize));
    }

    private static (byte[] SecretKey, byte[] Ciphertext) KemCase()
    {
        var publicKey = new byte[Sntrup761.PublicKeySize];
        var secretKey = new byte[Sntrup761.SecretKeySize];
        Sntrup761.GenerateKeyPair(publicKey, secretKey);
        var ciphertext = new byte[Sntrup761.CiphertextSize];
        Sntrup761.Encapsulate(ciphertext, new byte[Sntrup761.SharedSecretSize], publicKey);
        return (secretKey, ciphertext);
    }

    private static void Check(string name, int samples, byte[] fixedSecret, Action<byte[]> operation, Func<byte[]>? randomSecret = null)
    {
        // Inputs and the class order are prepared up front, so nothing but the operation is timed.
        randomSecret ??= () => RandomNumberGenerator.GetBytes(32);
        var coin = new Random(1);
        var inputs = Enumerable.Range(0, 2 * samples)
            .Select(_ => coin.Next(2) == 0 ? (Fixed: true, Secret: fixedSecret) : (Fixed: false, Secret: randomSecret()))
            .ToArray();

        // Warm up so tiering does not land in one class.
        for (var i = 0; i < Math.Min(2000, inputs.Length); i++)
        {
            operation(inputs[i % inputs.Length].Secret);
        }

        var fixedTimes = new List<double>(samples);
        var randomTimes = new List<double>(samples);
        foreach (var (isFixed, secret) in inputs)
        {
            var start = Stopwatch.GetTimestamp();
            operation(secret);
            var elapsed = (double)(Stopwatch.GetTimestamp() - start);
            (isFixed ? fixedTimes : randomTimes).Add(elapsed);
        }

        // Like dudect, drop the slowest measurements (interrupts, GC), keeping the 90th percentile and below of both classes.
        var cutoff = Percentile([.. fixedTimes, .. randomTimes], 0.90);
        var a = fixedTimes.Where(t => t <= cutoff).ToArray();
        var b = randomTimes.Where(t => t <= cutoff).ToArray();
        var t = WelchT(a, b);
        var verdict = Math.Abs(t) < 4.5 ? "no evidence of a leak" : Math.Abs(t) < 10 ? "SUSPICIOUS" : "LEAK LIKELY";
        Console.WriteLine($"{name,-14} t = {t,8:F2}   fixed mean {a.Average(),9:F1}   random mean {b.Average(),9:F1} ticks   {verdict}");
    }

    private static double Percentile(double[] values, double p)
    {
        Array.Sort(values);
        return values[(int)(p * (values.Length - 1))];
    }

    private static double WelchT(double[] a, double[] b)
    {
        static (double Mean, double Variance) Stats(double[] x)
        {
            var mean = x.Average();
            return (mean, x.Sum(v => (v - mean) * (v - mean)) / (x.Length - 1));
        }

        var (ma, va) = Stats(a);
        var (mb, vb) = Stats(b);
        return (ma - mb) / Math.Sqrt((va / a.Length) + (vb / b.Length));
    }
}
