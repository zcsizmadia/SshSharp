namespace SshSharp.Tests.Fuzz;

/// <summary>
/// The mutation fuzzing harness of the parser robustness tests. It is in a file of its own, compiled into every mutation scope, so a
/// scope can take only the fuzz tests that reach its code (tests/SshSharp.Tests/SshSharp.Tests.csproj, SSHSHARP_MUTATION_TESTS).
/// </summary>
internal static class FuzzHarness
{
    internal const int Iterations = 3000;

    internal static readonly Func<Exception, bool> ProtocolErrors = ex => ex is SshProtocolException;

    internal static readonly Func<Exception, bool> FormatErrors = ex => ex is FormatException;

    /// <summary>
    /// Runs mutations of the seeds through <paramref name="parse"/> and returns a description of each unexpected exception.
    /// <paramref name="allowed"/> says which exceptions are a clean rejection (null: none, the parser must never throw).
    /// </summary>
    internal static List<string> Run(byte[][] seeds, Action<byte[]> parse, Func<Exception, bool>? allowed, int iterations = Iterations)
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
}
