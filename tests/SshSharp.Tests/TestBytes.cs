namespace SshSharp.Tests;

/// <summary>Byte comparisons that say where data differs, so a failure shows a shift, a gap or overwritten bytes rather than just "false".</summary>
internal static class TestBytes
{
    /// <summary>"equal", or the first offset where the two differ with a few bytes of each from there.</summary>
    public static string Compare(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
    {
        var common = Math.Min(actual.Length, expected.Length);
        for (var i = 0; i < common; i++)
        {
            if (actual[i] != expected[i])
            {
                return $"differs at {i} of {expected.Length}: got {Hex(actual, i)}, expected {Hex(expected, i)}";
            }
        }

        return actual.Length == expected.Length ? "equal" : $"length {actual.Length}, expected {expected.Length}";
    }

    private static string Hex(ReadOnlySpan<byte> data, int at) => Convert.ToHexString(data.Slice(at, Math.Min(16, data.Length - at)));
}
