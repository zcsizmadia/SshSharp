using System.Numerics;

namespace SshSharp.Crypto;

/// <summary>Vectorized XOR for stream cipher keystreams.</summary>
internal static class XorHelper
{
    /// <summary>XORs <paramref name="keystream"/> into <paramref name="data"/> in place (keystream must be at least as long).</summary>
    public static void XorInPlace(Span<byte> data, ReadOnlySpan<byte> keystream)
    {
        var i = 0;
        // Stryker disable once Boolean : the byte loop below gives the same result; only the speed differs
        if (Vector.IsHardwareAccelerated)
        {
            var width = Vector<byte>.Count;
            // Stryker disable once Equality : with <, a last full vector goes to the byte loop instead, with the same result
            while (i <= data.Length - width)
            {
                (new Vector<byte>(data[i..]) ^ new Vector<byte>(keystream[i..])).CopyTo(data[i..]);
                i += width;
            }
        }

        for (; i < data.Length; i++)
        {
            data[i] ^= keystream[i];
        }
    }

    /// <summary>Writes <c>input ^ keystream</c> to <paramref name="output"/>. The spans may be the same but must not partially overlap.</summary>
    public static void Xor(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keystream, Span<byte> output)
    {
        var i = 0;
        // Stryker disable once Boolean : the byte loop below gives the same result; only the speed differs
        if (Vector.IsHardwareAccelerated)
        {
            var width = Vector<byte>.Count;
            // Stryker disable once Equality : with <, a last full vector goes to the byte loop instead, with the same result
            while (i <= input.Length - width)
            {
                (new Vector<byte>(input[i..]) ^ new Vector<byte>(keystream[i..])).CopyTo(output[i..]);
                i += width;
            }
        }

        for (; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ keystream[i]);
        }
    }
}