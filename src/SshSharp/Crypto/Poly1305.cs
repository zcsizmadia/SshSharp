using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace SshSharp.Crypto;

/// <summary>
/// Poly1305 one-time authenticator (RFC 8439 section 2.5) in constant time. In a 64-bit process the accumulator and r are three limbs of
/// 44, 44 and 42 bits (the poly1305-donna-64 representation), multiplied through 64×64→128-bit products
/// (<see cref="Math.BigMul(ulong, ulong, out ulong)"/>). A 32-bit process has no 64×64-bit multiply and would emulate each one with
/// four 32-bit multiplies, which made that code twice as slow there as the five 26-bit limbs of poly1305-donna-32
/// (Poly1305.Limbs26.cs), so a 32-bit process uses those.
/// </summary>
internal static partial class Poly1305
{
    public const int KeySize = 32;
    public const int TagSize = 16;

    private const ulong Mask44 = (1UL << 44) - 1;
    private const ulong Mask42 = (1UL << 42) - 1;

    /// <summary>Computes the tag of <paramref name="message"/> under the one-time <paramref name="key"/> (r || s).</summary>
    public static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        if (key.Length != KeySize || tag.Length != TagSize)
        {
            throw new ArgumentException("Poly1305 needs a 32-byte key and a 16-byte tag buffer.");
        }

        // A constant for the JIT, so only one of the two is compiled in. Both compute the same tag; the tests run each explicitly.
        // Stryker disable once Boolean : both branches compute the same tag; only the speed differs
        if (Environment.Is64BitProcess)
        {
            ComputeTag44(key, message, tag);
        }
        else
        {
            ComputeTag26(key, message, tag);
        }
    }

    /// <summary>
    /// <see cref="ComputeTag"/> with limbs of 44, 44 and 42 bits, whatever the process. The key and tag sizes are the caller's to check.
    /// </summary>
    internal static void ComputeTag44(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        // r, clamped, in limbs of 44, 44 and 42 bits (the top limb of a clamped r has only 36). The limbs weigh 2^0, 2^44 and 2^88, so
        // a product of weight 2^132 or 2^176 folds back into the low columns: 2^132 = 4 * 2^130 = 4 * 5 = 20 (mod p).
        var k0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
        var k1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
        var r0 = k0 & 0xffc0fffffff;
        var r1 = ((k0 >> 44) | (k1 << 20)) & 0xfffffc0ffff;
        var r2 = (k1 >> 24) & 0x00ffffffc0f;

        // The multipliers are kept shifted left by 20 bits (each still fits in 64), so that a 128-bit product splits at bit 44 for free
        // (see Mul). 20 * r1 would not fit shifted, so h2 is multiplied by 20 instead of r1.
        var r0x = r0 << 20;
        var r1x = r1 << 20;
        var r2x = r2 << 20;
        var s2x = (r2 * 20) << 20;

        ulong h0 = 0, h1 = 0, h2 = 0;
        Span<byte> last = stackalloc byte[16];
        var remaining = message;
        while (!remaining.IsEmpty)
        {
            // Whole blocks are read in place and get 2^128 added; a short final block is staged with its 0x01 terminator instead.
            // The branch depends only on the message length.
            ulong m0, m1, hibit;
            if (remaining.Length >= 16)
            {
                m0 = BinaryPrimitives.ReadUInt64LittleEndian(remaining);
                m1 = BinaryPrimitives.ReadUInt64LittleEndian(remaining[8..]);
                remaining = remaining[16..];
                hibit = 1UL << 40;
            }
            else
            {
                // Stryker disable once Statement : stackalloc zeroes the buffer (locals are initialized) and only the last block uses it
                last.Clear();
                remaining.CopyTo(last);
                last[remaining.Length] = 1;
                m0 = BinaryPrimitives.ReadUInt64LittleEndian(last);
                m1 = BinaryPrimitives.ReadUInt64LittleEndian(last[8..]);
                remaining = default;
                hibit = 0;
            }

            // h += m. On entry h0 < 2^44, h1 < 2^44 + 2^8 and h2 < 2^42, so afterwards h0, h1 < 2^45 and h2 < 2^43.
            h0 += m0 & Mask44;
            h1 += ((m0 >> 44) | (m1 << 20)) & Mask44;
            h2 += (m1 >> 24) | hibit;

            // h *= r (mod p), column by column: d0 = h0 r0 + 20 h1 r2 + 20 h2 r1, d1 = h0 r1 + h1 r0 + 20 h2 r2, d2 = h0 r2 + h1 r1 + h2 r0.
            // Every product is below 2^92 (20 h2 r1 is the largest, below 2^47.4 * 2^44) and every column sum below 2^93.
            var h2x20 = h2 * 20;
            var d0 = Mul(h0, r0x) + Mul(h1, s2x) + Mul(h2x20, r1x);
            var d1 = Mul(h0, r1x) + Mul(h1, r0x) + Mul(h2x20, r2x);
            var d2 = Mul(h0, r2x) + Mul(h1, r1x) + Mul(h2, r0x);

            // Carry with shifts and masks: the carry out of the top limb (bit 130 and up) comes back into h0 times 5.
            var c = d0.Shift44();
            h0 = d0.Low & Mask44;
            d1 += c;
            c = d1.Shift44();
            h1 = d1.Low & Mask44;
            d2 += c;
            c = d2.Shift42();
            h2 = d2.Low & Mask42;
            h0 += c * 5; // d2 is below 2^90, so c is below 2^48 and h0 stays below 2^51
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            c = h0 >> 44;
            h0 &= Mask44;
            h1 += c;
        }

        // Carry h1 into h2 and h2's overflow back into h0. Each carry is 0 or 1 (h1 < 2^44 + 2^8, h2 < 2^42), so afterwards h1 < 2^44,
        // h2 < 2^42 and h0 < 2^44 + 5, and h < 2^130 + 2^45 < 2p. poly1305-donna-64 also carries h0 into h1 and then repeats the pass;
        // here h0 is left as it is, because the steps below carry every limb exactly and so take h0 up to 2^44 + 4. (The carry out of
        // h0 needs a state no test can reach on purpose, which left that line's mutants alive, and the repeated pass never carries.)
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        var cc = h1 >> 44;
        h1 &= Mask44;
        h2 += cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h2 >> 42;
        h2 &= Mask42;
        h0 += cc * 5;

        // Compute g = h + 5 - 2^130 = h - p, and select g if it did not go negative (h >= p), else h: a mask, not a branch.
        var g0 = h0 + 5;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g0 >> 44;
        g0 &= Mask44;
        var g1 = h1 + cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g1 >> 44;
        g1 &= Mask44;
        var g2 = h2 + cc - (1UL << 42);

        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        var mask = (g2 >> 63) - 1; // all ones if h >= p (g2 did not underflow), else zero
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // h + s mod 2^128: s is added limb by limb, and the carry out of bit 128 is dropped with the top limb's mask.
        var t0 = BinaryPrimitives.ReadUInt64LittleEndian(key[16..]);
        var t1 = BinaryPrimitives.ReadUInt64LittleEndian(key[24..]);
        h0 += t0 & Mask44;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h0 >> 44;
        h0 &= Mask44;
        h1 += (((t0 >> 44) | (t1 << 20)) & Mask44) + cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h1 >> 44;
        h1 &= Mask44;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        h2 += (t1 >> 24) + cc;
        h2 &= Mask42;

        BinaryPrimitives.WriteUInt64LittleEndian(tag, h0 | (h1 << 44));
        BinaryPrimitives.WriteUInt64LittleEndian(tag[8..], (h1 >> 20) | (h2 << 24));
    }

    /// <summary>
    /// The product of a limb <paramref name="a"/> (below 2^48) and a multiplier b stored shifted left by 20 bits
    /// (<paramref name="shiftedB"/> = b * 2^20), split at bit 44. The 128-bit product is a * b * 2^20, so its high word is a * b shifted
    /// right by 44, and its low word holds the low 44 bits of a * b in its top 44 bits. Splitting a plain product would take four more
    /// operations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Wide Mul(ulong a, ulong shiftedB)
    {
        var high = Math.BigMul(a, shiftedB, out var low);
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        return new Wide(low >> 20, high);
    }

    /// <summary>
    /// A column sum of up to three products and a carry, held as High * 2^44 + Low, as in Field25519: products below 2^92 give High parts
    /// below 2^48 and Low parts below 2^44, so the two halves add up separately without overflowing 64 bits. Unlike
    /// <see cref="UInt128"/>, whose addition computes its carry with a comparison the JIT may turn into a branch, nothing here carries.
    /// </summary>
    private readonly struct Wide(ulong low, ulong high)
    {
        public ulong Low { get; } = low;

        public ulong High { get; } = high;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Wide operator +(Wide a, Wide b) => new(a.Low + b.Low, a.High + b.High);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Wide operator +(Wide a, ulong b) => new(a.Low + b, a.High);

        /// <summary>The value shifted right by 44 bits.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ulong Shift44()
        {
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            return High + (Low >> 44);
        }

        /// <summary>The value shifted right by 42 bits.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ulong Shift42()
        {
            var high = High << 2;

            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            return high + (Low >> 42);
        }
    }
}
