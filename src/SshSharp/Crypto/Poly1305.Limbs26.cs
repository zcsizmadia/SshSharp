using System.Buffers.Binary;

namespace SshSharp.Crypto;

/// <summary>
/// Poly1305 with five 26-bit limbs and 32×32→64-bit products (the poly1305-donna-32 representation): the code for 32-bit processes, and
/// the reference the 64-bit code is tested against. It was the only implementation before the 64-bit limbs.
/// </summary>
internal static partial class Poly1305
{
    /// <summary>
    /// <see cref="ComputeTag"/> with five 26-bit limbs, whatever the process. The key and tag sizes are the caller's to check.
    /// </summary>
    internal static void ComputeTag26(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        // r, clamped, in five 26-bit limbs.
        var r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & 0x3ffffff;
        var r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key[3..]) >> 2) & 0x3ffff03;
        var r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key[6..]) >> 4) & 0x3ffc0ff;
        var r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key[9..]) >> 6) & 0x3f03fff;
        var r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key[12..]) >> 8) & 0x00fffff;
        var s1 = r1 * 5;
        var s2 = r2 * 5;
        var s3 = r3 * 5;
        var s4 = r4 * 5;

        uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
        Span<byte> block = stackalloc byte[16];
        var remaining = message;
        while (!remaining.IsEmpty)
        {
            // Each 16-byte block is staged in a stack buffer; a short final block gets the 0x01 terminator.
            uint hibit;
            if (remaining.Length >= 16)
            {
                remaining[..16].CopyTo(block);
                remaining = remaining[16..];
                hibit = 1u << 24;
            }
            else
            {
                block.Clear();
                remaining.CopyTo(block);
                block[remaining.Length] = 1;
                remaining = default;
                hibit = 0;
            }

            ReadOnlySpan<byte> m = block;

            h0 += BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff;
            h1 += (BinaryPrimitives.ReadUInt32LittleEndian(m[3..]) >> 2) & 0x3ffffff;
            h2 += (BinaryPrimitives.ReadUInt32LittleEndian(m[6..]) >> 4) & 0x3ffffff;
            h3 += (BinaryPrimitives.ReadUInt32LittleEndian(m[9..]) >> 6) & 0x3ffffff;
            h4 += (BinaryPrimitives.ReadUInt32LittleEndian(m[12..]) >> 8) | hibit;

            var d0 = ((ulong)h0 * r0) + ((ulong)h1 * s4) + ((ulong)h2 * s3) + ((ulong)h3 * s2) + ((ulong)h4 * s1);
            var d1 = ((ulong)h0 * r1) + ((ulong)h1 * r0) + ((ulong)h2 * s4) + ((ulong)h3 * s3) + ((ulong)h4 * s2);
            var d2 = ((ulong)h0 * r2) + ((ulong)h1 * r1) + ((ulong)h2 * r0) + ((ulong)h3 * s4) + ((ulong)h4 * s3);
            var d3 = ((ulong)h0 * r3) + ((ulong)h1 * r2) + ((ulong)h2 * r1) + ((ulong)h3 * r0) + ((ulong)h4 * s4);
            var d4 = ((ulong)h0 * r4) + ((ulong)h1 * r3) + ((ulong)h2 * r2) + ((ulong)h3 * r1) + ((ulong)h4 * r0);

            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            var c = d0 >> 26;
            h0 = (uint)d0 & 0x3ffffff;
            d1 += c;
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            c = d1 >> 26;
            h1 = (uint)d1 & 0x3ffffff;
            d2 += c;
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            c = d2 >> 26;
            h2 = (uint)d2 & 0x3ffffff;
            d3 += c;
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            c = d3 >> 26;
            h3 = (uint)d3 & 0x3ffffff;
            d4 += c;
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            c = d4 >> 26;
            h4 = (uint)d4 & 0x3ffffff;
            h0 += (uint)c * 5;
            // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
            var carry = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += carry;
        }

        // Fully carry h.
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        var cc = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += cc * 5;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += cc;

        // Compute h + -p and select h if h < p, in constant time.
        var g0 = h0 + 5;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g0 >> 26;
        g0 &= 0x3ffffff;
        var g1 = h1 + cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g1 >> 26;
        g1 &= 0x3ffffff;
        var g2 = h2 + cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g2 >> 26;
        g2 &= 0x3ffffff;
        var g3 = h3 + cc;
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        cc = g3 >> 26;
        g3 &= 0x3ffffff;
        var g4 = h4 + cc - (1u << 26);

        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        var mask = (g4 >> 31) - 1; // all ones if h >= p (g4 did not underflow), else zero
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h mod 2^128, then add s.
        var t0 = h0 | (h1 << 26);
        var t1 = (h1 >> 6) | (h2 << 20);
        var t2 = (h2 >> 12) | (h3 << 14);
        var t3 = (h3 >> 18) | (h4 << 8);

        var f = (ulong)t0 + BinaryPrimitives.ReadUInt32LittleEndian(key[16..]);
        BinaryPrimitives.WriteUInt32LittleEndian(tag, (uint)f);
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        f = (ulong)t1 + BinaryPrimitives.ReadUInt32LittleEndian(key[20..]) + (f >> 32);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], (uint)f);
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        f = (ulong)t2 + BinaryPrimitives.ReadUInt32LittleEndian(key[24..]) + (f >> 32);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], (uint)f);
        // Stryker disable once Bitwise : on an unsigned value, >>> is the same shift as >>
        f = (ulong)t3 + BinaryPrimitives.ReadUInt32LittleEndian(key[28..]) + (f >> 32);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], (uint)f);
    }
}
