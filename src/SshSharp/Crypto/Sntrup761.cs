using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// Streamlined NTRU Prime sntrup761, the key encapsulation mechanism of <c>sntrup761x25519-sha512</c>: a port of the public-domain reference
/// implementation by D. J. Bernstein, C. Chuengsatiansup, T. Lange and C. van Vredendaal (NTRU Prime round 3; the code OpenSSH carries in
/// sntrup761.c). Everything that touches secrets is constant-time as in the reference: no branches or memory indexes depend on secret
/// values, divisions by public moduli use multiply-and-shift, and sorting is a fixed network.
/// </summary>
/// <remarks>
/// The ring is Z[x]/(x^761 - x - 1); "small" polynomials have coefficients in {-1, 0, 1} and Fq ones in [-(q-1)/2, (q-1)/2] with q = 4591.
/// Randomness is drawn exactly as the reference draws it (4 bytes per coefficient, then 191 bytes), so the known-answer tests reproduce.
/// </remarks>
internal static class Sntrup761
{
    public const int PublicKeySize = 1158;
    public const int SecretKeySize = 1763;
    public const int CiphertextSize = 1039;
    public const int SharedSecretSize = 32;

    private const int P = 761;
    private const int Q = 4591;
    private const int W = 286;
    private const int Q12 = (Q - 1) / 2;
    private const int SmallBytes = (P + 3) / 4; // 191
    private const int RoundedBytes = 1007;
    private const int HashBytes = 32;
    private const int InputsBytes = SmallBytes;
    private const int ZSecretKeyBytes = 2 * SmallBytes;

    /// <summary>The randomness the reference consumes: <c>urandom32</c> (4 bytes, little-endian) and <c>randombytes</c>.</summary>
    internal interface IRandom
    {
        uint Next32();

        void Fill(Span<byte> buffer);
    }

    /// <summary>Generates a key pair (<c>crypto_kem_keypair</c>).</summary>
    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey) => GenerateKeyPair(publicKey, secretKey, SystemRandom.Instance);

    internal static void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey, IRandom random)
    {
        if (publicKey.Length != PublicKeySize || secretKey.Length != SecretKeySize)
        {
            throw new ArgumentException("Wrong key buffer sizes.");
        }

        var h = new int[P];
        var f = new int[P];
        var ginv = new int[P];
        var g = new int[P];
        var finv = new int[P];
        try
        {
            // h = g / (3f) in Rq, with g invertible in R3 and f of weight w.
            do
            {
                SmallRandom(g, random);
            }
            while (R3Recip(ginv, g) != 0);

            ShortRandom(f, random);
            RqRecip3(finv, f); // always works
            RqMultSmall(h, finv, g);

            RqEncode(publicKey, h);
            SmallEncode(secretKey[..SmallBytes], f);
            SmallEncode(secretKey.Slice(SmallBytes, SmallBytes), ginv);
            publicKey.CopyTo(secretKey[ZSecretKeyBytes..]);
            random.Fill(secretKey.Slice(ZSecretKeyBytes + PublicKeySize, InputsBytes)); // rho, the implicit-rejection secret
            HashPrefix(secretKey.Slice(ZSecretKeyBytes + PublicKeySize + InputsBytes, HashBytes), 4, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(f));
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(ginv));
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(g));
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(finv));
        }
    }

    /// <summary>Encapsulates a fresh secret to <paramref name="publicKey"/> (<c>crypto_kem_enc</c>); the server's side, here for tests.</summary>
    public static void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret, ReadOnlySpan<byte> publicKey) =>
        Encapsulate(ciphertext, sharedSecret, publicKey, SystemRandom.Instance);

    internal static void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret, ReadOnlySpan<byte> publicKey, IRandom random)
    {
        if (ciphertext.Length != CiphertextSize || sharedSecret.Length != SharedSecretSize || publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException("Wrong buffer sizes.");
        }

        Span<byte> cache = stackalloc byte[HashBytes];
        Span<byte> rEnc = stackalloc byte[InputsBytes];
        var r = new int[P];
        try
        {
            HashPrefix(cache, 4, publicKey);
            ShortRandom(r, random);
            Hide(ciphertext, rEnc, r, publicKey, cache);
            HashSession(sharedSecret, 1, rEnc, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rEnc);
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(r));
        }
    }

    /// <summary>
    /// Decapsulates (<c>crypto_kem_dec</c>). A ciphertext that does not re-encrypt to itself yields a pseudorandom secret derived from rho
    /// (implicit rejection), chosen in constant time, so a tampered ciphertext is noticed only as a failed key exchange.
    /// </summary>
    public static void Decapsulate(Span<byte> sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> secretKey)
    {
        if (sharedSecret.Length != SharedSecretSize || ciphertext.Length != CiphertextSize || secretKey.Length != SecretKeySize)
        {
            throw new ArgumentException("Wrong buffer sizes.");
        }

        var publicKey = secretKey.Slice(ZSecretKeyBytes, PublicKeySize);
        var rho = secretKey.Slice(ZSecretKeyBytes + PublicKeySize, InputsBytes);
        var cache = secretKey.Slice(ZSecretKeyBytes + PublicKeySize + InputsBytes, HashBytes);

        var f = new int[P];
        var v = new int[P];
        var c = new int[P];
        var r = new int[P];
        Span<byte> rEnc = stackalloc byte[InputsBytes];
        var cnew = new byte[CiphertextSize];
        try
        {
            SmallDecode(f, secretKey[..SmallBytes]);
            SmallDecode(v, secretKey.Slice(SmallBytes, SmallBytes));
            RoundedDecode(c, ciphertext[..RoundedBytes]);
            Decrypt(r, c, f, v);
            Hide(cnew, rEnc, r, publicKey, cache);

            var mask = CiphertextsDiffMask(ciphertext, cnew); // 0 when equal, -1 otherwise
            for (var i = 0; i < InputsBytes; i++)
            {
                rEnc[i] ^= (byte)(mask & (rEnc[i] ^ rho[i]));
            }

            HashSession(sharedSecret, (byte)(1 + mask), rEnc, ciphertext);
        }
        finally
        {
            // cnew is the re-encryption of the decrypted r: for a tampered ciphertext, exactly what implicit rejection hides.
            CryptographicOperations.ZeroMemory(cnew);
            CryptographicOperations.ZeroMemory(rEnc);
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(f));
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(v));
            CryptographicOperations.ZeroMemory(MemoryMarshalBytes(r));
        }
    }

    // ---- constant-time integer helpers ----

    /// <summary>x = q*m + r with 0 &lt;= r &lt; m, for 0 &lt; m &lt; 16384, without a data-dependent division.</summary>
    private static void DivMod(uint x, uint m, out uint quotient, out uint remainder)
    {
        var v = 0x80000000u / m; // m is public
        var q = 0u;

        var qpart = (uint)(((ulong)x * v) >> 31);
        x -= qpart * m;
        q += qpart;

        qpart = (uint)(((ulong)x * v) >> 31);
        x -= qpart * m;
        q += qpart;

        x -= m;
        q += 1;
        var mask = 0u - (x >> 31);
        x += mask & m;
        q += mask;

        quotient = q;
        remainder = x;
    }

    private static uint Mod(uint x, uint m)
    {
        DivMod(x, m, out _, out var r);
        return r;
    }

    /// <summary>The non-negative remainder of a signed <paramref name="x"/> modulo <paramref name="m"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ModSigned(int x, uint m)
    {
        DivMod(0x80000000u + (uint)x, m, out _, out var r);
        DivMod(0x80000000u, m, out _, out var r2);
        var r16 = (ushort)(r - r2);
        var mask = 0u - (uint)(r16 >> 15);
        return (ushort)(r16 + (mask & m));
    }

    /// <summary>-1 when x != 0, else 0.</summary>
    private static int NonzeroMask(int x) => -(int)((0u - (uint)(ushort)x) >> 31);

    /// <summary>-1 when the 16-bit x is negative, else 0.</summary>
    private static int NegativeMask(int x) => -((ushort)x >> 15);

    private static int F3Freeze(int x) => ModSigned(x + 1, 3) - 1;

    private static int FqFreeze(int x) => ModSigned(x + Q12, Q) - Q12;

    private static int FqRecip(int a1)
    {
        var ai = a1;
        for (var i = 1; i < Q - 2; i++)
        {
            ai = FqFreeze(a1 * ai);
        }

        return ai;
    }

    // ---- polynomials ----

    /// <summary>h = f*g in R3. Products are accumulated (|sum| &lt;= 761) and reduced once.</summary>
    private static void R3Mult(int[] h, int[] f, int[] g)
    {
        var fg = new int[P + P - 1];
        for (var i = 0; i < P; i++)
        {
            var sum = 0;
            for (var j = 0; j <= i; j++)
            {
                sum += f[j] * g[i - j];
            }

            fg[i] = F3Freeze(sum);
        }

        for (var i = P; i < P + P - 1; i++)
        {
            var sum = 0;
            for (var j = i - P + 1; j < P; j++)
            {
                sum += f[j] * g[i - j];
            }

            fg[i] = F3Freeze(sum);
        }

        // x^p = x + 1.
        for (var i = P + P - 2; i >= P; i--)
        {
            fg[i - P] = F3Freeze(fg[i - P] + fg[i]);
            fg[i - P + 1] = F3Freeze(fg[i - P + 1] + fg[i]);
        }

        Array.Copy(fg, h, P);
        Array.Clear(fg);
    }

    /// <summary>out = 1/in in R3; returns 0 when invertible, else -1 (divstep-style, a fixed 2p-1 iterations).</summary>
    private static int R3Recip(int[] output, int[] input)
    {
        var f = new int[P + 1];
        var g = new int[P + 1];
        var v = new int[P + 1];
        var r = new int[P + 1];
        r[0] = 1;
        f[0] = 1;
        f[P - 1] = f[P] = -1;
        for (var i = 0; i < P; i++)
        {
            g[P - 1 - i] = input[i];
        }

        var delta = 1;
        for (var loop = 0; loop < (2 * P) - 1; loop++)
        {
            for (var i = P; i > 0; i--)
            {
                v[i] = v[i - 1];
            }

            v[0] = 0;

            var sign = -g[0] * f[0];
            var swap = NegativeMask(-delta) & NonzeroMask(g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (var i = 0; i < P + 1; i++)
            {
                var t = swap & (f[i] ^ g[i]);
                f[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            for (var i = 0; i < P + 1; i++)
            {
                g[i] = F3Freeze(g[i] + (sign * f[i]));
            }

            for (var i = 0; i < P + 1; i++)
            {
                r[i] = F3Freeze(r[i] + (sign * v[i]));
            }

            for (var i = 0; i < P; i++)
            {
                g[i] = g[i + 1];
            }

            g[P] = 0;
        }

        var s = f[0];
        for (var i = 0; i < P; i++)
        {
            output[i] = s * v[P - 1 - i];
        }

        var result = NonzeroMask(delta);
        Array.Clear(f);
        Array.Clear(g);
        Array.Clear(v);
        Array.Clear(r);
        return result;
    }

    /// <summary>h = f*g in Rq, g small. |sum| &lt;= 761 * 2295, so products are accumulated and reduced once.</summary>
    private static void RqMultSmall(int[] h, int[] f, int[] g)
    {
        var fg = new int[P + P - 1];
        for (var i = 0; i < P; i++)
        {
            var sum = 0;
            for (var j = 0; j <= i; j++)
            {
                sum += f[j] * g[i - j];
            }

            fg[i] = FqFreeze(sum);
        }

        for (var i = P; i < P + P - 1; i++)
        {
            var sum = 0;
            for (var j = i - P + 1; j < P; j++)
            {
                sum += f[j] * g[i - j];
            }

            fg[i] = FqFreeze(sum);
        }

        for (var i = P + P - 2; i >= P; i--)
        {
            fg[i - P] = FqFreeze(fg[i - P] + fg[i]);
            fg[i - P + 1] = FqFreeze(fg[i - P + 1] + fg[i]);
        }

        Array.Copy(fg, h, P);
        Array.Clear(fg);
    }

    /// <summary>out = 1/(3*in) in Rq; returns 0 when invertible, else -1.</summary>
    private static int RqRecip3(int[] output, int[] input)
    {
        var f = new int[P + 1];
        var g = new int[P + 1];
        var v = new int[P + 1];
        var r = new int[P + 1];
        r[0] = FqRecip(3);
        f[0] = 1;
        f[P - 1] = f[P] = -1;
        for (var i = 0; i < P; i++)
        {
            g[P - 1 - i] = input[i];
        }

        var delta = 1;
        for (var loop = 0; loop < (2 * P) - 1; loop++)
        {
            for (var i = P; i > 0; i--)
            {
                v[i] = v[i - 1];
            }

            v[0] = 0;

            var swap = NegativeMask(-delta) & NonzeroMask(g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (var i = 0; i < P + 1; i++)
            {
                var t = swap & (f[i] ^ g[i]);
                f[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            var f0 = f[0];
            var g0 = g[0];
            for (var i = 0; i < P + 1; i++)
            {
                g[i] = FqFreeze((f0 * g[i]) - (g0 * f[i]));
            }

            for (var i = 0; i < P + 1; i++)
            {
                r[i] = FqFreeze((f0 * r[i]) - (g0 * v[i]));
            }

            for (var i = 0; i < P; i++)
            {
                g[i] = g[i + 1];
            }

            g[P] = 0;
        }

        var scale = FqRecip(f[0]);
        for (var i = 0; i < P; i++)
        {
            output[i] = FqFreeze(scale * v[P - 1 - i]);
        }

        var result = NonzeroMask(delta);
        Array.Clear(f);
        Array.Clear(g);
        Array.Clear(v);
        Array.Clear(r);
        return result;
    }

    // ---- the core scheme ----

    /// <summary>r = Decrypt(c, (f, 1/g)): e = 3fc in R3, r = e/g, forced to weight w (or the default weight-w vector, in constant time).</summary>
    private static void Decrypt(int[] r, int[] c, int[] f, int[] ginv)
    {
        var cf = new int[P];
        var e = new int[P];
        var ev = new int[P];
        try
        {
            RqMultSmall(cf, c, f);
            for (var i = 0; i < P; i++)
            {
                e[i] = F3Freeze(FqFreeze(3 * cf[i]));
            }

            R3Mult(ev, e, ginv);

            var weight = 0;
            for (var i = 0; i < P; i++)
            {
                weight += ev[i] & 1;
            }

            var mask = NonzeroMask(weight - W); // 0 if weight w, else -1
            for (var i = 0; i < W; i++)
            {
                r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
            }

            for (var i = W; i < P; i++)
            {
                r[i] = ev[i] & ~mask;
            }
        }
        finally
        {
            Array.Clear(cf);
            Array.Clear(e);
            Array.Clear(ev);
        }
    }

    /// <summary>c, r_enc = Hide(r, pk, cache): the rounded encryption of r followed by the confirmation hash.</summary>
    private static void Hide(Span<byte> c, Span<byte> rEnc, int[] r, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> cache)
    {
        SmallEncode(rEnc, r);

        var h = new int[P];
        var hr = new int[P];
        RqDecode(h, publicKey);
        RqMultSmall(hr, h, r);
        for (var i = 0; i < P; i++)
        {
            hr[i] -= F3Freeze(hr[i]); // Round: the nearest multiple of 3
        }

        RoundedEncode(c[..RoundedBytes], hr);
        Array.Clear(hr);
        HashConfirm(c.Slice(RoundedBytes, HashBytes), rEnc, cache);
    }

    /// <summary>0 when the ciphertexts are equal, -1 otherwise, in constant time.</summary>
    private static int CiphertextsDiffMask(ReadOnlySpan<byte> c, ReadOnlySpan<byte> c2)
    {
        var differentBits = 0;
        for (var i = 0; i < CiphertextSize; i++)
        {
            differentBits |= c[i] ^ c2[i];
        }

        return (1 & ((differentBits - 1) >> 8)) - 1;
    }

    // ---- randomness ----

    private static void SmallRandom(int[] output, IRandom random)
    {
        for (var i = 0; i < P; i++)
        {
            output[i] = (int)(((random.Next32() & 0x3fffffffu) * 3) >> 30) - 1;
        }
    }

    /// <summary>A random small polynomial of weight w: w values of ±1 and the rest 0, shuffled by sorting random keys.</summary>
    private static void ShortRandom(int[] output, IRandom random)
    {
        var list = new uint[P];
        for (var i = 0; i < P; i++)
        {
            list[i] = random.Next32();
        }

        for (var i = 0; i < W; i++)
        {
            list[i] &= unchecked((uint)-2);
        }

        for (var i = W; i < P; i++)
        {
            list[i] = (list[i] & unchecked((uint)-3)) | 1;
        }

        SortUInt32(list);
        for (var i = 0; i < P; i++)
        {
            output[i] = (int)(list[i] & 3) - 1;
        }

        Array.Clear(list);
    }

    /// <summary>
    /// Sorts with Batcher's merge-exchange network (Knuth, TAOCP 5.2.2 algorithm M): which pairs are compared depends only on the length,
    /// and each compare-exchange is branch-free.
    /// </summary>
    internal static void SortUInt32(uint[] x)
    {
        var n = x.Length;
        if (n < 2)
        {
            return;
        }

        var t = 1;
        while ((1 << t) < n)
        {
            t++;
        }

        for (var p = 1 << (t - 1); p > 0; p >>= 1)
        {
            var q = 1 << (t - 1);
            var r = 0;
            var d = p;
            while (true)
            {
                for (var i = 0; i < n - d; i++)
                {
                    if ((i & p) == r)
                    {
                        MinMax(ref x[i], ref x[i + d]);
                    }
                }

                if (q == p)
                {
                    break;
                }

                d = q - p;
                q >>= 1;
                r = p;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MinMax(ref uint a, ref uint b)
    {
        long la = a, lb = b;
        var swap = (lb - la) >> 63; // all ones when b < a
        var c = (la ^ lb) & swap;
        a = (uint)(la ^ c);
        b = (uint)(lb ^ c);
    }

    // ---- encodings ----

    private static void SmallEncode(Span<byte> s, int[] f)
    {
        var k = 0;
        for (var i = 0; i < P / 4; i++)
        {
            var x = f[k++] + 1;
            x += (f[k++] + 1) << 2;
            x += (f[k++] + 1) << 4;
            x += (f[k++] + 1) << 6;
            s[i] = (byte)x;
        }

        s[P / 4] = (byte)(f[k] + 1);
    }

    private static void SmallDecode(int[] f, ReadOnlySpan<byte> s)
    {
        var k = 0;
        for (var i = 0; i < P / 4; i++)
        {
            int x = s[i];
            f[k++] = (x & 3) - 1;
            x >>= 2;
            f[k++] = (x & 3) - 1;
            x >>= 2;
            f[k++] = (x & 3) - 1;
            x >>= 2;
            f[k++] = (x & 3) - 1;
        }

        f[k] = (s[P / 4] & 3) - 1;
    }

    private static void RqEncode(Span<byte> s, int[] r)
    {
        var values = new ushort[P];
        var moduli = new ushort[P];
        for (var i = 0; i < P; i++)
        {
            values[i] = (ushort)(r[i] + Q12);
            moduli[i] = Q;
        }

        // Only the public key is encoded this way, but the buffer is cleared like every other polynomial.
        var written = Encode(s, values, moduli);
        Array.Clear(values);
        if (written != PublicKeySize)
        {
            throw new InvalidOperationException("Rq encoding size mismatch.");
        }
    }

    private static void RqDecode(int[] r, ReadOnlySpan<byte> s)
    {
        var moduli = new ushort[P];
        Array.Fill(moduli, (ushort)Q);
        var values = new ushort[P];
        Decode(values, s, moduli);
        for (var i = 0; i < P; i++)
        {
            r[i] = values[i] - Q12;
        }
    }

    private static void RoundedEncode(Span<byte> s, int[] r)
    {
        var values = new ushort[P];
        var moduli = new ushort[P];
        for (var i = 0; i < P; i++)
        {
            values[i] = (ushort)(((r[i] + Q12) * 10923) >> 15); // (r + q12) / 3, r + q12 being a multiple of 3
            moduli[i] = (Q + 2) / 3;
        }

        // The rounded h*r of a re-encryption is derived from the decrypted r: cleared after encoding.
        int written;
        try
        {
            written = Encode(s, values, moduli);
        }
        finally
        {
            Array.Clear(values);
        }

        if (written != RoundedBytes)
        {
            throw new InvalidOperationException("Rounded encoding size mismatch.");
        }
    }

    private static void RoundedDecode(int[] r, ReadOnlySpan<byte> s)
    {
        var moduli = new ushort[P];
        Array.Fill(moduli, (ushort)((Q + 2) / 3));
        var values = new ushort[P];
        Decode(values, s, moduli);
        for (var i = 0; i < P; i++)
        {
            r[i] = (values[i] * 3) - Q12;
        }
    }

    /// <summary>
    /// Encodes values 0 &lt;= R[i] &lt; M[i] &lt; 16384 compactly (the reference's mixed-radix Encode); returns the bytes written. The control
    /// flow depends only on the public moduli.
    /// </summary>
    private static int Encode(Span<byte> output, ushort[] values, ushort[] moduli)
    {
        var len = values.Length;
        var o = 0;
        if (len == 1)
        {
            uint r = values[0];
            uint m = moduli[0];
            while (m > 1)
            {
                output[o++] = (byte)r;
                r >>= 8;
                m = (m + 255) >> 8;
            }

            return o;
        }

        var half = (len + 1) / 2;
        var values2 = new ushort[half];
        var moduli2 = new ushort[half];
        int i;
        for (i = 0; i < len - 1; i += 2)
        {
            uint m0 = moduli[i];
            var r = values[i] + (values[i + 1] * m0);
            var m = moduli[i + 1] * m0;
            while (m >= 16384)
            {
                output[o++] = (byte)r;
                r >>= 8;
                m = (m + 255) >> 8;
            }

            values2[i / 2] = (ushort)r;
            moduli2[i / 2] = (ushort)m;
        }

        if (i < len)
        {
            values2[i / 2] = values[i];
            moduli2[i / 2] = moduli[i];
        }

        o += Encode(output[o..], values2, moduli2);
        Array.Clear(values2);
        return o;
    }

    /// <summary>The inverse of <see cref="Encode"/>; any input decodes to values below their moduli.</summary>
    private static int Decode(ushort[] output, ReadOnlySpan<byte> s, ushort[] moduli)
    {
        var len = moduli.Length;
        if (len == 1)
        {
            if (moduli[0] == 1)
            {
                output[0] = 0;
                return 0;
            }

            if (moduli[0] <= 256)
            {
                output[0] = (ushort)Mod(s[0], moduli[0]);
                return 1;
            }

            output[0] = (ushort)Mod(s[0] + ((uint)s[1] << 8), moduli[0]);
            return 2;
        }

        var half = (len + 1) / 2;
        var values2 = new ushort[half];
        var moduli2 = new ushort[half];
        var bottomR = new ushort[len / 2];
        var bottomT = new uint[len / 2];
        var consumed = 0;
        int i;
        for (i = 0; i < len - 1; i += 2)
        {
            var m = moduli[i] * (uint)moduli[i + 1];
            if (m > 256 * 16383)
            {
                bottomT[i / 2] = 256 * 256;
                bottomR[i / 2] = (ushort)(s[consumed] + (256 * s[consumed + 1]));
                consumed += 2;
                moduli2[i / 2] = (ushort)((((m + 255) >> 8) + 255) >> 8);
            }
            else if (m >= 16384)
            {
                bottomT[i / 2] = 256;
                bottomR[i / 2] = s[consumed];
                consumed += 1;
                moduli2[i / 2] = (ushort)((m + 255) >> 8);
            }
            else
            {
                bottomT[i / 2] = 1;
                bottomR[i / 2] = 0;
                moduli2[i / 2] = (ushort)m;
            }
        }

        if (i < len)
        {
            moduli2[i / 2] = moduli[i];
        }

        consumed += Decode(values2, s[consumed..], moduli2);

        var k = 0;
        for (i = 0; i < len - 1; i += 2)
        {
            var r = bottomR[i / 2] + (bottomT[i / 2] * values2[i / 2]);
            DivMod(r, moduli[i], out var r1, out var r0);
            r1 = Mod(r1, moduli[i + 1]); // only needed for invalid inputs
            output[k++] = (ushort)r0;
            output[k++] = (ushort)r1;
        }

        if (i < len)
        {
            output[k] = values2[i / 2];
        }

        return consumed;
    }

    // ---- hashing ----

    /// <summary>The first 32 bytes of SHA-512(b || input).</summary>
    private static void HashPrefix(Span<byte> output, byte b, ReadOnlySpan<byte> input)
    {
        var x = new byte[input.Length + 1];
        x[0] = b;
        input.CopyTo(x.AsSpan(1));
        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(x, h);
        h[..32].CopyTo(output);
        CryptographicOperations.ZeroMemory(x);
        CryptographicOperations.ZeroMemory(h);
    }

    private static void HashConfirm(Span<byte> h, ReadOnlySpan<byte> rEnc, ReadOnlySpan<byte> cache)
    {
        Span<byte> x = stackalloc byte[HashBytes * 2];
        HashPrefix(x[..HashBytes], 3, rEnc);
        cache.CopyTo(x[HashBytes..]);
        HashPrefix(h, 2, x);
        CryptographicOperations.ZeroMemory(x);
    }

    private static void HashSession(Span<byte> k, byte b, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z)
    {
        var x = new byte[HashBytes + CiphertextSize];
        HashPrefix(x.AsSpan(0, HashBytes), 3, y);
        z.CopyTo(x.AsSpan(HashBytes));
        HashPrefix(k, b, x);
        CryptographicOperations.ZeroMemory(x);
    }

    private static Span<byte> MemoryMarshalBytes(int[] values) => System.Runtime.InteropServices.MemoryMarshal.AsBytes(values.AsSpan());

    /// <summary>The operating system's CSPRNG, read in blocks.</summary>
    private sealed class SystemRandom : IRandom
    {
        public static readonly SystemRandom Instance = new();

        public uint Next32()
        {
            Span<byte> c = stackalloc byte[4];
            RandomNumberGenerator.Fill(c);
            var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(c);
            CryptographicOperations.ZeroMemory(c);
            return value;
        }

        public void Fill(Span<byte> buffer) => RandomNumberGenerator.Fill(buffer);
    }
}
