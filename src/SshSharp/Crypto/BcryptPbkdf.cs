using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// OpenBSD's <c>bcrypt_pbkdf</c>, the key derivation OpenSSH uses for passphrase-protected private keys (PROTOCOL.key,
/// kdfname <c>bcrypt</c>). A port of OpenBSD's bcrypt_pbkdf.c and the parts of blowfish.c it uses.
/// </summary>
/// <remarks>
/// Only passphrases and their hashes pass through Blowfish here, and the S-box lookups depend on them; that is inherent to bcrypt.
/// The KDF runs once when a key file is loaded, on the user's own machine, so there is no remote observer to time it.
/// </remarks>
internal static class BcryptPbkdf
{
    private const int HashSize = 32;

    /// <summary>The initial Blowfish state: P-array then S-boxes, the hexadecimal digits of pi after the point.</summary>
    private static readonly Lazy<uint[]> InitialState = new(ComputeInitialState);

    /// <summary>Derives <paramref name="output"/>.Length bytes from a passphrase and salt with <paramref name="rounds"/> rounds.</summary>
    public static void DeriveKey(ReadOnlySpan<byte> passphrase, ReadOnlySpan<byte> salt, int rounds, Span<byte> output)
    {
        if (rounds < 1 || passphrase.IsEmpty || salt.IsEmpty || output.IsEmpty || output.Length > HashSize * HashSize || salt.Length > 1 << 20)
        {
            throw new ArgumentException("Invalid bcrypt_pbkdf parameters.");
        }

        var stride = (output.Length + HashSize - 1) / HashSize;
        var amount = (output.Length + stride - 1) / stride;

        Span<byte> sha2Pass = stackalloc byte[64];
        Span<byte> sha2Salt = stackalloc byte[64];
        Span<byte> result = stackalloc byte[HashSize];
        Span<byte> temp = stackalloc byte[HashSize];
        var countSalt = new byte[salt.Length + 4];
        salt.CopyTo(countSalt);
        var state = new uint[InitialState.Value.Length];
        try
        {
            SHA512.HashData(passphrase, sha2Pass);
            var remaining = output.Length;
            for (uint count = 1; remaining > 0; count++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(countSalt.AsSpan(salt.Length), count);
                SHA512.HashData(countSalt, sha2Salt);
                Hash(state, sha2Pass, sha2Salt, temp);
                temp.CopyTo(result);

                for (var i = 1; i < rounds; i++)
                {
                    SHA512.HashData(temp, sha2Salt);
                    Hash(state, sha2Pass, sha2Salt, temp);
                    for (var j = 0; j < HashSize; j++)
                    {
                        result[j] ^= temp[j];
                    }
                }

                // Unlike PBKDF2, output bytes are spread across the key rather than written in blocks.
                var take = Math.Min(amount, remaining);
                var written = 0;
                for (; written < take; written++)
                {
                    var destination = (written * stride) + (int)(count - 1);
                    if (destination >= output.Length)
                    {
                        break;
                    }

                    output[destination] = result[written];
                }

                remaining -= written;
            }
        }
        finally
        {
            sha2Pass.Clear();
            sha2Salt.Clear();
            result.Clear();
            temp.Clear();
            CryptographicOperations.ZeroMemory(countSalt);
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(state.AsSpan()));
        }
    }

    /// <summary>bcrypt_hash: an expensive Blowfish key schedule keyed by both inputs, then encrypting a fixed string 64 times.</summary>
    private static void Hash(uint[] state, ReadOnlySpan<byte> sha2Pass, ReadOnlySpan<byte> sha2Salt, Span<byte> output)
    {
        InitialState.Value.CopyTo(state, 0);
        ExpandState(state, sha2Salt, sha2Pass);
        for (var i = 0; i < 64; i++)
        {
            ExpandState(state, ReadOnlySpan<byte>.Empty, sha2Salt);
            ExpandState(state, ReadOnlySpan<byte>.Empty, sha2Pass);
        }

        Span<uint> data = stackalloc uint[8];
        var position = 0;
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = StreamToWord("OxychromaticBlowfishSwatDynamite"u8, ref position);
        }

        for (var i = 0; i < 64; i++)
        {
            for (var block = 0; block < data.Length; block += 2)
            {
                Encipher(state, ref data[block], ref data[block + 1]);
            }
        }

        for (var i = 0; i < data.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], data[i]);
        }

        data.Clear();
    }

    /// <summary>
    /// Blowfish_expandstate (with <paramref name="data"/>) or Blowfish_expand0state (empty data): XOR the key into the P-array, then
    /// re-encrypt the whole state, mixing in data words when there are any.
    /// </summary>
    private static void ExpandState(uint[] state, ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        var position = 0;
        for (var i = 0; i < 18; i++)
        {
            state[i] ^= StreamToWord(key, ref position);
        }

        position = 0;
        uint left = 0, right = 0;
        for (var i = 0; i < state.Length; i += 2)
        {
            if (!data.IsEmpty)
            {
                left ^= StreamToWord(data, ref position);
                right ^= StreamToWord(data, ref position);
            }

            Encipher(state, ref left, ref right);
            state[i] = left;
            state[i + 1] = right;
        }
    }

    private static void Encipher(uint[] state, ref uint left, ref uint right)
    {
        var l = left ^ state[0];
        var r = right;
        for (var i = 1; i <= 16; i += 2)
        {
            r ^= F(state, l) ^ state[i];
            l ^= F(state, r) ^ state[i + 1];
        }

        left = r ^ state[17];
        right = l;
    }

    private static uint F(uint[] state, uint x) =>
        ((state[18 + (x >> 24)] + state[18 + 256 + ((x >> 16) & 0xff)]) ^ state[18 + 512 + ((x >> 8) & 0xff)]) + state[18 + 768 + (x & 0xff)];

    /// <summary>Reads four bytes big-endian, wrapping around to the start of <paramref name="data"/>.</summary>
    private static uint StreamToWord(ReadOnlySpan<byte> data, ref int position)
    {
        uint word = 0;
        for (var i = 0; i < 4; i++)
        {
            if (position >= data.Length)
            {
                position = 0;
            }

            word = (word << 8) | data[position++];
        }

        return word;
    }

    /// <summary>Word <paramref name="index"/> of the initial Blowfish state (P-array, then S-boxes), for tests.</summary>
    internal static uint InitialWord(int index) => InitialState.Value[index];

    /// <summary>18 P-array words and 4 x 256 S-box words: the first 33,344 bits of pi's fractional part.</summary>
    private static uint[] ComputeInitialState()
    {
        const int words = 18 + (4 * 256);
        const int bits = words * 32;
        var fraction = ModpGroup.ScaledPi(bits) - (new BigInteger(3) << bits);
        var state = new uint[words];
        for (var i = 0; i < words; i++)
        {
            state[i] = (uint)((fraction >> (bits - (32 * (i + 1)))) & uint.MaxValue);
        }

        return state;
    }
}
