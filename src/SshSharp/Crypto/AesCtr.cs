using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>AES in counter mode (NIST SP 800-38A): a 128-bit big-endian counter block, incremented per 16 bytes of keystream.</summary>
internal sealed class AesCtr : IDisposable
{
    private const int BlockSize = 16;
    private const int BatchBlocks = 16;

    private readonly Aes _aes = Aes.Create();
    private readonly byte[] _counter = new byte[BlockSize];

    public AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> initialCounter)
    {
        if (initialCounter.Length != BlockSize)
        {
            throw new ArgumentException("The initial counter block must be 16 bytes.", nameof(initialCounter));
        }

        _aes.Key = key.ToArray();
        initialCounter.CopyTo(_counter);
    }

    /// <summary>XORs the keystream into <paramref name="data"/> in place and advances the counter. Keystream continues across calls only in whole blocks.</summary>
    public void Transform(Span<byte> data)
    {
        Span<byte> counters = stackalloc byte[BatchBlocks * BlockSize];
        Span<byte> keystream = stackalloc byte[BatchBlocks * BlockSize];
        var offset = 0;
        while (offset < data.Length)
        {
            var blocks = Math.Min(BatchBlocks, (data.Length - offset + BlockSize - 1) / BlockSize);
            for (var i = 0; i < blocks; i++)
            {
                _counter.CopyTo(counters[(i * BlockSize)..]);
                Increment();
            }

            _aes.EncryptEcb(counters[..(blocks * BlockSize)], keystream, PaddingMode.None);
            var count = Math.Min(blocks * BlockSize, data.Length - offset);
            for (var i = 0; i < count; i++)
            {
                data[offset + i] ^= keystream[i];
            }

            offset += count;
        }

        keystream.Clear();
    }

    public void Dispose()
    {
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_counter);
    }

    private void Increment()
    {
        for (var i = BlockSize - 1; i >= 0; i--)
        {
            if (++_counter[i] != 0)
            {
                return;
            }
        }
    }
}