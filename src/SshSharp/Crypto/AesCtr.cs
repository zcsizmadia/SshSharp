using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// AES in counter mode (NIST SP 800-38A): a 128-bit big-endian counter block, incremented per 16 bytes of keystream. One persistent
/// ECB encryptor and fixed scratch buffers are used, so transforming data allocates nothing (the span-based <c>EncryptEcb</c> API allocates on
/// some platforms on every call).
/// </summary>
internal sealed class AesCtr : IDisposable
{
    private const int BlockSize = 16;
    private const int BatchBlocks = 64;

    private readonly Aes _aes = Aes.Create();
    private readonly ICryptoTransform _encryptor;
    private readonly byte[] _counter = new byte[BlockSize];
    private readonly byte[] _counters = new byte[BatchBlocks * BlockSize];
    private readonly byte[] _keystream = new byte[BatchBlocks * BlockSize];

    public AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> initialCounter)
    {
        if (initialCounter.Length != BlockSize)
        {
            throw new ArgumentException("The initial counter block must be 16 bytes.", nameof(initialCounter));
        }

        _aes.Key = key.ToArray();
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        _encryptor = _aes.CreateEncryptor();
        initialCounter.CopyTo(_counter);
    }

    /// <summary>XORs the keystream into <paramref name="data"/> in place and advances the counter. Keystream continues across calls only in whole blocks.</summary>
    public void Transform(Span<byte> data)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            var blocks = Math.Min(BatchBlocks, (data.Length - offset + BlockSize - 1) / BlockSize);
            for (var i = 0; i < blocks; i++)
            {
                _counter.CopyTo(_counters, i * BlockSize);
                Increment();
            }

            _encryptor.TransformBlock(_counters, 0, blocks * BlockSize, _keystream, 0);
            var count = Math.Min(blocks * BlockSize, data.Length - offset);
            XorHelper.XorInPlace(data.Slice(offset, count), _keystream);
            offset += count;
        }
    }

    public void Dispose()
    {
        _encryptor.Dispose();
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_counter);
        CryptographicOperations.ZeroMemory(_counters);
        CryptographicOperations.ZeroMemory(_keystream);
    }

    private void Increment()
    {
        var low = BinaryPrimitives.ReadUInt64BigEndian(_counter.AsSpan(8)) + 1;
        BinaryPrimitives.WriteUInt64BigEndian(_counter.AsSpan(8), low);
        if (low == 0)
        {
            var high = BinaryPrimitives.ReadUInt64BigEndian(_counter) + 1;
            BinaryPrimitives.WriteUInt64BigEndian(_counter, high);
        }
    }
}