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

        // The setter keeps its own copy; wipe ours.
        var keyCopy = key.ToArray();
        _aes.Key = keyCopy;
        CryptographicOperations.ZeroMemory(keyCopy);
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

    /// <summary>
    /// Writes the first <c>destination.Length</c> bytes (at most one block) of the next keystream block without advancing the counter. A
    /// receiver whose packet length is encrypted needs it before the whole packet has arrived; the packet is then decrypted from the same
    /// counter.
    /// </summary>
    public void PeekKeystream(Span<byte> destination)
    {
        if (destination.Length > BlockSize)
        {
            throw new ArgumentException("At most one block of keystream can be peeked.", nameof(destination));
        }

        _encryptor.TransformBlock(_counter, 0, BlockSize, _keystream, 0);
        _keystream.AsSpan(0, destination.Length).CopyTo(destination);
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