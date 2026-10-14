using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Keys;

/// <summary>
/// A growable buffer for secrets: unlike <see cref="ArrayBufferWriter{T}"/>, which abandons its old array when it grows, it zeroes the
/// array it replaces, and <see cref="Dispose"/> zeroes the last one, so no copy of what was written is left in the heap.
/// </summary>
internal sealed class ZeroingBufferWriter(int initialCapacity) : IBufferWriter<byte>, IDisposable
{
    private byte[] _buffer = new byte[Math.Max(initialCapacity, 16)];
    private int _written;

    /// <summary>How many times the buffer grew (for tests).</summary>
    public int Reallocations { get; private set; }

    public int WrittenCount => _written;

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (_written + count > _buffer.Length)
        {
            throw new InvalidOperationException("Advanced past the end of the buffer.");
        }

        _written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsSpan(_written);
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        _written = 0;
    }

    private void Ensure(int sizeHint)
    {
        var needed = _written + Math.Max(sizeHint, 1);
        if (needed <= _buffer.Length)
        {
            return;
        }

        var larger = new byte[Math.Max(needed, _buffer.Length * 2)];
        _buffer.AsSpan(0, _written).CopyTo(larger);
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = larger;
        Reallocations++;
    }
}
