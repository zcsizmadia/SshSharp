using System.Buffers.Binary;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>
/// Reads SSH wire types (RFC 4251 section 5) from a span without copying. Every read is bounds-checked and throws
/// <see cref="SshProtocolException"/> on truncated or oversized data, so a malicious peer cannot cause out-of-range access
/// or large allocations.
/// </summary>
internal ref struct SshReader
{
    /// <summary>The largest string, mpint or name-list the reader accepts (256 KiB, RFC 4253 section 6.1 packet size limit).</summary>
    public const int MaxStringLength = 256 * 1024;

    private ReadOnlySpan<byte> _data;

    public SshReader(ReadOnlySpan<byte> data) => _data = data;

    /// <summary>The bytes not yet read.</summary>
    public readonly ReadOnlySpan<byte> Remaining => _data;

    public readonly bool IsEmpty => _data.IsEmpty;

    public byte ReadByte()
    {
        Require(1);
        var value = _data[0];
        _data = _data[1..];
        return value;
    }

    public bool ReadBoolean() => ReadByte() != 0;

    public uint ReadUInt32()
    {
        Require(4);
        var value = BinaryPrimitives.ReadUInt32BigEndian(_data);
        _data = _data[4..];
        return value;
    }

    public ulong ReadUInt64()
    {
        Require(8);
        var value = BinaryPrimitives.ReadUInt64BigEndian(_data);
        _data = _data[8..];
        return value;
    }

    /// <summary>Reads exactly <paramref name="count"/> raw bytes (no length prefix).</summary>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        Require(count);
        var value = _data[..count];
        _data = _data[count..];
        return value;
    }

    /// <summary>Reads a length-prefixed byte string (<c>string</c>).</summary>
    public ReadOnlySpan<byte> ReadString()
    {
        var length = ReadUInt32();
        if (length > MaxStringLength)
        {
            throw new SshProtocolException($"String length {length} exceeds the limit of {MaxStringLength}.");
        }

        return ReadBytes((int)length);
    }

    /// <summary>Reads a length-prefixed UTF-8 string.</summary>
    public string ReadUtf8String()
    {
        var bytes = ReadString();
        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (ArgumentException ex)
        {
            throw new SshProtocolException($"Invalid UTF-8 in string: {ex.Message}");
        }
    }

    /// <summary>Reads an ASCII name-list (<c>name-list</c>): comma-separated names, no empty names.</summary>
    public IReadOnlyList<string> ReadNameList()
    {
        var bytes = ReadString();
        if (bytes.IsEmpty)
        {
            return [];
        }

        foreach (var b in bytes)
        {
            if (b is < 0x21 or > 0x7E)
            {
                throw new SshProtocolException("Name-list contains a non-printable or non-ASCII character.");
            }
        }

        var names = Encoding.ASCII.GetString(bytes).Split(',');
        if (Array.Exists(names, n => n.Length == 0))
        {
            throw new SshProtocolException("Name-list contains an empty name.");
        }

        return names;
    }

    /// <summary>
    /// Reads an <c>mpint</c> and returns its magnitude as unsigned big-endian bytes without the sign-padding zero.
    /// Negative values are rejected (SSH key exchange never uses them).
    /// </summary>
    public ReadOnlySpan<byte> ReadMpint()
    {
        var bytes = ReadString();
        if (bytes.IsEmpty)
        {
            return bytes;
        }

        if ((bytes[0] & 0x80) != 0)
        {
            throw new SshProtocolException("Negative mpint.");
        }

        if (bytes[0] == 0)
        {
            bytes = bytes[1..];
            if (!bytes.IsEmpty && (bytes[0] & 0x80) == 0)
            {
                throw new SshProtocolException("Non-minimal mpint encoding.");
            }
        }

        return bytes;
    }

    private readonly void Require(int count)
    {
        if (_data.Length < count)
        {
            throw new SshProtocolException($"Truncated packet: need {count} bytes, {_data.Length} left.");
        }
    }
}