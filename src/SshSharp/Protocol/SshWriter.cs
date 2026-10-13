using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>Writes SSH wire types (RFC 4251 section 5) straight into an <see cref="IBufferWriter{T}"/>, without intermediate arrays.</summary>
internal readonly struct SshWriter(IBufferWriter<byte> output)
{
    public void WriteByte(byte value)
    {
        var span = output.GetSpan(1);
        span[0] = value;
        output.Advance(1);
    }

    public void WriteBoolean(bool value) => WriteByte(value ? (byte)1 : (byte)0);

    public void WriteUInt32(uint value)
    {
        var span = output.GetSpan(4);
        BinaryPrimitives.WriteUInt32BigEndian(span, value);
        output.Advance(4);
    }

    public void WriteUInt64(ulong value)
    {
        var span = output.GetSpan(8);
        BinaryPrimitives.WriteUInt64BigEndian(span, value);
        output.Advance(8);
    }

    /// <summary>Writes raw bytes with no length prefix.</summary>
    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        var span = output.GetSpan(value.Length);
        value.CopyTo(span);
        output.Advance(value.Length);
    }

    /// <summary>Writes a length-prefixed byte string.</summary>
    public void WriteString(ReadOnlySpan<byte> value)
    {
        WriteUInt32((uint)value.Length);
        WriteBytes(value);
    }

    /// <summary>Writes a length-prefixed UTF-8 string.</summary>
    public void WriteString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var length = Encoding.UTF8.GetByteCount(value);
        WriteUInt32((uint)length);
        var span = output.GetSpan(length);
        Encoding.UTF8.GetBytes(value, span);
        output.Advance(length);
    }

    /// <summary>Writes a name-list: comma-separated ASCII names.</summary>
    public void WriteNameList(IReadOnlyList<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        WriteString(string.Join(',', names));
    }

    /// <summary>Writes an <c>mpint</c> from an unsigned big-endian magnitude (leading zeros are dropped, a zero is added if the top bit is set).</summary>
    public void WriteMpint(ReadOnlySpan<byte> unsignedBigEndian)
    {
        var trimmed = unsignedBigEndian.TrimStart((byte)0);
        var pad = !trimmed.IsEmpty && (trimmed[0] & 0x80) != 0;
        WriteUInt32((uint)(trimmed.Length + (pad ? 1 : 0)));
        if (pad)
        {
            WriteByte(0);
        }

        WriteBytes(trimmed);
    }
}