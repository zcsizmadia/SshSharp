using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>A decoded packet. The payload lives in a pooled buffer: dispose to return it (it is zeroed first, as it may carry secrets).</summary>
internal sealed class DecodedPacket : IDisposable
{
    private byte[]? _buffer;
    private readonly int _offset;
    private readonly int _length;

    public DecodedPacket(byte[] buffer, int offset, int length)
    {
        _buffer = buffer;
        _offset = offset;
        _length = length;
    }

    /// <summary>The message payload (first byte is the message number).</summary>
    public ReadOnlyMemory<byte> Payload => _buffer is null
        ? throw new ObjectDisposedException(nameof(DecodedPacket))
        : _buffer.AsMemory(_offset, _length);

    public void Dispose()
    {
        if (_buffer is { } buffer)
        {
            _buffer = null;
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}

/// <summary>Builds and parses SSH binary packets (RFC 4253 section 6) on top of a <see cref="PacketProtector"/>.</summary>
internal static class PacketCodec
{
    /// <summary>The largest packet_length accepted (OpenSSH's limit); RFC 4253 requires support for 35000 bytes.</summary>
    public const int MaxPacketLength = 256 * 1024;

    private const int MinPadding = 4;

    /// <summary>Writes one packet carrying <paramref name="payload"/> into <paramref name="output"/>.</summary>
    public static void Encode(IBufferWriter<byte> output, ReadOnlySpan<byte> payload, PacketProtector protector, uint sequenceNumber)
    {
        var unpadded = 1 + payload.Length + (protector.LengthExcludedFromAlignment ? 0 : 4);
        var padding = protector.Alignment - (unpadded % protector.Alignment);
        if (padding < MinPadding)
        {
            padding += protector.Alignment;
        }

        var packetLength = 1 + payload.Length + padding;
        if (packetLength > MaxPacketLength)
        {
            throw new ArgumentException($"Payload of {payload.Length} bytes exceeds the maximum packet size.", nameof(payload));
        }

        var total = 4 + packetLength;
        var span = output.GetSpan(total + protector.TagSize);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(span, (uint)packetLength);
        span[4] = (byte)padding;
        payload.CopyTo(span[5..]);
        RandomNumberGenerator.Fill(span.Slice(5 + payload.Length, padding));
        protector.Encrypt(sequenceNumber, span[..total], span.Slice(total, protector.TagSize));
        output.Advance(total + protector.TagSize);
    }

    /// <summary>
    /// Tries to decode one packet from the start of <paramref name="input"/>. Returns false when more data is needed.
    /// Throws <see cref="SshProtocolException"/> for invalid lengths, padding, or a failed MAC/tag; the connection must then be dropped.
    /// </summary>
    /// <param name="input">The received bytes.</param>
    /// <param name="protector">The protector for this direction.</param>
    /// <param name="sequenceNumber">The expected sequence number of this packet.</param>
    /// <param name="packet">The decoded packet when the result is true.</param>
    /// <param name="consumed">The number of input bytes the packet occupied.</param>
    public static bool TryDecode(ReadOnlySequence<byte> input, PacketProtector protector, uint sequenceNumber, out DecodedPacket? packet, out long consumed)
    {
        packet = null;
        consumed = 0;
        if (input.Length < 4)
        {
            return false;
        }

        Span<byte> first = stackalloc byte[4];
        input.Slice(0, 4).CopyTo(first);
        var length = protector.ReadLength(sequenceNumber, first);
        Validate(length, protector);

        var total = 4L + length + protector.TagSize;
        if (input.Length < total)
        {
            return false;
        }

        var packetSize = 4 + (int)length;
        var buffer = ArrayPool<byte>.Shared.Rent(packetSize + protector.TagSize);
        try
        {
            input.Slice(0, total).CopyTo(buffer);
            var packetSpan = buffer.AsSpan(0, packetSize);
            if (!protector.TryDecrypt(sequenceNumber, packetSpan, buffer.AsSpan(packetSize, protector.TagSize)))
            {
                throw new SshProtocolException("Packet authentication failed (bad MAC or tag).");
            }

            var padding = buffer[4];
            if (padding < MinPadding || padding > length - 1)
            {
                throw new SshProtocolException($"Invalid padding length {padding} in a packet of {length} bytes.");
            }

            packet = new DecodedPacket(buffer, 5, (int)length - 1 - padding);
            consumed = total;
            buffer = null!;
            return true;
        }
        finally
        {
            if (buffer is not null)
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }
    }

    private static void Validate(uint length, PacketProtector protector)
    {
        if (length < 1 + MinPadding || length > MaxPacketLength)
        {
            throw new SshProtocolException($"Invalid packet length {length}.");
        }

        var aligned = protector.LengthExcludedFromAlignment ? length : length + 4;
        if (aligned % protector.Alignment != 0)
        {
            throw new SshProtocolException($"Packet length {length} is not a multiple of the cipher block size.");
        }
    }
}