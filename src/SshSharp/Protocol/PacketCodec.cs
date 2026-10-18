using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>
/// A decoded packet. The payload lives in a pooled buffer: dispose to return it. The part of the buffer the packet was written into is
/// zeroed first, as it may carry secrets.
/// </summary>
internal sealed class DecodedPacket : IDisposable
{
    private byte[]? _buffer;
    private readonly int _offset;
    private readonly int _length;
    private readonly int _used;

    /// <param name="buffer">The pooled buffer, returned to <see cref="ArrayPool{T}.Shared"/> on disposal.</param>
    /// <param name="offset">Where the payload starts.</param>
    /// <param name="length">The payload's length.</param>
    /// <param name="used">
    /// How many bytes from the start of <paramref name="buffer"/> were ever written (the whole packet and its tag). Only these are zeroed
    /// on disposal: the pool hands out arrays rounded up to a power of two, so a full 32 KiB packet sits in a 64 KiB array, and clearing
    /// all of it zeroed twice what the packet ever touched.
    /// </param>
    public DecodedPacket(byte[] buffer, int offset, int length, int used)
    {
        _buffer = buffer;
        _offset = offset;
        _length = length;
        _used = used;
    }

    /// <summary>The message payload (first byte is the message number).</summary>
    public ReadOnlyMemory<byte> Payload => _buffer is null
        ? throw new ObjectDisposedException(nameof(DecodedPacket))
        : _buffer.AsMemory(_offset, _length);

    /// <summary>
    /// Zeroes the used part of the buffer and returns it to the pool, once, even when two threads dispose at the same moment: a buffer
    /// returned twice would be handed to two renters, and one's data would silently overwrite the other's.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _buffer, null) is { } buffer)
        {
            PacketCodec.ZeroAndReturn(buffer, _used, nameof(DecodedPacket));
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
    public static bool TryDecode(ReadOnlySequence<byte> input, PacketProtector protector, uint sequenceNumber, out DecodedPacket? packet, out long consumed) =>
        TryDecode(input, protector, sequenceNumber, out packet, out consumed, out _);

    /// <inheritdoc cref="TryDecode(ReadOnlySequence{byte}, PacketProtector, uint, out DecodedPacket?, out long)"/>
    /// <param name="input">The received bytes.</param>
    /// <param name="protector">The protector for this direction.</param>
    /// <param name="sequenceNumber">The expected sequence number of this packet.</param>
    /// <param name="packet">The decoded packet when the result is true.</param>
    /// <param name="consumed">The number of input bytes the packet occupied.</param>
    /// <param name="required">
    /// When the result is false, how many bytes the packet needs in all: 4 until its length is known, then the whole packet with its tag.
    /// A reader waits for that many before asking again, rather than decoding the length again each time a piece arrives (for
    /// chacha20-poly1305 that costs a ChaCha20 block, for encrypt-and-MAC AES-CTR a keystream block).
    /// </param>
    public static bool TryDecode(ReadOnlySequence<byte> input, PacketProtector protector, uint sequenceNumber, out DecodedPacket? packet, out long consumed, out long required)
    {
        packet = null;
        consumed = 0;
        required = 4;
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
            required = total;
            return false;
        }

        // Everything written into the buffer: the packet, decrypted in place, and its tag. Nothing past it is touched, so zeroing this much
        // wipes all the packet ever put there.
        var used = (int)total;
        var packetSize = 4 + (int)length;
        var buffer = ArrayPool<byte>.Shared.Rent(used);
        Instrumentation.Rented(buffer, nameof(TryDecode));
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

            packet = new DecodedPacket(buffer, 5, (int)length - 1 - padding, used);
            consumed = total;
            buffer = null!;
            return true;
        }
        finally
        {
            if (buffer is not null)
            {
                ZeroAndReturn(buffer, used, nameof(TryDecode));
            }
        }
    }

    /// <summary>
    /// Zeroes the first <paramref name="used"/> bytes of a packet buffer, all a packet ever wrote there, and returns it to the pool without
    /// clearing the rest again.
    /// </summary>
    internal static void ZeroAndReturn(byte[] buffer, int used, string owner)
    {
        CryptographicOperations.ZeroMemory(buffer.AsSpan(0, used));
        Instrumentation.Returning(buffer, owner);
        ArrayPool<byte>.Shared.Return(buffer);
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
