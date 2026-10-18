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

    /// <summary>A decoded packet whose payload lies in a pooled buffer.</summary>
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

    /// <summary>Writes one packet carrying <paramref name="payload"/> into <paramref name="output"/>, its padding straight from the system RNG.</summary>
    public static void Encode(IBufferWriter<byte> output, ReadOnlySpan<byte> payload, PacketProtector protector, uint sequenceNumber) =>
        Encode(output, [], payload, protector, sequenceNumber, null);

    /// <summary>
    /// Writes one packet whose payload is <paramref name="prefix"/> followed by <paramref name="body"/>. Both are copied once, straight into
    /// <paramref name="output"/>'s buffer, where the packet is encrypted in place: a channel data message passes its small header as the
    /// prefix and the caller's data as the body, so the data is not first copied into a buffer of its own. The protector sees exactly the
    /// bytes it would for the same payload in one piece.
    /// </summary>
    /// <param name="output">Where the packet is written.</param>
    /// <param name="prefix">The start of the payload (the message number first), or empty when <paramref name="body"/> is all of it.</param>
    /// <param name="body">The rest of the payload.</param>
    /// <param name="protector">The protector for this direction.</param>
    /// <param name="sequenceNumber">The packet's sequence number.</param>
    /// <param name="padding">Where the padding bytes come from; null for <see cref="RandomNumberGenerator"/> directly.</param>
    public static void Encode(IBufferWriter<byte> output, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> body, PacketProtector protector, uint sequenceNumber,
        PaddingRandom? padding)
    {
        var payloadLength = prefix.Length + body.Length;
        var unpadded = 1 + payloadLength + (protector.LengthExcludedFromAlignment ? 0 : 4);
        var paddingLength = protector.Alignment - (unpadded % protector.Alignment);
        if (paddingLength < MinPadding)
        {
            paddingLength += protector.Alignment;
        }

        var packetLength = 1 + payloadLength + paddingLength;
        if (packetLength > MaxPacketLength)
        {
            throw new ArgumentException($"Payload of {payloadLength} bytes exceeds the maximum packet size.", nameof(body));
        }

        var total = 4 + packetLength;
        var span = output.GetSpan(total + protector.TagSize);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(span, (uint)packetLength);
        span[4] = (byte)paddingLength;
        prefix.CopyTo(span[5..]);
        body.CopyTo(span[(5 + prefix.Length)..]);
        var paddingBytes = span.Slice(5 + payloadLength, paddingLength);
        if (padding is null)
        {
            RandomNumberGenerator.Fill(paddingBytes);
        }
        else
        {
            padding.Fill(paddingBytes);
        }

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

/// <summary>Fills a span with random bytes (the source behind <see cref="PaddingRandom"/>; replaceable in tests).</summary>
internal delegate void RandomFill(Span<byte> destination);

/// <summary>
/// Random bytes for packet padding, taken from <see cref="RandomNumberGenerator"/> a block at a time instead of one call per packet (a
/// packet needs only 4 to 19 bytes). The padding stays cryptographically random: every byte comes from the system RNG, and each is used
/// once. The bytes are not secret (the padding only has to be unpredictable, RFC 4253 section 6), and they are encrypted with the packet.
/// </summary>
/// <remarks>
/// Not thread-safe. A transport owns one and uses it only under its send lock, which already serializes every encode (application
/// messages, KEXINIT, NEWKEYS and EXT_INFO alike).
/// </remarks>
internal sealed class PaddingRandom
{
    /// <summary>How many random bytes are drawn at a time: enough for a dozen or more packets.</summary>
    public const int DefaultSize = 256;

    private readonly byte[] _buffer;
    private readonly RandomFill _refill;
    private int _position;

    /// <param name="size">The block size.</param>
    /// <param name="refill">The source of the random bytes; <see cref="RandomNumberGenerator.Fill"/> unless a test gives another.</param>
    public PaddingRandom(int size = DefaultSize, RandomFill? refill = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 1);
        _buffer = new byte[size];
        _refill = refill ?? RandomNumberGenerator.Fill;
        _position = size; // empty: the first use fills it
    }

    /// <summary>Fills <paramref name="destination"/> with random bytes that have not been handed out before.</summary>
    public void Fill(Span<byte> destination)
    {
        if (destination.Length > _buffer.Length)
        {
            _refill(destination);
            return;
        }

        if (_buffer.Length - _position < destination.Length)
        {
            // What is left is too short for this packet: dropped rather than spliced, which keeps this simple and costs a few bytes.
            _refill(_buffer);
            _position = 0;
        }

        _buffer.AsSpan(_position, destination.Length).CopyTo(destination);
        _position += destination.Length;
    }

    /// <summary>Wipes the bytes not yet used (the transport is being disposed).</summary>
    public void Clear()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        _position = _buffer.Length;
    }
}

/// <summary>
/// The header of <c>SSH_MSG_CHANNEL_DATA</c> (RFC 4254 section 5.2): the message number, the recipient channel and the data's length. It
/// is written in front of the data as the packet is encoded (<see cref="PacketCodec.Encode(IBufferWriter{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte}, PacketProtector, uint, PaddingRandom?)"/>),
/// so the data is copied only once, into the packet.
/// </summary>
internal readonly record struct ChannelDataHeader(uint RecipientChannel, uint Length)
{
    /// <summary>The header's size on the wire.</summary>
    public const int Size = 9;

    /// <summary>Writes the header into the first <see cref="Size"/> bytes of <paramref name="destination"/>.</summary>
    public void Write(Span<byte> destination)
    {
        destination[0] = SshMessage.ChannelData;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(destination[1..], RecipientChannel);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(destination[5..], Length);
    }
}
