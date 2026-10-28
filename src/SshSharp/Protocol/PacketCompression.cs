using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>
/// The sending half of <c>zlib@openssh.com</c> (OpenSSH's PROTOCOL, "delayed compression"): one zlib stream for the direction, from the
/// first packet after authentication until the next key exchange, each packet's payload flushed out whole, so the peer can inflate it
/// as soon as it arrives. The compression is zlib's, through <see cref="ZLibStream"/>.
/// </summary>
/// <remarks>
/// As OpenSSH since September 2026, it codes with Huffman coding only (<c>Z_HUFFMAN_ONLY</c>), without LZ77's back-references. Those
/// refer to anything earlier in the stream, which every channel shares, so the length of a packet would tell whoever controls the data
/// of one channel whether it repeats what another channel carried (the CRIME and "Crossing the Streams" attacks). Huffman coding alone
/// still shrinks text, by less. .NET 8 cannot choose the strategy (<c>ZLibCompressionOptions</c> came in .NET 9), so there SshSharp does
/// not compress what it sends at all (<see cref="SshAlgorithms.CanCompressOutgoing"/>): it only offers <c>none</c> for that direction.
/// Not thread-safe: the transport uses it under its send lock.
/// </remarks>
internal sealed class ZlibCompressor : IDisposable
{
    private readonly CompressedOutput _output = new();
    private ZLibStream? _zlib;

    /// <summary>
    /// Compresses one payload, <paramref name="prefix"/> followed by <paramref name="body"/>, and returns its compressed form, which stays
    /// valid until <see cref="Clear"/> or the next call. The stream's zlib header comes with the first payload.
    /// </summary>
    public ReadOnlySpan<byte> Compress(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> body)
    {
        var zlib = _zlib ??= Create(_output);
        zlib.Write(prefix);
        zlib.Write(body);

        // A sync flush: everything written so far comes out, ending on a byte boundary (an empty stored block). OpenSSH flushes with
        // Z_PARTIAL_FLUSH; its inflate, with Z_SYNC_FLUSH, reads either.
        zlib.Flush();
        return _output.Written;
    }

    /// <summary>Wipes the compressed payload once it has been encoded into a packet: it is the plaintext in another form.</summary>
    public void Clear() => _output.Clear();

    // Stryker disable once Statement : ending the stream and wiping its output is hygiene that the API cannot observe
    public void Dispose()
    {
        // Disposing ends the stream with a final block and the checksum, written into the output and wiped with it; nothing is sent.
        _zlib?.Dispose();
        _zlib = null;
        _output.Clear();
    }

    private static ZLibStream Create(Stream output)
    {
#if NET10_0_OR_GREATER
        // Stryker disable once Boolean : disposing CompressedOutput does nothing, so whether ZLibStream leaves it open makes no difference
        // OpenSSH's settings: Z_BEST_SPEED with Z_HUFFMAN_ONLY (window 15 and memory level 8 are zlib's defaults, as here).
        return new ZLibStream(output, new ZLibCompressionOptions { CompressionLevel = 1, CompressionStrategy = ZLibCompressionStrategy.HuffmanOnly },
            leaveOpen: true);
#else
        // Never reached: without the Huffman-only strategy, zlib@openssh.com is not offered for what the client sends.
        _ = output;
        throw new PlatformNotSupportedException("Compressing outgoing packets needs .NET 10.");
#endif
    }

    /// <summary>The compressor's output for one payload, in a buffer that grows to the largest payload and is wiped after each.</summary>
    private sealed class CompressedOutput : Stream
    {
        private byte[] _buffer = new byte[4096];
        private int _length;

        public ReadOnlySpan<byte> Written => _buffer.AsSpan(0, _length);

        public void Clear()
        {
            // Stryker disable once Statement : wiping the payload is hygiene that the API cannot observe
            CryptographicOperations.ZeroMemory(_buffer.AsSpan(0, _length));
            _length = 0;
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            // Stryker disable once Equality : growing when the data would just fit leaves the output the same
            if (_buffer.Length - _length < buffer.Length)
            {
                // Stryker disable once Arithmetic : another growth factor leaves the output the same (the buffer is always large enough)
                var doubled = _buffer.Length * 2;
                var larger = new byte[Math.Max(doubled, _length + buffer.Length)];
                _buffer.AsSpan(0, _length).CopyTo(larger);
                // Stryker disable once Statement : wiping the old buffer is hygiene that the API cannot observe
                CryptographicOperations.ZeroMemory(_buffer.AsSpan(0, _length));
                _buffer = larger;
            }

            buffer.CopyTo(_buffer.AsSpan(_length));
            _length += buffer.Length;
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void WriteByte(byte value) => Write([value]);

        // Stryker disable once Boolean : ZLibStream asks a stream it writes to only whether it can write
        public override bool CanRead => false;

        // Stryker disable once Boolean : ZLibStream asks a stream it writes to only whether it can write
        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _length;

        public override long Position
        {
            get => _length;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

/// <summary>
/// The receiving half of <c>zlib@openssh.com</c>: one zlib stream for the direction, fed one packet's payload at a time. Each payload
/// inflates to one message, which must stay under <see cref="PacketCodec.MaxPacketLength"/> (as OpenSSH checks): a few hundred bytes of
/// compressed data can inflate to megabytes, so a hostile server's payload fails the connection once it passes the limit, rather than
/// growing a buffer without end. Not thread-safe: the transport's receive side uses it, one packet at a time.
/// </summary>
internal sealed class ZlibDecompressor : IDisposable
{
    /// <summary>The first output buffer's size: a full 32 KiB channel data packet fits, so the common large packet needs no second one.</summary>
    private const int InitialCapacity = 64 * 1024;

    private readonly CompressedInput _input = new();
    private readonly int _limit;
    private ZLibStream? _zlib;

    /// <summary>A decompressor whose messages must be shorter than <paramref name="limit"/> bytes.</summary>
    /// <param name="limit">The bound on a decompressed payload; <see cref="PacketCodec.MaxPacketLength"/> unless a test sets a smaller one.</param>
    public ZlibDecompressor(int limit = PacketCodec.MaxPacketLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        _limit = limit;
    }

    /// <summary>
    /// Called with the output buffer of a packet that failed, once it is wiped and just before it goes back to the pool (tests check it
    /// holds nothing of the payload).
    /// </summary>
    internal Action<byte[]>? Discarding { get; init; }

    /// <summary>
    /// Inflates the payload of <paramref name="compressed"/>, which it disposes, into a packet of its own (the caller disposes that one).
    /// </summary>
    /// <exception cref="SshProtocolException">
    /// The data is not valid zlib, ends the stream, or inflates to <see cref="PacketCodec.MaxPacketLength"/> bytes or more.
    /// </exception>
    public DecodedPacket Decompress(DecodedPacket compressed)
    {
        using (compressed)
        {
            return Decompress(compressed.Payload);
        }
    }

    /// <inheritdoc cref="Decompress(DecodedPacket)"/>
    public DecodedPacket Decompress(ReadOnlyMemory<byte> compressed)
    {
        var zlib = _zlib ??= new ZLibStream(_input, CompressionMode.Decompress, leaveOpen: true);
        _input.Set(compressed);
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(InitialCapacity, _limit));
        Instrumentation.Rented(buffer, nameof(ZlibDecompressor));
        var capacity = Math.Min(buffer.Length, _limit);
        var total = 0;
        try
        {
            while (true)
            {
                if (total == capacity)
                {
                    if (capacity >= _limit)
                    {
                        throw new SshProtocolException($"A compressed packet inflates to {_limit} bytes or more.");
                    }

                    var larger = ArrayPool<byte>.Shared.Rent(Math.Min(capacity * 2, _limit));
                    Instrumentation.Rented(larger, nameof(ZlibDecompressor));
                    buffer.AsSpan(0, total).CopyTo(larger);
                    PacketCodec.ZeroAndReturn(buffer, total, nameof(ZlibDecompressor));
                    buffer = larger;
                    capacity = Math.Min(buffer.Length, _limit);
                }

                // Each read inflates what the stream holds and takes more of the payload when it needs it. Zero means all of the payload
                // has been inflated: what this packet carries is complete, as the sender flushed it.
                int read;
                try
                {
                    read = zlib.Read(buffer.AsSpan(total, capacity - total));
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException)
                {
                    // Invalid data, or zlib's other refusals (ZLibException, an IOException: a preset dictionary, which SSH never uses).
                    throw new SshProtocolException("A compressed packet is not valid zlib data.", ex);
                }

                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            if (_input.Remaining > 0)
            {
                // The sender ended its stream inside this packet (a final block): nothing more can follow it. What the zlib stream had
                // already read past the end (it reads 8 KiB at a time) is dropped unseen; then the next packet inflates to nothing, and the
                // transport rejects it as empty. Either way the connection fails.
                throw new SshProtocolException("A compressed packet ends the zlib stream before its end.");
            }

            var packet = new DecodedPacket(buffer, 0, total, total);
            buffer = null!;
            return packet;
        }
        finally
        {
            _input.Clear();
            if (buffer is not null)
            {
                // The packet failed. A read that fails has often written output past total first (zlib inflates into the buffer, then
                // meets the bad data and the count is lost), so all of it that zlib could write to is wiped, not only the counted bytes.
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, capacity));
                Discarding?.Invoke(buffer);
                PacketCodec.ZeroAndReturn(buffer, 0, nameof(ZlibDecompressor));
            }
        }
    }

    public void Dispose()
    {
        _zlib?.Dispose();
        _zlib = null;
    }

    /// <summary>The payload being inflated, handed to the zlib stream as it reads.</summary>
    private sealed class CompressedInput : Stream
    {
        private ReadOnlyMemory<byte> _data;

        public int Remaining => _data.Length;

        public void Set(ReadOnlyMemory<byte> data) => _data = data;

        public void Clear() => _data = default;

        public override int Read(Span<byte> buffer)
        {
            var count = Math.Min(buffer.Length, _data.Length);
            _data.Span[..count].CopyTo(buffer);
            _data = _data[count..];
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override bool CanRead => true;

        // Stryker disable once Boolean : ZLibStream asks a stream it reads from only whether it can read
        public override bool CanSeek => false;

        // Stryker disable once Boolean : ZLibStream asks a stream it reads from only whether it can read
        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
