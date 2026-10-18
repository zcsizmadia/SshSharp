using System.Buffers;
using System.Buffers.Binary;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>
/// An SFTP request built in a buffer rented from the shared pool, laid out as it goes on the wire: <c>uint32 length || byte type ||
/// uint32 id || body</c>. The length and the id are left as space and filled in when the request is sent, so the packet is written once
/// and sent from where it was built: no intermediate array, no copy into a separate frame.
/// </summary>
/// <remarks>
/// <para>
/// Ownership: the code that starts a frame owns it until it hands it to <see cref="SftpChannel.RequestAsync(SftpRequestFrame, CancellationToken, Action{SftpResponse}?)"/>,
/// which takes it over whatever happens and disposes it once the send has completed or failed. A frame that is never handed over is
/// disposed by the code that started it. Nothing else may keep a reference to the buffer.
/// </para>
/// <para>
/// The buffer is free once the send completes, before the reply arrives: the session's input stream copies the bytes into packets of its
/// own (<see cref="SshChannel.SendDataAsync"/>) and completes only after the last one is sent.
/// </para>
/// </remarks>
internal sealed class SftpRequestFrame : IBufferWriter<byte>, IDisposable
{
    /// <summary>The length, type and id that start every request.</summary>
    public const int HeaderLength = 9;

    /// <summary>What a request with a path or a handle usually fits in; a larger one grows (rents a larger buffer and copies).</summary>
    private const int DefaultCapacity = 256;

    private byte[]? _buffer;
    private int _written;

    private SftpRequestFrame(byte type, int capacity)
    {
        _buffer = Rent(Math.Max(capacity, HeaderLength));
        _buffer[4] = type;
        _written = HeaderLength;
    }

    /// <summary>
    /// Starts a request of <paramref name="type"/>. <paramref name="capacity"/> is the whole frame's size when it is known (a WRITE), so
    /// the buffer never grows.
    /// </summary>
    public static SftpRequestFrame Start(byte type, int capacity = DefaultCapacity) => new(type, capacity);

    /// <summary>A writer that appends to the request's body.</summary>
    public SshWriter Writer => new(this);

    /// <summary>The bytes written so far, the header included.</summary>
    public int Length => _written;

    private byte[] Buffer => _buffer ?? throw new ObjectDisposedException(nameof(SftpRequestFrame));

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, Buffer.Length - _written);
        _written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return Buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return Buffer.AsSpan(_written);
    }

    /// <summary>Overwrites a <c>uint32</c> written earlier, at <paramref name="at"/> from the start of the frame (a length known only later).</summary>
    public void PatchUInt32(int at, uint value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(at, HeaderLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(at, _written - 4);
        BinaryPrimitives.WriteUInt32BigEndian(Buffer.AsSpan(at), value);
    }

    /// <summary>Fills in the length and <paramref name="id"/>; returns the frame to send, valid until this is disposed.</summary>
    public ReadOnlyMemory<byte> Complete(uint id)
    {
        var buffer = Buffer;
        BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)(_written - 4));
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(5), id);
        return buffer.AsMemory(0, _written);
    }

    /// <summary>Returns the buffer to the pool (once; later calls do nothing).</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _buffer, null) is { } buffer)
        {
            Release(buffer);
        }
    }

    private void Ensure(int sizeHint)
    {
        var buffer = Buffer;
        sizeHint = Math.Max(sizeHint, 1);
        if (buffer.Length - _written >= sizeHint)
        {
            return;
        }

        var larger = Rent(Math.Max(_written + sizeHint, buffer.Length * 2));
        buffer.AsSpan(0, _written).CopyTo(larger);
        _buffer = larger;
        Release(buffer);
    }

    private static byte[] Rent(int length)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        Instrumentation.Rented(buffer, nameof(SftpRequestFrame));
        return buffer;
    }

    private static void Release(byte[] buffer)
    {
        Instrumentation.Returning(buffer, nameof(SftpRequestFrame));
        ArrayPool<byte>.Shared.Return(buffer);
    }
}
