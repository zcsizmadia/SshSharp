using System.Buffers;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// What <see cref="SshClient.RunCommandAsync(string, SshSessionOptions?, SshCommandInput?, CancellationToken)"/> writes to the command's
/// standard input: bytes, text or a stream. The input is written while the output is collected, and end-of-file follows it, so commands
/// that read to the end of their input (<c>cat</c>, <c>sh -s</c>, <c>tee</c>) finish.
/// </summary>
public sealed class SshCommandInput
{
    /// <summary>How much of a stream is read at a time.</summary>
    private const int StreamBufferSize = 64 * 1024;

    private readonly ReadOnlyMemory<byte> _data;
    private readonly Stream? _stream;

    private SshCommandInput(ReadOnlyMemory<byte> data, Stream? stream)
    {
        _data = data;
        _stream = stream;
    }

    /// <summary>Input from bytes, sent as they are. The bytes are not copied: leave them unchanged until the command has finished.</summary>
    /// <param name="data">The input.</param>
    public static SshCommandInput FromBytes(ReadOnlyMemory<byte> data) => new(data, null);

    /// <summary>Input from text, encoded with <paramref name="encoding"/> (UTF-8 when null), without a byte order mark.</summary>
    /// <param name="text">The input. Line endings are sent as they are: use <c>\n</c> for a Unix server.</param>
    /// <param name="encoding">The encoding; UTF-8 when null.</param>
    public static SshCommandInput FromText(string text, Encoding? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new((encoding ?? Encoding.UTF8).GetBytes(text), null);
    }

    /// <summary>
    /// Input read from <paramref name="stream"/>, from its current position to its end, while the command runs: a large file is sent without
    /// being held in memory. The stream stays open (the caller disposes it), and since it is read once, this input is for one command.
    /// </summary>
    /// <param name="stream">A readable stream.</param>
    public static SshCommandInput FromStream(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The stream must be readable.", nameof(stream));
        }

        return new(default, stream);
    }

    /// <summary>Sends the input on the channel (not the end-of-file that follows it).</summary>
    internal async Task WriteToAsync(SshChannel channel, CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            await channel.SendDataAsync(_data, cancellationToken).ConfigureAwait(false);
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
        Instrumentation.Rented(buffer, nameof(WriteToAsync));
        try
        {
            int read;
            while ((read = await _stream.ReadAsync(buffer.AsMemory(0, StreamBufferSize), cancellationToken).ConfigureAwait(false)) > 0)
            {
                await channel.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            Instrumentation.Returning(buffer, nameof(WriteToAsync));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
