using System.Buffers;
using System.IO.Pipelines;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>The identification string exchanged first on every connection (RFC 4253 section 4.2): <c>SSH-protoversion-softwareversion SP comments</c>.</summary>
internal sealed record SshIdentification(string ProtocolVersion, string SoftwareVersion, string? Comments)
{
    /// <summary>The longest identification line allowed, including the CR LF (RFC 4253 section 4.2).</summary>
    public const int MaxLength = 255;

    private const int MaxBannerLineLength = 4096;
    private const int MaxBannerLines = 256;

    /// <summary>The identification line without the CR LF terminator.</summary>
    public string Line => $"SSH-{ProtocolVersion}-{SoftwareVersion}" + (string.IsNullOrEmpty(Comments) ? string.Empty : " " + Comments);

    /// <summary>This library's identification.</summary>
    public static SshIdentification ForClient() => new("2.0", SshSharpInfo.SoftwareVersion, null);

    /// <summary>Parses an identification line (without CR LF). Only protocol versions 2.0 and 1.99 are accepted.</summary>
    public static bool TryParse(string line, out SshIdentification? identification)
    {
        identification = null;
        if (!line.StartsWith("SSH-", StringComparison.Ordinal) || line.Length + 2 > MaxLength)
        {
            return false;
        }

        var rest = line.AsSpan(4);
        var dash = rest.IndexOf('-');
        if (dash <= 0)
        {
            return false;
        }

        var protocol = rest[..dash].ToString();
        if (protocol is not ("2.0" or "1.99"))
        {
            return false;
        }

        rest = rest[(dash + 1)..];
        var space = rest.IndexOf(' ');
        var software = (space < 0 ? rest : rest[..space]).ToString();
        if (software.Length == 0 || software.Any(c => c < 0x21 || c > 0x7E))
        {
            return false;
        }

        identification = new SshIdentification(protocol, software, space < 0 ? null : rest[(space + 1)..].ToString());
        return true;
    }

    /// <summary>
    /// Reads the peer's identification, skipping any banner lines that precede it. Bytes after the identification line stay in the reader.
    /// </summary>
    public static async ValueTask<SshIdentification> ReadAsync(PipeReader reader, CancellationToken cancellationToken)
    {
        var bannerLines = 0;
        while (true)
        {
            var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            var buffer = result.Buffer;
            var newline = buffer.PositionOf((byte)'\n');
            if (newline is null)
            {
                if (buffer.Length > MaxBannerLineLength)
                {
                    throw new SshProtocolException("The server's identification line is too long.");
                }

                if (result.IsCompleted)
                {
                    throw new SshException(SshFailureReason.ConnectionClosed, "The connection closed before the server sent its identification.");
                }

                reader.AdvanceTo(buffer.Start, buffer.End);
                continue;
            }

            var lineSequence = buffer.Slice(0, newline.Value);
            var line = Encoding.UTF8.GetString(lineSequence).TrimEnd('\r');
            reader.AdvanceTo(buffer.GetPosition(1, newline.Value));

            if (line.StartsWith("SSH-", StringComparison.Ordinal))
            {
                return TryParse(line, out var id)
                    ? id!
                    : throw new SshException(SshFailureReason.ProtocolError, $"Unsupported or malformed server identification: '{Truncate(line)}'.");
            }

            if (++bannerLines > MaxBannerLines || line.Length > MaxBannerLineLength)
            {
                throw new SshProtocolException("The server sent too much text before its identification.");
            }
        }
    }

    /// <summary>Writes the identification line followed by CR LF.</summary>
    public void Write(IBufferWriter<byte> output)
    {
        var line = Line;
        if (line.Length + 2 > MaxLength)
        {
            throw new InvalidOperationException("The identification string is too long.");
        }

        var span = output.GetSpan(line.Length + 2);
        var count = Encoding.ASCII.GetBytes(line, span);
        span[count] = (byte)'\r';
        span[count + 1] = (byte)'\n';
        output.Advance(count + 2);
    }

    private static string Truncate(string text) => text.Length <= 80 ? text : text[..80] + "...";
}