using System.Text;
using System.Text.RegularExpressions;

namespace SshSharp;

/// <summary>
/// Drives an interactive program, as <c>expect</c> does: wait until its output shows a prompt or other text, then send the next input.
/// Wrap a shell session (<see cref="SshClient.StartShellAsync"/>, usually with a terminal) and use <see cref="ExpectAsync(string, CancellationToken)"/>
/// and <see cref="SendLineAsync"/>; timeouts are <see cref="CancellationToken"/>s.
/// </summary>
/// <remarks>
/// <para>
/// This reads the output stream itself: do not read it elsewhere while using this. Output is decoded with <see cref="Encoding"/>, and a
/// character split across two reads is decoded whole; invalid bytes become U+FFFD and are never dropped silently. Text after a match
/// stays buffered for the next call. Without a terminal, standard error is a separate stream and is not searched.
/// </para>
/// <para>
/// A regular expression is tried against the output received so far, so a pattern that could also match a shorter prefix (<c>\d+</c>
/// against a number still arriving) may match early; anchor patterns to what follows them, such as a prompt's trailing <c>$ </c>.
/// </para>
/// </remarks>
public sealed class SshExpect
{
    private readonly Stream _output;
    private readonly Stream _input;
    private readonly Decoder _decoder;
    private readonly byte[] _bytes = new byte[8192];
    private readonly char[] _chars;
    private readonly StringBuilder _pending = new();
    private bool _ended;

    /// <summary>Drives <paramref name="session"/>: reads its standard output, writes its standard input.</summary>
    /// <param name="session">The session, for example a shell started with a terminal.</param>
    /// <param name="encoding">How the program's output and input are encoded; UTF-8 by default.</param>
    public SshExpect(SshSession session, Encoding? encoding = null)
        : this((session ?? throw new ArgumentNullException(nameof(session))).StandardOutput, session.StandardInput, encoding)
    {
    }

    /// <summary>Drives a program through its output and input streams.</summary>
    /// <param name="output">What the program writes: searched by <see cref="ExpectAsync(string, CancellationToken)"/>.</param>
    /// <param name="input">Where <see cref="SendAsync"/> and <see cref="SendLineAsync"/> write.</param>
    /// <param name="encoding">How the program's output and input are encoded; UTF-8 by default.</param>
    public SshExpect(Stream output, Stream input, Encoding? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(input);
        _output = output;
        _input = input;
        Encoding = encoding ?? new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        _decoder = Encoding.GetDecoder(); // replacement fallback by default: invalid bytes become U+FFFD
        _chars = new char[Encoding.GetMaxCharCount(_bytes.Length)];
    }

    /// <summary>The encoding of the program's output and input.</summary>
    public Encoding Encoding { get; }

    /// <summary>What <see cref="SendLineAsync"/> ends a line with: <c>\n</c> by default (a terminal turns it into what the program expects).</summary>
    public string NewLine { get; init; } = "\n";

    /// <summary>
    /// The most output kept while waiting for a match, in characters (1 MiB by default). When more arrives without a match, the oldest
    /// text is dropped, so a program that prints a lot without the expected text cannot exhaust memory.
    /// </summary>
    public int MaxBufferLength
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            field = value;
        }
    } = 1 << 20;

    /// <summary>Output received but not yet consumed by a match.</summary>
    public string Pending => _pending.ToString();

    /// <summary>Waits until the output contains <paramref name="text"/> (an ordinal match).</summary>
    /// <param name="text">The text to wait for, for example a prompt.</param>
    /// <param name="cancellationToken">A timeout or cancellation.</param>
    /// <returns>The output before the match, and the match; both are consumed.</returns>
    /// <exception cref="EndOfStreamException">The output ended without the text appearing (<see cref="Pending"/> holds what came).</exception>
    /// <exception cref="OperationCanceledException">Cancelled; nothing is lost, and the output read so far stays in <see cref="Pending"/>.</exception>
    public Task<SshExpectMatch> ExpectAsync(string text, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        return ExpectCoreAsync(pending =>
        {
            var index = pending.IndexOf(text, StringComparison.Ordinal);
            return index < 0 ? null : (index, text.Length, null);
        }, cancellationToken);
    }

    /// <summary>Waits until the output matches <paramref name="pattern"/>.</summary>
    /// <param name="pattern">The pattern to wait for, for example <c>new Regex(@"[$#] $")</c> for a shell prompt.</param>
    /// <param name="cancellationToken">A timeout or cancellation.</param>
    /// <returns>The output before the match, and the match with its groups; both are consumed.</returns>
    /// <exception cref="EndOfStreamException">The output ended without a match (<see cref="Pending"/> holds what came).</exception>
    /// <exception cref="OperationCanceledException">Cancelled; nothing is lost, and the output read so far stays in <see cref="Pending"/>.</exception>
    public Task<SshExpectMatch> ExpectAsync(Regex pattern, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        return ExpectCoreAsync(pending =>
        {
            var match = pattern.Match(pending);
            return match.Success ? (match.Index, match.Length, match) : null;
        }, cancellationToken);
    }

    /// <summary>Sends <paramref name="text"/> to the program as it is.</summary>
    public async Task SendAsync(string text, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        await _input.WriteAsync(Encoding.GetBytes(text), cancellationToken).ConfigureAwait(false);
        await _input.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends <paramref name="line"/> followed by <see cref="NewLine"/>, as typing it and pressing Enter does.</summary>
    public Task SendLineAsync(string line, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(line);
        return SendAsync(line + NewLine, cancellationToken);
    }

    private async Task<SshExpectMatch> ExpectCoreAsync(Func<string, (int Index, int Length, Match? Match)?> find, CancellationToken cancellationToken)
    {
        while (true)
        {
            var pending = _pending.ToString();
            if (find(pending) is { } found)
            {
                _pending.Remove(0, found.Index + found.Length);
                return new SshExpectMatch(pending[..found.Index], pending.Substring(found.Index, found.Length), found.Match);
            }

            if (_ended)
            {
                throw new EndOfStreamException("The output ended before the expected text appeared.");
            }

            await ReadMoreAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads one chunk of output into the buffer (decoded), or notes the end of the output.</summary>
    private async Task ReadMoreAsync(CancellationToken cancellationToken)
    {
        var read = await _output.ReadAsync(_bytes, cancellationToken).ConfigureAwait(false);
        var flush = read == 0;
        var count = _decoder.GetChars(_bytes, 0, read, _chars, 0, flush); // keeps a split character's first bytes for the next read
        _pending.Append(_chars, 0, count);
        _ended = flush;
        if (_pending.Length > MaxBufferLength)
        {
            _pending.Remove(0, _pending.Length - MaxBufferLength);
        }
    }
}

/// <summary>A match found by <see cref="SshExpect"/>.</summary>
public sealed class SshExpectMatch
{
    internal SshExpectMatch(string before, string value, Match? match)
    {
        Before = before;
        Value = value;
        Match = match;
    }

    /// <summary>The output before the match.</summary>
    public string Before { get; }

    /// <summary>The matched text.</summary>
    public string Value { get; }

    /// <summary>The regular expression match with its groups, when a <see cref="Regex"/> was used; null for plain text.</summary>
    public Match? Match { get; }
}
