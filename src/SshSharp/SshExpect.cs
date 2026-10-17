using System.Text;
using System.Text.RegularExpressions;

namespace SshSharp;

/// <summary>
/// Drives an interactive program, as <c>expect</c> does: wait until its output shows a prompt or other text, then send the next input.
/// Wrap a shell session (<see cref="SshClient.StartShellAsync"/>, usually with a terminal) and use <see cref="ExpectAsync(string, CancellationToken)"/>,
/// <see cref="ReadLineAsync"/> and <see cref="SendLineAsync"/>; timeouts are <see cref="CancellationToken"/>s.
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
/// <para>
/// Plain text is searched for only in the output that arrived since the last search (and the few characters before it), so waiting
/// costs time in proportion to the output. A regular expression is tried against all the pending output after each read, up to
/// <see cref="MaxBufferLength"/>: the program on the other side decides what that output is, so give patterns a
/// <see cref="Regex.MatchTimeout"/> (a <see cref="RegexMatchTimeoutException"/> then ends the wait) and keep
/// <see cref="MaxBufferLength"/> no larger than needed.
/// </para>
/// </remarks>
public sealed class SshExpect
{
    private readonly Stream _output;
    private readonly Stream _input;
    private readonly Decoder _decoder;
    private readonly byte[] _bytes = new byte[8192];
    private readonly char[] _chars;

    // The pending output is _buffer[_start.._length]: dropping old text moves _start (no copying); the buffer is compacted only when the
    // dropped part is at least as long as what is kept, so the work stays in proportion to the output.
    private char[] _buffer = new char[1024];
    private int _start;
    private int _length;

    // Where the last fruitless plain-text search ended: the next one starts there (less the text's length, for a match across reads).
    private int _searched;
    private bool _ended;

    // How many characters MaxBufferLength has made the buffer drop, so a line read can tell that it lost its start.
    private long _dropped;

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
    public string Pending => new(_buffer, _start, _length - _start);

    /// <summary>Waits until the output contains <paramref name="text"/> (an ordinal match).</summary>
    /// <param name="text">The text to wait for, for example a prompt.</param>
    /// <param name="cancellationToken">A timeout or cancellation.</param>
    /// <returns>The output before the match, and the match; both are consumed.</returns>
    /// <exception cref="EndOfStreamException">The output ended without the text appearing (<see cref="Pending"/> holds what came).</exception>
    /// <exception cref="OperationCanceledException">Cancelled; nothing is lost, and the output read so far stays in <see cref="Pending"/>.</exception>
    public Task<SshExpectMatch> ExpectAsync(string text, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        _searched = _start; // a new search: everything pending is new to it
        return ExpectCoreAsync(() =>
        {
            // Only what arrived since the last search, plus enough before it for a match that straddles two reads.
            var from = Math.Max(_start, _searched - (text.Length - 1));
            var index = _buffer.AsSpan(from, _length - from).IndexOf(text.AsSpan(), StringComparison.Ordinal);
            _searched = _length;
            return index < 0 ? null : (from + index - _start, text.Length, null);
        }, cancellationToken);
    }

    /// <summary>Waits until the output matches <paramref name="pattern"/>.</summary>
    /// <param name="pattern">The pattern to wait for, for example <c>new Regex(@"[$#] $")</c> for a shell prompt.</param>
    /// <param name="cancellationToken">A timeout or cancellation.</param>
    /// <returns>The output before the match, and the match with its groups; both are consumed.</returns>
    /// <exception cref="EndOfStreamException">The output ended without a match (<see cref="Pending"/> holds what came).</exception>
    /// <exception cref="OperationCanceledException">Cancelled; nothing is lost, and the output read so far stays in <see cref="Pending"/>.</exception>
    /// <exception cref="RegexMatchTimeoutException">Matching took longer than the pattern's <see cref="Regex.MatchTimeout"/>; the output stays
    /// in <see cref="Pending"/>.</exception>
    public Task<SshExpectMatch> ExpectAsync(Regex pattern, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        return ExpectCoreAsync(() =>
        {
            // Tested on the buffer itself; the string (for the match's groups) is made only once there is a match.
            bool any;
            try
            {
                any = pattern.IsMatch(_buffer.AsSpan(_start, _length - _start));
            }
            catch (NotSupportedException)
            {
                any = true; // a construct the span API does not take: let Match decide
            }

            if (!any)
            {
                return null;
            }

            var match = pattern.Match(Pending);
            return match.Success ? (match.Index, match.Length, match) : null;
        }, cancellationToken);
    }

    /// <summary>
    /// Reads the next line of output: the text up to the next line feed, without it or a carriage return before it (a terminal ends
    /// lines with <c>\r\n</c>). Once the output has ended, the text left without a line feed is the last line, and then null.
    /// </summary>
    /// <remarks>
    /// With a terminal, the program's output includes the echo of what was sent (a shell shows the command typed), and a prompt ends
    /// without a line feed, so a read that reaches a prompt waits for more: wait for a prompt with
    /// <see cref="ExpectAsync(string, CancellationToken)"/> instead. To run one command and read its output, <see cref="SshClient.RunCommandAsync"/>
    /// needs neither.
    /// </remarks>
    /// <param name="cancellationToken">A timeout or cancellation.</param>
    /// <returns>The line, or null when the output has ended and nothing is left.</returns>
    /// <exception cref="InvalidDataException">The line is longer than <see cref="MaxBufferLength"/>, so its start was dropped.</exception>
    /// <exception cref="OperationCanceledException">Cancelled; nothing is lost, and the partial line stays in <see cref="Pending"/>.</exception>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken = default)
    {
        var dropped = _dropped;
        _searched = _start; // a new search: everything pending is new to it
        while (true)
        {
            var from = Math.Max(_start, _searched);
            var index = _buffer.AsSpan(from, _length - from).IndexOf('\n');
            if (index >= 0)
            {
                var feed = from + index;
                var end = feed > _start && _buffer[feed - 1] == '\r' ? feed - 1 : feed;
                var line = new string(_buffer, _start, end - _start);
                _start = feed + 1;
                _searched = _start;
                return line;
            }

            _searched = _length;
            if (_ended)
            {
                if (_length == _start)
                {
                    return null;
                }

                var last = new string(_buffer, _start, _length - _start);
                _start = _searched = _length;
                return last;
            }

            await ReadMoreAsync(cancellationToken).ConfigureAwait(false);
            if (_dropped != dropped)
            {
                throw new InvalidDataException($"A line of output is longer than MaxBufferLength ({MaxBufferLength} characters); its start was dropped.");
            }
        }
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

    /// <summary><paramref name="find"/> returns the match's index relative to the pending output, or null to read more.</summary>
    private async Task<SshExpectMatch> ExpectCoreAsync(Func<(int Index, int Length, Match? Match)?> find, CancellationToken cancellationToken)
    {
        while (true)
        {
            if (find() is { } found)
            {
                var before = new string(_buffer, _start, found.Index);
                var value = new string(_buffer, _start + found.Index, found.Length);
                _start += found.Index + found.Length;
                _searched = _start;
                return new SshExpectMatch(before, value, found.Match);
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
        _ended = flush;
        Append(_chars.AsSpan(0, count));

        // Keep at most MaxBufferLength characters: the oldest go first.
        if (_length - _start > MaxBufferLength)
        {
            _dropped += _length - MaxBufferLength - _start;
            _start = _length - MaxBufferLength;
            _searched = Math.Max(_searched, _start);
        }
    }

    private void Append(ReadOnlySpan<char> chars)
    {
        if (_length + chars.Length > _buffer.Length)
        {
            // Compact (drop what is consumed) when that frees enough room; otherwise grow. Either way each character is moved O(1) times
            // on average.
            var kept = _length - _start;
            var target = _start >= kept && kept + chars.Length <= _buffer.Length
                ? _buffer
                : new char[Math.Max(_buffer.Length * 2, kept + chars.Length)];
            Array.Copy(_buffer, _start, target, 0, kept);
            _searched -= _start;
            _buffer = target;
            _start = 0;
            _length = kept;
        }

        chars.CopyTo(_buffer.AsSpan(_length));
        _length += chars.Length;
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
