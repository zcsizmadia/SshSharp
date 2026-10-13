using System.Globalization;
using System.Text;

namespace SshSharp.Scp;

/// <summary>
/// One run of the remote scp program in sink (<c>-t</c>) or source (<c>-f</c>) mode, and the protocol's framing over its standard
/// streams: control lines (<c>C</c>, <c>D</c>, <c>E</c>, <c>T</c>), acknowledgements (0, or 1/2 with a message), and file data.
/// </summary>
internal sealed class ScpChannel : IAsyncDisposable
{
    private const int MaxLine = 64 * 1024;
    private const int MaxError = 64 * 1024;

    private readonly SshSession _session;
    private readonly Task<string> _errors;
    private readonly byte[] _buffer = new byte[64 * 1024];
    private int _position;
    private int _length;

    private ScpChannel(SshSession session)
    {
        _session = session;
        _errors = ReadErrorsAsync(session.StandardError);
    }

    /// <summary>Starts <c>scp {flags} -- {path}</c> on the server, with the path quoted for its shell.</summary>
    public static async Task<ScpChannel> StartAsync(SshClient client, SshScpOptions options, string flags, string path, CancellationToken cancellationToken)
    {
        var command = $"{options.ScpCommand} {flags}{(options.PreserveTimes ? " -p" : "")} -- {QuoteForShell(path)}";
        var session = await client.StartCommandAsync(command, cancellationToken: cancellationToken).ConfigureAwait(false);
        return new ScpChannel(session);
    }

    /// <summary>A POSIX shell word for <paramref name="path"/>: single-quoted, with embedded quotes as <c>'\''</c>.</summary>
    internal static string QuoteForShell(string path)
    {
        if (path.Length == 0 || path.Any(c => c is '\0' or '\n' or '\r'))
        {
            throw new ArgumentException("A remote path must be non-empty, without NUL or line breaks.", nameof(path));
        }

        return "'" + path.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    // ---- reading ----

    /// <summary>The next byte from the remote scp, or -1 at the end of its output.</summary>
    public async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (_position == _length && !await FillAsync(cancellationToken).ConfigureAwait(false))
        {
            return -1;
        }

        return _buffer[_position++];
    }

    /// <summary>A control line or message, up to the newline (not included).</summary>
    public async ValueTask<string> ReadLineAsync(CancellationToken cancellationToken)
    {
        var line = new List<byte>();
        while (true)
        {
            var b = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (b == -1)
            {
                throw await FailureAsync("The remote scp ended in the middle of a line.").ConfigureAwait(false);
            }

            if (b == '\n')
            {
                return Encoding.UTF8.GetString([.. line]);
            }

            if (line.Count == MaxLine)
            {
                throw await FailureAsync("The remote scp sent an overlong line.").ConfigureAwait(false);
            }

            line.Add((byte)b);
        }
    }

    /// <summary>Waits for the remote side's acknowledgement: 0, or an error (1 or 2 and a message), which is thrown.</summary>
    public async ValueTask ReadAckAsync(CancellationToken cancellationToken)
    {
        var b = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
        switch (b)
        {
            case 0:
                return;
            case 1 or 2:
                throw new SshException(SshFailureReason.TransferFailed, (await ReadLineAsync(cancellationToken).ConfigureAwait(false)).Trim());
            case -1:
                throw await FailureAsync("The remote scp ended without answering.").ConfigureAwait(false);
            default:
                throw await FailureAsync($"The remote scp answered with byte {b} instead of an acknowledgement.").ConfigureAwait(false);
        }
    }

    /// <summary>Copies exactly <paramref name="count"/> bytes of file data to <paramref name="destination"/>.</summary>
    public async Task ReadDataAsync(Stream destination, long count, Action<long> progress, CancellationToken cancellationToken)
    {
        long done = 0;
        while (done < count)
        {
            if (_position == _length && !await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                throw await FailureAsync($"The remote scp ended after {done} of {count} bytes.").ConfigureAwait(false);
            }

            var take = (int)Math.Min(_length - _position, count - done);
            await destination.WriteAsync(_buffer.AsMemory(_position, take), cancellationToken).ConfigureAwait(false);
            _position += take;
            done += take;
            progress(done);
        }
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        _position = 0;
        _length = await _session.StandardOutput.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
        return _length > 0;
    }

    // ---- writing ----

    public Task SendLineAsync(string line, CancellationToken cancellationToken) => WriteAsync(Encoding.UTF8.GetBytes(line + "\n"), cancellationToken);

    public Task SendAckAsync(CancellationToken cancellationToken) => WriteAsync(new byte[] { 0 }, cancellationToken);

    /// <summary>Writes to the remote scp's input; one that has already gone away is a transfer error, with its own message if it left one.</summary>
    private async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        try
        {
            await _session.StandardInput.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            throw await FailureAsync("The remote scp closed the connection.").ConfigureAwait(false);
        }
    }

    /// <summary>Sends exactly <paramref name="count"/> bytes of <paramref name="source"/>, then the end-of-data byte.</summary>
    public async Task SendDataAsync(Stream source, long count, Action<long> progress, CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        long done = 0;
        while (done < count)
        {
            var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, count - done)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException($"The source ended after {done} of {count} bytes.");
            }

            await WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            done += read;
            progress(done);
        }

        await SendAckAsync(cancellationToken).ConfigureAwait(false);
    }

    // ---- ending ----

    /// <summary>Ends the input, waits for the remote scp to exit, and throws when it failed.</summary>
    public async Task FinishAsync(CancellationToken cancellationToken)
    {
        await _session.CloseInputAsync(cancellationToken).ConfigureAwait(false);
        while (await ReadByteAsync(cancellationToken).ConfigureAwait(false) != -1)
        {
            // Nothing more is expected; drain to the end so the program can finish.
        }

        await _session.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (_session.ExitStatus is not 0)
        {
            throw await FailureAsync($"The remote scp failed (exit status {_session.ExitStatus?.ToString(CultureInfo.InvariantCulture) ?? _session.ExitSignal ?? "unknown"}).").ConfigureAwait(false);
        }
    }

    /// <summary>A transfer error carrying what the remote scp wrote to stderr, if anything.</summary>
    internal async Task<SshException> FailureAsync(string message)
    {
        // The program's own message (No such file or directory, Permission denied) usually explains it; give it a moment to arrive.
        await Task.WhenAny(_errors, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
        var errors = _errors.IsCompleted ? await _errors.ConfigureAwait(false) : string.Empty;
        return new SshException(SshFailureReason.TransferFailed, errors.Length > 0 ? $"{message} {errors.Trim()}" : message);
    }

    private static async Task<string> ReadErrorsAsync(Stream errors)
    {
        // Drained to the end whatever it holds (unread stderr would hold the channel window), keeping the first 64 KiB.
        var kept = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            while (await errors.ReadAsync(buffer).ConfigureAwait(false) is var read and > 0)
            {
                kept.Write(buffer, 0, (int)Math.Min(read, Math.Max(0, MaxError - kept.Length)));
            }
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException)
        {
            // The session ended.
        }

        return Encoding.UTF8.GetString(kept.ToArray());
    }

    public async ValueTask DisposeAsync() => await _session.DisposeAsync().ConfigureAwait(false);
}
