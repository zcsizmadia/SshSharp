using System.Buffers;
using System.Globalization;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Scp;

/// <summary>
/// One run of the remote scp program in sink (<c>-t</c>) or source (<c>-f</c>) mode, and the protocol's framing over its standard
/// streams: control lines (<c>C</c>, <c>D</c>, <c>E</c>, <c>T</c>), acknowledgements (0, or 1/2 with a message), and file data.
/// </summary>
internal sealed class ScpChannel : IAsyncDisposable
{
    private const int MaxLine = 64 * 1024;
    private const int MaxError = 64 * 1024;

    private const int BufferSize = 64 * 1024;
    private const int ErrorReadSize = 4096;

    private static readonly byte[] Ack = [0];

    private readonly SshSession _session;
    private readonly ArrayPool<byte> _pool;
    private readonly Task<string> _errors;

    // The read buffer, rented for the run and returned on disposal (null after that, so nothing can use it once it is back in the pool).
    private byte[]? _buffer;
    private int _position;
    private int _length;

    /// <summary>File data moved so far, in either direction, for the transfer's span.</summary>
    public long Bytes { get; private set; }

    /// <summary>Files whose data has been sent or received in full.</summary>
    public int Files { get; private set; }

    /// <summary>Directories sent or entered below the top one of a recursive transfer (counted by the caller, which knows the tree).</summary>
    public int Directories { get; private set; }

    public void CountDirectory() => Directories++;

    /// <summary>What the transfer moved, for its span.</summary>
    public ScpTransferred Transferred => new(Bytes, Files, Directories);

    private ScpChannel(SshSession session, ArrayPool<byte> pool)
    {
        _session = session;
        _pool = pool;
        _buffer = pool.Rent(BufferSize);
        Instrumentation.Rented(_buffer, nameof(ScpChannel));
        _errors = ReadErrorsAsync(session.StandardError, pool);
    }

    /// <summary>
    /// Starts <c>scp {flags} -- {path}</c> on the server, with the path written as <see cref="SshScpOptions.PathQuoting"/> says. A path
    /// that mode cannot carry is refused before anything is sent.
    /// </summary>
    /// <param name="client">The connected client.</param>
    /// <param name="options">The transfer's options.</param>
    /// <param name="flags">The scp mode and flags.</param>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels starting the program.</param>
    /// <param name="pool">Where the transfer buffers come from: <see cref="ArrayPool{T}.Shared"/>, or a test's pool that checks their use.</param>
    public static async Task<ScpChannel> StartAsync(SshClient client, SshScpOptions options, string flags, string path, CancellationToken cancellationToken,
        ArrayPool<byte>? pool = null)
    {
        var command = CommandLine(options, flags, path);
        var session = await client.StartCommandAsync(command, cancellationToken: cancellationToken).ConfigureAwait(false);
        return new ScpChannel(session, pool ?? ArrayPool<byte>.Shared);
    }

    private byte[] Buffer => _buffer ?? throw new ObjectDisposedException(nameof(ScpChannel));

    /// <summary>The command line that runs the remote scp: <c>scp {flags} [-p] -- {path}</c>, with the path written as the options say.</summary>
    internal static string CommandLine(SshScpOptions options, string flags, string path)
    {
        var preserve = options.Preserve ? " -p" : "";
        return options.PathQuoting switch
        {
            SshScpPathQuoting.Posix => $"{options.ScpCommand} {flags}{preserve} -- {QuoteForShell(path)}",

            // Devices parse the line themselves and may take "--" for the path, so it is left out; CheckUnquoted refuses a leading "-".
            SshScpPathQuoting.None => $"{options.ScpCommand} {flags}{preserve} {CheckUnquoted(path)}",
            SshScpPathQuoting.DoubleQuote => $"{options.ScpCommand} {flags}{preserve} -- {QuoteForCmd(path)}",
            _ => throw new ArgumentOutOfRangeException(nameof(options), options.PathQuoting, "Unknown SshScpPathQuoting value."),
        };
    }

    /// <summary>A POSIX shell word for <paramref name="remotePath"/>: single-quoted, with embedded quotes as <c>'\''</c>.</summary>
    internal static string QuoteForShell(string remotePath)
    {
        if (remotePath.Length == 0 || remotePath.Any(c => c is '\0' or '\n' or '\r'))
        {
            throw new ArgumentException("A remote path must be non-empty, without NUL or line breaks.", nameof(remotePath));
        }

        return "'" + remotePath.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    /// <summary>
    /// <paramref name="remotePath"/> unchanged, for <see cref="SshScpPathQuoting.None"/>, once it is known to be one word that no shell or
    /// device reads specially: letters, digits and <c>/ . _ - : + @ =</c>, not starting with <c>-</c>, <c>=</c> or <c>@</c>.
    /// </summary>
    internal static string CheckUnquoted(string remotePath)
    {
        RefuseEmptyOrControl(remotePath);
        if (remotePath[0] is '-' or '=' or '@')
        {
            // '-' would be read as an option; zsh and tcsh expand a leading '=' (to a command's path, or a directory-stack entry), and
            // PowerShell splats a leading '@name'.
            throw new ArgumentException($"A remote path sent without quoting must not start with '{remotePath[0]}'.", nameof(remotePath));
        }

        foreach (var c in remotePath)
        {
            // An allow list rather than a list of what to refuse: whatever reads the line (a device's parser, or a shell if the server
            // turns out to have one) treats none of these specially, so the path stays one word that names a file and nothing else.
            // No ',': PowerShell splits a word there into several arguments.
            if (!char.IsLetterOrDigit(c) && c is not ('/' or '.' or '_' or '-' or ':' or '+' or '@' or '='))
            {
                throw new ArgumentException(
                    $"A remote path sent without quoting may hold only letters, digits and / . _ - : + @ = (it has {Describe(c)}).", nameof(remotePath));
            }
        }

        return remotePath;
    }

    /// <summary>
    /// A double-quoted word for <paramref name="remotePath"/>, for <see cref="SshScpPathQuoting.DoubleQuote"/>: Windows OpenSSH runs the line
    /// as <c>cmd.exe /c "line"</c> (or <c>powershell -c line</c>), and scp.exe splits its command line by the C runtime's rules.
    /// </summary>
    internal static string QuoteForCmd(string remotePath)
    {
        RefuseEmptyOrControl(remotePath);
        if (remotePath[0] == '-')
        {
            // The '--' before the path keeps scp.exe from reading it as an option, but only if the shell passes '--' on; not every
            // PowerShell version is known to, and no Windows path starts with '-' anyway.
            throw new ArgumentException("A double-quoted remote path must not start with '-'.", nameof(remotePath));
        }

        foreach (var c in remotePath)
        {
            // cmd.exe expands %name% (and !name! with delayed expansion) even inside double quotes, and PowerShell expands $ and `
            // there and also ends the string at its typographic quotes. Without these, and without any '"' (which no Windows name
            // has), the quoted word is literal to both shells, so & | < > ^ ( ) ; and spaces in it cannot run anything.
            if (c is '"' or '%' or '!' or '$' or '`' or '\u201C' or '\u201D' or '\u201E' or '<' or '>' or '|' or '*' or '?')
            {
                throw new ArgumentException($"A double-quoted remote path must not hold {Describe(c)}.", nameof(remotePath));
            }
        }

        // The C runtime reads \" as a literal quote, so a trailing backslash would swallow the closing quote and join the path with
        // whatever followed it.
        if (remotePath[^1] == '\\')
        {
            throw new ArgumentException(@"A double-quoted remote path must not end with '\': write C:\dir or C:/dir/ instead.", nameof(remotePath));
        }

        return "\"" + remotePath + "\"";
    }

    private static void RefuseEmptyOrControl(string remotePath)
    {
        if (remotePath.Length == 0)
        {
            throw new ArgumentException("A remote path must be non-empty.", nameof(remotePath));
        }

        foreach (var c in remotePath)
        {
            if (char.IsControl(c) || c is '\u2028' or '\u2029')
            {
                throw new ArgumentException($"A remote path must not hold control characters (it has {Describe(c)}).", nameof(remotePath));
            }
        }
    }

    /// <summary>Names a refused character by its code point, so the message shows it even when it is invisible or a quote.</summary>
    private static string Describe(char c) =>
        char.IsControl(c) || char.IsWhiteSpace(c) || char.IsSurrogate(c)
            ? $"U+{(int)c:X4}"
            : $"'{c}' (U+{(int)c:X4})";

    // ---- reading ----

    /// <summary>The next byte from the remote scp, or -1 at the end of its output.</summary>
    public async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (_position == _length && !await FillAsync(cancellationToken).ConfigureAwait(false))
        {
            return -1;
        }

        return Buffer[_position++];
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
                throw new SshException(SshFailureReason.TransferFailed, ServerText.Clean(await ReadLineAsync(cancellationToken).ConfigureAwait(false)));
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
            await destination.WriteAsync(Buffer.AsMemory(_position, take), cancellationToken).ConfigureAwait(false);
            _position += take;
            done += take;
            Bytes += take;
            SshTelemetry.ScpBytes.Add(take, SshTelemetry.ScpDownload);
            progress(done);
        }

        Files++;
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        _position = 0;
        _length = 0;
        var buffer = Buffer;
        _length = await _session.StandardOutput.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false);
        return _length > 0;
    }

    // ---- writing ----

    public Task SendLineAsync(string line, CancellationToken cancellationToken) => WriteAsync(Encoding.UTF8.GetBytes(line + "\n"), cancellationToken);

    public Task SendAckAsync(CancellationToken cancellationToken) => WriteAsync(Ack, cancellationToken);

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
        // Returned when this file is done, failed or cancelled. Every write has completed by then (the channel copies the data into the
        // packet before a write completes, even a cancelled one), so the buffer is not read after it is back in the pool.
        var buffer = _pool.Rent(BufferSize);
        Instrumentation.Rented(buffer, nameof(SendDataAsync));
        try
        {
            long done = 0;
            while (done < count)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(BufferSize, count - done)), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new IOException($"The source ended after {done} of {count} bytes.");
                }

                await WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                done += read;
                Bytes += read;
                SshTelemetry.ScpBytes.Add(read, SshTelemetry.ScpUpload);
                progress(done);
            }

            Files++;
        }
        finally
        {
            Instrumentation.Returning(buffer, nameof(SendDataAsync));
            _pool.Return(buffer);
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
            throw await FailureAsync($"The remote scp failed (exit status {_session.ExitStatus?.ToString(CultureInfo.InvariantCulture) ?? _session.ExitSignal?.Name ?? "unknown"}).").ConfigureAwait(false);
        }
    }

    /// <summary>A transfer error carrying what the remote scp wrote to stderr, if anything.</summary>
    internal async Task<SshException> FailureAsync(string message)
    {
        // The program's own message (No such file or directory, Permission denied) usually explains it; give it a moment to arrive.
        // As a plain Task: SuppressThrowing is not allowed on a Task<T>, and the timeout must not throw.
        Task errorsRead = _errors;
        await errorsRead.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        var errors = _errors.IsCompletedSuccessfully ? _errors.Result : string.Empty;
        // What the remote scp wrote to stderr is its own text: cleaned, and longer than a status line may be.
        var said = ServerText.Clean(errors, 1000);
        return new SshException(SshFailureReason.TransferFailed, said.Length > 0 ? $"{message} {said}" : message);
    }

    private static async Task<string> ReadErrorsAsync(Stream errors, ArrayPool<byte> pool)
    {
        // Drained to the end whatever it holds (unread stderr would hold the channel window), keeping the first 64 KiB. Usually there is
        // nothing, so the copy kept is made only when something arrives. The read buffer is this task's own, returned when it ends.
        MemoryStream? kept = null;
        var buffer = pool.Rent(ErrorReadSize);
        Instrumentation.Rented(buffer, nameof(ReadErrorsAsync));
        try
        {
            while (await errors.ReadAsync(buffer.AsMemory(0, ErrorReadSize)).ConfigureAwait(false) is var read and > 0)
            {
                kept ??= new MemoryStream();
                kept.Write(buffer, 0, (int)Math.Min(read, Math.Max(0, MaxError - kept.Length)));
            }
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException)
        {
            // The session ended.
        }
        finally
        {
            Instrumentation.Returning(buffer, nameof(ReadErrorsAsync));
            pool.Return(buffer);
        }

        if (kept is null)
        {
            return string.Empty;
        }

        using (kept)
        {
            return Encoding.UTF8.GetString(kept.GetBuffer(), 0, (int)kept.Length);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _session.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            // Once, after the session: nothing reads into the buffer any more, and later use throws ObjectDisposedException.
            if (Interlocked.Exchange(ref _buffer, null) is { } buffer)
            {
                Instrumentation.Returning(buffer, nameof(ScpChannel));
                _pool.Return(buffer);
            }
        }
    }
}

/// <summary>What one SCP transfer moved: file data bytes, files, and directories below the top one.</summary>
internal readonly record struct ScpTransferred(long Bytes, int Files, int Directories);
