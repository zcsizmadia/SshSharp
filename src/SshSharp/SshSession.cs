using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A shell or command running on the server (an SSH <c>session</c> channel), with its input and output as streams. Start one with
/// <see cref="SshClient.StartShellAsync"/> or <see cref="SshClient.StartCommandAsync"/>; dispose it to close the channel.
/// </summary>
/// <remarks>
/// Read <see cref="StandardOutput"/> and <see cref="StandardError"/> as the program produces them: output that is not read holds the
/// channel's receive window (2 MiB), and once it is full the server sends nothing more on either stream, as with redirected process
/// streams. With a terminal, the server merges stderr into stdout.
/// </remarks>
public sealed class SshSession : IAsyncDisposable
{
    private readonly SshChannel _channel;
    private readonly ILogger _logger;
    private readonly SshChannelWriteStream _input;
    private readonly SshChannelReadStream _output;
    private readonly SshChannelReadStream _error;
    private int _disposed;

    internal SshSession(SshChannel channel, bool hasTerminal, ILogger logger)
    {
        _channel = channel;
        _logger = logger;
        HasTerminal = hasTerminal;
        _input = new SshChannelWriteStream(channel);
        _output = new SshChannelReadStream(channel.ReadAsync);
        _error = new SshChannelReadStream(channel.ReadExtendedAsync);
    }

    /// <summary>The program's input. Writes are sent as they are made; <see cref="CloseInputAsync"/> (or disposing the stream) sends end-of-file.</summary>
    public Stream StandardInput => _input;

    /// <summary>The program's output (asynchronous reads only). Ends when the server sends end-of-file.</summary>
    public Stream StandardOutput => _output;

    /// <summary>The program's error output (asynchronous reads only). Empty with a terminal, where the server merges it into <see cref="StandardOutput"/>.</summary>
    public Stream StandardError => _error;

    /// <summary>Whether the session has a pseudo-terminal (<see cref="SshSessionOptions.Terminal"/>).</summary>
    public bool HasTerminal { get; }

    /// <summary>The program's exit status, once the server has reported it; null before that, or if it ended by a signal.</summary>
    public int? ExitStatus => _channel.ExitStatus is { } status ? (int)status : null;

    /// <summary>The name of the signal that ended the program (for example <c>KILL</c>), if any.</summary>
    public string? ExitSignal => _channel.ExitSignal;

    /// <summary>
    /// Completes when the server closes the session, after the program has ended and its output has been sent. Output that is never read
    /// can keep the server from finishing (see the remarks on <see cref="SshSession"/>).
    /// </summary>
    /// <exception cref="SshException">The connection failed.</exception>
    public Task WaitForExitAsync(CancellationToken cancellationToken = default) => _channel.WaitClosedAsync(cancellationToken);

    /// <summary>Sends end-of-file on <see cref="StandardInput"/>: the program sees the end of its input (a shell exits).</summary>
    public ValueTask CloseInputAsync(CancellationToken cancellationToken = default) => _input.CloseAsync(cancellationToken);

    /// <summary>Tells the server the terminal's new size (<c>window-change</c>), so full-screen programs redraw for it.</summary>
    /// <exception cref="InvalidOperationException">The session has no terminal.</exception>
    public async Task ResizeTerminalAsync(int columns, int rows, int widthPixels = 0, int heightPixels = 0, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (!HasTerminal)
        {
            throw new InvalidOperationException("The session has no terminal to resize.");
        }

        SshTerminalOptions.Validate(columns, rows, widthPixels, heightPixels);
        await _channel.RequestAsync("window-change", false, w =>
        {
            w.WriteUInt32((uint)columns);
            w.WriteUInt32((uint)rows);
            w.WriteUInt32((uint)widthPixels);
            w.WriteUInt32((uint)heightPixels);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a signal to the program (RFC 4254 section 6.9): a name without the <c>SIG</c> prefix, such as <c>INT</c>, <c>TERM</c> or
    /// <c>KILL</c>. Current OpenSSH delivers it; older versions and other servers may ignore it, since the request has no reply. With a
    /// terminal, writing Ctrl-C (<c>0x03</c>) to <see cref="StandardInput"/> interrupts the foreground program the way a user would.
    /// </summary>
    public async Task SendSignalAsync(string signal, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(signal);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (signal.StartsWith("SIG", StringComparison.Ordinal) || !signal.All(char.IsAsciiLetterOrDigit))
        {
            throw new ArgumentException("A signal is a name without the SIG prefix, such as INT, TERM or KILL.", nameof(signal));
        }

        await _channel.RequestAsync("signal", false, w => w.WriteString(signal), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes the session. A program still running gets a hangup from the server.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        await _output.DisposeAsync().ConfigureAwait(false);
        await _error.DisposeAsync().ConfigureAwait(false);
        _channel.DiscardUnread();
        SshLog.SessionClosed(_logger, _channel.LocalId, ExitStatus, ExitSignal);
    }
}
