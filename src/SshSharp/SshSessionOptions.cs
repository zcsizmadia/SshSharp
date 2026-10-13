namespace SshSharp;

/// <summary>Options for <see cref="SshClient.StartShellAsync"/> and <see cref="SshClient.StartCommandAsync"/>.</summary>
public sealed class SshSessionOptions
{
    /// <summary>A pseudo-terminal for the session (needed by interactive programs, editors, password prompts), or null for none.</summary>
    public SshTerminalOptions? Terminal { get; init; }

    /// <summary>
    /// Environment variables to set (<c>env</c> requests, like ssh's <c>SetEnv</c>). Servers accept only the names they allow (sshd's
    /// <c>AcceptEnv</c>) and silently drop the rest.
    /// </summary>
    public IReadOnlyDictionary<string, string> Environment { get; init; } = new Dictionary<string, string>();
}

/// <summary>A pseudo-terminal request (RFC 4254 section 6.2).</summary>
public sealed class SshTerminalOptions
{
    /// <summary>The terminal type, which becomes <c>TERM</c> on the server. Default <c>xterm-256color</c>.</summary>
    public string TerminalType { get; init; } = "xterm-256color";

    /// <summary>The width in characters. Default 80.</summary>
    public int Columns { get; init; } = 80;

    /// <summary>The height in lines. Default 24.</summary>
    public int Rows { get; init; } = 24;

    /// <summary>The width in pixels, or 0 if unknown (the default).</summary>
    public int WidthPixels { get; init; }

    /// <summary>The height in pixels, or 0 if unknown (the default).</summary>
    public int HeightPixels { get; init; }

    /// <summary>
    /// Terminal modes to set (RFC 4254 section 8), for example <c>{ [SshTerminalMode.ECHO] = 0 }</c> to turn off echo. Modes not listed
    /// keep the server's defaults.
    /// </summary>
    public IReadOnlyDictionary<SshTerminalMode, uint> Modes { get; init; } = new Dictionary<SshTerminalMode, uint>();

    internal void Validate()
    {
        if (string.IsNullOrEmpty(TerminalType) || TerminalType.Any(c => c <= ' ' || c > '~'))
        {
            throw new ArgumentException("The terminal type must be printable ASCII without spaces, such as xterm-256color.", nameof(TerminalType));
        }

        Validate(Columns, Rows, WidthPixels, HeightPixels);
        foreach (var mode in Modes.Keys)
        {
            if (!Enum.IsDefined(mode))
            {
                throw new ArgumentException($"Unknown terminal mode {(byte)mode}.", nameof(Modes));
            }
        }
    }

    internal static void Validate(int columns, int rows, int widthPixels, int heightPixels)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(columns);
        ArgumentOutOfRangeException.ThrowIfNegative(rows);
        ArgumentOutOfRangeException.ThrowIfNegative(widthPixels);
        ArgumentOutOfRangeException.ThrowIfNegative(heightPixels);
    }

    /// <summary>The encoded modes: each opcode with a uint32 argument, in opcode order, then <c>TTY_OP_END</c>.</summary>
    internal byte[] EncodeModes()
    {
        var encoded = new byte[(Modes.Count * 5) + 1];
        var offset = 0;
        foreach (var (mode, value) in Modes.OrderBy(m => (byte)m.Key))
        {
            encoded[offset] = (byte)mode;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset + 1), value);
            offset += 5;
        }

        encoded[offset] = 0; // TTY_OP_END
        return encoded;
    }
}

#pragma warning disable CA1707 // the POSIX names, as RFC 4254 lists them
/// <summary>Terminal mode opcodes (RFC 4254 section 8, and <c>IUTF8</c> from RFC 8160), named as in POSIX <c>termios</c>.</summary>
public enum SshTerminalMode : byte
{
    /// <summary>Interrupt character (usually Ctrl-C).</summary>
    VINTR = 1,

    /// <summary>Quit character (usually Ctrl-\).</summary>
    VQUIT = 2,

    /// <summary>Erase the character to the left of the cursor.</summary>
    VERASE = 3,

    /// <summary>Kill the current input line.</summary>
    VKILL = 4,

    /// <summary>End-of-file character (usually Ctrl-D).</summary>
    VEOF = 5,

    /// <summary>End-of-line character in addition to newline.</summary>
    VEOL = 6,

    /// <summary>Additional end-of-line character.</summary>
    VEOL2 = 7,

    /// <summary>Continue paused output (usually Ctrl-Q).</summary>
    VSTART = 8,

    /// <summary>Pause output (usually Ctrl-S).</summary>
    VSTOP = 9,

    /// <summary>Suspend the current program (usually Ctrl-Z).</summary>
    VSUSP = 10,

    /// <summary>Another suspend character.</summary>
    VDSUSP = 11,

    /// <summary>Reprint the current input line.</summary>
    VREPRINT = 12,

    /// <summary>Erase a word to the left of the cursor.</summary>
    VWERASE = 13,

    /// <summary>Enter the next character typed literally.</summary>
    VLNEXT = 14,

    /// <summary>Character to flush output.</summary>
    VFLUSH = 15,

    /// <summary>Switch to a different shell layer.</summary>
    VSWTCH = 16,

    /// <summary>Print system status line.</summary>
    VSTATUS = 17,

    /// <summary>Toggle flushing of terminal output.</summary>
    VDISCARD = 18,

    /// <summary>Ignore parity errors (0 or 1).</summary>
    IGNPAR = 30,

    /// <summary>Mark parity and framing errors.</summary>
    PARMRK = 31,

    /// <summary>Enable checking of parity errors.</summary>
    INPCK = 32,

    /// <summary>Strip the eighth bit of characters.</summary>
    ISTRIP = 33,

    /// <summary>Map newline to carriage return on input.</summary>
    INLCR = 34,

    /// <summary>Ignore carriage return on input.</summary>
    IGNCR = 35,

    /// <summary>Map carriage return to newline on input.</summary>
    ICRNL = 36,

    /// <summary>Translate uppercase characters to lowercase.</summary>
    IUCLC = 37,

    /// <summary>Enable output flow control.</summary>
    IXON = 38,

    /// <summary>Any character restarts paused output.</summary>
    IXANY = 39,

    /// <summary>Enable input flow control.</summary>
    IXOFF = 40,

    /// <summary>Ring the bell when the input queue is full.</summary>
    IMAXBEL = 41,

    /// <summary>The terminal input and output are UTF-8 (RFC 8160).</summary>
    IUTF8 = 42,

    /// <summary>Enable the interrupt, quit and suspend characters.</summary>
    ISIG = 50,

    /// <summary>Canonical (line-by-line) input.</summary>
    ICANON = 51,

    /// <summary>Uppercase-only terminal handling.</summary>
    XCASE = 52,

    /// <summary>Echo input characters.</summary>
    ECHO = 53,

    /// <summary>Visually erase characters.</summary>
    ECHOE = 54,

    /// <summary>Kill character discards the current line.</summary>
    ECHOK = 55,

    /// <summary>Echo newline even when echo is off.</summary>
    ECHONL = 56,

    /// <summary>Do not flush after interrupt.</summary>
    NOFLSH = 57,

    /// <summary>Stop background jobs that write to the terminal.</summary>
    TOSTOP = 58,

    /// <summary>Enable extensions.</summary>
    IEXTEN = 59,

    /// <summary>Echo control characters as ^X.</summary>
    ECHOCTL = 60,

    /// <summary>Visual erase for line kill.</summary>
    ECHOKE = 61,

    /// <summary>Retype pending input.</summary>
    PENDIN = 62,

    /// <summary>Enable output processing.</summary>
    OPOST = 70,

    /// <summary>Convert lowercase to uppercase on output.</summary>
    OLCUC = 71,

    /// <summary>Map newline to carriage return and newline on output.</summary>
    ONLCR = 72,

    /// <summary>Translate carriage return to newline on output.</summary>
    OCRNL = 73,

    /// <summary>Do not output carriage return at column 0.</summary>
    ONOCR = 74,

    /// <summary>Newline performs a carriage return.</summary>
    ONLRET = 75,

    /// <summary>7-bit characters.</summary>
    CS7 = 90,

    /// <summary>8-bit characters.</summary>
    CS8 = 91,

    /// <summary>Parity enable.</summary>
    PARENB = 92,

    /// <summary>Odd parity (else even).</summary>
    PARODD = 93,

    /// <summary>Input speed in bits per second.</summary>
    TTY_OP_ISPEED = 128,

    /// <summary>Output speed in bits per second.</summary>
    TTY_OP_OSPEED = 129,
}
#pragma warning restore CA1707
