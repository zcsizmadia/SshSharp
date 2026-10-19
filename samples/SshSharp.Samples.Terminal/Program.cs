using System.Runtime.InteropServices;
using System.Text;
using SshSharp;

// A terminal client, as `ssh host` with no command: every key goes to the server as it is pressed (arrow keys, Ctrl+C, Tab, ...), the
// server's output goes to the console unchanged, and the remote terminal follows the console window's size.
//
//   dotnet run --project samples/SshSharp.Samples.Terminal -- <destination>
//
// <destination> is an ~/.ssh/config alias, user@host or ssh://user@host:port, connected through ssh_config (keys, the agent,
// known_hosts). A password, if the server asks for one, comes from SSHSHARP_PASSWORD. Run it in a terminal that understands VT
// sequences (any Unix terminal, Windows Terminal).
if (args.Length != 1 || Console.IsInputRedirected || Console.IsOutputRedirected)
{
    Console.Error.WriteLine("usage: <destination> (in an interactive terminal)");
    return 2;
}

using var stop = new CancellationTokenSource();
await using var client = await SshClient.ConnectAsync(args[0], new SshConfigConnectOptions
{
    Password = Environment.GetEnvironmentVariable("SSHSHARP_PASSWORD"),
}, stop.Token);

var size = (Columns: Console.WindowWidth, Rows: Console.WindowHeight);
await using var shell = await client.StartShellAsync(new SshSessionOptions
{
    Terminal = new SshTerminalOptions
    {
        TerminalType = Environment.GetEnvironmentVariable("TERM") is { Length: > 0 } term ? term : "xterm-256color",
        Columns = size.Columns,
        Rows = size.Rows,
    },
}, stop.Token);

// Ctrl+C is a key for the remote program, not a signal for this one.
Console.TreatControlCAsInput = true;

// The server's output, as it arrives. With a terminal the server sends standard error in it too, but copy both anyway.
var output = Task.WhenAll(
    shell.StandardOutput.CopyToAsync(Console.OpenStandardOutput(), stop.Token),
    shell.StandardError.CopyToAsync(Console.OpenStandardError(), stop.Token));

// Resizes: SIGWINCH tells a Unix process at once; Windows has no such signal, so the size is also checked twice a second.
using var resized = new SemaphoreSlim(0);
using var winch = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGWINCH, _ => resized.Release());
var resizing = FollowWindowSizeAsync(stop.Token);

// Keys: Console.ReadKey blocks, so it runs on a thread of its own. It is a console read, not network I/O. It is not awaited: when the
// shell exits, the thread is still waiting for a key, and the process ends without it.
_ = Task.Factory.StartNew(SendKeysAsync, stop.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();

await shell.WaitForExitAsync(CancellationToken.None);
await output;
await stop.CancelAsync();
await resizing;

Console.TreatControlCAsInput = false;
Console.Error.WriteLine();
Console.Error.WriteLine($"Connection closed (exit status {shell.ExitStatus?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none"}).");
return shell.ExitStatus ?? 255;

async Task FollowWindowSizeAsync(CancellationToken cancellationToken)
{
    try
    {
        while (true)
        {
            await resized.WaitAsync(TimeSpan.FromMilliseconds(500), cancellationToken);
            var now = (Columns: Console.WindowWidth, Rows: Console.WindowHeight);
            if (now != size && now.Columns > 0 && now.Rows > 0)
            {
                size = now;
                await shell.ResizeTerminalAsync(now.Columns, now.Rows, cancellationToken: cancellationToken);
            }
        }
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        // The shell has exited.
    }
    catch (SshException)
    {
        // The session closed between the check and the request: there is nothing left to resize.
    }
}

async Task SendKeysAsync()
{
    // Stateful, so a character outside the BMP, which arrives as two keys (a surrogate pair), is encoded as one UTF-8 sequence.
    var encoder = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetEncoder();
    var buffer = new byte[16];
    while (!stop.IsCancellationRequested)
    {
        var key = Console.ReadKey(intercept: true);
        var bytes = Encode(key, encoder, buffer);
        if (bytes.Length > 0)
        {
            await shell.StandardInput.WriteAsync(bytes, stop.Token);
            await shell.StandardInput.FlushAsync(stop.Token);
        }
    }
}

// What an xterm sends for a key: the character itself (UTF-8, with ESC in front for Alt), a control character, or an escape sequence.
static ReadOnlyMemory<byte> Encode(ConsoleKeyInfo key, Encoder encoder, byte[] buffer)
{
    var sequence = key.Key switch
    {
        ConsoleKey.UpArrow => "\e[A",
        ConsoleKey.DownArrow => "\e[B",
        ConsoleKey.RightArrow => "\e[C",
        ConsoleKey.LeftArrow => "\e[D",
        ConsoleKey.Home => "\e[H",
        ConsoleKey.End => "\e[F",
        ConsoleKey.Insert => "\e[2~",
        ConsoleKey.Delete => "\e[3~",
        ConsoleKey.PageUp => "\e[5~",
        ConsoleKey.PageDown => "\e[6~",
        ConsoleKey.F1 => "\eOP",
        ConsoleKey.F2 => "\eOQ",
        ConsoleKey.F3 => "\eOR",
        ConsoleKey.F4 => "\eOS",
        ConsoleKey.F5 => "\e[15~",
        ConsoleKey.F6 => "\e[17~",
        ConsoleKey.F7 => "\e[18~",
        ConsoleKey.F8 => "\e[19~",
        ConsoleKey.F9 => "\e[20~",
        ConsoleKey.F10 => "\e[21~",
        ConsoleKey.F11 => "\e[23~",
        ConsoleKey.F12 => "\e[24~",
        ConsoleKey.Tab when key.Modifiers.HasFlag(ConsoleModifiers.Shift) => "\e[Z",
        ConsoleKey.Backspace => "\x7f",
        ConsoleKey.Enter => "\r",
        _ => null,
    };
    if (sequence is not null)
    {
        return Encoding.ASCII.GetBytes(sequence);
    }

    var c = key.KeyChar;
    if (c == '\0' && key.Modifiers.HasFlag(ConsoleModifiers.Control) && key.Key is >= ConsoleKey.A and <= ConsoleKey.Z)
    {
        c = (char)(key.Key - ConsoleKey.A + 1); // Ctrl+A is 0x01, as a terminal sends it
    }

    if (c == '\0')
    {
        return ReadOnlyMemory<byte>.Empty; // a key with no character (Shift alone, a media key)
    }

    var offset = 0;
    if (key.Modifiers.HasFlag(ConsoleModifiers.Alt) && !char.IsSurrogate(c))
    {
        buffer[offset++] = 0x1b;
    }

    var written = encoder.GetBytes([c], buffer.AsSpan(offset), flush: false);
    return buffer.AsMemory(0, offset + written);
}
