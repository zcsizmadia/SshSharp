# Commands and shells

## Run a command and collect its output

```csharp
var result = await client.RunCommandAsync("df -h /");
Console.WriteLine(result.ExitStatus);          // null if the command was killed by a signal (see ExitSignal)
Console.WriteLine(result.StandardOutputText);
Console.Error.WriteLine(result.StandardErrorText);
```

Output is collected in memory, up to `SshClientOptions.MaxCommandOutputBytes` (128 MiB by default). The command text is a
shell command line on the server: quote untrusted input.

## Stream a command's input and output

`StartCommandAsync` returns an `SshSession` with the program's standard streams. Read output as it arrives, and write input.

```csharp
await using var session = await client.StartCommandAsync("gzip -c > backup.gz");
await using (var file = File.OpenRead("backup.tar"))
{
    await file.CopyToAsync(session.StandardInput);
}

await session.CloseInputAsync();     // end of input: gzip finishes
await session.WaitForExitAsync();
Console.WriteLine(session.ExitStatus);
```

Read `StandardOutput` and `StandardError` while the program runs: output nobody reads fills the channel window (2 MiB),
and then the server sends nothing more on either stream, as with redirected process streams.

```csharp
await using var session = await client.StartCommandAsync("make test");
var output = Task.Run(async () =>
{
    using var reader = new StreamReader(session.StandardOutput);
    while (await reader.ReadLineAsync() is { } line)
    {
        Console.WriteLine(line);
    }
});
var errors = new StreamReader(session.StandardError).ReadToEndAsync();
await output;
Console.Error.Write(await errors);
await session.WaitForExitAsync();
```

## Interactive shell with a terminal

```csharp
var options = new SshSessionOptions
{
    Terminal = new SshTerminalOptions
    {
        TerminalType = "xterm-256color",
        Columns = Console.WindowWidth,
        Rows = Console.WindowHeight,
        Modes = new Dictionary<SshTerminalMode, uint> { [SshTerminalMode.ECHO] = 1 },
    },
    Environment = new Dictionary<string, string> { ["LANG"] = "en_US.UTF-8" },
};
await using var shell = await client.StartShellAsync(options);

await shell.StandardInput.WriteAsync("ls -la\n"u8.ToArray());
await shell.ResizeTerminalAsync(columns: 160, rows: 48);    // when the local window changes
await shell.StandardInput.WriteAsync("exit\n"u8.ToArray());
await shell.StandardOutput.CopyToAsync(Console.OpenStandardOutput());
```

With a terminal the server merges stderr into stdout. Writing Ctrl-C (`0x03`) interrupts the foreground program the way a
user would; `SendSignalAsync("TERM")` sends a signal request, which current OpenSSH delivers and other servers may
ignore. Environment variables are only set when the server allows them (sshd's `AcceptEnv`). The terminal modes are those
of RFC 4254 section 8, named as in POSIX `termios`.

`StartCommandAsync(command, options)` takes the same options, for commands that need a terminal (`sudo`, `top`, editors).

## Subsystems

A subsystem is a protocol the server runs by name instead of a command: `sftp`, `netconf`, or anything configured with
sshd's `Subsystem` keyword. `StartSubsystemAsync` starts one, as `ssh -s` does, with no shell in between. The session's
streams then carry the subsystem's own protocol, byte for byte:

```csharp
await using var netconf = await client.StartSubsystemAsync("netconf");
await netconf.StandardInput.WriteAsync(helloMessage);
// ... read the server's hello from netconf.StandardOutput, and so on.
```

A server that does not offer the subsystem refuses it with `SshException` (`ChannelClosed`), and the connection stays
usable. SFTP itself will come as the separate `SshSharp.Sftp` package, built on this.

## Ending a session

Disposing an `SshSession` closes the channel; a program still running gets a hangup from the server. Disposing the
`SshClient` closes every session.
