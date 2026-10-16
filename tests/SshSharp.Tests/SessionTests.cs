using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Shells and streamed commands (<see cref="SshSession"/>): terminals, environment, input and output streams, signals, resizing.</summary>
public class SessionTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>A shell that echoes its input until EOF, then exits 0.</summary>
    private static async Task EchoAsync(ExecScript script)
    {
        while (await script.ReadInputAsync() is { } data)
        {
            await script.StdoutAsync(data);
        }

        await script.FinishAsync(0);
    }

    private static async Task<string> ReadAllAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, Timeout());
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static async Task<string> ReadExactlyAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, Timeout());
        return Encoding.UTF8.GetString(buffer);
    }

    private static FakeSessionServer.ChannelRequestRecord[] Requests(FakeSessionServer server)
    {
        var channel = server.Channels.Single();
        lock (channel.Requests)
        {
            return [.. channel.Requests];
        }
    }

    [Test]
    public async Task AShellWithATerminal_AsksForThePtyFirst_AndEchoesInput()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        var terminal = new SshTerminalOptions
        {
            Columns = 120,
            Rows = 40,
            Modes = new Dictionary<SshTerminalMode, uint> { [SshTerminalMode.TTY_OP_ISPEED] = 38400, [SshTerminalMode.ECHO] = 0 },
        };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = terminal }, Timeout());
        await Assert.That(session.HasTerminal).IsTrue();

        await session.StandardInput.WriteAsync("hello\n"u8.ToArray(), Timeout());
        await Assert.That(await ReadExactlyAsync(session.StandardOutput, 6)).IsEqualTo("hello\n");

        await session.CloseInputAsync(Timeout());
        await Assert.That(await ReadAllAsync(session.StandardOutput)).IsEqualTo("");
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsEqualTo(0);

        var requests = Requests(server);
        await Assert.That(requests.Select(r => r.Type)).IsEquivalentTo(new[] { "pty-req", "shell" });
        await Assert.That(requests[0].Args).IsEquivalentTo(new[] { "xterm-256color", "120", "40", "0", "0" });

        // Modes in opcode order, each with a uint32, then TTY_OP_END.
        await Assert.That(requests[0].Modes!).IsEquivalentTo(new byte[] { 53, 0, 0, 0, 0, 128, 0, 0, 0x96, 0, 0 });
    }

    [Test]
    public async Task ASubsystem_CarriesItsProtocolBothWays_ByteForByte()
    {
        // A binary request/reply protocol, as SFTP is: every byte the client writes comes back unchanged (no shell, no line handling).
        await using var server = new FakeSessionServer();
        server.Subsystems["echo-binary"] = EchoAsync;
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartSubsystemAsync("echo-binary", cancellationToken: Timeout());

        byte[] request = [0, 0, 0, 5, 1, 0, 0, 0, 3, 0xFF, 0x0D, 0x0A, 0x00];
        await session.StandardInput.WriteAsync(request, Timeout());
        var reply = new byte[request.Length];
        await session.StandardOutput.ReadExactlyAsync(reply, Timeout());
        await Assert.That(reply).IsEquivalentTo(request);

        await session.CloseInputAsync(Timeout());
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsEqualTo(0);
        await Assert.That(session.HasTerminal).IsFalse();
        var subsystem = Requests(server).Single();
        await Assert.That(subsystem.Type).IsEqualTo("subsystem");
        await Assert.That(subsystem.Args).IsEquivalentTo(new[] { "echo-binary" });
        await Assert.That(server.Commands).IsEmpty(); // a subsystem is not a command: no shell runs it
    }

    [Test]
    public async Task ASubsystemTheServerDoesNotOffer_FailsWithItsName_AndTheChannelIsClosed()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var error = await Assert.ThrowsAsync<SshException>(async () => await client.StartSubsystemAsync("sftp", cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(error.Message).Contains("'sftp'");

        // The connection is still usable.
        var result = await client.RunCommandAsync("true", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task SubsystemNames_AreChecked()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.That(async () => await client.StartSubsystemAsync("")).Throws<ArgumentException>();
        await Assert.That(async () => await client.StartSubsystemAsync("sftp\nexec")).Throws<ArgumentException>();
    }

    [Test]
    public async Task ACommandWithoutATerminal_KeepsStdoutAndStderrApart()
    {
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.StdoutAsync("out 1\n"u8.ToArray());
                await script.StderrAsync("err 1\n"u8.ToArray());
                await script.StdoutAsync("out 2\n"u8.ToArray());
                await script.FinishAsync(3);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("build", cancellationToken: Timeout());

        var output = ReadAllAsync(session.StandardOutput);
        var error = ReadAllAsync(session.StandardError);
        await Assert.That(await output).IsEqualTo("out 1\nout 2\n");
        await Assert.That(await error).IsEqualTo("err 1\n");
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsEqualTo(3);
        await Assert.That(session.HasTerminal).IsFalse();
        await Assert.That(Requests(server).Select(r => r.Type)).IsEquivalentTo(new[] { "exec" });
        await Assert.That(server.Commands).IsEquivalentTo(new[] { "build" });
    }

    [Test]
    public async Task AProgramKilledByASignal_ReportsIt()
    {
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.ExitSignalAsync("KILL");
                await script.EofAsync();
                await script.CloseAsync();
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("sleep 100", cancellationToken: Timeout());
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsNull();
        await Assert.That(session.ExitSignal).IsEqualTo(new SshExitSignal("KILL", false, null));
    }

    [Test]
    public async Task InputLargerThanTheServersWindow_WaitsForTheServerToGrantMore()
    {
        // A 16 KiB window and 4 KiB packets: 256 KiB of input only gets through as the server consumes it and adjusts the window.
        await using var server = new FakeSessionServer
        {
            ServerWindow = 16 * 1024,
            ServerMaxPacket = 4 * 1024,
            OnExec = async script =>
            {
                long total = 0;
                while (await script.ReadInputAsync() is { } data)
                {
                    total += data.Length;
                    await script.GrantWindowAsync((uint)data.Length);
                }

                await script.StdoutAsync(Encoding.UTF8.GetBytes(total.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                await script.FinishAsync(0);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("wc -c", cancellationToken: Timeout());

        var input = new byte[256 * 1024];
        Random.Shared.NextBytes(input);
        await session.StandardInput.WriteAsync(input, Timeout());
        await session.CloseInputAsync(Timeout());
        await Assert.That(await ReadAllAsync(session.StandardOutput)).IsEqualTo("262144");
        await Assert.That(server.Channels.Single().Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task OutputLargerThanTheClientsWindow_StreamsThrough()
    {
        var chunk = new byte[64 * 1024];
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                for (var i = 0; i < 80; i++)
                {
                    await script.StdoutAsync(chunk); // 5 MiB in all, more than twice the 2 MiB window
                }

                await script.FinishAsync(0);
            },
        };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartCommandAsync("cat big", cancellationToken: Timeout());
        long total = 0;
        var buffer = new byte[10000];
        while (await session.StandardOutput.ReadAsync(buffer, Timeout()) is var read and > 0)
        {
            total += read;
        }

        await Assert.That(total).IsEqualTo(80L * 64 * 1024);
    }

    [Test]
    public async Task EnvironmentVariables_AreOfferedWithoutWaitingForReplies()
    {
        await using var server = new FakeSessionServer { AcceptEnv = ["LANG"], OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        var environment = new Dictionary<string, string> { ["LANG"] = "C.UTF-8", ["NOT_ACCEPTED"] = "x" };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Environment = environment }, Timeout());
        await session.CloseInputAsync(Timeout());
        await session.WaitForExitAsync(Timeout());

        var requests = Requests(server);
        await Assert.That(requests.Select(r => r.Type)).IsEquivalentTo(new[] { "env", "env", "shell" });
        await Assert.That(requests.Take(2).All(r => !r.WantReply)).IsTrue();
        await Assert.That(requests[0].Args).IsEquivalentTo(new[] { "LANG", "C.UTF-8" });
    }

    [Test]
    public async Task ARefusedTerminalOrShell_FailsAndClosesTheChannel()
    {
        await using (var server = new FakeSessionServer { RefusePty = true })
        {
            await using var client = await ConnectAsync(server);
            var error = await Assert.ThrowsAsync<SshException>(() =>
                client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions() }, Timeout()));
            await Assert.That(error!.Message).Contains("terminal");
            await WaitForCloseAsync(server);
        }

        await using (var server = new FakeSessionServer { RefuseShell = true })
        {
            await using var client = await ConnectAsync(server);
            var error = await Assert.ThrowsAsync<SshException>(() => client.StartShellAsync(cancellationToken: Timeout()));
            await Assert.That(error!.Message).Contains("shell");
            await WaitForCloseAsync(server);
        }
    }

    private static async Task WaitForCloseAsync(FakeSessionServer server)
    {
        for (var i = 0; i < 500 && !server.Channels.Single().CloseReceived; i++)
        {
            await Task.Delay(10);
        }

        await Assert.That(server.Channels.Single().CloseReceived).IsTrue();
    }

    [Test]
    public async Task ResizeAndSignals_ReachTheServer()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions() }, Timeout());
        await session.ResizeTerminalAsync(100, 30, 800, 600, Timeout());
        await session.SendSignalAsync("INT", Timeout());
        await session.CloseInputAsync(Timeout());
        await session.WaitForExitAsync(Timeout());

        var requests = Requests(server);
        await Assert.That(requests.Select(r => r.Type)).IsEquivalentTo(new[] { "pty-req", "shell", "window-change", "signal" });
        await Assert.That(requests[2].Args).IsEquivalentTo(new[] { "100", "30", "800", "600" });
        await Assert.That(requests[3].Args).IsEquivalentTo(new[] { "INT" });
    }

    [Test]
    public async Task ABreak_ReachesATerminal_AndIsDeclinedWithoutOne()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        await using (var terminal = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions() }, Timeout()))
        {
            await Assert.That(await terminal.SendBreakAsync(cancellationToken: Timeout())).IsTrue();
            await Assert.That(await terminal.SendBreakAsync(TimeSpan.FromMilliseconds(250), Timeout())).IsTrue();
        }

        await using (var plain = await client.StartShellAsync(cancellationToken: Timeout()))
        {
            await Assert.That(await plain.SendBreakAsync(cancellationToken: Timeout())).IsFalse();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => plain.SendBreakAsync(TimeSpan.FromSeconds(-1), Timeout()));
        }

        var breaks = server.Channels.SelectMany(c => { lock (c.Requests) { return c.Requests.Where(r => r.Type == "break").ToList(); } }).ToList();
        await Assert.That(breaks.Select(b => b.Args[0])).IsEquivalentTo(new[] { "1000", "250", "1000" });
        await Assert.That(breaks.All(b => b.WantReply)).IsTrue();
    }

    [Test]
    public async Task ResizingWithoutATerminal_OrBadSignalNames_AreRejected()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartShellAsync(cancellationToken: Timeout());
        await Assert.ThrowsAsync<InvalidOperationException>(() => session.ResizeTerminalAsync(80, 24, cancellationToken: Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => session.SendSignalAsync("SIGINT", Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => session.SendSignalAsync("IN T", Timeout()));
    }

    [Test]
    public async Task InvalidOptions_FailBeforeAnyChannelOpens()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        SshSessionOptions[] invalid =
        [
            new() { Terminal = new SshTerminalOptions { TerminalType = "x term" } },
            new() { Terminal = new SshTerminalOptions { TerminalType = "" } },
            new() { Terminal = new SshTerminalOptions { Columns = -1 } },
            new() { Terminal = new SshTerminalOptions { Modes = new Dictionary<SshTerminalMode, uint> { [(SshTerminalMode)200] = 1 } } },
            new() { Environment = new Dictionary<string, string> { ["A=B"] = "x" } },
            new() { Environment = new Dictionary<string, string> { [""] = "x" } },
            new() { Environment = new Dictionary<string, string> { ["A"] = "x\0y" } },
        ];
        foreach (var options in invalid)
        {
            await Assert.ThrowsAsync<ArgumentException>(() => client.StartShellAsync(options, Timeout()));
        }

        await Assert.ThrowsAsync<ArgumentException>(() => client.StartCommandAsync("", cancellationToken: Timeout()));
        await Assert.That(server.Channels).IsEmpty();
    }

    [Test]
    public async Task DisposingARunningSession_ClosesTheChannel_AndTheStreams()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        var session = await client.StartShellAsync(cancellationToken: Timeout());
        await session.StandardInput.WriteAsync("unread\n"u8.ToArray(), Timeout());
        await session.DisposeAsync();
        await session.DisposeAsync(); // twice is harmless

        await WaitForCloseAsync(server);
        await Assert.That(session.StandardOutput.CanRead).IsFalse();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await session.StandardOutput.ReadExactlyAsync(new byte[1], Timeout()));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => session.SendSignalAsync("TERM", Timeout()));
        await Assert.That(client.ConnectionError?.ToString()).IsNull();
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task TheStreams_AreAsynchronousOnly_AndOneWay()
    {
        await using var server = new FakeSessionServer { OnShell = EchoAsync };
        await using var client = await ConnectAsync(server);
        await using var session = await client.StartShellAsync(cancellationToken: Timeout());

        await Assert.That(session.StandardInput.CanWrite && !session.StandardInput.CanRead && !session.StandardInput.CanSeek).IsTrue();
        await Assert.That(session.StandardOutput.CanRead && !session.StandardOutput.CanWrite && !session.StandardOutput.CanSeek).IsTrue();
        await Assert.That(() => session.StandardInput.Write(new byte[1], 0, 1)).Throws<NotSupportedException>();
        await Assert.That(() => session.StandardOutput.Read(new byte[1], 0, 1)).Throws<NotSupportedException>();
        await Assert.That(() => session.StandardOutput.Write(new byte[1], 0, 1)).Throws<NotSupportedException>();
        await Assert.That(() => session.StandardInput.Read(new byte[1], 0, 1)).Throws<NotSupportedException>();
        await Assert.That(() => session.StandardOutput.Length).Throws<NotSupportedException>();
        await Assert.That(() => session.StandardInput.Seek(0, SeekOrigin.Begin)).Throws<NotSupportedException>();

        // Disposing the input stream sends EOF, like CloseInputAsync: the echo shell exits.
        await session.StandardInput.DisposeAsync();
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsEqualTo(0);
    }
}
