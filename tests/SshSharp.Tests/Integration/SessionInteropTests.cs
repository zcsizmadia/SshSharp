using System.Text;

namespace SshSharp.Tests.Integration;

/// <summary>Shells and streamed commands against a real server. Needs SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD.</summary>
public class SessionInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient?> ConnectAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        // The key is not disposed until the process ends; fine for a test.
        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadFileAsync(keyFile) : null;
        var options = new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(host, port, options, Timeout());
    }

    private static async Task<string> ReadAllAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, Timeout());
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    [Test]
    public async Task AShellWithATerminal_RunsWhatIsTyped()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var terminal = new SshTerminalOptions { TerminalType = "dumb", Columns = 132, Rows = 50 };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = terminal }, Timeout());
        await Assert.That(session.HasTerminal).IsTrue();

        // The terminal reports its size to programs; "exit 7" ends the shell with that status.
        await session.StandardInput.WriteAsync("stty size; echo marker-$((6*7)); exit 7\n"u8.ToArray(), Timeout());
        var output = await ReadAllAsync(session.StandardOutput);
        await session.WaitForExitAsync(Timeout());

        await Assert.That(output).Contains("50 132");
        await Assert.That(output).Contains("marker-42");
        if (!RealServer.IsWindows)
        {
            // OpenSSH for Windows runs the shell through ConPTY and does not pass its exit status on.
            await Assert.That(session.ExitStatus).IsEqualTo(7);
        }
    }

    [Test]
    public async Task ABreak_IsAnswered_AndTheSessionCarriesOn()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        // Whether the break is performed depends on the server and its pty (sshd answers with tcsendbreak's result, Dropbear
        // declines), so only the answer and the session's health are checked.
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions { TerminalType = "dumb" } }, Timeout());
        _ = await session.SendBreakAsync(TimeSpan.FromMilliseconds(100), Timeout());
        await session.StandardInput.WriteAsync("echo after-$((40+2)); exit\n"u8.ToArray(), Timeout());
        var output = await ReadAllAsync(session.StandardOutput);
        await Assert.That(output).Contains("after-42");
    }

    [Test]
    public async Task Expect_DrivesARealShell()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var terminal = new SshTerminalOptions { TerminalType = "dumb", Columns = 132, Rows = 50 };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = terminal }, Timeout());
        var expect = new SshExpect(session);

        // The terminal echoes what is typed; the arithmetic makes the output differ from the echo, so only the result can match.
        await expect.SendLineAsync("echo first-$((6*7))", Timeout());
        await expect.ExpectAsync("first-42", Timeout());
        await expect.SendLineAsync("echo second-$((7*8))-end", Timeout());
        var match = await expect.ExpectAsync(new System.Text.RegularExpressions.Regex(@"second-(\d+)-end"), Timeout());
        await Assert.That(match.Match!.Groups[1].Value).IsEqualTo("56");

        await expect.SendLineAsync("exit", Timeout());
        await Assert.That(async () => await expect.ExpectAsync("never-printed", Timeout())).Throws<EndOfStreamException>();
    }

    [Test]
    public async Task TheSftpSubsystem_AnswersTheVersionHandshake()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        if (!RealServer.IsOpenSsh)
        {
            Skip.Test("Dropbear needs a separate sftp-server, which the test image does not install.");
            return;
        }

        // SFTP's first exchange (draft-ietf-secsh-filexfer-02): SSH_FXP_INIT with version 3, answered by SSH_FXP_VERSION. Enough to show
        // that a subsystem carries a binary protocol both ways with a real server; SFTP itself is SshSharp.Sftp's job (#7).
        await using var sftp = await client.StartSubsystemAsync("sftp", cancellationToken: Timeout());
        await sftp.StandardInput.WriteAsync(new byte[] { 0, 0, 0, 5, 1, 0, 0, 0, 3 }, Timeout());
        var header = new byte[4];
        await sftp.StandardOutput.ReadExactlyAsync(header, Timeout());
        var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header);
        await Assert.That(length).IsGreaterThanOrEqualTo(5u).And.IsLessThan(64u * 1024);
        var reply = new byte[length];
        await sftp.StandardOutput.ReadExactlyAsync(reply, Timeout());
        await Assert.That(reply[0]).IsEqualTo((byte)2); // SSH_FXP_VERSION
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(1))).IsEqualTo(3u);
    }

    [Test]
    public async Task ASubsystemTheServerDoesNotOffer_IsRefused()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var error = await Assert.ThrowsAsync<SshException>(async () => await client.StartSubsystemAsync("sshsharp-no-such-subsystem", cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That((await client.RunCommandAsync("true", Timeout())).ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task ACommandWithoutATerminal_KeepsStdoutAndStderrApart_AndReadsStdin()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        // OpenSSH for Windows deadlocks when a command's output backs up while its input is being closed (#86): its pipe close
        // (contrib/win32/win32compat/fileio.c, fileio_close) blocks the whole sshd until the last input write into the command's stdin
        // completes, but the command (tr) is itself blocked writing output that only that sshd drains. All the input and our EOF reach
        // sshd (its log shows rcvd eof, obuf empty, chan_shutdown_write), and then nothing more. So against Windows the output is
        // counted on the server (tr | wc -c): the same input, window and EOF, with only a few bytes back through sshd's stdout pipe.
        var windows = RealServer.IsWindows;
        var command = windows ? "echo to-err 1>&2; tr a-z A-Z | wc -c; exit 4" : "echo to-err 1>&2; tr a-z A-Z; exit 4";
        await using var session = await client.StartCommandAsync(command, cancellationToken: Timeout());
        await Assert.That(session.HasTerminal).IsFalse();

        // Where it stands, for the failure message: a hang should say which step it is stuck in and how far the data got.
        var stage = "writing";
        long written = 0, outRead = 0, errRead = 0;
        async Task<string> CountAsync(Stream stream, Action<int> counted)
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(chunk, Timeout())) > 0)
            {
                buffer.Write(chunk, 0, read);
                counted(read);
            }

            return Encoding.UTF8.GetString(buffer.ToArray());
        }

        var output = CountAsync(session.StandardOutput, n => Interlocked.Add(ref outRead, n));
        var error = CountAsync(session.StandardError, n => Interlocked.Add(ref errRead, n));

        // More than the server's initial window, so the input only gets through as the server adjusts it.
        var line = new string('x', 1023) + "\n";
        var input = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(line, 4096)));
        try
        {
            for (var offset = 0; offset < input.Length; offset += line.Length * 64)
            {
                var part = input.AsMemory(offset, Math.Min(line.Length * 64, input.Length - offset));
                await session.StandardInput.WriteAsync(part, Timeout());
                written += part.Length;
            }

            stage = "sending EOF";
            await session.CloseInputAsync(Timeout());
            stage = "reading stdout";
            var stdout = await output;
            stage = "reading stderr";
            var stderr = await error;
            stage = "waiting for the exit status";
            await session.WaitForExitAsync(Timeout());

            if (windows)
            {
                await Assert.That(stdout.Trim()).IsEqualTo(input.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                await Assert.That(stdout.Length).IsEqualTo(input.Length);
                await Assert.That(stdout.All(c => c is 'X' or '\n')).IsTrue();
            }

            await Assert.That(stderr.Trim()).IsEqualTo("to-err");
            await Assert.That(session.ExitStatus).IsEqualTo(4);
        }
        catch (OperationCanceledException ex)
        {
            throw new TimeoutException($"Stuck {stage}: {written} of {input.Length} bytes written, {Interlocked.Read(ref outRead)} read from stdout, " +
                $"{Interlocked.Read(ref errRead)} from stderr; stdout {(output.IsCompleted ? "ended" : "open")}, stderr {(error.IsCompleted ? "ended" : "open")}, " +
                $"exit status {session.ExitStatus?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none"}, connected {client.IsConnected}.", ex);
        }
    }

    [Test]
    public async Task OpenSshExtensions_EndOfWrite_AndNoMoreSessions()
    {
        await using var client = await ConnectAsync();
        if (client is null || !RealServer.IsOpenSsh || RealServer.IsWindows)
        {
            Skip.Test("An OpenSSH server on a Unix-like system is needed (eow@openssh.com and no-more-sessions@openssh.com are OpenSSH's).");
            return;
        }

        SshSession? yes = null;
        await Stages.RunAsync(async stages =>
        {
            // Our output closed: sshd stops sending, so `yes` gets SIGPIPE and ends instead of running on.
            stages.Step("starting yes");
            yes = await client.StartCommandAsync("yes", cancellationToken: Timeout());
            stages.Step("reading some of its output");
            var buffer = new byte[4096];
            await yes.StandardOutput.ReadExactlyAsync(buffer, Timeout());
            stages.Step("disposing its output");
            await yes.StandardOutput.DisposeAsync();
            stages.Step("waiting for yes to end");
            await yes.WaitForExitAsync(Timeout());
            await Assert.That(yes.ExitSignal is "PIPE" || yes.ExitStatus is not null and not 0).IsTrue();
            stages.Step("closing the session");
            await yes.DisposeAsync();
            stages.Step("pinging after the eow session");
            await client.PingAsync(Timeout());

            // The other direction (sshd telling us the program closed its input) cannot be seen here: sshd sends eow@openssh.com only
            // to clients whose identification says OpenSSH (channels.c). The unit tests cover it.

            // OpenSSH takes no-more-sessions@openssh.com without dropping the connection; other channels still work.
            stages.Step("sending no-more-sessions");
            await Assert.That(await client.PreventNewSessionsAsync(Timeout())).IsTrue();
            await Assert.That(async () => await client.RunCommandAsync("true", Timeout())).Throws<InvalidOperationException>();
            stages.Step("pinging after no-more-sessions");
            await client.PingAsync(Timeout());
            await Assert.That(client.IsConnected).IsTrue();
        }, () => $"yes: exit status {yes?.ExitStatus?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none"}, signal {yes?.ExitSignal ?? "none"}; connected {client.IsConnected}, error {client.ConnectionError?.Message ?? "none"}. {ConnectionInternals(client)}");
    }

    /// <summary>For a stuck test: when the connection last received a packet, whether a key re-exchange is under way, what waits to be sent.</summary>
    private static string ConnectionInternals(SshClient client)
    {
        const System.Reflection.BindingFlags Private = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var connection = client.Connection;
        var lastReceived = (long)typeof(SshSharp.Protocol.SshConnection).GetField("_lastReceived", Private)!.GetValue(connection)!;
        var transport = typeof(SshSharp.Protocol.SshConnection).GetField("_transport", Private)!.GetValue(connection)!;
        var rekeying = transport.GetType().GetField("_rekeying", Private)!.GetValue(transport);
        var outbox = typeof(SshSharp.Protocol.SshConnection).GetField("_outbox", Private)!.GetValue(connection)!;
        var reader = outbox.GetType().GetProperty("Reader")!.GetValue(outbox)!;
        var queued = reader.GetType().GetProperty("CanCount")?.GetValue(reader) is true ? reader.GetType().GetProperty("Count")!.GetValue(reader) : "?";
        object? Field(object target, string name) => target.GetType().GetField(name, Private)?.GetValue(target);
        var sendLock = (SemaphoreSlim)Field(transport, "_sendLock")!;
        var receiveLoop = Field(connection, "_loop") as Task;
        var outboxLoop = Field(connection, "_outboxLoop") as Task;
        var pings = Field(connection, "_pings") as System.Collections.ICollection;
        return $"Last packet received {connection.Time.GetElapsedTime(lastReceived).TotalSeconds:0.0} s ago; rekeying {rekeying}; {queued} messages waiting "
            + $"in the outbox; transport send lock {(sendLock.CurrentCount == 0 ? "HELD" : "free")}; receive loop {receiveLoop?.Status}; outbox loop "
            + $"{outboxLoop?.Status}; {pings?.Count} pings awaiting a pong; packets received since the key exchange {Field(transport, "_packetsReceivedSinceKex")}.";
    }

    [Test]
    public async Task PingAsync_MeasuresARoundTrip_WithPingsOrWithoutThem()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        // OpenSSH 9.5+ answers transport pings; older OpenSSH and Dropbear answer the keepalive@openssh.com request instead.
        for (var i = 0; i < 3; i++)
        {
            var roundTrip = await client.PingAsync(Timeout());
            await Assert.That(roundTrip).IsLessThan(TimeSpan.FromSeconds(30));
        }

        var result = await client.RunCommandAsync("echo still-here", Timeout());
        await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("still-here");
    }
}
