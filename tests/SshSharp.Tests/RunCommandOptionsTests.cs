using System.Security.Cryptography;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// <see cref="SshClient.RunCommandAsync(string, SshSessionOptions?, SshCommandInput?, CancellationToken)"/> (environment, terminal and
/// standard input) and <see cref="SshCommandResult.EnsureSuccess"/>.
/// </summary>
public class RunCommandOptionsTests
{
    // Generated per run: the fake server checks it, and no password is written down.
    private static readonly string TestPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static FakeSessionServer Server(Func<ExecScript, Task> onExec, string[]? acceptEnv = null, bool refusePty = false) =>
        new() { Password = TestPassword, OnExec = onExec, AcceptEnv = acceptEnv ?? [], RefusePty = refusePty };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, long maxOutput = 128L * 1024 * 1024)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = TestPassword,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            MaxCommandOutputBytes = maxOutput,
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>Plays <c>cat</c>: echoes the input as it arrives (granting the window back, as a server does), and exits 0 at its EOF.</summary>
    private static async Task CatAsync(ExecScript script)
    {
        while (await script.ReadInputAsync() is { } data)
        {
            await script.GrantWindowAsync((uint)data.Length);
            await script.StdoutAsync(data);
        }

        await script.FinishAsync(0);
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
    public async Task LargeInput_IsSentIntact_AcrossManyDataPackets()
    {
        // Each packet's data goes from the caller's memory straight into the packet; 1 MiB crosses many packets and window refills.
        var input = new byte[1024 * 1024 + 17];
        new Random(9).NextBytes(input);
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("cat", null, SshCommandInput.FromBytes(input), Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(Convert.ToHexString(result.StandardOutput.Span)).IsEqualTo(Convert.ToHexString(input));
        await Assert.That(result.StandardError.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Stderr_IsCollected_WithAndWithoutSplitting_AndIsEmptyWhenNothingIsWritten()
    {
        await using var server = Server(async script =>
        {
            await script.StdoutAsync(Encoding.UTF8.GetBytes("out:" + script.Command));
            if (script.Command.StartsWith("loud", StringComparison.Ordinal))
            {
                await script.StderrAsync(Encoding.UTF8.GetBytes("err:" + script.Command));
            }

            await script.FinishAsync(0);
        });
        await using var client = await ConnectAsync(server);

        // Collected (stderr is not split from the channel's output; it is told apart chunk by chunk).
        var loud = await client.RunCommandAsync("loud", Timeout());
        await Assert.That(loud.StandardOutputText).IsEqualTo("out:loud");
        await Assert.That(loud.StandardErrorText).IsEqualTo("err:loud");
        var quiet = await client.RunCommandAsync("quiet", null, null, Timeout());
        await Assert.That(quiet.StandardOutputText).IsEqualTo("out:quiet");
        await Assert.That(quiet.StandardError.IsEmpty).IsTrue();

        // Streamed (stderr split into a stream of its own).
        foreach (var command in new[] { "loud-session", "quiet-session" })
        {
            await using var session = await client.StartCommandAsync(command, cancellationToken: Timeout());
            using var output = new MemoryStream();
            using var error = new MemoryStream();
            await Task.WhenAll(session.StandardOutput.CopyToAsync(output, Timeout()), session.StandardError.CopyToAsync(error, Timeout()));
            await session.WaitForExitAsync(Timeout());
            await Assert.That(Encoding.UTF8.GetString(output.ToArray())).IsEqualTo("out:" + command);
            await Assert.That(Encoding.UTF8.GetString(error.ToArray())).IsEqualTo(command.StartsWith("loud", StringComparison.Ordinal) ? "err:" + command : "");
        }
    }

    [Test]
    public async Task BytesAreTheCommandsInput_AndEndOfFileFollows_SoCatFinishes()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("cat", null, SshCommandInput.FromBytes("line one\nline two\n"u8.ToArray()), Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(result.StandardOutputText).IsEqualTo("line one\nline two\n");
        await Assert.That(server.Channels.Single().EofReceived).IsTrue();
    }

    [Test]
    public async Task TextIsEncodedAsUtf8ByDefault_OrWithTheEncodingGiven_WithoutAByteOrderMark()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);

        var utf8 = await client.RunCommandAsync("cat", null, SshCommandInput.FromText("héllo\n"), Timeout());
        await Assert.That(utf8.StandardOutput.ToArray()).IsEquivalentTo(new byte[] { (byte)'h', 0xC3, 0xA9, (byte)'l', (byte)'l', (byte)'o', (byte)'\n' });

        var explicitUtf8 = await client.RunCommandAsync("cat", null, SshCommandInput.FromText("x", Encoding.UTF8), Timeout());
        await Assert.That(explicitUtf8.StandardOutput.ToArray()).IsEquivalentTo(new byte[] { (byte)'x' });

        var latin1 = await client.RunCommandAsync("cat", null, SshCommandInput.FromText("hé", Encoding.Latin1), Timeout());
        await Assert.That(latin1.StandardOutput.ToArray()).IsEquivalentTo(new byte[] { (byte)'h', 0xE9 });
    }

    [Test]
    public async Task AStreamLargerThanTheServersWindow_IsSentWhole_AndLeftOpen()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);
        var data = RandomNumberGenerator.GetBytes(5 * 1024 * 1024 + 123); // over the fake server's 2 MiB window
        await using var stream = new MemoryStream(data);

        var result = await client.RunCommandAsync("cat", null, SshCommandInput.FromStream(stream), Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(result.StandardOutput.Span.SequenceEqual(data)).IsTrue();
        await Assert.That(stream.CanRead).IsTrue(); // the caller owns the stream
    }

    [Test]
    public async Task AStreamIsReadFromItsCurrentPosition()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);
        await using var stream = new MemoryStream("skip-this|send-this"u8.ToArray());
        stream.Position = "skip-this|".Length;

        var result = await client.RunCommandAsync("cat", null, SshCommandInput.FromStream(stream), Timeout());

        await Assert.That(result.StandardOutputText).IsEqualTo("send-this");
    }

    [Test]
    public async Task WithoutInput_EndOfFileIsSentAtOnce()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("cat", options: null, standardInput: null, Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(result.StandardOutput.Length).IsEqualTo(0);
        await Assert.That(server.Channels.Single().EofReceived).IsTrue();
    }

    [Test]
    public async Task TheOriginalOverload_StillLeavesTheInputOpen()
    {
        // 1.0 behaviour, kept: exec, and no EOF. (Without ForwardAgent, as here, nothing else is asked; see AgentForwardingTests.)
        await using var server = Server(script => script.FinishAsync(0));
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("true", Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(server.Channels.Single().EofReceived).IsFalse();
        await Assert.That(Requests(server).Select(r => r.Type)).IsEquivalentTo(new[] { "exec" });
    }

    [Test]
    public async Task EnvironmentAndTerminal_AreRequestedAsStartCommandRequestsThem_BeforeTheCommand()
    {
        await using var server = Server(CatAsync, acceptEnv: ["LANG"]);
        await using var client = await ConnectAsync(server);
        var options = new SshSessionOptions
        {
            Terminal = new SshTerminalOptions { TerminalType = "vt100", Columns = 132, Rows = 50 },
            Environment = new Dictionary<string, string> { ["LANG"] = "C.UTF-8", ["DEPLOY_ENV"] = "staging" },
        };

        var result = await client.RunCommandAsync("cat", options, SshCommandInput.FromText("typed\n"), Timeout());

        await Assert.That(result.StandardOutputText).IsEqualTo("typed\n");
        var requests = Requests(server);
        await Assert.That(requests.Select(r => r.Type)).IsEquivalentTo(new[] { "pty-req", "env", "env", "exec" });
        await Assert.That(requests[0].Args.Take(3)).IsEquivalentTo(new[] { "vt100", "132", "50" });
        await Assert.That(requests.Where(r => r.Type == "env").Select(r => $"{r.Args[0]}={r.Args[1]}"))
            .IsEquivalentTo(new[] { "LANG=C.UTF-8", "DEPLOY_ENV=staging" });
        await Assert.That(requests[^1].Args[0]).IsEqualTo("cat");
    }

    [Test]
    public async Task ARefusedTerminal_IsAnSshException_AndBadEnvironmentNamesFailBeforeAnythingIsSent()
    {
        await using var server = Server(CatAsync, refusePty: true);
        await using var client = await ConnectAsync(server);

        var refused = await Assert.ThrowsAsync<SshException>(async () =>
            await client.RunCommandAsync("cat", new SshSessionOptions { Terminal = new() }, null, Timeout()));
        await Assert.That(refused!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);

        var opened = server.ChannelOpensReceived;
        await Assert.That(async () => await client.RunCommandAsync("cat", new SshSessionOptions { Environment = new Dictionary<string, string> { ["A=B"] = "x" } }, null, Timeout()))
            .Throws<ArgumentException>();
        await Assert.That(server.ChannelOpensReceived).IsEqualTo(opened);
    }

    [Test]
    public async Task ACommandThatExitsWithoutReadingItsInput_IsNotAnError()
    {
        // The input is larger than the server's window, so the writer is still waiting for window when the command ends.
        await using var server = Server(script => script.FinishAsync(3));
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("true", null, SshCommandInput.FromBytes(new byte[5 * 1024 * 1024]), Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(3);
    }

    [Test]
    public async Task ACommandThatClosesItsInput_StopsTheInput_WithoutAnError()
    {
        await using var server = Server(async script =>
        {
            await script.EndOfWriteAsync(); // eow@openssh.com: the program closed its stdin
            await script.StdoutAsync("done"u8.ToArray());
            await script.FinishAsync(0);
        });
        await using var client = await ConnectAsync(server);
        await using var stream = new MemoryStream(new byte[5 * 1024 * 1024]);

        var result = await client.RunCommandAsync("head -c0", null, SshCommandInput.FromStream(stream), Timeout());

        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(result.StandardOutputText).IsEqualTo("done");
    }

    [Test]
    public async Task AnInputStreamThatFails_FailsTheCommand_AndTheConnectionStaysUsable()
    {
        await using var server = Server(CatAsync);
        await using var client = await ConnectAsync(server);

        var ex = await Assert.ThrowsAsync<IOException>(async () =>
            await client.RunCommandAsync("cat", null, SshCommandInput.FromStream(new FailingStream()), Timeout()));
        await Assert.That(ex!.Message).IsEqualTo("disk gone");

        var next = await client.RunCommandAsync("cat", null, SshCommandInput.FromText("again"), Timeout());
        await Assert.That(next.StandardOutputText).IsEqualTo("again");
    }

    [Test]
    public async Task Cancellation_StopsTheCommandWhileItsInputIsBeingSent()
    {
        var started = new TaskCompletionSource();
        await using var server = Server(async script =>
        {
            started.TrySetResult();
            await Task.Delay(60_000); // reads nothing, so the input waits for window
        });
        await using var client = await ConnectAsync(server);
        using var cts = new CancellationTokenSource();

        var running = client.RunCommandAsync("hang", null, SshCommandInput.FromBytes(new byte[5 * 1024 * 1024]), cts.Token);
        await started.Task.WaitAsync(Timeout());
        await cts.CancelAsync();
        await Assert.That(async () => await running).Throws<OperationCanceledException>();

        server.OnExec = CatAsync;
        var next = await client.RunCommandAsync("cat", null, SshCommandInput.FromText("after"), Timeout());
        await Assert.That(next.StandardOutputText).IsEqualTo("after");
    }

    [Test]
    public async Task Cancellation_StopsACommandBlockedOnAStreamThatNeverEnds()
    {
        var started = new TaskCompletionSource();
        await using var server = Server(async script =>
        {
            started.TrySetResult();
            await CatAsync(script);
        });
        await using var client = await ConnectAsync(server);
        using var cts = new CancellationTokenSource();

        var running = client.RunCommandAsync("cat", null, SshCommandInput.FromStream(new EndlessStream()), cts.Token);
        await started.Task.WaitAsync(Timeout());
        await cts.CancelAsync();
        await Assert.That(async () => await running).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task TheOutputLimit_AppliesToTheOverloadToo()
    {
        await using var server = Server(async script => { await script.StdoutAsync(new byte[100_000]); await script.FinishAsync(0); });
        await using var client = await ConnectAsync(server, maxOutput: 10_000);

        await Assert.That(async () => await client.RunCommandAsync("flood", null, SshCommandInput.FromText("x"), Timeout()))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task InputFactories_CheckTheirArguments()
    {
        await Assert.That(() => SshCommandInput.FromText(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => SshCommandInput.FromStream(null!)).Throws<ArgumentNullException>();
        await using var unreadable = new FailingStream(canRead: false);
        await Assert.That(() => SshCommandInput.FromStream(unreadable)).Throws<ArgumentException>();
    }

    [Test]
    public async Task EnsureSuccess_ReturnsTheResult_WhenTheCommandExitedWithZero()
    {
        await using var server = Server(async script => { await script.StdoutAsync("ok\n"u8.ToArray()); await script.FinishAsync(0); });
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("true", Timeout());

        await Assert.That(result.EnsureSuccess()).IsSameReferenceAs(result);
        await Assert.That((await client.RunCommandAsync("true", Timeout())).EnsureSuccess().StandardOutputText).IsEqualTo("ok\n");
    }

    [Test]
    public async Task EnsureSuccess_OnANonZeroStatus_ThrowsWithTheStatusAndStderr_ButNotStdout()
    {
        await using var server = Server(async script =>
        {
            await script.StdoutAsync("stdout-marker\n"u8.ToArray());
            await script.StderrAsync("make: *** [all] Error 2\n"u8.ToArray());
            await script.FinishAsync(2);
        });
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("make", Timeout());

        var ex = Assert.Throws<SshCommandException>(() => result.EnsureSuccess());

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.CommandFailed);
        await Assert.That(ex).IsAssignableTo<SshException>();
        await Assert.That(ex.ExitStatus).IsEqualTo(2);
        await Assert.That(ex.ExitSignal).IsNull();
        await Assert.That(ex.StandardErrorText).IsEqualTo("make: *** [all] Error 2\n");
        await Assert.That(ex.IsStandardErrorTruncated).IsFalse();
        await Assert.That(ex.Message).IsEqualTo("The command failed with exit status 2.");
        await Assert.That(ex.Message).DoesNotContain("stdout-marker");
        await Assert.That(ex.Message).DoesNotContain("make"); // neither the command nor its stderr
    }

    [Test]
    public async Task EnsureSuccess_OnAnExitSignal_ThrowsWithTheSignal()
    {
        await using var server = Server(async script =>
        {
            await script.ExitSignalAsync("KILL", coreDumped: true, message: "killed");
            await script.EofAsync();
            await script.CloseAsync();
        });
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("doomed", Timeout());

        var ex = Assert.Throws<SshCommandException>(() => result.EnsureSuccess());

        await Assert.That(ex!.ExitStatus).IsNull();
        await Assert.That(ex.ExitSignal!.Name).IsEqualTo("KILL");
        await Assert.That(ex.ExitSignal.CoreDumped).IsTrue();
        await Assert.That(ex.Message).IsEqualTo("The command was ended by signal KILL (core dumped).");
    }

    [Test]
    public async Task EnsureSuccess_WithoutAnExitStatusOrSignal_Throws()
    {
        await using var server = Server(async script => { await script.EofAsync(); await script.CloseAsync(); });
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("vanished", Timeout());

        var ex = Assert.Throws<SshCommandException>(() => result.EnsureSuccess());

        await Assert.That(ex!.ExitStatus).IsNull();
        await Assert.That(ex.ExitSignal).IsNull();
        await Assert.That(ex.Message).IsEqualTo("The command ended without reporting an exit status.");
    }

    [Test]
    public async Task EnsureSuccess_KeepsOnlyTheLast4KiBOfStderr_WithoutHalfACharacterAtTheCut()
    {
        // 6000 ASCII bytes, then 2048 two-byte characters (4096 bytes), then '!': the last 4 KiB starts in the middle of the first é.
        var stderr = Encoding.UTF8.GetBytes(new string('x', 6000) + string.Concat(Enumerable.Repeat("é", 2048)) + "!");
        await using var server = Server(async script => { await script.StderrAsync(stderr); await script.FinishAsync(1); });
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("noisy", Timeout());

        var ex = Assert.Throws<SshCommandException>(() => result.EnsureSuccess());

        await Assert.That(result.StandardError.Length).IsEqualTo(stderr.Length); // the result keeps everything
        await Assert.That(ex!.StandardError.Length).IsEqualTo(4096);
        await Assert.That(ex.StandardError.Span.SequenceEqual(stderr.AsSpan(stderr.Length - 4096))).IsTrue();
        await Assert.That(ex.IsStandardErrorTruncated).IsTrue();
        await Assert.That(ex.StandardErrorText).IsEqualTo(string.Concat(Enumerable.Repeat("é", 2047)) + "!");
    }

    [Test]
    public async Task TheExceptionBoundsAndCopiesStderr_WhenConstructedDirectly()
    {
        var exact = new byte[4096];
        var atLimit = new SshCommandException("m", 1, null, exact);
        await Assert.That(atLimit.StandardError.Length).IsEqualTo(4096);
        await Assert.That(atLimit.IsStandardErrorTruncated).IsFalse();

        var over = new byte[4097];
        over[0] = 1;
        var truncated = new SshCommandException("m", 1, null, over);
        await Assert.That(truncated.StandardError.Length).IsEqualTo(4096);
        await Assert.That(truncated.IsStandardErrorTruncated).IsTrue();
        await Assert.That(truncated.StandardError.Span.IndexOf((byte)1)).IsEqualTo(-1); // the first byte was cut

        exact[0] = 9;
        await Assert.That(atLimit.StandardError.Span[0]).IsEqualTo((byte)0); // a copy, not a view of the caller's buffer

        var empty = new SshCommandException("m", null, new SshExitSignal("TERM", false, null), default);
        await Assert.That(empty.StandardErrorText).IsEqualTo(string.Empty);
        await Assert.That(empty.Reason).IsEqualTo(SshFailureReason.CommandFailed);
    }

    /// <summary>Gives a little data, then fails as a local disk or network read can (or reports itself unreadable).</summary>
    private sealed class FailingStream(bool canRead = true) : Stream
    {
        private bool _served;

        public override bool CanRead => canRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_served)
            {
                throw new IOException("disk gone");
            }

            _served = true;
            buffer.Span[0] = (byte)'a';
            return ValueTask.FromResult(1);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>A stream that never ends and never has data (a pipe nobody writes to): only cancellation stops a read.</summary>
    private sealed class EndlessStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
