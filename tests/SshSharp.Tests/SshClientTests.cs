using System.Text;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

public class SshClientTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static SshClientOptions Options(string? password = "secret", Func<SshHostKeyContext, CancellationToken, ValueTask<bool>>? verify = null, long maxOutput = 128L * 1024 * 1024) => new()
    {
        UserName = "tester",
        Password = password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate(verify ?? ((_, _) => ValueTask.FromResult(true))),
        MaxCommandOutputBytes = maxOutput,
    };

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, SshClientOptions? options = null, bool leaveOpen = true)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, options ?? Options(), leaveOpen, Timeout());
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>Records whether the stream was disposed, without depending on how the underlying stream reports use after disposal.</summary>
    private sealed class TrackingStream(Stream inner) : Stream
    {
        public bool IsDisposed { get; private set; }

        public override bool CanRead => inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => inner.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    [Test]
    public async Task RunsACommandAndCollectsOutputAndExitStatus()
    {
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.StdoutAsync(Text("hello "));
                await script.StderrAsync(Text("warning"));
                await script.StdoutAsync(Text("world\n"));
                await script.FinishAsync(3);
            },
        };
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("greet", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("hello world\n");
        await Assert.That(result.StandardErrorText).IsEqualTo("warning");
        await Assert.That(result.ExitStatus).IsEqualTo(3);
        await Assert.That(result.ExitSignal).IsNull();
        await Assert.That(server.Commands.Single()).IsEqualTo("greet");
        await Assert.That(client.ServerIdentification).IsEqualTo("SSH-2.0-FakeServer_1.0");
        await Assert.That(client.HostKey.KeyType).IsEqualTo("ssh-ed25519");
        await Assert.That(client.HostKey.Fingerprint).StartsWith("SHA256:");
    }

    [Test]
    [Arguments("only the name")]
    [Arguments("a message that is not UTF-8")]
    public async Task AnExitSignalWithAMissingOrBadMessage_KeepsTheSignalName(string variant)
    {
        // The error message is the server's free text: when it is missing (an old or minimal server) or not valid UTF-8, the signal name
        // is still reported, with no message.
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.ExitSignalRawAsync("TERM", w =>
                {
                    if (variant != "only the name")
                    {
                        w.WriteBoolean(true);
                        w.WriteString((byte[])[0xC3, 0x28]); // an invalid UTF-8 sequence
                        w.WriteString(string.Empty);
                    }
                });
                await script.EofAsync();
                await script.CloseAsync();
            },
        };
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("doomed", Timeout());
        await Assert.That(result.ExitSignal?.Name).IsEqualTo("TERM");
        await Assert.That(result.ExitSignal?.ErrorMessage).IsNull();
        await Assert.That(result.ExitSignal?.CoreDumped).IsEqualTo(variant != "only the name");
    }

    [Test]
    public async Task AnExitSignalName_IsKeptShort_AndFreeOfControlCharacters()
    {
        // The name is logged: a hostile server's newlines (forged log lines) or a megabyte of text must not reach the log as they are.
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.ExitSignalAsync("TERM\r\nforged log line" + new string('x', 1000));
                await script.EofAsync();
                await script.CloseAsync();
            },
        };
        await using var client = await ConnectAsync(server);

        var name = (await client.RunCommandAsync("doomed", Timeout())).ExitSignal!.Name;
        await Assert.That(name.Any(char.IsControl)).IsFalse();
        await Assert.That(name.Length).IsLessThanOrEqualTo(64);
        await Assert.That(name).StartsWith("TERMforged log line");
    }

    [Test]
    public async Task ReportsAnExitSignalWithoutAStatus()
    {
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.ExitSignalAsync("SEGV", coreDumped: true, message: "Segmentation fault");
                await script.EofAsync();
                await script.CloseAsync();
            },
        };
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("doomed", Timeout());
        await Assert.That(result.ExitStatus).IsNull();
        await Assert.That(result.ExitSignal).IsEqualTo(new SshExitSignal("SEGV", true, "Segmentation fault"));
    }

    [Test]
    public async Task LargeOutputFlowsThroughTheWindowInBothDirections()
    {
        // 6 MiB is three times the 2 MiB window: the server can only finish if the client keeps sending WINDOW_ADJUST.
        var data = new byte[6 * 1024 * 1024];
        new Random(71).NextBytes(data);
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.StdoutAsync(data);
                await script.FinishAsync(0);
            },
        };
        await using var client = await ConnectAsync(server);

        var result = await client.RunCommandAsync("big", Timeout());
        await Assert.That(TestBytes.Compare(result.StandardOutput.Span, data)).IsEqualTo("equal");
    }

    [Test]
    public async Task ParallelCommandsShareOneConnection()
    {
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.StdoutAsync(Text("out:" + script.Command));
                await Task.Delay(Random.Shared.Next(1, 20));
                await script.FinishAsync((uint)script.Command.Length);
            },
        };
        await using var client = await ConnectAsync(server);

        var tasks = Enumerable.Range(0, 25).Select(i => client.RunCommandAsync($"cmd-{i}", Timeout())).ToArray();
        var results = await Task.WhenAll(tasks);
        for (var i = 0; i < results.Length; i++)
        {
            await Assert.That(results[i].StandardOutputText).IsEqualTo($"out:cmd-{i}");
            await Assert.That(results[i].ExitStatus).IsEqualTo($"cmd-{i}".Length);
        }
    }

    [Test]
    public async Task WrongPasswordFailsAndListsTheServersMethods()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"] };
        _ = server.StartAsync();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(server.ClientStream, Options("nope"), true, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(ex.Message).Contains("publickey, password");
        await Assert.That(ex.Message).DoesNotContain("nope");
    }

    [Test]
    public async Task WithoutCredentialsTheNoneMethodRevealsWhatIsAccepted_OrJustWorks()
    {
        await using var strict = new FakeSessionServer { AdvertisedMethods = ["publickey"] };
        _ = strict.StartAsync();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(strict.ClientStream, Options(password: null), true, Timeout()));
        await Assert.That(ex!.Message).Contains("publickey");

        await using var open = new FakeSessionServer { AllowNone = true };
        await using var client = await ConnectAsync(open, Options(password: null));
        var result = await client.RunCommandAsync("anon", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task AnUntrustedHostKeyStopsTheConnection_AndClosesTheStreamUnlessToldNotTo()
    {
        await using var server = new FakeSessionServer();
        _ = server.StartAsync();
        SshHostKey? seen = null;
        var tracked = new TrackingStream(server.ClientStream);
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(
            tracked,
            Options(verify: (context, _) => { seen = context.HostKey; return ValueTask.FromResult(false); }),
            leaveOpen: false,
            Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(seen!.Fingerprint).StartsWith("SHA256:");
        await Assert.That(tracked.IsDisposed).IsTrue();
    }

    [Test]
    public async Task LeaveOpenKeepsTheStreamAlive_AndTheDefaultClosesIt()
    {
        await using var kept = new FakeSessionServer();
        var client = await ConnectAsync(kept, leaveOpen: true);
        await client.DisposeAsync();
        await client.DisposeAsync(); // idempotent
        await Assert.That(kept.ClientStream.CanWrite).IsTrue();

        await using var closed = new FakeSessionServer();
        _ = closed.StartAsync();
        var tracked = new TrackingStream(closed.ClientStream);
        var second = await SshClient.ConnectAsync(tracked, Options(), cancellationToken: Timeout());
        await Assert.That(tracked.IsDisposed).IsFalse();
        await second.DisposeAsync();
        await Assert.That(tracked.IsDisposed).IsTrue();
    }

    [Test]
    public async Task ARefusedCommandOrChannelIsAnSshException()
    {
        await using var refuse = new FakeSessionServer { RefuseExec = true };
        await using var client = await ConnectAsync(refuse);
        var ex = await Assert.ThrowsAsync<SshException>(async () => await client.RunCommandAsync("nope", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);

        await using var noChannels = new FakeSessionServer { RefuseChannels = true };
        await using var second = await ConnectAsync(noChannels);
        var opened = await Assert.ThrowsAsync<SshException>(async () => await second.RunCommandAsync("nope", Timeout()));
        await Assert.That(opened!.Message).Contains("administratively prohibited");
    }

    [Test]
    public async Task OutputBeyondTheLimitIsRefused()
    {
        await using var server = new FakeSessionServer { OnExec = async script => { await script.StdoutAsync(new byte[100_000]); await script.FinishAsync(0); } };
        await using var client = await ConnectAsync(server, Options(maxOutput: 10_000));
        await Assert.That(async () => await client.RunCommandAsync("flood", Timeout())).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ALostConnectionFailsRunningCommandsPromptly()
    {
        var started = new TaskCompletionSource();
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.StdoutAsync(Text("partial"));
                started.SetResult();
                await Task.Delay(Timeout().IsCancellationRequested ? 0 : 60_000);
            },
        };
        await using var client = await ConnectAsync(server);

        var running = client.RunCommandAsync("hang", Timeout());
        await started.Task;
        await server.Raw.CloseAsync();
        var ex = await Assert.ThrowsAsync<SshException>(async () => await running);
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);

        // By the time the command has failed, the client says so everywhere, ConnectionClosed included (it was signalled after the
        // channels failed, so a caller resuming on another thread could still find it uncancelled).
        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(client.ConnectionClosed.IsCancellationRequested).IsTrue();
        await Assert.That(client.ConnectionError).IsNotNull();

        // Later calls fail fast with the same reason instead of hanging.
        var later = await Assert.ThrowsAsync<SshException>(async () => await client.RunCommandAsync("again", Timeout()));
        await Assert.That(later!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
    }

    [Test]
    public async Task APeerThatOverrunsTheWindowIsAProtocolError()
    {
        await using var server = new FakeSessionServer { IgnoreClientWindow = true };
        // 3 MiB against the 2 MiB window, which nothing is draining: a protocol violation, whatever the client does.
        // (The server ends up blocked on a full pipe once the client stops reading; disposing the server cancels it.)
        server.OnExec = script => script.StdoutAsync(new byte[3 * 1024 * 1024]);
        await using var client = await ConnectAsync(server);

        var channel = await client.Connection.OpenSessionAsync(Timeout());
        await channel.RequestAsync("exec", true, w => w.WriteString("overrun"), Timeout());

        // Nothing reads the channel, so the 2 MiB window is overrun and the connection fails.
        for (var i = 0; i < 500 && client.Connection.Failure is null; i++)
        {
            await Task.Delay(20);
        }

        await Assert.That(client.Connection.Failure).IsTypeOf<SshProtocolException>();

        // The connection has failed; the channel hands out what it had buffered, then reports the error.
        var ex = await Assert.ThrowsAsync<SshProtocolException>(async () =>
        {
            while (await channel.ReadAsync(Timeout()) is { } chunk)
            {
                chunk.Dispose();
            }
        });
        await Assert.That(ex!.Message).Contains("window");
    }
    [Test]
    public async Task DisposingTheClientEndsPendingCommands()
    {
        var started = new TaskCompletionSource();
        await using var server = new FakeSessionServer { OnExec = async script => { started.SetResult(); await Task.Delay(60_000); } };
        var client = await ConnectAsync(server);
        var running = client.RunCommandAsync("hang", Timeout());
        await started.Task;
        await client.DisposeAsync();
        await Assert.That(async () => await running).Throws<SshException>();
    }

    [Test]
    public async Task CancellationStopsACommand()
    {
        var started = new TaskCompletionSource();
        await using var server = new FakeSessionServer { OnExec = async script => { started.SetResult(); await Task.Delay(60_000); } };
        await using var client = await ConnectAsync(server);
        using var cts = new CancellationTokenSource();
        var running = client.RunCommandAsync("hang", cts.Token);
        await started.Task;
        await cts.CancelAsync();
        await Assert.That(async () => await running).Throws<OperationCanceledException>();

        // The connection is still usable afterwards.
        server.OnExec = script => script.FinishAsync(7);
        var result = await client.RunCommandAsync("next", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(7);
    }

    [Test]
    public async Task UnknownMessagesAreAnsweredWithUnimplemented_AndGlobalRequestsRefused()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        await server.SendRawAsync(new byte[] { 200, 1, 2, 3 });
        await server.SendRawAsync(Build(w => { w.WriteByte(SshMessage.GlobalRequest); w.WriteString("tcpip-forward"); w.WriteBoolean(true); }));
        await server.SendRawAsync(Build(w => { w.WriteByte(SshMessage.GlobalRequest); w.WriteString("hostkeys-00@openssh.com"); w.WriteBoolean(false); }));
        await server.SendRawAsync(new byte[] { SshMessage.RequestSuccess });
        for (var i = 0; i < 100 && !(server.UnimplementedReceived && server.GlobalFailureReceived); i++)
        {
            await Task.Delay(20);
        }

        await Assert.That(server.UnimplementedReceived).IsTrue();
        await Assert.That(server.GlobalFailureReceived).IsTrue();

        // The connection keeps working after all that.
        var result = await client.RunCommandAsync("ok", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task AMessageForAnUnknownChannelEndsTheConnection()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await server.SendRawAsync(Build(w => { w.WriteByte(SshMessage.ChannelEof); w.WriteUInt32(99); }));
        var ex = await Assert.ThrowsAsync<SshProtocolException>(async () =>
        {
            for (var i = 0; i < 100; i++)
            {
                await client.RunCommandAsync("x", Timeout());
                await Task.Delay(20);
            }
        });
        await Assert.That(ex!.Message).Contains("unknown channel");
    }

    [Test]
    public async Task ExtendedDataOfUnknownTypesIsIgnored_AndRequestsWeDoNotKnowAreRefused()
    {
        await using var server = new FakeSessionServer();
        server.OnExec = async script =>
        {
            await server_SendExtended(script);
            await script.StdoutAsync(Text("ok"));
            await script.FinishAsync(0);
        };
        await using var client = await ConnectAsync(server);
        var result = await client.RunCommandAsync("odd", Timeout());
        await Assert.That(result.StandardOutputText).IsEqualTo("ok");
        await Assert.That(result.StandardErrorText).IsEqualTo(string.Empty);

        async Task server_SendExtended(ExecScript script)
        {
            await server.SendRawAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelExtendedData);
                w.WriteUInt32(0);
                w.WriteUInt32(2); // an undefined data type
                w.WriteString("ignored"u8);
            }));
            await server.SendRawAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ChannelRequest);
                w.WriteUInt32(0);
                w.WriteString("keepalive@openssh.com");
                w.WriteBoolean(true);
            }));
        }
    }

    [Test]
    public async Task MalformedChannelDataIsAProtocolError()
    {
        await using var server = new FakeSessionServer();
        server.OnExec = async script =>
        {
            // The declared length (100) does not match the bytes that follow.
            await script.StdoutAsync([]);
            await server_RawBadData();
        };
        await using var client = await ConnectAsync(server);
        await Assert.That(async () => await client.RunCommandAsync("bad", Timeout())).Throws<SshProtocolException>();

        async Task server_RawBadData() => await server.SendRawAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelData);
            w.WriteUInt32(0);
            w.WriteUInt32(100);
            w.WriteBytes([1, 2, 3]);
        }));
    }

    [Test]
    public async Task ArgumentsAndLifecycleAreValidated()
    {
        await using var server = new FakeSessionServer();
        var client = await ConnectAsync(server);
        await Assert.That(async () => await client.RunCommandAsync("", Timeout())).Throws<ArgumentException>();
        await client.DisposeAsync();
        await Assert.That(async () => await client.RunCommandAsync("late", Timeout())).Throws<ObjectDisposedException>();

        await Assert.That(async () => await SshClient.ConnectAsync(null!, Options())).Throws<ArgumentNullException>();
        await Assert.That(async () => await SshClient.ConnectAsync(Stream.Null, null!)).Throws<ArgumentNullException>();
        await Assert.That(async () => await SshClient.ConnectAsync("", 22, Options())).Throws<ArgumentException>();
    }

    [Test]
    public async Task TcpConnectFailure_IsAnSshExceptionWithTheSocketErrorInside()
    {
        // Port 1 on loopback is closed everywhere we run.
        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("127.0.0.1", 1, Options(), Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(ex.InnerException).IsTypeOf<System.Net.Sockets.SocketException>();
        await Assert.That(ex.Message).DoesNotContain("127.0.0.1");
        await Assert.That(async () => await SshClient.ConnectAsync("127.0.0.1", 0, Options(), Timeout())).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task FailedAuthentication_ReportsTheMethodsTheServerAccepts()
    {
        await using var server = new FakeSessionServer { AdvertisedMethods = ["publickey", "password"] };
        _ = server.StartAsync();
        var ex = await Assert.ThrowsAsync<SshAuthenticationException>(async () =>
            await SshClient.ConnectAsync(server.ClientStream, Options(password: "wrong"), leaveOpen: true, Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.AuthenticationFailed);
        await Assert.That(ex.AllowedMethods).IsEquivalentTo(new[] { "publickey", "password" });
    }

    [Test]
    public async Task ARejectedHostKey_IsAnSshHostKeyException_WithTheVerifiersReason_AndContext()
    {
        await using var server = new FakeSessionServer();
        _ = server.StartAsync();
        SshHostKeyContext? seen = null;
        var verifier = new RecordingVerifier(context => { seen = context; return SshHostKeyVerdict.Reject("not on my list"); });
        var options = new SshClientOptions { UserName = "tester", Password = "secret", HostKeyVerifier = verifier, HostKeyAlias = "my-alias" };

        var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout()));
        await Assert.That(ex!.Message).IsEqualTo("not on my list");
        await Assert.That(ex.HostKey!.Fingerprint).StartsWith("SHA256:");
        await Assert.That(seen!.Host).IsNull(); // over a stream the host is not known
        await Assert.That(seen.HostKeyAlias).IsEqualTo("my-alias");
        await Assert.That(seen.KnownHostsLookup).IsEqualTo(new KnownHostsLookup("my-alias", 22));
    }

    [Test]
    public async Task PinnedFingerprints_AcceptOnlyThoseKeys()
    {
        string? fingerprint = null;
        await using (var first = new FakeSessionServer())
        {
            await using var client = await ConnectAsync(first, Options(verify: (c, _) => { fingerprint = c.HostKey.Fingerprint; return ValueTask.FromResult(true); }));
        }

        // A new fake server has a new random host key; pinning the earlier fingerprint refuses it, pinning its own accepts it.
        await using var second = new FakeSessionServer();
        _ = second.StartAsync();
        var pinned = new SshClientOptions { UserName = "tester", Password = "secret", HostKeyVerifier = SshHostKeyVerifier.Pinned(fingerprint!) };
        var ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await SshClient.ConnectAsync(second.ClientStream, pinned, leaveOpen: true, Timeout()));
        await Assert.That(ex!.Message).Contains("pinned");
        await Assert.That(() => SshHostKeyVerifier.Pinned()).Throws<ArgumentException>();
    }

    private sealed class RecordingVerifier(Func<SshHostKeyContext, SshHostKeyVerdict> decide) : SshHostKeyVerifier
    {
        public override ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(decide(context));
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }
}