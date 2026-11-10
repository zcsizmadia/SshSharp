using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// The replies the client owes the server (pongs, request replies, channel open refusals, UNIMPLEMENTED) are queued against one budget:
/// a server that keeps asking but stops reading must not grow the client's memory without limit.
/// </summary>
public class OwedReplyBudgetTests
{
    private const string Marker = "marker@example.com";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, Stream stream, SshAgent? agent = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(stream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ForwardAgent = agent,
        }, leaveOpen: true, Timeout());
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 6000 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        if (!condition())
        {
            throw new TimeoutException("The condition did not become true.");
        }
    }

    /// <summary>
    /// A global request of the client's that the server leaves unanswered until <see cref="AnswerMarkerAsync"/>. One loop receives
    /// everything in order, so when it completes, the client has handled everything the server sent before the answer.
    /// </summary>
    private static async Task<Task<GlobalReply>> SendMarkerAsync(SshClient client, FakeSessionServer server)
    {
        server.IgnoreGlobalRequests = true;
        var reply = client.Connection.SendGlobalRequestAsync(Marker, wantReply: true, null, Timeout());
        await WaitUntilAsync(() =>
        {
            lock (server.GlobalRequests)
            {
                return server.GlobalRequests.Contains(Marker);
            }
        });
        return reply;
    }

    private static ValueTask AnswerMarkerAsync(FakeSessionServer server) => server.SendRawAsync([SshMessage.RequestSuccess]);

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] GlobalRequest() => Build(w =>
    {
        w.WriteByte(SshMessage.GlobalRequest);
        w.WriteString("flood@example.com");
        w.WriteBoolean(true);
    });

    [Test]
    public async Task PingsFromAServerThatStopsReading_AreAnsweredUpToTheBudget_AndTheConnectionStays()
    {
        await using var server = new FakeSessionServer();
        var gated = new SshConnectionTests.GatedStream(server.ClientStream);
        await using var client = await ConnectAsync(server, gated);
        var marker = await SendMarkerAsync(client, server);

        // The server pings twice the budget's worth and reads nothing: the pongs past the budget are dropped, as pongs are optional.
        var data = new byte[1000];
        var ping = Build(w =>
        {
            w.WriteByte(SshMessage.Ping);
            w.WriteString(data);
        });
        var pongCost = 1 + 4 + data.Length + SshConnection.OwedReplyOverhead;
        gated.Stall();
        for (var i = 0; i < 2 * SshConnection.MaxOwedReplyBytes / pongCost; i++)
        {
            await server.SendRawAsync(ping);
        }

        await AnswerMarkerAsync(server);
        await marker.WaitAsync(Timeout());

        var expectedPongs = (int)(SshConnection.MaxOwedReplyBytes / pongCost);
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.Connection.OwedReplyBytes).IsEqualTo(expectedPongs * (long)pongCost);

        // Once the server reads again, the queued pongs go out and give the budget back, and the connection carries on.
        gated.Resume();
        await WaitUntilAsync(() => client.Connection.OwedReplyBytes == 0);
        server.IgnoreGlobalRequests = false;
        var result = await client.RunCommandAsync("after", Timeout());
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        int pongs;
        lock (server.Unrecognized)
        {
            pongs = server.Unrecognized.Count(m => m[0] == SshMessage.Pong);
        }

        await Assert.That(pongs).IsEqualTo(expectedPongs);
        await Assert.That(client.ConnectionError).IsNull();
    }

    [Test]
    [Arguments("global-request")]
    [Arguments("channel-request")]
    [Arguments("channel-open")]
    [Arguments("agent-channel-open")]
    [Arguments("unknown-message")]
    public async Task AServerThatKeepsAskingForRepliesButStopsReading_FailsTheConnection_WithinTheBudget(string kind)
    {
        await using var server = new FakeSessionServer();
        var gated = new SshConnectionTests.GatedStream(server.ClientStream);
        await using var client = await ConnectAsync(server, gated, kind == "agent-channel-open" ? SshAgent.FromKeys() : null);
        if (kind == "channel-request")
        {
            // A session for the server to send its requests on; it ends with the connection.
            await client.Connection.OpenSessionAsync(Timeout());
        }

        if (kind == "agent-channel-open")
        {
            // A session asks for agent forwarding, after which the client accepts the agent channels the server opens.
            await client.RunCommandAsync("true", Timeout());
        }

        var sessionId = kind == "channel-request" ? server.Channels.Single().ClientId : 0;
        Func<int, byte[]> request = kind switch
        {
            "global-request" => _ => GlobalRequest(),
            "channel-request" => _ => Build(w =>
            {
                w.WriteByte(SshMessage.ChannelRequest);
                w.WriteUInt32(sessionId);
                w.WriteString("flood@example.com");
                w.WriteBoolean(true);
            }),
            "channel-open" or "agent-channel-open" => i => Build(w =>
            {
                w.WriteByte(SshMessage.ChannelOpen);
                w.WriteString(kind == "channel-open" ? "x11" : "auth-agent@openssh.com");
                w.WriteUInt32(1_000_000 + (uint)i);
                w.WriteUInt32(2 * 1024 * 1024);
                w.WriteUInt32(32768);
            }),
            _ => _ => [199], // a local extension message number nobody here implements
        };

        var marker = await SendMarkerAsync(client, server);
        gated.Stall();

        // Even the smallest reply (one byte, plus its overhead) runs out of budget well within this many requests. The server sends
        // faster than the client receives, so a send can be waiting for the client to read when the connection fails, and the client
        // reads nothing after that: the sends stop when the connection does.
        var flood = Task.Run(async () =>
        {
            try
            {
                for (var i = 0; i < 2 * SshConnection.MaxOwedReplyBytes / (1 + SshConnection.OwedReplyOverhead); i++)
                {
                    await server.SendRawAsync(request(i), client.ConnectionClosed);
                }

                await AnswerMarkerAsync(server);
            }
            catch (OperationCanceledException) when (client.ConnectionClosed.IsCancellationRequested)
            {
                // The connection failed, as it should.
            }
        });

        var failure = await Assert.ThrowsAsync<SshProtocolException>(async () => await marker.WaitAsync(Timeout()));
        await flood.WaitAsync(Timeout());

        await Assert.That(failure!.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(failure.Message).Contains("not reading the replies it asked for");
        await Assert.That(client.IsConnected).IsFalse();
        await Assert.That(client.ConnectionError).IsSameReferenceAs(failure);
        await Assert.That(client.Connection.OwedReplyBytes).IsLessThanOrEqualTo(SshConnection.MaxOwedReplyBytes);
        gated.Resume();
    }

    [Test]
    public async Task ABurstOfRequestsWhileTheClientCannotSend_IsAnsweredInFull_OnceItCan()
    {
        await using var server = new FakeSessionServer();
        var gated = new SshConnectionTests.GatedStream(server.ClientStream);
        await using var client = await ConnectAsync(server, gated);
        var marker = await SendMarkerAsync(client, server);

        // Well under the budget: the replies wait, all of them, and nothing fails.
        const int burst = 1000;
        gated.Stall();
        for (var i = 0; i < burst; i++)
        {
            await server.SendRawAsync(GlobalRequest());
        }

        await AnswerMarkerAsync(server);
        await marker.WaitAsync(Timeout());
        await Assert.That(client.Connection.OwedReplyBytes).IsEqualTo(burst * (1L + SshConnection.OwedReplyOverhead));

        gated.Resume();
        await WaitUntilAsync(() => server.GlobalFailuresReceived == burst);
        await WaitUntilAsync(() => client.Connection.OwedReplyBytes == 0);
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.ConnectionError).IsNull();
    }

    [Test]
    public async Task AServerThatReads_HasEveryRequestAnswered_FarBeyondTheBudget()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, server.ClientStream);

        // The budget limits the replies waiting to be sent, not the replies over the connection's life: many times its worth all go out
        // to a server that reads them. Up to a thousand requests are outstanding at a time, far under the budget, so the test does not
        // depend on how fast either side runs.
        var total = (int)(10 * SshConnection.MaxOwedReplyBytes / (1 + SshConnection.OwedReplyOverhead));
        const int outstanding = 1000;
        for (var i = 0; i < total; i++)
        {
            if (i - server.GlobalFailuresReceived >= outstanding)
            {
                var sent = i;
                await WaitUntilAsync(() => sent - server.GlobalFailuresReceived < outstanding);
            }

            await server.SendRawAsync(GlobalRequest());
        }

        await WaitUntilAsync(() => server.GlobalFailuresReceived == total);
        await WaitUntilAsync(() => client.Connection.OwedReplyBytes == 0);
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(client.ConnectionError).IsNull();
    }
}
