using System.Text;
using Microsoft.Extensions.Logging;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Remote forwarding to a handler in this process (a port, or a Unix socket on the server): the fake server plays the connections, and
/// the handler is the application's code. Each test runs for both kinds (<c>unix</c>).
/// </summary>
public class RemoteForwardingHandlerTests
{
    private const string SocketPath = "/run/app/handler.sock";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, ILogger? logger = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            Logger = logger,
        }, leaveOpen: true, Timeout());
    }

    /// <summary>The forwarding under test: a remote port (the fake server picks 40000) or a Unix socket on the server.</summary>
    private sealed class Forwarding(SshRemotePortForwarder? port, SshRemoteSocketForwarder? socket) : IAsyncDisposable
    {
        public SshRemotePortForwarder? Port { get; } = port;

        public SshRemoteSocketForwarder? Socket { get; } = socket;

        public int ActiveConnections => Port?.ActiveConnections ?? Socket!.ActiveConnections;

        public ValueTask DisposeAsync() => Port is not null ? Port.DisposeAsync() : Socket!.DisposeAsync();
    }

    private static async Task<Forwarding> ForwardAsync(SshClient client, bool unix, Func<SshForwardedConnection, CancellationToken, Task> handler, int maxConnections = 100) =>
        unix
            ? new Forwarding(null, await client.ForwardRemoteUnixSocketAsync(SocketPath, handler, maxConnections, Timeout()))
            : new Forwarding(await client.ForwardRemotePortAsync("localhost", 0, handler, maxConnections, Timeout()), null);

    /// <summary>Plays a program on the server connecting to the forwarded port or socket; null when the client refuses it.</summary>
    private static Task<Stream?> ConnectRemoteAsync(FakeSessionServer server, Forwarding forwarding) =>
        forwarding.Port is { } port ? server.ConnectForwardedAsync(port.RemotePort) : server.ConnectForwardedSocketAsync(SocketPath);

    /// <summary>Reads everything the client sent, then answers it in upper case.</summary>
    private static async Task UpperCaseAsync(SshForwardedConnection connection, CancellationToken cancellationToken)
    {
        using var received = new MemoryStream();
        await connection.Stream.CopyToAsync(received, cancellationToken);
        await connection.Stream.WriteAsync(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(received.ToArray()).ToUpperInvariant()), cancellationToken);
    }

    /// <summary>What the remote program gets back for <paramref name="request"/>, sent with a half-close after it.</summary>
    private static async Task<string> ExchangeAsync(Stream remote, string request)
    {
        await remote.WriteAsync(Encoding.ASCII.GetBytes(request), Timeout());
        ((DuplexStream)remote).CloseWrite();
        return await ReadToEndAsync(remote);
    }

    private static async Task<string> ReadToEndAsync(Stream remote)
    {
        using var buffer = new MemoryStream();
        await remote.CopyToAsync(buffer, Timeout());
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    /// <summary>Waits for a condition the code under test brings about asynchronously; fails after 30 seconds.</summary>
    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("The condition did not come about.");
            }

            await Task.Delay(20);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TheHandler_ServesEachConnection_AndSeesWhereItCameFrom(bool unix)
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var seen = new List<SshForwardedConnection>();
        await using var forwarding = await ForwardAsync(client, unix, async (connection, ct) =>
        {
            lock (seen)
            {
                seen.Add(connection);
            }

            await UpperCaseAsync(connection, ct);
        });

        await using (var remote = (await ConnectRemoteAsync(server, forwarding))!)
        {
            await Assert.That(await ExchangeAsync(remote, "hello handler")).IsEqualTo("HELLO HANDLER");
        }

        var connection = seen.Single();
        if (unix)
        {
            await Assert.That(server.RemoteSocketForwards).Contains(SocketPath);
            await Assert.That(connection.RemoteSocketPath).IsEqualTo(SocketPath);
            await Assert.That((connection.BoundAddress, connection.BoundPort, connection.OriginatorAddress, connection.OriginatorPort))
                .IsEqualTo(((string?)null, (int?)null, (string?)null, (int?)null));
            await Assert.That((forwarding.Socket!.LocalHost, forwarding.Socket.LocalPort, forwarding.Socket.LocalSocketPath))
                .IsEqualTo(((string?)null, 0, (string?)null));
        }
        else
        {
            // The fake server picks port 40000 for port 0, and reports the originator 203.0.113.7:50123.
            await Assert.That(forwarding.Port!.RemotePort).IsEqualTo(40000);
            await Assert.That((forwarding.Port.LocalHost, forwarding.Port.LocalPort, forwarding.Port.IsDynamic)).IsEqualTo((string.Empty, 0, false));
            await Assert.That((connection.BoundAddress, connection.BoundPort, connection.OriginatorAddress, connection.OriginatorPort))
                .IsEqualTo(("localhost", (int?)40000, "203.0.113.7", (int?)50123));
            await Assert.That(connection.RemoteSocketPath).IsNull();
        }

        // The handler returned: its stream was disposed for it, so the connection is no longer counted.
        await WaitUntilAsync(() => forwarding.ActiveConnections == 0 && client.ForwardedConnections == 0);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConcurrentConnections_EachGetTheirOwnHandler(bool unix)
    {
        const int count = 5;
        var allIn = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = 0;
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarding = await ForwardAsync(client, unix, async (connection, ct) =>
        {
            // Every handler waits until all of them run at once.
            if (Interlocked.Increment(ref entered) == count)
            {
                allIn.SetResult();
            }

            await allIn.Task.WaitAsync(ct);
            await UpperCaseAsync(connection, ct);
        });

        var remotes = new List<Stream>();
        for (var i = 0; i < count; i++)
        {
            remotes.Add((await ConnectRemoteAsync(server, forwarding))!);
        }

        await allIn.Task.WaitAsync(Timeout());
        await Assert.That(forwarding.ActiveConnections).IsEqualTo(count);
        var answers = await Task.WhenAll(remotes.Select((remote, i) => ExchangeAsync(remote, $"request {i}")));
        await Assert.That(answers).IsEquivalentTo(Enumerable.Range(0, count).Select(i => $"REQUEST {i}"));
        foreach (var remote in remotes)
        {
            await remote.DisposeAsync();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConnectionsOverTheCap_AreRefused_UntilOneEnds(bool unix)
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);

        // Each handler holds its connection until the remote program ends it.
        await using var forwarding = await ForwardAsync(client, unix, UpperCaseAsync, maxConnections: 2);
        var first = (await ConnectRemoteAsync(server, forwarding))!;
        await using var second = (await ConnectRemoteAsync(server, forwarding))!;
        await Assert.That(await ConnectRemoteAsync(server, forwarding)).IsNull(); // refused at channel open
        await Assert.That(forwarding.ActiveConnections).IsEqualTo(2);
        await Assert.That(client.ForwardedConnections).IsEqualTo(2); // the refused one gave back its client-wide slot too

        await Assert.That(await ExchangeAsync(first, "done")).IsEqualTo("DONE");
        await first.DisposeAsync();
        await WaitUntilAsync(() => forwarding.ActiveConnections < 2);

        await using var third = await ConnectRemoteAsync(server, forwarding);
        await Assert.That(third).IsNotNull();
        await Assert.That(await ExchangeAsync(third!, "third")).IsEqualTo("THIRD");
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AHandlerThatThrows_ClosesOnlyItsConnection_AndIsLoggedWithoutItsMessage(bool unix)
    {
        var logger = new CapturingLogger();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, logger);
        await using var forwarding = await ForwardAsync(client, unix, async (connection, ct) =>
        {
            var first = new byte[1];
            await connection.Stream.ReadExactlyAsync(first, ct);
            if (first[0] == (byte)'!')
            {
                throw new InvalidOperationException("secret-payload-detail");
            }

            using var rest = new MemoryStream();
            await connection.Stream.CopyToAsync(rest, ct);
            await connection.Stream.WriteAsync(Encoding.ASCII.GetBytes(((char)first[0] + Encoding.ASCII.GetString(rest.ToArray())).ToUpperInvariant()), ct);
        });

        // A connection open across the failure is not affected by it.
        await using var survivor = (await ConnectRemoteAsync(server, forwarding))!;
        await survivor.WriteAsync("s"u8.ToArray(), Timeout());

        await using (var failing = (await ConnectRemoteAsync(server, forwarding))!)
        {
            // The handler throws: the connection is closed, with nothing sent back.
            await Assert.That(await ExchangeAsync(failing, "!boom")).IsEqualTo(string.Empty);
        }

        await Assert.That(await ExchangeAsync(survivor, "till alive")).IsEqualTo("STILL ALIVE");
        await using (var later = (await ConnectRemoteAsync(server, forwarding))!)
        {
            await Assert.That(await ExchangeAsync(later, "next")).IsEqualTo("NEXT");
        }

        await Assert.That(client.IsConnected).IsTrue();
        await WaitUntilAsync(() => logger.Messages.Any(m => m.Contains("failed with InvalidOperationException", StringComparison.Ordinal)));
        await Assert.That(string.Join("\n", logger.Messages)).DoesNotContain("secret-payload-detail");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AHandlerThatDoesNotRead_HoldsBackTheServer_AtTheChannelWindow(bool unix)
    {
        var startReading = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarding = await ForwardAsync(client, unix, async (connection, ct) =>
        {
            await startReading.Task.WaitAsync(ct);
            using var all = new MemoryStream();
            await connection.Stream.CopyToAsync(all, ct);
            received.SetResult(all.Length);
        });

        var remote = (await ConnectRemoteAsync(server, forwarding))!;
        var channel = server.LastChannelToClient!;

        // More than the client's window (2 MiB): the server may send only up to the window, and then waits.
        var payload = new byte[3 * 1024 * 1024];
        var sending = Task.Run(async () =>
        {
            await remote.WriteAsync(payload, Timeout());
            ((DuplexStream)remote).CloseWrite();
        });
        await WaitUntilAsync(() => FakeSessionServer.ClientWindowOf(channel) < channel.ClientMaxPacket);

        // A round trip on the same connection: anything the client sent before it (a window adjustment) has arrived by now. Nothing was
        // read, so nothing was given back.
        await client.RunCommandAsync("true", Timeout());
        await Assert.That(FakeSessionServer.ClientWindowOf(channel)).IsLessThan(channel.ClientMaxPacket);
        await Assert.That(received.Task.IsCompleted).IsFalse();

        // Once the handler reads, the window opens again and everything arrives.
        startReading.SetResult();
        await Assert.That(await received.Task.WaitAsync(Timeout())).IsEqualTo(payload.Length);
        await sending;
        await remote.DisposeAsync();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DisposingTheForwarder_CancelsItOnTheServer_AndCancelsTheHandlers(bool unix)
    {
        const int count = 3;
        var running = 0;
        var cancelled = 0;
        var allRunning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var forwarding = await ForwardAsync(client, unix, async (_, ct) =>
        {
            if (Interlocked.Increment(ref running) == count)
            {
                allRunning.SetResult();
            }

            try
            {
                await Task.Delay(System.Threading.Timeout.Infinite, ct);
            }
            catch (OperationCanceledException)
            {
                Interlocked.Increment(ref cancelled);
                throw;
            }
        });

        var remotes = new List<Stream>();
        for (var i = 0; i < count; i++)
        {
            remotes.Add((await ConnectRemoteAsync(server, forwarding))!);
        }

        await allRunning.Task.WaitAsync(Timeout());
        await forwarding.DisposeAsync();

        // Disposal waited for the handlers, which saw their token cancelled; their connections were closed.
        await Assert.That(Volatile.Read(ref cancelled)).IsEqualTo(count);
        await Assert.That(forwarding.ActiveConnections).IsEqualTo(0);
        foreach (var remote in remotes)
        {
            await Assert.That(await ReadToEndAsync(remote)).IsEqualTo(string.Empty);
            await remote.DisposeAsync();
        }

        if (unix)
        {
            await Assert.That(server.CancelledRemoteSocketForwards).IsEquivalentTo(new[] { SocketPath });
        }
        else
        {
            await Assert.That(server.CancelledRemoteForwards).IsEquivalentTo(new[] { forwarding.Port!.RemotePort });
        }

        await Assert.That(await ConnectRemoteAsync(server, forwarding)).IsNull(); // a late connection is refused
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AHandlerThatIgnoresItsToken_HasItsConnectionClosed_AfterTheGracePeriod()
    {
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        var forwarding = await ForwardAsync(client, unix: false, async (connection, _) =>
        {
            // Reads without the token: only the connection closing ends this.
            started.SetResult();
            var buffer = new byte[1024];
            try
            {
                while (await connection.Stream.ReadAsync(buffer, CancellationToken.None) > 0)
                {
                }
            }
            catch (ObjectDisposedException)
            {
                // Closed under it.
            }

            finished.SetResult();
        });

        await using var remote = (await ConnectRemoteAsync(server, forwarding))!;
        await started.Task.WaitAsync(Timeout());
        await forwarding.DisposeAsync().AsTask().WaitAsync(Timeout());
        await finished.Task.WaitAsync(Timeout());
        await Assert.That(await ReadToEndAsync(remote)).IsEqualTo(string.Empty);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TheConnectionEnding_CancelsTheHandlers(bool unix)
    {
        var running = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await using var forwarding = await ForwardAsync(client, unix, async (_, ct) =>
        {
            await using var registration = ct.Register(() => cancelled.TrySetResult());
            running.SetResult();
            await Task.Delay(System.Threading.Timeout.Infinite, ct);
        });

        _ = await ConnectRemoteAsync(server, forwarding);
        await running.Task.WaitAsync(Timeout());

        await server.Raw.CloseAsync(); // the server goes away
        await cancelled.Task.WaitAsync(Timeout());
        await WaitUntilAsync(() => forwarding.ActiveConnections == 0);
    }

    [Test]
    public async Task InvalidArguments_AreRejectedBeforeAnythingIsSent()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        Func<SshForwardedConnection, CancellationToken, Task> handler = (_, _) => Task.CompletedTask;
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.ForwardRemotePortAsync("localhost", 0, (Func<SshForwardedConnection, CancellationToken, Task>)null!));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemotePortAsync("localhost", 0, handler, maxConnections: 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemotePortAsync("localhost", 70000, handler));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardRemotePortAsync("local\nhost", 0, handler));
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.ForwardRemoteUnixSocketAsync("/run/x.sock", (Func<SshForwardedConnection, CancellationToken, Task>)null!));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardRemoteUnixSocketAsync("/run/x.sock", handler, maxConnections: 0));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ForwardRemoteUnixSocketAsync("/run/x\n.sock", handler));
        await Assert.That(server.RemoteForwards).IsEmpty();
        await Assert.That(server.RemoteSocketForwards).IsEmpty();
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception));
            }
        }
    }
}
