using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>ChannelTimeout: channels without data for their type's timeout are closed by the client, as OpenSSH 9.2+ does.</summary>
public class ChannelTimeoutTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(40);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server, FakeTimeProvider time, params SshChannelTimeout[] timeouts)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            ChannelTimeouts = timeouts,
            TimeProvider = time,
        }, leaveOpen: true, Timeout());
    }

    /// <summary>Moves the fake clock a quarter of the limit at a time (the sweep's period), until <paramref name="done"/> or <paramref name="span"/> has passed.</summary>
    private static async Task AdvanceAsync(FakeTimeProvider time, TimeSpan span, Func<bool>? done = null)
    {
        for (var passed = TimeSpan.Zero; passed < span && !(done?.Invoke() ?? false); passed += Limit / 4)
        {
            time.Advance(Limit / 4);
            await Task.Delay(30);
        }

        for (var i = 0; done is not null && !done() && i < 200; i++)
        {
            await Task.Delay(10); // the close and the server's answer are on their way
        }
    }

    /// <summary>A shell that says nothing and reads its input until the client ends it.</summary>
    private static async Task NeverEnds(ExecScript script)
    {
        while (await script.ReadInputAsync() is not null)
        {
        }
    }

    [Test]
    public async Task AnIdleSession_IsClosed_AndItsOutputEnds()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer { OnShell = NeverEnds };
        await using var client = await ConnectAsync(server, time, new SshChannelTimeout("session", Limit));
        await using var session = await client.StartShellAsync(cancellationToken: Timeout());
        var read = session.StandardOutput.ReadAsync(new byte[16], Timeout()).AsTask();

        await AdvanceAsync(time, Limit * 3, () => server.Channels.Any(c => c.CloseReceived));

        await Assert.That(server.Channels.Single().CloseReceived).IsTrue();
        await Assert.That(await read.WaitAsync(Timeout())).IsEqualTo(0); // end of stream, as when the server closes it
        await Assert.That(client.IsConnected).IsTrue(); // only the channel ends
    }

    [Test]
    public async Task ASessionWithTraffic_StaysOpen()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer { OnShell = NeverEnds };
        await using var client = await ConnectAsync(server, time, new SshChannelTimeout("session", Limit));
        await using var session = await client.StartShellAsync(cancellationToken: Timeout());

        // Data every half limit, for three limits in all.
        for (var i = 0; i < 6; i++)
        {
            await session.StandardInput.WriteAsync("x"u8.ToArray(), Timeout());
            await AdvanceAsync(time, Limit / 2);
        }

        await Assert.That(server.Channels.Single().CloseReceived).IsFalse();
    }

    [Test]
    public async Task TheFirstMatchingType_Applies_AndZeroMeansNone()
    {
        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer { OnShell = NeverEnds, DirectTcpIp = (_, _) => new SilentStream() };
        await using var client = await ConnectAsync(server, time, new SshChannelTimeout("session", TimeSpan.Zero), new SshChannelTimeout("*", Limit));
        await using var session = await client.StartShellAsync(cancellationToken: Timeout());
        await using var tunnel = await client.OpenTcpTunnelAsync("db.internal", 5432, Timeout());

        var tunnelChannel = server.Channels.Single(c => c.Tunnel is not null);
        await AdvanceAsync(time, Limit * 3, () => tunnelChannel.CloseReceived);

        await Assert.That(tunnelChannel.CloseReceived).IsTrue(); // direct-tcpip matched "*"
        await Assert.That(server.Channels.Single(c => c != tunnelChannel).CloseReceived).IsFalse(); // session=0: no timeout
        await Assert.That(await tunnel.ReadAsync(new byte[1], Timeout())).IsEqualTo(0);
    }

    [Test]
    public async Task AnIdleRemoteForwarding_ClosesTheChannel_AndTheLocalConnection()
    {
        using var service = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        service.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Listen();
        var accepted = service.AcceptAsync(Timeout()).AsTask();

        var time = new FakeTimeProvider();
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server, time, new SshChannelTimeout("forwarded-tcpip", Limit));
        await using var forwarder = await client.ForwardRemotePortAsync("localhost", 8080, "127.0.0.1", ((IPEndPoint)service.LocalEndPoint!).Port, Timeout());
        await using var remote = (await server.ConnectForwardedAsync(forwarder.RemotePort))!;
        using var local = await accepted.WaitAsync(Timeout());

        await AdvanceAsync(time, Limit * 3, () => server.Channels.Any(c => c.CloseReceived));

        await Assert.That(server.Channels.Single().CloseReceived).IsTrue();
        await Assert.That(await remote.ReadAsync(new byte[1], Timeout())).IsEqualTo(0);
        await Assert.That(await local.ReceiveAsync(new byte[1], SocketFlags.None, Timeout())).IsEqualTo(0); // the relay closed its socket
    }

    [Test]
    public async Task Timeouts_MatchFirst_AndAreValidated()
    {
        SshChannelTimeout[] timeouts = [new("direct-*", TimeSpan.FromMinutes(1)), new("session", TimeSpan.Zero), new("*", TimeSpan.FromHours(1))];

        await Assert.That(SshChannelTimeout.For(timeouts, "direct-tcpip")).IsEqualTo(TimeSpan.FromMinutes(1));
        await Assert.That(SshChannelTimeout.For(timeouts, "direct-streamlocal@openssh.com")).IsEqualTo(TimeSpan.FromMinutes(1));
        await Assert.That(SshChannelTimeout.For(timeouts, "session")).IsNull();
        await Assert.That(SshChannelTimeout.For(timeouts, "agent-connection")).IsEqualTo(TimeSpan.FromHours(1));
        await Assert.That(SshChannelTimeout.For(timeouts, "Session")).IsEqualTo(TimeSpan.FromHours(1)); // case-sensitive, as OpenSSH
        await Assert.That(SshChannelTimeout.For([], "session")).IsNull();

        await Assert.That(() => new SshChannelTimeout("", TimeSpan.FromMinutes(1))).Throws<ArgumentException>();
        await Assert.That(() => new SshChannelTimeout("a b", TimeSpan.FromMinutes(1))).Throws<ArgumentException>();
        await Assert.That(() => new SshChannelTimeout("session", TimeSpan.FromSeconds(-1))).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments("ChannelTimeout session=5m direct-tcpip=1h *=0", "session=00:05:00|direct-tcpip=01:00:00|*=00:00:00")]
    [Arguments("ChannelTimeout none", "")]
    [Arguments("ChannelTimeout agent-connection=30 bogus =10 x=later", "agent-connection=00:00:30")]
    [Arguments("", "")]
    public async Task ChannelTimeout_IsReadFromSshConfig(string line, string expected)
    {
        var host = SshConfig.Parse($"Host *\n {line}\n").Resolve("h", new SshConfigResolveOptions { LocalUser = "l", HomeDirectory = "/h" });

        var actual = string.Join('|', host.ChannelTimeouts.Select(t => $"{t.ChannelType}={t.Timeout}"));
        await Assert.That(actual).IsEqualTo(expected);
    }

    /// <summary>A service that accepts a connection and never says anything (until it is closed).</summary>
    private sealed class SilentStream : Stream
    {
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _closed.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
        }

        protected override void Dispose(bool disposing)
        {
            _closed.TrySetResult();
            base.Dispose(disposing);
        }
    }
}
