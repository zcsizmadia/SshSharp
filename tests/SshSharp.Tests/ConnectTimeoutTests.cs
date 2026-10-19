using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SshSharp.Config;

namespace SshSharp.Tests;

/// <summary>SshClientOptions.ConnectTimeout and SshClientOptions.AddressFamily (#270).</summary>
public sealed class ConnectTimeoutTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>Short, so a test spends little time waiting for it; the assertions do not depend on how short.</summary>
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);

    private static SshClientOptions Options(TimeSpan? connectTimeout, SshAddressFamily family = SshAddressFamily.Any) => new()
    {
        UserName = "tester",
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        ConnectTimeout = connectTimeout,
        AddressFamily = family,
    };

    /// <summary>
    /// A loopback listener that accepts connections and never says anything: a server that hangs before its identification. It holds the
    /// connections it accepted until disposed.
    /// </summary>
    private sealed class SilentListener : IAsyncDisposable
    {
        private readonly Socket _listener;
        private readonly List<Socket> _accepted = [];
        private readonly TaskCompletionSource _first = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _accepting;

        public SilentListener(IPAddress address, int port = 0)
        {
            _listener = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                _listener.DualMode = false; // only IPv6, so an IPv4 connection cannot arrive here
            }

            try
            {
                _listener.Bind(new IPEndPoint(address, port));
                _listener.Listen();
            }
            catch
            {
                _listener.Dispose();
                throw;
            }

            _accepting = AcceptAsync();
        }

        public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

        /// <summary>Completes when the first connection is accepted.</summary>
        public Task Accepted => _first.Task;

        private async Task AcceptAsync()
        {
            while (true)
            {
                Socket socket;
                try
                {
                    socket = await _listener.AcceptAsync();
                }
                catch (Exception)
                {
                    return; // disposed
                }

                lock (_accepted)
                {
                    _accepted.Add(socket);
                }

                _first.TrySetResult();
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Dispose();
            await _accepting;
            lock (_accepted)
            {
                foreach (var socket in _accepted)
                {
                    socket.Dispose();
                }
            }
        }
    }

    [Test]
    public async Task ConnectTimeout_StopsAServerThatNeverSendsItsIdentification()
    {
        await using var silent = new SilentListener(IPAddress.Loopback);
        var watch = Stopwatch.StartNew();

        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync("127.0.0.1", silent.Port, Options(Short), Timeout()));

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>();
        await Assert.That(ex.Message).Contains("ConnectTimeout");
        // The TCP connection was made: the handshake is what timed out. Awaited, not checked at once: the client's connect completes in
        // the listen backlog, and the listener's accept continuation, which completes Accepted, may not have run yet on a busy thread pool.
        await silent.Accepted.WaitAsync(Timeout());
        await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(20));
    }

    [Test]
    public async Task ConnectTimeout_OverAStream_BoundsTheHandshake()
    {
        await using var silent = new SilentListener(IPAddress.Loopback);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, silent.Port, Timeout());

        var ex = await Assert.ThrowsAsync<SshException>(async () => await SshClient.ConnectAsync(tcp.GetStream(), Options(Short), leaveOpen: true, Timeout()));

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(ex.InnerException).IsTypeOf<TimeoutException>();
    }

    [Test]
    public async Task TheCallersCancellation_IsACancellation_NotATimeout()
    {
        await using var silent = new SilentListener(IPAddress.Loopback);
        using var cancel = new CancellationTokenSource();

        // Cancelled once the connection is made, so the attempt is in the handshake, well within its (long) ConnectTimeout.
        var attempt = SshClient.ConnectAsync("127.0.0.1", silent.Port, Options(TimeSpan.FromMinutes(5)), cancel.Token);
        await silent.Accepted.WaitAsync(Timeout());
        await cancel.CancelAsync();

        await Assert.That(async () => await attempt).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task TheCallersCancellation_IsACancellation_WithNoConnectTimeout()
    {
        await using var silent = new SilentListener(IPAddress.Loopback);
        using var cancel = new CancellationTokenSource();

        var attempt = SshClient.ConnectAsync("127.0.0.1", silent.Port, Options(null), cancel.Token);
        await silent.Accepted.WaitAsync(Timeout());
        await cancel.CancelAsync();

        await Assert.That(async () => await attempt).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task ConnectTimeout_MustBePositive_InfiniteOrNull()
    {
        await Assert.That(() => Options(TimeSpan.Zero)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(TimeSpan.FromSeconds(-1))).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => Options(TimeSpan.FromDays(30))).Throws<ArgumentOutOfRangeException>();
        await Assert.That(Options(System.Threading.Timeout.InfiniteTimeSpan).ConnectTimeout).IsEqualTo(System.Threading.Timeout.InfiniteTimeSpan);
        await Assert.That(Options(null).ConnectTimeout).IsNull();
        await Assert.That(Options(null).AddressFamily).IsEqualTo(SshAddressFamily.Any);
    }

    [Test]
    [Arguments(SshAddressFamily.Inet)]
    [Arguments(SshAddressFamily.Inet6)]
    public async Task AddressFamily_ChoosesWhichAddressOfTheNameIsTried(SshAddressFamily family)
    {
        // "localhost" names both loopback addresses on most systems; a silent listener on each (same port) shows which one was tried.
        if (!Socket.OSSupportsIPv4 || !Socket.OSSupportsIPv6)
        {
            Skip.Test("This system lacks IPv4 or IPv6.");
            return;
        }

        var addresses = await Dns.GetHostAddressesAsync("localhost", Timeout());
        if (!addresses.Contains(IPAddress.Loopback) || !addresses.Contains(IPAddress.IPv6Loopback))
        {
            Skip.Test("localhost does not resolve to both 127.0.0.1 and ::1 here.");
            return;
        }

        await using var v4 = new SilentListener(IPAddress.Loopback);
        SilentListener v6;
        try
        {
            v6 = new SilentListener(IPAddress.IPv6Loopback, v4.Port);
        }
        catch (SocketException)
        {
            Skip.Test("The IPv4 listener's port is taken on ::1.");
            return;
        }

        await using (v6)
        {
            // No ConnectTimeout: under load, resolving "localhost" alone can outlast a short one, and the attempt then times out before
            // any address is tried (stress run 39100315796). The connection is watched until it arrives, then cancelled.
            using var cancel = new CancellationTokenSource();
            var connecting = SshClient.ConnectAsync("localhost", v4.Port, Options(null, family), cancel.Token);

            var (tried, other) = family == SshAddressFamily.Inet ? (v4, v6) : (v6, v4);
            await tried.Accepted.WaitAsync(Timeout());
            await cancel.CancelAsync();
            await Assert.ThrowsAsync<OperationCanceledException>(async () => await connecting);
            await Assert.That(other.Accepted.IsCompleted).IsFalse();
        }
    }

    [Test]
    public async Task AddressFamily_WithNoAddressOfThatFamily_FailsToConnect()
    {
        // An IPv4 literal has no IPv6 address: restricted to IPv6, there is nothing to try, and nothing reaches the listener.
        await using var silent = new SilentListener(IPAddress.Loopback);

        var ex = await Assert.ThrowsAsync<SshException>(async () =>
            await SshClient.ConnectAsync("127.0.0.1", silent.Port, Options(TimeSpan.FromSeconds(20), SshAddressFamily.Inet6), Timeout()));

        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(silent.Accepted.IsCompleted).IsFalse();
    }
}
