using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// Runs an application's handler for the connections a remote forwarding receives (<see cref="SshForwardedConnection"/>), shared by
/// <see cref="SshRemotePortForwarder"/> and <see cref="SshRemoteSocketForwarder"/>. Each connection is isolated: a handler that throws
/// closes its own channel only. On disposal the handlers are cancelled, given <see cref="ShutdownTimeout"/> to return, and the channels
/// of any still running are then closed under them.
/// </summary>
internal sealed class ForwardedHandlerSet(Func<SshForwardedConnection, CancellationToken, Task> handler, int maxConnections, ILogger logger,
    TimeProvider time)
{
    /// <summary>How long disposal waits for cancelled handlers to return before it closes their connections, unless set otherwise.</summary>
    internal static readonly TimeSpan DefaultShutdownTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The longest wait <see cref="ShutdownTimeout"/> takes, short of none at all (<see cref="Timeout.InfiniteTimeSpan"/>).</summary>
    internal static readonly TimeSpan MaxShutdownTimeout = TimeSpan.FromMilliseconds(int.MaxValue);

    private readonly HashSet<SshChannelStream> _open = [];

    // Ticks, read and written whole: the forwarder's property may be set from any thread while disposal reads it.
    private long _shutdownTimeoutTicks = DefaultShutdownTimeout.Ticks;

    /// <summary>The most connections the forwarding serves at once; the server's channels above it are refused.</summary>
    public int MaxConnections { get; } = maxConnections;

    /// <summary>How long <see cref="StopAsync"/> waits for the handlers; checked by the forwarder's setter.</summary>
    public TimeSpan ShutdownTimeout
    {
        get => TimeSpan.FromTicks(Interlocked.Read(ref _shutdownTimeoutTicks));
        set => Interlocked.Exchange(ref _shutdownTimeoutTicks, value.Ticks);
    }

    /// <summary>
    /// Checks a value for a forwarder's <c>HandlerShutdownTimeout</c>: zero or more, up to <see cref="MaxShutdownTimeout"/>, or
    /// <see cref="Timeout.InfiniteTimeSpan"/>.
    /// </summary>
    public static TimeSpan Validate(TimeSpan value, string paramName)
    {
        if (value != Timeout.InfiniteTimeSpan)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero, paramName);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, MaxShutdownTimeout, paramName);
        }

        return value;
    }

    /// <summary>
    /// Runs the handler for one connection and disposes its stream when the handler returns (a no-op when the handler already did).
    /// Never faults: a handler's exception is logged, by type only, since its message can carry anything the application put there.
    /// </summary>
    public async Task RunAsync(SshForwardedConnection connection, SshChannelStream stream, int remotePort, CancellationToken stop)
    {
        lock (_open)
        {
            _open.Add(stream);
        }

        try
        {
            await handler(connection, stop).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // The forwarding was disposed or the connection ended: the handler stopped as asked.
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The handler is the application's code, and its failure must end this connection only (but not hide the process running
            // out of memory).
            SshLog.RemoteForwardingHandlerFailed(logger, remotePort, ex.GetType().Name);
        }
        finally
        {
            lock (_open)
            {
                _open.Remove(stream);
            }

            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Waits for the handlers (already cancelled) to return, up to <see cref="ShutdownTimeout"/> on the connection's clock, then closes
    /// the channels of those still running, so their reads end and their writes fail. Returns whether every handler has returned.
    /// <paramref name="handlers"/> must not fault.
    /// </summary>
    public async Task<bool> StopAsync(Task handlers)
    {
        try
        {
            await handlers.WaitAsync(ShutdownTimeout, time).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            // A handler that ignores its token: close its connection under it.
        }

        SshChannelStream[] stuck;
        lock (_open)
        {
            stuck = [.. _open];
        }

        foreach (var stream in stuck)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }

        return handlers.IsCompleted;
    }
}
