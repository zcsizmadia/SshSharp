using Microsoft.Extensions.Logging;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// Runs an application's handler for the connections a remote forwarding receives (<see cref="SshForwardedConnection"/>), shared by
/// <see cref="SshRemotePortForwarder"/> and <see cref="SshRemoteSocketForwarder"/>. Each connection is isolated: a handler that throws
/// closes its own channel only. On disposal the handlers are cancelled, given <see cref="ShutdownGrace"/> to return, and the channels of
/// any still running are then closed under them.
/// </summary>
internal sealed class ForwardedHandlerSet(Func<SshForwardedConnection, CancellationToken, Task> handler, int maxConnections, ILogger logger)
{
    /// <summary>How long disposal waits for cancelled handlers to return before it closes their connections.</summary>
    internal static readonly TimeSpan ShutdownGrace = TimeSpan.FromSeconds(5);

    private readonly HashSet<SshChannelStream> _open = [];

    /// <summary>The most connections the forwarding serves at once; the server's channels above it are refused.</summary>
    public int MaxConnections { get; } = maxConnections;

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
    /// Waits for the handlers (already cancelled) to return, up to <see cref="ShutdownGrace"/>, then closes the channels of those still
    /// running, so their reads end and their writes fail. Returns whether every handler has returned. <paramref name="handlers"/> must
    /// not fault.
    /// </summary>
    public async Task<bool> StopAsync(Task handlers)
    {
        try
        {
            await handlers.WaitAsync(ShutdownGrace).ConfigureAwait(false);
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
