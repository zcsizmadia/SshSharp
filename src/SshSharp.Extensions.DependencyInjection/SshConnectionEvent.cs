namespace SshSharp.Extensions.DependencyInjection;

/// <summary>What happened to an endpoint's shared connection, in a <see cref="SshConnectionEvent"/>.</summary>
public enum SshConnectionEventKind
{
    /// <summary>
    /// The shared connection is up: it was opened for the first time, or it was already up when watching began.
    /// </summary>
    Connected,

    /// <summary>
    /// The shared connection ended (the server or the network closed it, or a keep-alive went unanswered), or it had ended when watching
    /// began. The provider does not reconnect by itself: the next <see cref="ISshConnectionProvider.GetClientAsync"/> does.
    /// </summary>
    Disconnected,

    /// <summary>A new shared connection replaced one that had ended: forwardings and long-running commands of the old one are gone.</summary>
    Reconnected,
}

/// <summary>
/// A change of an endpoint's shared connection, from <see cref="ISshConnectionProvider.WatchAsync"/>. It names the endpoint by its
/// registered name only; no host or user name is in it.
/// </summary>
public sealed class SshConnectionEvent
{
    internal SshConnectionEvent(string endpointName, SshConnectionEventKind kind, SshClient client, Exception? error, DateTimeOffset timestamp)
    {
        EndpointName = endpointName;
        Kind = kind;
        Client = client;
        Error = error;
        Timestamp = timestamp;
    }

    /// <summary>The endpoint, as registered with <c>AddSshClient</c>.</summary>
    public string EndpointName { get; }

    /// <summary>What happened.</summary>
    public SshConnectionEventKind Kind { get; }

    /// <summary>
    /// The client concerned: the new connection for <see cref="SshConnectionEventKind.Connected"/> and
    /// <see cref="SshConnectionEventKind.Reconnected"/> (owned by the provider: do not dispose it), the one that ended for
    /// <see cref="SshConnectionEventKind.Disconnected"/> (no longer usable).
    /// </summary>
    /// <remarks>
    /// Events are delivered after the fact, so by the time one is handled the client may have ended and already been disposed: the
    /// provider disposes an ended connection when the next <see cref="ISshConnectionProvider.GetClientAsync"/> replaces it. Using it can
    /// then throw <see cref="ObjectDisposedException"/> as well as <see cref="SshException"/>; check <see cref="SshClient.IsConnected"/>
    /// when either is caught, and wait for the next event.
    /// </remarks>
    public SshClient Client { get; }

    /// <summary>
    /// Why the connection ended (<see cref="SshClient.ConnectionError"/>): for <see cref="SshConnectionEventKind.Disconnected"/>, and for
    /// <see cref="SshConnectionEventKind.Reconnected"/> the reason the previous connection ended. Null for
    /// <see cref="SshConnectionEventKind.Connected"/>. Its message can hold the server's disconnect text: log it, but keep it out of public
    /// responses.
    /// </summary>
    public Exception? Error { get; }

    /// <summary>When it happened (from the container's <see cref="TimeProvider"/>, if one is registered).</summary>
    public DateTimeOffset Timestamp { get; }
}
