namespace SshSharp.Extensions.DependencyInjection;

/// <summary>Opens new connections to the endpoints registered with <c>services.AddSshClient(name)</c>.</summary>
public interface ISshClientFactory
{
    /// <summary>Connects to the endpoint registered as <paramref name="name"/>. The caller owns the client and disposes it.</summary>
    /// <exception cref="InvalidOperationException">No endpoint is registered as <paramref name="name"/>.</exception>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection or authentication failed.</exception>
    /// <exception cref="TimeoutException">The attempt took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    Task<SshClient> ConnectAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>
/// One long-lived connection per endpoint registered with <c>services.AddSshClient(name)</c>, shared by its callers and opened again
/// when it drops. The provider owns the clients and disposes them with the container: callers must not dispose them.
/// </summary>
public interface ISshConnectionProvider
{
    /// <summary>
    /// The connected client for <paramref name="name"/>: the shared one if it is still up, otherwise a new connection, which then
    /// becomes the shared one. Concurrent callers share one attempt. After a failed attempt the next one waits (from
    /// <see cref="SshEndpointOptions.ReconnectDelay"/>, doubling, up to <see cref="SshEndpointOptions.MaxReconnectDelay"/>); a call
    /// made during that wait fails at once, with an <see cref="SshException"/> whose inner exception is the last failure, rather than
    /// connecting again.
    /// </summary>
    /// <exception cref="InvalidOperationException">No endpoint is registered as <paramref name="name"/>.</exception>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection or authentication failed, now or (as its inner exception) in the last attempt.</exception>
    /// <exception cref="TimeoutException">The attempt took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    Task<SshClient> GetClientAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// The changes of the shared connection for <paramref name="name"/>, as they happen, until <paramref name="cancellationToken"/> is
    /// cancelled or the provider is disposed: <see cref="SshConnectionEventKind.Connected"/> when it is opened,
    /// <see cref="SshConnectionEventKind.Disconnected"/> when it ends, and <see cref="SshConnectionEventKind.Reconnected"/> when a new
    /// connection replaces it. Use it to restore what lived on the old connection (forwardings, long-running commands) on the new one.
    /// Each enumeration is a watcher of its own; none misses an event, however slowly it reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A watcher first gets the current state, when there is one: <see cref="SshConnectionEventKind.Connected"/> when the connection is
    /// up, <see cref="SshConnectionEventKind.Disconnected"/> when the last one ended and none has replaced it yet. So connecting first
    /// and then watching misses nothing.
    /// </para>
    /// <para>
    /// Watching does not connect or reconnect: the provider connects when <see cref="GetClientAsync"/> is called. A watcher that should
    /// keep the connection up calls <see cref="GetClientAsync"/> after <see cref="SshConnectionEventKind.Disconnected"/>, which waits
    /// between failed attempts as described there. Watching starts when the enumeration does (the first <c>MoveNextAsync</c>), and ends
    /// with it (cancelling, or leaving <c>await foreach</c>).
    /// </para>
    /// </remarks>
    /// <param name="name">The endpoint, as registered with <c>AddSshClient</c>.</param>
    /// <param name="cancellationToken">Stops watching; the enumeration then ends with <see cref="OperationCanceledException"/>.</param>
    /// <exception cref="InvalidOperationException">No endpoint is registered as <paramref name="name"/>.</exception>
    /// <exception cref="NotSupportedException">The implementation does not support watching (the default for implementations other than
    /// the package's own, such as test fakes written before it existed).</exception>
    IAsyncEnumerable<SshConnectionEvent> WatchAsync(string name, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException($"{GetType().Name} does not support watching connections.");
}

/// <summary>
/// One endpoint registered with <c>services.AddSshClient(name)</c>, resolved by its name as a keyed service:
/// <c>[FromKeyedServices("deploy")] ISshEndpoint deploy</c>, or <c>GetRequiredKeyedService&lt;ISshEndpoint&gt;("deploy")</c>. It is
/// <see cref="ISshConnectionProvider"/> and <see cref="ISshClientFactory"/> for that one name, with the same lifetimes: a singleton,
/// whose shared connection is the provider's.
/// </summary>
public interface ISshEndpoint
{
    /// <summary>The endpoint's name, as registered with <c>AddSshClient</c>.</summary>
    string Name { get; }

    /// <summary>The endpoint's shared connection, as <see cref="ISshConnectionProvider.GetClientAsync"/> returns it: owned by the provider, not to be disposed.</summary>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection or authentication failed, now or (as its inner exception) in the last attempt.</exception>
    /// <exception cref="TimeoutException">The attempt took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    Task<SshClient> GetClientAsync(CancellationToken cancellationToken = default);

    /// <summary>A new connection to the endpoint, as <see cref="ISshClientFactory.ConnectAsync"/> opens it: the caller owns it and disposes it.</summary>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection or authentication failed.</exception>
    /// <exception cref="TimeoutException">The attempt took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    Task<SshClient> ConnectAsync(CancellationToken cancellationToken = default);

    /// <summary>The changes of the endpoint's shared connection, as <see cref="ISshConnectionProvider.WatchAsync"/> gives them.</summary>
    IAsyncEnumerable<SshConnectionEvent> WatchAsync(CancellationToken cancellationToken = default);
}
