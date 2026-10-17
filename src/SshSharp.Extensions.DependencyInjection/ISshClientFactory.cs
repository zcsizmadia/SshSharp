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
    /// made during that wait fails at once with the last error rather than connecting again.
    /// </summary>
    /// <exception cref="InvalidOperationException">No endpoint is registered as <paramref name="name"/>.</exception>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection or authentication failed, now or in the last attempt.</exception>
    /// <exception cref="TimeoutException">The attempt took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    Task<SshClient> GetClientAsync(string name, CancellationToken cancellationToken = default);
}
