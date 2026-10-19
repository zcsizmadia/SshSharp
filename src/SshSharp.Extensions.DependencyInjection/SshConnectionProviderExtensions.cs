using SshSharp.Sftp;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>SFTP on the shared connections of <see cref="ISshConnectionProvider"/> and <see cref="ISshEndpoint"/>.</summary>
public static class SshConnectionProviderExtensions
{
    /// <summary>
    /// Opens a new SFTP session on the shared connection to the endpoint <paramref name="name"/>, connecting first if it is down. The
    /// caller owns the session and disposes it; the connection stays the provider's. As the session factory of
    /// <c>SftpFileProvider</c> or <c>SftpFileSystem</c>, it lets the adapter follow the shared connection: after a drop, the adapter's
    /// next session is opened on the new connection.
    /// </summary>
    /// <remarks>
    /// When the shared connection turns out to have dropped as the session opens, the provider connects again and the session is opened
    /// on the new connection, once.
    /// </remarks>
    /// <param name="connections">The shared connections.</param>
    /// <param name="name">The endpoint, as registered with <c>AddSshClient</c>.</param>
    /// <param name="cancellationToken">Cancels connecting and opening the session.</param>
    /// <exception cref="InvalidOperationException">No endpoint is registered as <paramref name="name"/>.</exception>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection failed (see <see cref="ISshConnectionProvider.GetClientAsync"/>), or the server
    /// offers no SFTP.</exception>
    /// <exception cref="TimeoutException">Connecting took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    public static async Task<SftpClient> OpenSftpAsync(this ISshConnectionProvider connections, string name, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentException.ThrowIfNullOrEmpty(name);
        return await OnSharedConnectionAsync(ct => connections.GetClientAsync(name, ct), static (client, ct) => client.OpenSftpAsync(ct), cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Opens a new SFTP session on the endpoint's shared connection, as
    /// <see cref="OpenSftpAsync(ISshConnectionProvider, string, CancellationToken)"/> does for its name.
    /// </summary>
    /// <param name="endpoint">The endpoint, resolved as a keyed service.</param>
    /// <param name="cancellationToken">Cancels connecting and opening the session.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">The endpoint's settings are invalid.</exception>
    /// <exception cref="SshException">The connection failed, or the server offers no SFTP.</exception>
    /// <exception cref="TimeoutException">Connecting took longer than <see cref="SshEndpointOptions.ConnectTimeout"/>.</exception>
    public static async Task<SftpClient> OpenSftpAsync(this ISshEndpoint endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return await OnSharedConnectionAsync(endpoint.GetClientAsync, static (client, ct) => client.OpenSftpAsync(ct), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens a TCP connection through the endpoint's shared connection (<see cref="SshClient.OpenTcpTunnelAsync"/>), as the
    /// HttpClient helper does for each of its connections. Retried once on a new shared connection when the old one turns out to have
    /// dropped: nothing has been sent through the tunnel by then.
    /// </summary>
    internal static Task<Stream> OpenTcpTunnelAsync(ISshConnectionProvider connections, string name, string host, int port, CancellationToken cancellationToken) =>
        OnSharedConnectionAsync(ct => connections.GetClientAsync(name, ct), (client, ct) => client.OpenTcpTunnelAsync(host, port, ct), cancellationToken);

    /// <summary>
    /// Opens something on the shared connection. When the shared connection turns out to have dropped (the provider had not noticed
    /// yet), the next <c>GetClientAsync</c> connects again, and it is opened there, once.
    /// </summary>
    private static async Task<T> OnSharedConnectionAsync<T>(Func<CancellationToken, Task<SshClient>> getClient, Func<SshClient, CancellationToken, Task<T>> open,
        CancellationToken cancellationToken)
    {
        var client = await getClient(cancellationToken).ConfigureAwait(false);
        try
        {
            return await open(client, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException) when (!client.IsConnected)
        {
            client = await getClient(cancellationToken).ConfigureAwait(false);
            return await open(client, cancellationToken).ConfigureAwait(false);
        }
    }
}
