using SshSharp.Sftp;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>SFTP on the shared connections of <see cref="ISshConnectionProvider"/>.</summary>
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
        var client = await connections.GetClientAsync(name, cancellationToken).ConfigureAwait(false);
        try
        {
            return await client.OpenSftpAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SshException) when (!client.IsConnected)
        {
            // The shared connection dropped before the provider noticed: the next GetClientAsync connects again.
            client = await connections.GetClientAsync(name, cancellationToken).ConfigureAwait(false);
            return await client.OpenSftpAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
