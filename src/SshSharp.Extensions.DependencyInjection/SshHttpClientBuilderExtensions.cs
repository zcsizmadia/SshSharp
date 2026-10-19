using SshSharp.Extensions.DependencyInjection;

// In the namespace of IHttpClientBuilder, as Microsoft's own extensions of it are, so they are found without another using.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Sends an <see cref="HttpClient"/>'s requests through an SSH endpoint's shared connection.</summary>
public static class SshHttpClientBuilderExtensions
{
    /// <summary>
    /// Makes the named or typed <see cref="HttpClient"/> connect through the shared connection of the SSH endpoint
    /// <paramref name="endpointName"/> (<see cref="ISshConnectionProvider"/>): each of its TCP connections is a <c>direct-tcpip</c> channel
    /// from the server, as <c>ssh -L</c> opens, so it reaches services only the server reaches, such as an internal API behind a bastion.
    /// Host names in request URIs are resolved by the server. TLS still runs end to end, from here to the service.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It sets the client's primary handler to a <see cref="SocketsHttpHandler"/> whose
    /// <see cref="SocketsHttpHandler.ConnectCallback"/> opens the channel, with <see cref="SocketsHttpHandler.UseProxy"/> false (a system
    /// proxy would otherwise be connected to through the server instead of the service). <paramref name="configureHandler"/> can adjust
    /// that handler (TLS options, connection pool settings), but must leave those two as they are.
    /// </para>
    /// <para>
    /// The shared connection is opened on the first request, and again after it drops, as <see cref="ISshConnectionProvider.GetClientAsync"/>
    /// opens it. A channel that fails because the connection had just dropped is opened once more on a new connection; nothing had
    /// been sent through it. Requests already running on the dropped connection fail, and are not retried.
    /// </para>
    /// </remarks>
    /// <param name="builder">The HttpClient's builder, from <c>AddHttpClient</c>.</param>
    /// <param name="endpointName">The SSH endpoint, as registered with <c>AddSshClient</c>.</param>
    /// <param name="configureHandler">Adjusts the handler, or null.</param>
    /// <returns>The builder.</returns>
    /// <exception cref="InvalidOperationException">(When the handler is built.) No SSH endpoint is registered as
    /// <paramref name="endpointName"/>.</exception>
    public static IHttpClientBuilder UseSshTunnel(this IHttpClientBuilder builder, string endpointName, Action<SocketsHttpHandler>? configureHandler = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(endpointName);
        return builder.ConfigurePrimaryHttpMessageHandler(services =>
        {
            // Checked when the handler is built, so a misspelt name fails the first request plainly rather than inside every connection.
            (services.GetService<SshEndpointRegistry>() ?? new SshEndpointRegistry()).ThrowIfUnknown(endpointName);
            var connections = services.GetRequiredService<ISshConnectionProvider>();
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                ConnectCallback = async (context, cancellationToken) => await SshConnectionProviderExtensions.OpenTcpTunnelAsync(
                    connections, endpointName, context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false),
            };
            configureHandler?.Invoke(handler);
            return handler;
        });
    }
}
