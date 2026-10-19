namespace SshSharp.Extensions.DependencyInjection;

/// <summary>The keyed <see cref="ISshEndpoint"/> of one name: the provider and the factory, for that name. Owns nothing.</summary>
internal sealed class SshEndpoint(string name, ISshConnectionProvider connections, ISshClientFactory factory) : ISshEndpoint
{
    public string Name => name;

    public Task<SshClient> GetClientAsync(CancellationToken cancellationToken = default) => connections.GetClientAsync(name, cancellationToken);

    public Task<SshClient> ConnectAsync(CancellationToken cancellationToken = default) => factory.ConnectAsync(name, cancellationToken);

    public IAsyncEnumerable<SshConnectionEvent> WatchAsync(CancellationToken cancellationToken = default) => connections.WatchAsync(name, cancellationToken);
}
