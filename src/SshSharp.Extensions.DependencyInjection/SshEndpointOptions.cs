namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// One named SSH endpoint, registered with <c>services.AddSshClient(name)</c>: where to connect and how to authenticate. Mutable, so
/// configuration can bind to it (<c>.BindConfiguration("Ssh:Deploy")</c>). Set either <see cref="ConfigAlias"/>, to connect through
/// <c>ssh_config</c>, or <see cref="Host"/>.
/// </summary>
public sealed class SshEndpointOptions
{
    /// <summary>The server's host name or address. Required unless <see cref="ConfigAlias"/> is set.</summary>
    public string? Host { get; set; }

    /// <summary>The server's port (default 22).</summary>
    public int Port { get; set; } = 22;

    /// <summary>The user to log in as. Required unless <see cref="ConfigAlias"/> is set (then ssh_config, or the local user, decides).</summary>
    public string? UserName { get; set; }

    /// <summary>A password, tried after any keys. Keep it out of source control: bind it from a secret store.</summary>
    public string? Password { get; set; }

    /// <summary>Private key files (OpenSSH, PEM or PuTTY format) to authenticate with, tried in order.</summary>
    public IList<string> PrivateKeyFiles { get; set; } = [];

    /// <summary>The passphrase of encrypted <see cref="PrivateKeyFiles"/>.</summary>
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>
    /// The known_hosts files that hold the server's host keys (default: the user's <c>~/.ssh/known_hosts</c>). New keys are recorded in
    /// the first one when <see cref="AcceptNewHostKeys"/> is set.
    /// </summary>
    public IList<string> KnownHostsFiles { get; set; } = [];

    /// <summary>
    /// Accept and record the key of a host not yet in <see cref="KnownHostsFiles"/> (<c>StrictHostKeyChecking accept-new</c>). Off by
    /// default: an unknown host fails the connection. A changed key always fails it.
    /// </summary>
    public bool AcceptNewHostKeys { get; set; }

    /// <summary>
    /// Connect by this <c>ssh_config</c> alias instead (ProxyJump, IdentityFile, known_hosts and the rest come from the user's and the
    /// system's ssh_config). <see cref="Host"/>, <see cref="Port"/>, <see cref="UserName"/>, <see cref="PrivateKeyFiles"/> and
    /// <see cref="KnownHostsFiles"/> are then ignored; <see cref="Password"/> is still offered.
    /// </summary>
    public string? ConfigAlias { get; set; }

    /// <summary>Send keep-alives at this interval, so a dead connection is noticed (none by default).</summary>
    public TimeSpan? KeepAliveInterval { get; set; }

    /// <summary>How long one connection attempt, handshake and authentication included, may take (default 30 seconds).</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The wait before the shared connection's first reconnection attempt; it doubles after each failure (default 1 second).</summary>
    public TimeSpan ReconnectDelay { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>The longest wait between the shared connection's reconnection attempts (default 1 minute).</summary>
    public TimeSpan MaxReconnectDelay { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Adjusts the client options built from these settings (an agent, a custom host key verifier, keys held elsewhere, a proxy, ...):
    /// receives the services and the options built so far, and returns the options to use. Not used with <see cref="ConfigAlias"/>.
    /// </summary>
    public Func<IServiceProvider, SshClientOptions, SshClientOptions>? ConfigureClientOptions { get; set; }
}
