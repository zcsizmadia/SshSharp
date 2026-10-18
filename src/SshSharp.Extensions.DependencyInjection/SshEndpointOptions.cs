using System.Diagnostics;

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
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? Password { get; set; }

    /// <summary>Private key files (OpenSSH, PEM or PuTTY format) to authenticate with, tried in order.</summary>
    public IList<string> PrivateKeyFiles { get; set; } = [];

    /// <summary>The passphrase of encrypted <see cref="PrivateKeyFiles"/>.</summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>
    /// Private keys given as values instead of files (from environment variables, a mounted secret, Key Vault or user secrets), each with
    /// its own optional passphrase. They are offered after <see cref="PrivateKeyFiles"/>, in order. Each is checked when the settings are
    /// validated (at start with <c>ValidateOnStart</c>), and read again for each connection, which does not keep it after authenticating.
    /// Cannot be combined with <see cref="ConfigAlias"/>.
    /// </summary>
    public IList<SshEndpointPrivateKey> PrivateKeys { get; set; } = [];

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
    /// Trust only host keys with one of these SHA-256 fingerprints, in OpenSSH's format (<c>SHA256:</c> and 43 base64 characters, as
    /// <c>ssh-keygen -lf</c> prints them), as <see cref="SshHostKeyVerifier.Pinned(string[])"/> does. They replace known_hosts: setting
    /// <see cref="KnownHostsFiles"/>, <see cref="AcceptNewHostKeys"/> or <see cref="ConfigAlias"/> as well fails validation, so it is
    /// never unclear which of them decides. List more than one to allow for a host key rotation.
    /// </summary>
    public IList<string> HostKeyFingerprints { get; set; } = [];

    /// <summary>
    /// An HTTP or SOCKS proxy to connect through, as a URI: <c>http://proxy.example.com:3128</c>, <c>socks5://</c>, <c>socks5h://</c>,
    /// <c>socks4://</c> or <c>socks4a://</c>, with optional percent-encoded <c>user:password@</c> (see <see cref="SshProxy.FromUri"/>).
    /// Bind it from a secret store when it holds a password. Cannot be combined with <see cref="ConfigAlias"/>, where ssh_config's
    /// <c>ProxyJump</c> or <c>ProxyCommand</c> apply.
    /// </summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? Proxy { get; set; }

    /// <summary>
    /// Connect by this <c>ssh_config</c> alias instead (ProxyJump, IdentityFile, known_hosts and the rest come from the user's and the
    /// system's ssh_config). <see cref="Host"/>, <see cref="Port"/>, <see cref="UserName"/>, <see cref="PrivateKeyFiles"/> and
    /// <see cref="KnownHostsFiles"/> are then ignored; <see cref="Password"/> is still offered. <see cref="PrivateKeys"/>,
    /// <see cref="HostKeyFingerprints"/> and <see cref="Proxy"/> cannot be combined with it (validation fails), as ssh_config decides
    /// keys, host keys and proxies there.
    /// </summary>
    public string? ConfigAlias { get; set; }

    /// <summary>Send keep-alives at this interval, so a dead connection is noticed (none by default).</summary>
    public TimeSpan? KeepAliveInterval { get; set; }

    /// <summary>
    /// How long one connection attempt, handshake and authentication included, may take (default 30 seconds). It is also the
    /// <see cref="SshClientOptions.ConnectTimeout"/> of the client options built from these settings, which
    /// <see cref="ConfigureClientOptions"/> may shorten; it cannot extend the attempt past this limit.
    /// </summary>
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
