namespace SshSharp;

/// <summary>
/// A jump host (bastion) to reach the server through, as <c>ssh -J</c> and ssh_config's <c>ProxyJump</c> do: list them, first to last, in
/// <see cref="SshClientOptions.JumpHosts"/>. Each hop is a complete SSH connection of its own, with its own <see cref="Options"/>: user,
/// credentials, host key verification, algorithms and keep-alives. The next hop (or the destination) is reached through a
/// <c>direct-tcpip</c> channel the hop opens, and the hop only relays bytes it cannot decrypt.
/// </summary>
/// <remarks>
/// A hop is offered only what its own <see cref="Options"/> hold. The destination's password, keys and keyboard-interactive handler never
/// reach a jump host, and a jump host's never reach the destination.
/// </remarks>
public sealed class SshJumpHost
{
    /// <summary>A jump host at <paramref name="host"/>:<paramref name="port"/>, logged in to and verified with <paramref name="options"/>.</summary>
    /// <param name="host">The jump host's name or address. For the first hop, it is resolved locally (or by the destination's
    /// <see cref="SshClientOptions.Proxy"/>); for later hops, by the hop before it.</param>
    /// <param name="port">The jump host's SSH port.</param>
    /// <param name="options">The hop's user, credentials, <see cref="SshClientOptions.HostKeyVerifier"/> and other settings. Its
    /// <see cref="SshClientOptions.ConnectTimeout"/> bounds this hop's connection; the destination's bounds the whole chain. The network
    /// settings are the destination's: <see cref="SshClientOptions.Proxy"/>, <see cref="SshClientOptions.LocalEndPoint"/>,
    /// <see cref="SshClientOptions.AddressFamily"/>, <see cref="SshClientOptions.ConfigureSocket"/>,
    /// <see cref="SshClientOptions.ConnectionAttempts"/> and <see cref="SshClientOptions.StaggeredConnectDelay"/> of the destination's options
    /// apply to the first network connection, the first hop's, so the hop's must not be set (its <see cref="SshClientOptions.AddressFamily"/>,
    /// <see cref="SshClientOptions.ConfigureSocket"/>, <see cref="SshClientOptions.ConnectionAttempts"/> and
    /// <see cref="SshClientOptions.StaggeredConnectDelay"/> are not used). A hop has no jump hosts of its own: list every hop, in
    /// order, in the destination's <see cref="SshClientOptions.JumpHosts"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="host"/> is empty, or <paramref name="options"/> set
    /// <see cref="SshClientOptions.JumpHosts"/>, <see cref="SshClientOptions.Proxy"/> or <see cref="SshClientOptions.LocalEndPoint"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="port"/> is not between 1 and 65535.</exception>
    public SshJumpHost(string host, int port, SshClientOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        ArgumentNullException.ThrowIfNull(options);
        if (options.JumpHosts.Count > 0)
        {
            throw new ArgumentException("A jump host's options cannot list jump hosts of their own; list every hop, in order, in the destination's JumpHosts.",
                nameof(options));
        }

        if (options.Proxy is not null || options.LocalEndPoint is not null)
        {
            throw new ArgumentException("A jump host's options cannot set Proxy or LocalEndPoint: the destination's apply to the first network connection.",
                nameof(options));
        }

        Host = host;
        Port = port;
        Options = options;
    }

    /// <summary>The jump host's name or address.</summary>
    public string Host { get; }

    /// <summary>The jump host's SSH port.</summary>
    public int Port { get; }

    /// <summary>How to log in to the jump host and verify it.</summary>
    public SshClientOptions Options { get; }
}
