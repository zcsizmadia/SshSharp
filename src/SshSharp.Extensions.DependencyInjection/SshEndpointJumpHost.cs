using System.Diagnostics;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// A jump host (bastion) for <see cref="SshEndpointOptions.JumpHosts"/>: where it is, how to log in to it and how to verify its host key,
/// as <c>ssh -J</c> and ssh_config's <c>ProxyJump</c> reach a server through it. Mutable, so configuration can bind to it
/// (<c>Ssh:Deploy:JumpHosts:0:Host</c>). Each hop is offered only its own credentials: the endpoint's password and keys never reach a
/// jump host, and a jump host's never reach the endpoint.
/// </summary>
public sealed class SshEndpointJumpHost
{
    /// <summary>The jump host's name or address. Required. The first hop's is resolved locally (or by the endpoint's proxy), the others' by the hop before.</summary>
    public string? Host { get; set; }

    /// <summary>The jump host's SSH port (default 22).</summary>
    public int Port { get; set; } = 22;

    /// <summary>The user to log in to the jump host as. Required: it is not taken from the endpoint, whose user is the destination's.</summary>
    public string? UserName { get; set; }

    /// <summary>A password for the jump host, tried after any keys. Bind it from a secret store.</summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? Password { get; set; }

    /// <summary>Private key files (OpenSSH, PEM or PuTTY format) to log in to the jump host with, tried in order.</summary>
    public IList<string> PrivateKeyFiles { get; set; } = [];

    /// <summary>The passphrase of encrypted <see cref="PrivateKeyFiles"/>.</summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>
    /// Private keys given as values for the jump host, as <see cref="SshEndpointOptions.PrivateKeys"/> are for the endpoint: offered after
    /// <see cref="PrivateKeyFiles"/>, checked when the settings are validated.
    /// </summary>
    public IList<SshEndpointPrivateKey> PrivateKeys { get; set; } = [];

    /// <summary>
    /// Also offer the keys of the user's SSH agent to the jump host, after <see cref="PrivateKeyFiles"/> and <see cref="PrivateKeys"/>
    /// (see <see cref="SshEndpointOptions.UseAgent"/> for which agent). Off by default.
    /// </summary>
    public bool UseAgent { get; set; }

    /// <summary>
    /// Trust only these host keys for the jump host: SHA-256 fingerprints or public key lines, as
    /// <see cref="SshEndpointOptions.HostKeyFingerprints"/> takes them. They replace known_hosts for this hop.
    /// </summary>
    public IList<string> HostKeyFingerprints { get; set; } = [];

    /// <summary>
    /// The known_hosts files that hold the jump host's key. When neither these nor <see cref="HostKeyFingerprints"/> are set, the hop is
    /// checked against the endpoint's <see cref="SshEndpointOptions.KnownHostsFiles"/> (default <c>~/.ssh/known_hosts</c>), as ssh
    /// checks a ProxyJump host against the same files; an endpoint that pins its own fingerprints needs the hop's set here instead.
    /// </summary>
    public IList<string> KnownHostsFiles { get; set; } = [];

    /// <summary>
    /// Accept and record the jump host's key when it is not in the known_hosts files yet (<c>StrictHostKeyChecking accept-new</c>). A hop
    /// checked against the endpoint's files also follows the endpoint's <see cref="SshEndpointOptions.AcceptNewHostKeys"/>.
    /// </summary>
    public bool AcceptNewHostKeys { get; set; }
}
