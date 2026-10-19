using Microsoft.Extensions.Logging;
using SshSharp.Config;

namespace SshSharp;

/// <summary>
/// Options for <see cref="SshClient.ConnectAsync(string, SshConfigConnectOptions?, CancellationToken)"/>, which takes everything else
/// from <c>ssh_config</c>: host name, port, user, identity files, known_hosts and StrictHostKeyChecking, algorithms, ProxyJump,
/// ProxyCommand, ServerAliveInterval, ConnectTimeout, ConnectionAttempts and AddressFamily. A few of these can be set here instead,
/// overriding what the configuration says: <see cref="Port"/>, <see cref="ConnectTimeout"/>, <see cref="ConnectionAttempts"/>,
/// <see cref="AddressFamily"/>, <see cref="KeepAliveInterval"/> and <see cref="KeepAliveCountMax"/>, as <see cref="HostKeyVerifier"/>
/// and <see cref="Proxy"/> do for host key checking and the first network hop.
/// </summary>
public sealed class SshConfigConnectOptions
{
    /// <summary>The configuration to resolve against. Default: the user's and the system's files (<see cref="SshConfig.LoadDefault"/>).</summary>
    public SshConfig? Config { get; init; }

    /// <summary>Inputs for resolution (home directory, environment, <c>Match exec</c> runner, ...). Default: the current process's.</summary>
    public SshConfigResolveOptions? ResolveOptions { get; init; }

    /// <summary>
    /// The destination's password, sent with the <c>password</c> method unless <c>PasswordAuthentication</c> is <c>no</c>, or through
    /// keyboard-interactive (see <see cref="SshClientOptions.Password"/>) unless <c>KbdInteractiveAuthentication</c> is <c>no</c>. Never
    /// offered to a ProxyJump hop, which logs in with keys or the agent.
    /// </summary>
    [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
    public string? Password { get; init; }

    /// <summary>
    /// Asks for the destination's password when authentication reaches it, at most <c>NumberOfPasswordPrompts</c> times (default 3); see
    /// <see cref="SshClientOptions.PasswordProvider"/>. Not called in <c>BatchMode</c>, when both <c>PasswordAuthentication</c> and
    /// <c>KbdInteractiveAuthentication</c> are <c>no</c>, or for a ProxyJump hop.
    /// </summary>
    public Func<SshPasswordPrompt, CancellationToken, ValueTask<string?>>? PasswordProvider { get; init; }

    /// <summary>
    /// Answers the destination's request to change an expired password (see <see cref="SshClientOptions.ChangePassword"/>). Not called
    /// in <c>BatchMode</c> or for a ProxyJump hop.
    /// </summary>
    public Func<SshPasswordChangeRequest, CancellationToken, ValueTask<string?>>? ChangePassword { get; init; }

    /// <summary>
    /// Answers the destination's keyboard-interactive authentication (see <see cref="SshClientOptions.KeyboardInteractive"/>). Not called
    /// in <c>BatchMode</c>, with <c>KbdInteractiveAuthentication no</c>, or for a ProxyJump hop.
    /// </summary>
    public Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>>? KeyboardInteractive { get; init; }

    /// <summary>Receives the server's pre-authentication banner (see <see cref="SshClientOptions.AuthenticationBanner"/>).</summary>
    public Func<string, CancellationToken, ValueTask>? AuthenticationBanner { get; init; }

    /// <summary>
    /// Asked for the passphrase of an encrypted <c>IdentityFile</c> (the argument is the file's path). Return null to skip that key.
    /// Not called in <c>BatchMode</c>. Without it, encrypted identity files are skipped.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<string?>>? PassphraseProvider { get; init; }

    /// <summary>
    /// Answers <c>AddKeysToAgent ask</c>: called for each identity-file key the server accepted, before it goes to the agent, as ssh
    /// asks through <c>SSH_ASKPASS</c> ("Add key ... to agent?"). Complete with true to add it (with no lifetime or confirmation
    /// constraint, as ssh adds it), false to leave it out. Without it, or in <c>BatchMode</c>, <c>ask</c> adds nothing, as ssh does when
    /// it cannot ask. Called after the connection is made; the caller's token, not <c>ConnectTimeout</c>, bounds it. What it throws
    /// closes the new connection and is thrown from <c>ConnectAsync</c>.
    /// </summary>
    public Func<SshAddKeyToAgentPrompt, CancellationToken, ValueTask<bool>>? ConfirmAddKeyToAgent { get; init; }

    /// <summary>
    /// Keys to offer the destination before its configured <c>IdentityFile</c>s. The client does not dispose them. Never offered to a
    /// ProxyJump hop, which logs in with its own configuration's identity files and the agent, as <see cref="Password"/> is never sent
    /// to one. (Before 1.1 they were offered to every hop too: a hop that needs one of these keys now needs it in its own
    /// <c>IdentityFile</c>, or in the agent.)
    /// </summary>
    public IReadOnlyList<SshPrivateKey> PrivateKeys { get; init; } = [];

    /// <summary>
    /// Whether to offer the SSH agent's keys, as ssh does: the agent named by <c>IdentityAgent</c>, or <see cref="SshAgent.FromEnvironment"/>.
    /// With <c>IdentitiesOnly yes</c>, only agent keys that match an <c>IdentityFile</c> are offered. Default true.
    /// </summary>
    public bool UseAgent { get; init; } = true;

    /// <summary>
    /// The agent to use instead of the configured or environment one: another agent's path, or an in-process one
    /// (<see cref="SshAgent.FromKeys"/>). It is also the agent <c>ForwardAgent yes</c> forwards.
    /// </summary>
    public SshAgent? Agent { get; init; }

    /// <summary>
    /// Decides what programs on the server may do with the forwarded agent (<c>ForwardAgent yes</c>), for the destination and every
    /// <c>ProxyJump</c> hop that forwards it; see <see cref="SshClientOptions.ForwardAgentFilter"/>.
    /// </summary>
    public Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? ForwardAgentFilter { get; init; }

    /// <summary>
    /// Start the destination's <c>LocalForward</c>, <c>RemoteForward</c> and <c>DynamicForward</c> forwardings once connected, as ssh does
    /// (see <see cref="SshClient.LocalForwardings"/> and its siblings). Off by default: forwardings open listening ports, which a library
    /// should not do unasked. <c>GatewayPorts</c>, <c>ExitOnForwardFailure</c> and <c>ClearAllForwardings</c> apply.
    /// </summary>
    public bool StartForwardings { get; init; }

    /// <summary>
    /// Replaces the default host key verification, which is a <see cref="KnownHostsVerifier"/> built from the host's configuration
    /// (<c>UserKnownHostsFile</c>, <c>GlobalKnownHostsFile</c>, <c>StrictHostKeyChecking</c>, <c>HashKnownHosts</c>).
    /// </summary>
    public SshHostKeyVerifier? HostKeyVerifier { get; init; }

    /// <summary>Answers <c>StrictHostKeyChecking ask</c> for an unknown host key (see <see cref="KnownHostsVerifier.AskHostKey"/>). Not called in <c>BatchMode</c>.</summary>
    public Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? AskHostKey { get; init; }

    /// <summary>Confirms known_hosts changes under <c>UpdateHostKeys ask</c> (see <see cref="KnownHostsVerifier.ConfirmHostKeyUpdate"/>). Without it, <c>ask</c> leaves known_hosts alone. Not called in <c>BatchMode</c>.</summary>
    public Func<SshHostKeyUpdate, CancellationToken, ValueTask<bool>>? ConfirmHostKeyUpdate { get; init; }

    /// <summary>Whether a configured <c>ProxyCommand</c> may be run (it is a local shell command, as in OpenSSH). Default true.</summary>
    public bool AllowProxyCommand { get; init; } = true;

    /// <summary>
    /// Whether a configured <c>KnownHostsCommand</c> may be run (a local shell command whose output is trusted as known_hosts lines).
    /// Default false: unlike <c>ProxyCommand</c>, which only carries the connection, this one decides which host keys are trusted, so a
    /// configuration the application does not control must not be able to supply them. Off, a configuration that names one fails the
    /// connection rather than silently checking fewer keys than it says.
    /// </summary>
    public bool AllowKnownHostsCommand { get; init; }

    /// <summary>Receives diagnostics for this connection and every jump host.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>
    /// An HTTP or SOCKS proxy for the first network hop: the destination, or the first ProxyJump host (later hops are reached through
    /// SSH). Not used for a host with a <c>ProxyCommand</c>, which makes its own connection.
    /// </summary>
    public SshProxy? Proxy { get; init; }

    /// <summary>
    /// The destination's port, overriding ssh_config's <c>Port</c> as <c>ssh -p</c> does: resolution sees it too (<c>%p</c>, and the
    /// port a <c>Match</c> block and the result report). A port in an <c>ssh://host:port</c> destination wins. Not used for ProxyJump
    /// hops, whose ports come from their own entries and configuration. Null (the default) leaves it to ssh_config (22 when unset).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not between 1 and 65535.</exception>
    public int? Port
    {
        get => _port;
        init
        {
            if (value is { } port)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(port, 1, nameof(value));
                ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535, nameof(value));
            }

            _port = value;
        }
    }

    private readonly int? _port;

    /// <summary>
    /// Overrides ssh_config's <c>ConnectTimeout</c> for the destination and every ProxyJump hop: how long each may take, from loading
    /// its identity files through authentication (see <see cref="SshClientOptions.ConnectTimeout"/>). A hop's time counts toward the
    /// host it leads to. <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> sets no limit whatever the configuration says; null (the
    /// default) leaves it to ssh_config.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero or negative (other than infinite), or longer than about 24 days.</exception>
    public TimeSpan? ConnectTimeout
    {
        get => _connectTimeout;
        init
        {
            if (value is { } limit && limit != System.Threading.Timeout.InfiniteTimeSpan && (limit <= TimeSpan.Zero || limit.TotalMilliseconds > int.MaxValue))
            {
                throw new ArgumentOutOfRangeException(nameof(value), limit, "The connect timeout must be positive (at most about 24 days), infinite, or null.");
            }

            _connectTimeout = value;
        }
    }

    private readonly TimeSpan? _connectTimeout;

    /// <summary>
    /// Overrides ssh_config's <c>ConnectionAttempts</c> for the destination and every ProxyJump hop: how many times to try the TCP
    /// connection (to the server, or to <see cref="Proxy"/>), one second apart. Only failures to reach it are tried again (refused,
    /// unreachable, timed out), never a failed handshake or authentication, and the <c>ConnectTimeout</c> bounds all the attempts
    /// together. Null (the default) leaves it to ssh_config (1 when unset).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1.</exception>
    public int? ConnectionAttempts
    {
        get => _connectionAttempts;
        init
        {
            if (value is { } attempts)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(attempts, 1, nameof(value));
            }

            _connectionAttempts = value;
        }
    }

    private readonly int? _connectionAttempts;

    /// <summary>
    /// Overrides ssh_config's <c>AddressFamily</c>: which of the server's addresses are tried (see
    /// <see cref="SshClientOptions.AddressFamily"/>). It applies to the first network connection, the only one this machine makes: to the
    /// destination, or to the first ProxyJump hop. Not with a <c>ProxyCommand</c> or a <see cref="Proxy"/>, which make the connection.
    /// Null (the default) leaves it to ssh_config.
    /// </summary>
    public SshAddressFamily? AddressFamily { get; init; }

    /// <summary>
    /// Sets socket options on the TCP connection this machine makes: to the destination, or to the first ProxyJump hop (see
    /// <see cref="SshClientOptions.ConfigureSocket"/>). It runs after the settings ssh_config gives the socket (<c>TCPKeepAlive</c>,
    /// on unless the configuration says <c>no</c>, and <c>IPQoS</c>), so what it sets wins. Not called with a <c>ProxyCommand</c> or a
    /// <see cref="Proxy"/>, which make the connection; hosts reached through a ProxyJump hop are tunnels, with no socket of their own.
    /// What it throws ends the attempt and is thrown from <c>ConnectAsync</c> as it is.
    /// </summary>
    public Action<System.Net.Sockets.Socket>? ConfigureSocket { get; init; }

    /// <summary>
    /// Overrides ssh_config's <c>ServerAliveInterval</c> for the destination and every ProxyJump hop (see
    /// <see cref="SshClientOptions.KeepAliveInterval"/>). <see cref="TimeSpan.Zero"/> sends no keep-alives whatever the configuration
    /// says; null (the default) leaves it to ssh_config.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan? KeepAliveInterval
    {
        get => _keepAliveInterval;
        init
        {
            if (value is { } interval && interval < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), interval, "The keep-alive interval must not be negative.");
            }

            _keepAliveInterval = value;
        }
    }

    private readonly TimeSpan? _keepAliveInterval;

    /// <summary>
    /// Overrides ssh_config's <c>ServerAliveCountMax</c> for the destination and every ProxyJump hop (see
    /// <see cref="SshClientOptions.KeepAliveCountMax"/>). Null (the default) leaves it to ssh_config (3 when unset).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1.</exception>
    public int? KeepAliveCountMax
    {
        get => _keepAliveCountMax;
        init
        {
            if (value is { } count)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(count, 1, nameof(value));
            }

            _keepAliveCountMax = value;
        }
    }

    private readonly int? _keepAliveCountMax;

    /// <summary>Opens TCP connections; replaceable in tests.</summary>
    internal Func<string, int, SshAddressFamily, CancellationToken, ValueTask<(Stream Stream, IAsyncDisposable? Owner)>>? TcpConnector { get; init; }

    /// <summary>The clock for keep-alive and rekey timing; replaceable in tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Makes the GSS-API context for <c>GSSAPIAuthentication yes</c>; replaceable in tests (host, credential, delegate).</summary>
    internal Func<string, System.Net.NetworkCredential?, bool, SshSharp.Protocol.IGssapiContext>? GssapiContextFactory { get; init; }
}
