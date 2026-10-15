using Microsoft.Extensions.Logging;
using SshSharp.Config;

namespace SshSharp;

/// <summary>
/// Options for <see cref="SshClient.ConnectAsync(string, SshConfigConnectOptions?, CancellationToken)"/>, which takes everything else
/// from <c>ssh_config</c>: host name, port, user, identity files, known_hosts and StrictHostKeyChecking, algorithms, ProxyJump,
/// ProxyCommand, ServerAliveInterval, ConnectTimeout and AddressFamily.
/// </summary>
public sealed class SshConfigConnectOptions
{
    /// <summary>The configuration to resolve against. Default: the user's and the system's files (<see cref="SshConfig.LoadDefault"/>).</summary>
    public SshConfig? Config { get; init; }

    /// <summary>Inputs for resolution (home directory, environment, <c>Match exec</c> runner, ...). Default: the current process's.</summary>
    public SshConfigResolveOptions? ResolveOptions { get; init; }

    /// <summary>
    /// The password, sent with the <c>password</c> method unless <c>PasswordAuthentication</c> is <c>no</c>, or through
    /// keyboard-interactive (see <see cref="SshClientOptions.Password"/>) unless <c>KbdInteractiveAuthentication</c> is <c>no</c>.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Answers keyboard-interactive authentication (see <see cref="SshClientOptions.KeyboardInteractive"/>). Not called in <c>BatchMode</c>
    /// or with <c>KbdInteractiveAuthentication no</c>.
    /// </summary>
    public Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>>? KeyboardInteractive { get; init; }

    /// <summary>Receives the server's pre-authentication banner (see <see cref="SshClientOptions.AuthenticationBanner"/>).</summary>
    public Func<string, CancellationToken, ValueTask>? AuthenticationBanner { get; init; }

    /// <summary>
    /// Asked for the passphrase of an encrypted <c>IdentityFile</c> (the argument is the file's path). Return null to skip that key.
    /// Not called in <c>BatchMode</c>. Without it, encrypted identity files are skipped.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<string?>>? PassphraseProvider { get; init; }

    /// <summary>Keys to offer before the configured <c>IdentityFile</c>s. The client does not dispose them.</summary>
    public IReadOnlyList<SshPrivateKey> PrivateKeys { get; init; } = [];

    /// <summary>
    /// Whether to offer the SSH agent's keys, as ssh does: the agent named by <c>IdentityAgent</c>, or <see cref="SshAgent.FromEnvironment"/>.
    /// With <c>IdentitiesOnly yes</c>, only agent keys that match an <c>IdentityFile</c> are offered. Default true.
    /// </summary>
    public bool UseAgent { get; init; } = true;

    /// <summary>The agent to use instead of the configured or environment one.</summary>
    public SshAgent? Agent { get; init; }

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

    /// <summary>Answers <c>StrictHostKeyChecking ask</c> for an unknown host key (see <see cref="KnownHostsVerifier.Ask"/>). Not called in <c>BatchMode</c>.</summary>
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

    /// <summary>Opens TCP connections; replaceable in tests.</summary>
    internal Func<string, int, SshAddressFamily, CancellationToken, ValueTask<(Stream Stream, IAsyncDisposable? Owner)>>? TcpConnector { get; init; }

    /// <summary>The clock for keep-alive and rekey timing; replaceable in tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
