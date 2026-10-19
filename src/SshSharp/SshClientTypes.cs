using Microsoft.Extensions.Logging;

namespace SshSharp;

/// <summary>The host key the server proved possession of during key exchange. Decide whether to trust it in <see cref="SshClientOptions.HostKeyVerifier"/>.</summary>
/// <param name="Algorithm">The negotiated signature algorithm, for example <c>rsa-sha2-512</c>.</param>
/// <param name="KeyType">The key type, for example <c>ssh-rsa</c>.</param>
/// <param name="Fingerprint">The OpenSSH-style SHA-256 fingerprint (<c>SHA256:...</c>).</param>
/// <param name="PublicKey">The public key in SSH wire format, as stored in <c>known_hosts</c> after base64 decoding.</param>
/// <param name="KeySizeBits">The key size in bits.</param>
public sealed record SshHostKey(string Algorithm, string KeyType, string Fingerprint, ReadOnlyMemory<byte> PublicKey, int KeySizeBits)
{
    /// <summary>
    /// The host certificate, when the server presented one (an OpenSSH <c>-cert-v01@openssh.com</c> host key). The other members then
    /// describe the certified key, which is what a plain known_hosts entry or a pinned fingerprint refers to.
    /// </summary>
    public SshCertificate? Certificate { get; init; }

    /// <summary>
    /// <see cref="PublicKey"/> as an <see cref="SshPublicKey"/>, to compare with a key you hold (<c>hostKey.GetPublicKey() == expected</c>),
    /// write as a line, or fingerprint with another hash. For a host certificate it is the certified key, as <see cref="PublicKey"/> is.
    /// </summary>
    /// <exception cref="FormatException"><see cref="PublicKey"/> is not a key <see cref="SshPublicKey"/> reads (only possible for a
    /// host key made by hand).</exception>
    public SshPublicKey GetPublicKey() => SshPublicKey.Read(PublicKey.Span);

    /// <summary>Equal when they describe the same key: the key bytes are compared, not the buffers that hold them.</summary>
    public bool Equals(SshHostKey? other) =>
        other is not null
        && Algorithm == other.Algorithm
        && KeyType == other.KeyType
        && Fingerprint == other.Fingerprint
        && KeySizeBits == other.KeySizeBits
        && PublicKey.Span.SequenceEqual(other.PublicKey.Span)
        && Equals(Certificate, other.Certificate);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Algorithm, KeyType, Fingerprint, KeySizeBits);
}

/// <summary>The algorithms a connection negotiated (they can change at a key re-exchange). See <see cref="SshClient.Algorithms"/>.</summary>
public sealed class SshNegotiatedAlgorithms
{
    internal SshNegotiatedAlgorithms(Protocol.NegotiatedAlgorithms negotiated)
    {
        KeyExchange = negotiated.Kex;
        HostKeyAlgorithm = negotiated.HostKey;
        EncryptionClientToServer = negotiated.CipherClientToServer;
        EncryptionServerToClient = negotiated.CipherServerToClient;
        // The negotiator may still pick a MAC name next to an AEAD cipher (when both lists have one), but it is not used: report none.
        MacClientToServer = IsAead(negotiated.CipherClientToServer) ? string.Empty : negotiated.MacClientToServer;
        MacServerToClient = IsAead(negotiated.CipherServerToClient) ? string.Empty : negotiated.MacServerToClient;
        StrictKeyExchange = negotiated.StrictKex;
        CompressionClientToServer = negotiated.CompressionClientToServer;
        CompressionServerToClient = negotiated.CompressionServerToClient;
    }

    /// <summary>The key exchange method, for example <c>mlkem768x25519-sha256</c> or <c>curve25519-sha256</c>.</summary>
    public string KeyExchange { get; }

    /// <summary>
    /// Whether the key exchange is post-quantum: a hybrid with a post-quantum KEM, so traffic recorded today stays protected against a
    /// future quantum computer ("store now, decrypt later"). OpenSSH 10.1 and later warn when it is not (<c>WarnWeakCrypto</c>).
    /// </summary>
    public bool IsPostQuantum => Protocol.SshAlgorithms.IsPostQuantum(KeyExchange);

    /// <summary>The host key signature algorithm, for example <c>ssh-ed25519</c> or <c>rsa-sha2-512</c>.</summary>
    public string HostKeyAlgorithm { get; }

    /// <summary>The cipher for data from the client to the server.</summary>
    public string EncryptionClientToServer { get; }

    /// <summary>The cipher for data from the server to the client.</summary>
    public string EncryptionServerToClient { get; }

    /// <summary>The MAC from the client to the server; empty with an AEAD cipher (AES-GCM, ChaCha20-Poly1305), which needs none.</summary>
    public string MacClientToServer { get; }

    /// <summary>The MAC from the server to the client; empty with an AEAD cipher.</summary>
    public string MacServerToClient { get; }

    /// <summary>Whether strict key exchange (the Terrapin fix, CVE-2023-48795) is in effect: the server supports it.</summary>
    public bool StrictKeyExchange { get; }

    /// <summary>
    /// The compression from the client to the server: <c>none</c>, or <c>zlib@openssh.com</c> when <see cref="SshClientOptions.Compression"/>
    /// is on and the server offers it. That compression is delayed: it starts once authentication has succeeded. On .NET 8 SshSharp does
    /// not compress what it sends, so this is always <c>none</c> there.
    /// </summary>
    public string CompressionClientToServer { get; }

    /// <summary>The compression from the server to the client: <c>none</c>, or <c>zlib@openssh.com</c> (see <see cref="CompressionClientToServer"/>).</summary>
    public string CompressionServerToClient { get; }

    private static bool IsAead(string cipher) => Protocol.SshAlgorithms.TryGetCipher(cipher, out var info) && info.IsAead;
}

/// <summary>Options for <see cref="SshClient.ScanHostKeysAsync(string, int, SshHostKeyScanOptions?, CancellationToken)"/>.</summary>
public sealed class SshHostKeyScanOptions
{
    /// <summary>
    /// The host key algorithms to ask for, for example <c>ssh-ed25519</c> or <c>rsa-sha2-512</c>; null for every plain key type SshSharp
    /// supports. Algorithms of one key type (<c>rsa-sha2-512</c> and <c>rsa-sha2-256</c>) find the same key, so it is reported once.
    /// </summary>
    public IReadOnlyList<string>? HostKeyAlgorithms { get; init; }

    /// <summary>Also ask for host certificates (<c>-cert-v01@openssh.com</c>), when <see cref="HostKeyAlgorithms"/> is null.</summary>
    public bool IncludeCertificates { get; init; }

    /// <summary>Use only FIPS-approved algorithms, as <see cref="SshClientOptions.FipsMode"/> does (no Ed25519 keys are found then).</summary>
    public bool FipsMode { get; init; }

    /// <summary>Where diagnostics go. Never receives secrets.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>
    /// How long each connection of the scan (connecting and one key exchange) may take before the scan fails with
    /// <see cref="SshFailureReason.Timeout"/>, as <c>ssh-keyscan -T</c>. Default 5 seconds, as ssh-keyscan;
    /// <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> for no limit but the cancellation token.
    /// </summary>
    public TimeSpan Timeout
    {
        get => _timeout;
        init
        {
            if (value != System.Threading.Timeout.InfiniteTimeSpan && (value <= TimeSpan.Zero || value.TotalMilliseconds > int.MaxValue))
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "The timeout must be positive (at most about 24 days), or infinite.");
            }

            _timeout = value;
        }
    }

    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(5);
}

/// <summary>Options for <see cref="SshClient"/>.</summary>
public sealed class SshClientOptions
{
    /// <summary>The user to authenticate as.</summary>
    public required string UserName { get; init; }

    /// <summary>
    /// The password, if used. Tried after <see cref="PrivateKeys"/> and <see cref="KeyboardInteractive"/> with the <c>password</c> method.
    /// When the server offers only <c>keyboard-interactive</c> (common with PAM) and there is no handler, it answers a round that asks
    /// for exactly one hidden input. With a <see cref="PasswordProvider"/> too, this password is tried first, and the provider is asked
    /// only if the server refuses it.
    /// </summary>
    [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
    public string? Password { get; init; }

    /// <summary>
    /// Asks for the password when authentication reaches it, as ssh prompts <c>user@host's password:</c>: only after the keys (and
    /// Kerberos) did not log in, so an interactive tool prompts only when it has to. It is called again after each refused password,
    /// at most <see cref="NumberOfPasswordPrompts"/> times per connection; return null to stop asking. It answers the <c>password</c>
    /// method, and keyboard-interactive the way <see cref="Password"/> does (a round that asks for exactly one hidden input) when there
    /// is no <see cref="KeyboardInteractive"/> handler. A <see cref="Password"/> that is set is tried first.
    /// </summary>
    /// <remarks>
    /// It gets the connect's cancellation token; an exception it throws (an <see cref="OperationCanceledException"/> when the user
    /// cancels) fails the connect. The password is sent to the server being authenticated with only, and is not kept.
    /// </remarks>
    public Func<SshPasswordPrompt, CancellationToken, ValueTask<string?>>? PasswordProvider { get; init; }

    /// <summary>
    /// How many times <see cref="PasswordProvider"/> may be asked on one connection, as ssh_config's <c>NumberOfPasswordPrompts</c>.
    /// Default 3, as in ssh; 0 never asks. A given <see cref="Password"/> is not counted.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public int NumberOfPasswordPrompts
    {
        get => _numberOfPasswordPrompts;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _numberOfPasswordPrompts = value;
        }
    }

    private readonly int _numberOfPasswordPrompts = DefaultNumberOfPasswordPrompts;

    /// <summary>ssh's default for <c>NumberOfPasswordPrompts</c>.</summary>
    internal const int DefaultNumberOfPasswordPrompts = 3;

    /// <summary>
    /// Answers the server's request to change an expired password (<c>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</c>, RFC 4252 section 8) with
    /// the new one, or null to decline. The password just sent is sent again as the old one, with the new one; when the server
    /// refuses the new password it can ask again (at most 3 times), and when it accepts it, the connection is authenticated (or goes
    /// on to the next method the server requires). Null (the default), or declining, leaves the password unchanged: the attempt counts
    /// as failed (<see cref="SshAuthenticationOutcome.PasswordChangeRequired"/>) and the other methods are tried.
    /// </summary>
    /// <remarks>
    /// Store the new password only once the connect succeeds: until then the server may not have accepted it. Servers that change
    /// passwords through PAM ask through keyboard-interactive instead, which <see cref="KeyboardInteractive"/> answers.
    /// </remarks>
    public Func<SshPasswordChangeRequest, CancellationToken, ValueTask<string?>>? ChangePassword { get; init; }

    /// <summary>
    /// Answers keyboard-interactive authentication (RFC 4256): one-time codes, PAM prompts, or a password the server asks for this way.
    /// Called once per round with the server's questions; return one answer per prompt, or null to give up on the method. Tried after
    /// <see cref="PrivateKeys"/> and before <see cref="Password"/>, like ssh. Unlike <see cref="PasswordProvider"/>, the method is not
    /// retried after the server refuses the answers: it is tried once per walk of the authentication order.
    /// </summary>
    public Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>>? KeyboardInteractive { get; init; }

    /// <summary>
    /// Receives the server's pre-authentication banner (<c>SSH_MSG_USERAUTH_BANNER</c>, sshd's <c>Banner</c>), for example a legal notice.
    /// The text comes from the server: strip control characters before showing it in a terminal.
    /// </summary>
    public Func<string, CancellationToken, ValueTask>? AuthenticationBanner { get; init; }

    /// <summary>
    /// Forward this agent to the server (<c>ssh -A</c>, <c>ForwardAgent yes</c>): sessions ask the server to offer it, so programs there
    /// (ssh, git) can authenticate onward with your keys. Null (the default) forwards nothing. Only forward to servers you trust: while
    /// connected, anyone with enough rights on the server can use the agent to sign with your keys (not read them).
    /// An in-process agent (<see cref="SshAgent.FromKeys"/>) is answered here, with no agent process; <see cref="ForwardAgentFilter"/>
    /// decides what the server's side may do with either kind.
    /// </summary>
    public SshAgent? ForwardAgent { get; init; }

    /// <summary>
    /// Decides each request a program on the server makes of the forwarded agent (<see cref="ForwardAgent"/>): which keys it lists and
    /// whether each signature is made. Return true to allow. It can be asynchronous, to ask the user (as <c>ssh-add -c</c> does) or
    /// another service. Null (the default) allows everything, as <c>ssh -A</c> does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The filter is asked once for each key in a listing (<see cref="SshAgentOperation.ListKeys"/>; a refused key is left out) and
    /// for every signature (<see cref="SshAgentOperation.Sign"/>; a refused one is answered with <c>SSH_AGENT_FAILURE</c>, as an agent
    /// whose user declines a confirmation answers). A key is checked again when it signs, whether or not it was listed: a public key is no
    /// secret, so hiding it does not stop a request for it. To confirm each use as <c>ssh-add -c</c> does, allow every listing and ask
    /// on <see cref="SshAgentOperation.Sign"/>.
    /// </para>
    /// <para>
    /// With a filter, the forwarded agent is read-only and narrowed: requests to add, remove or lock keys are refused, RSA keys never
    /// sign with SHA-1, and keys whose type <see cref="SshPublicKey"/> does not read are hidden. Without one, a real agent's connection
    /// is relayed byte for byte, as before.
    /// </para>
    /// <para>
    /// Data to sign that is not a login request, an SSH signature or a certificate reaches the filter with a null
    /// <see cref="SshAgentRequest.Purpose"/>: programs sign their own formats through agents (pam_ssh_agent_auth, for one), so it is the
    /// filter's to allow. Allowing only the purposes the application knows keeps a forwarded agent from signing anything else.
    /// </para>
    /// <para>
    /// It runs on the connection's background work, possibly for several agent channels at once; it gets a token that is cancelled when
    /// the connection closes. Anything it throws refuses the request (and is logged). It is not asked for this client's own
    /// authentication through the agent, only for requests that come through agent forwarding.
    /// </para>
    /// </remarks>
    public Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? ForwardAgentFilter { get; init; }

    /// <summary>
    /// The authentication methods to try and their order, as ssh_config's <c>PreferredAuthentications</c>: any of
    /// <c>gssapi-with-mic</c>, <c>publickey</c>, <c>keyboard-interactive</c> and <c>password</c>. A method that is left out is not tried,
    /// even when its credentials are set. Null (the default) uses ssh's order: <c>gssapi-with-mic</c> (only with <see cref="Gssapi"/>),
    /// <c>publickey</c>, <c>keyboard-interactive</c>, <c>password</c>. A method is tried only when the server offers it and its credentials
    /// are set (<see cref="PrivateKeys"/>, <see cref="Password"/>, <see cref="KeyboardInteractive"/>, <see cref="Gssapi"/>).
    /// </summary>
    /// <exception cref="ArgumentException">A name is not one of the methods above (SshSharp does not implement <c>hostbased</c>).</exception>
    public IReadOnlyList<string>? PreferredAuthentications
    {
        get => _preferredAuthentications;
        init
        {
            if (value is not null)
            {
                foreach (var method in value)
                {
                    if (method is null || !SshClient.DefaultAuthenticationOrder.Contains(method, StringComparer.Ordinal))
                    {
                        throw new ArgumentException(
                            $"'{method}' is not an authentication method SshSharp supports. Supported: {string.Join(", ", SshClient.DefaultAuthenticationOrder)}.",
                            nameof(value));
                    }
                }

                value = [.. value.Distinct(StringComparer.Ordinal)];
            }

            _preferredAuthentications = value;
        }
    }

    private readonly IReadOnlyList<string>? _preferredAuthentications;

    /// <summary>
    /// Authenticate with Kerberos (<c>gssapi-with-mic</c>) when the server offers it, before the other methods, as ssh does with
    /// <c>GSSAPIAuthentication yes</c>. Null (the default) does not try it. Needs .NET 10 (<see cref="SshGssapiOptions.IsSupported"/>).
    /// </summary>
    public SshGssapiOptions? Gssapi { get; init; }

    /// <summary>
    /// Keys for public-key authentication, tried in order (load them with <see cref="SshPrivateKey.LoadAsync"/>). The client does not
    /// dispose them. A key whose private material is in this process (loaded, parsed or generated) signs its request straight away; a
    /// key held by an agent or an <see cref="SshKeySigner"/> is offered first, and signs only if the server would accept it.
    /// </summary>
    public IReadOnlyList<SshPrivateKey> PrivateKeys { get; init; } = [];

    /// <summary>
    /// Decides whether to trust the server's host key: a <see cref="KnownHostsVerifier"/>, <see cref="SshHostKeyVerifier.Pinned(string[])"/>,
    /// or your own (<see cref="SshHostKeyVerifier.FromDelegate"/>). There is deliberately no default: accepting unknown keys silently
    /// would defeat the purpose of host authentication.
    /// </summary>
    public required SshHostKeyVerifier HostKeyVerifier { get; init; }

    /// <summary>
    /// The name to look the host key up under (OpenSSH's <c>HostKeyAlias</c>), instead of the host name. Needed to use
    /// <c>known_hosts</c> when connecting over a <see cref="Stream"/>, where the host name is not known.
    /// </summary>
    public string? HostKeyAlias { get; init; }

    /// <summary>
    /// Send a keep-alive when the server has been silent this long (OpenSSH's <c>ServerAliveInterval</c>). Null (the default),
    /// <see cref="TimeSpan.Zero"/> (as <c>ServerAliveInterval 0</c>) and <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> send none,
    /// and so does an interval longer than about 49 days, the longest a timer waits. Keep-alives detect a dead connection and stop idle
    /// NAT and firewall timeouts from dropping it.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative (other than infinite).</exception>
    public TimeSpan? KeepAliveInterval
    {
        get => _keepAliveInterval;
        init
        {
            // Checked here, so the mistake is not found only after the connection has been authenticated.
            if (value is { } interval && interval < TimeSpan.Zero && interval != System.Threading.Timeout.InfiniteTimeSpan)
            {
                throw new ArgumentOutOfRangeException(nameof(value), interval, "The keep-alive interval must not be negative (zero or infinite sends none).");
            }

            _keepAliveInterval = value;
        }
    }

    private readonly TimeSpan? _keepAliveInterval;

    /// <summary>The keep-alive interval to run, or null when <see cref="KeepAliveInterval"/> sends none.</summary>
    internal TimeSpan? EffectiveKeepAliveInterval =>
        _keepAliveInterval is { } interval && interval > TimeSpan.Zero && interval <= ConnectDeadline.MaxTimerDelay ? interval : null;

    /// <summary>
    /// After this many keep-alive intervals without hearing from the server, the connection is declared dead and fails with
    /// <see cref="SshFailureReason.Timeout"/> (OpenSSH's <c>ServerAliveCountMax</c>). Default 3.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public int KeepAliveCountMax
    {
        get => _keepAliveCountMax;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _keepAliveCountMax = value;
        }
    }

    private readonly int _keepAliveCountMax = 3;

    /// <summary>The clock for rekey and keep-alive timing; replaceable in tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>The most output (stdout plus stderr) <see cref="SshClient.RunCommandAsync(string, CancellationToken)"/> and its overloads will collect before failing. Default 128 MiB.</summary>
    public long MaxCommandOutputBytes { get; init; } = 128L * 1024 * 1024;

    /// <summary>
    /// The most connections the server may have forwarded to this client at once, across all remote forwardings (port, dynamic and
    /// Unix-socket). Each one makes a connection on this machine, so this bounds what a misbehaving server can make it open; above it, the
    /// server's channel is refused (resource shortage) and its client sees the connection fail. Default 1000.
    /// </summary>
    public int MaxForwardedConnections
    {
        get => _maxForwardedConnections;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxForwardedConnections = value;
        }
    }

    private readonly int _maxForwardedConnections = 1000;

    /// <summary>
    /// Idle timeouts by channel type, as OpenSSH's <c>ChannelTimeout</c> (9.2+) sets them on the client: a channel that carries no data in
    /// either direction for its type's timeout is closed, with an ordinary <c>CLOSE</c>. Its streams then end as when the server closes
    /// it, and a forwarded or tunnelled connection's local socket is closed. Empty by default (no timeouts). For example
    /// <c>[new("direct-tcpip", TimeSpan.FromMinutes(10)), new("session", TimeSpan.Zero), new("*", TimeSpan.FromHours(1))]</c>: the first
    /// entry whose type pattern matches applies (see <see cref="SshChannelTimeout"/>).
    /// </summary>
    public IReadOnlyList<SshChannelTimeout> ChannelTimeouts { get; init; } = [];

    /// <summary>
    /// Hide the timing of keystrokes in sessions with a terminal, as OpenSSH's <c>ObscureKeystrokeTiming</c> (9.5+) does: while someone
    /// types, small writes to <see cref="SshSession.StandardInput"/> are sent only once per interval (a write completes when its interval
    /// comes), and the intervals with nothing typed carry a chaff packet of the same size, for a random 1 to 3 seconds after the last key.
    /// Someone watching the encrypted traffic then cannot tell keys, or the time between them, from the packets. Larger writes (256 bytes
    /// or more, such as a paste) go at once. Chaff is sent only to servers that announce <c>ping@openssh.com</c> (OpenSSH 9.5+). Null (the
    /// default) sends every write at once. ssh uses 20 ms, and so does <see cref="SshClient.ConnectAsync(string, SshConfigConnectOptions?, CancellationToken)"/>
    /// unless the config says otherwise. Between 1 ms and 1 second, as ssh allows.
    /// </summary>
    public TimeSpan? ObscureKeystrokeTiming
    {
        get => _obscureKeystrokeTiming;
        init
        {
            if (value is { } interval && (interval < TimeSpan.FromMilliseconds(1) || interval > TimeSpan.FromSeconds(1)))
            {
                throw new ArgumentOutOfRangeException(nameof(value), interval, "The keystroke interval must be between 1 ms and 1 second.");
            }

            _obscureKeystrokeTiming = value;
        }
    }

    private readonly TimeSpan? _obscureKeystrokeTiming;

    /// <summary>
    /// Negotiate new keys after this many bytes have been transferred under the current ones. Default 1 GiB (RFC 4253 section 9).
    /// Values above 64 GiB (2^32 cipher blocks, the limit OpenSSH applies) are capped, and keys are also renewed every 2^31 packets.
    /// As in OpenSSH, the client starts a re-exchange only once the user is authenticated; one the server starts is carried out at any
    /// time.
    /// </summary>
    public long RekeyAfterBytes { get; init; } = 1L << 30;

    /// <summary>The largest effective <see cref="RekeyAfterBytes"/>: 2^32 blocks of a 128-bit cipher.</summary>
    internal const long MaxRekeyAfterBytes = 1L << 36;

    /// <summary>
    /// Negotiate new keys after the current ones have been in use this long. Default 1 hour (RFC 4253 section 9). Like
    /// <see cref="RekeyAfterBytes"/>, it applies only once the user is authenticated.
    /// </summary>
    public TimeSpan RekeyAfterTime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Receives diagnostics (connection, algorithms, authentication outcome, channels, rekeys). Never receives passwords or command text. Default: no logging.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>
    /// An HTTP or SOCKS proxy to reach the server through, for <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>.
    /// The server's host name is resolved by the proxy. With <see cref="JumpHosts"/>, it carries the connection to the first jump host
    /// instead. Ignored when connecting over a stream you opened.
    /// </summary>
    public SshProxy? Proxy { get; init; }

    /// <summary>
    /// Jump hosts to reach the server through, first to last, as <c>ssh -J</c> and ssh_config's <c>ProxyJump</c>: the client connects
    /// to the first, reaches each next one through the one before, and the server through the last. Each hop logs in and verifies its
    /// host key with its own <see cref="SshJumpHost.Options"/>; these options (credentials, <see cref="HostKeyVerifier"/>) are the
    /// destination's alone and never offered to a hop. <see cref="Proxy"/>, <see cref="LocalEndPoint"/>, <see cref="AddressFamily"/>,
    /// <see cref="ConfigureSocket"/> and <see cref="ConnectionAttempts"/> apply to the first network connection, which is the first hop's
    /// (a hop's own are not used). <see cref="ConnectTimeout"/> bounds the whole chain. Disposing the
    /// client closes every hop. Empty (the default) connects directly. Used by
    /// <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>; ignored when connecting over a stream you opened.
    /// </summary>
    /// <exception cref="ArgumentException">The list contains null.</exception>
    public IReadOnlyList<SshJumpHost> JumpHosts
    {
        get => _jumpHosts;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Any(hop => hop is null))
            {
                throw new ArgumentException("A jump host list cannot contain null.", nameof(value));
            }

            _jumpHosts = [.. value];
        }
    }

    private readonly IReadOnlyList<SshJumpHost> _jumpHosts = [];

    /// <summary>
    /// The local address (and usually port 0) to connect from, as <c>ssh -b</c>, for machines on several networks; null lets the system
    /// choose. Only destination addresses of the same family are tried. Used by
    /// <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>, also for the connection to <see cref="Proxy"/>.
    /// </summary>
    public System.Net.IPEndPoint? LocalEndPoint { get; init; }

    /// <summary>
    /// How long the connection attempt may take, as ssh_config's <c>ConnectTimeout</c>: resolving the name and the TCP connection (or the
    /// connection through <see cref="Proxy"/>), the SSH handshake, host key verification and authentication, the time spent in your
    /// callbacks included (<see cref="KeyboardInteractive"/>, a host key prompt). When it passes, the attempt fails with an
    /// <see cref="SshException"/> whose <see cref="SshException.Reason"/> is <see cref="SshFailureReason.Timeout"/> (its inner exception is a
    /// <see cref="TimeoutException"/>); a cancelled <see cref="CancellationToken"/> still ends it with an
    /// <see cref="OperationCanceledException"/>. It ends with the connection: once connected, operations are bounded by their own tokens.
    /// Null (the default) or <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> sets no limit but the token. Over a stream you
    /// opened (<see cref="SshClient.ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>) it bounds the handshake and
    /// authentication.
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
    /// Which addresses of the server to try, as ssh_config's <c>AddressFamily</c> (<c>ssh -4</c>, <c>ssh -6</c>): any (the default), IPv4
    /// only or IPv6 only. Applies to <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>; with a
    /// <see cref="Proxy"/>, the proxy resolves the server's name and this does not apply (the connection to the proxy itself uses any
    /// family). With a <see cref="LocalEndPoint"/> too, only addresses that are of the allowed family and of the local endpoint's are tried.
    /// </summary>
    public Config.SshAddressFamily AddressFamily { get; init; }

    /// <summary>
    /// How many times to try the network connection, one second apart, as ssh_config's <c>ConnectionAttempts</c>: the TCP connection to
    /// the server, or to the first of the <see cref="JumpHosts"/>, or to the <see cref="Proxy"/>. Only failures to reach it are tried
    /// again (refused, unreachable, timed out), never a name that does not resolve, a proxy's refusal, a failed handshake or
    /// authentication, and <see cref="ConnectTimeout"/> bounds all the attempts together. Default 1. Used by
    /// <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>; ignored when connecting over a stream you opened.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1.</exception>
    public int ConnectionAttempts
    {
        get => _connectionAttempts;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _connectionAttempts = value;
        }
    }

    private readonly int _connectionAttempts = 1;

    /// <summary>
    /// Sets socket options on the TCP connection to the server: TCP keep-alive, buffer sizes, the type of service (DSCP), and so on. It is
    /// called with the new socket before it connects (after it is bound to <see cref="LocalEndPoint"/>, if set), so options that must be
    /// set before the handshake, such as the receive buffer size that TCP window scaling depends on, take effect. Null (the default)
    /// leaves the system's defaults; SshSharp itself turns Nagle's algorithm off (<see cref="System.Net.Sockets.Socket.NoDelay"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used by <see cref="SshClient.ConnectAsync(string, int, SshClientOptions, CancellationToken)"/> only, for a direct connection: with
    /// <see cref="JumpHosts"/>, that is the connection to the first hop (whose own options' <c>ConfigureSocket</c> is not used). It
    /// is not called when the connection goes through a <see cref="Proxy"/>, nor over a stream you opened yourself
    /// (<see cref="SshClient.ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>), where the socket, if there is one, is
    /// yours to configure.
    /// </para>
    /// <para>
    /// It is called once for each socket SshSharp creates, and each address of the server that is tried gets a socket of its own: once
    /// per attempt for an IP address or a name with one address, and again for each further address tried when a name has several and
    /// the first cannot be reached. Each retry that <see cref="ConnectionAttempts"/> makes creates new sockets too. The socket's family is the address's (IPv4 or IPv6, not dual-mode). It runs on the connecting thread and should
    /// only set options.
    /// An exception it throws ends the attempt and is thrown from <c>ConnectAsync</c> as it is.
    /// </para>
    /// </remarks>
    public Action<System.Net.Sockets.Socket>? ConfigureSocket { get; init; }

    /// <summary>
    /// A comment appended to this client's identification line, which then reads <c>SSH-2.0-SshSharp_1.2.3 comment</c> (RFC 4253 section
    /// 4.2), for example to tell your application's connections apart in the server's logs. Null (the default) sends none. The line is
    /// sent before encryption starts, so anyone on the network path can read it, and servers log it: put no secrets or personal data in it.
    /// </summary>
    /// <exception cref="ArgumentException">The comment is empty, has a character other than printable US-ASCII (space to <c>~</c>),
    /// starts or ends with a space, or makes the line longer than the 255 bytes RFC 4253 allows.</exception>
    public string? VersionAddendum
    {
        get => _versionAddendum;
        init
        {
            if (value is not null && !Protocol.SshIdentification.IsValidClientComments(value))
            {
                throw new ArgumentException(
                    $"The version addendum must be 1 to {Protocol.SshIdentification.MaxClientCommentsLength} printable US-ASCII characters, not starting or ending with a space.",
                    nameof(value));
            }

            _versionAddendum = value;
        }
    }

    private readonly string? _versionAddendum;

    /// <summary>
    /// The window each channel grants the server (RFC 4254 section 5.2): how many bytes it may send on a channel before SshSharp has
    /// consumed some. One channel moves at most one window per round trip, so on a link with a large bandwidth-delay product (a fast,
    /// distant link) a larger window makes a single download, command output or tunnel faster: 2 MiB per 100 ms of round trip is about
    /// 20 MiB/s. Each channel can then hold up to this much received data that your code has not read yet. It applies to every channel:
    /// sessions, SFTP, SCP, tunnels and forwarded connections. Default 2 MiB, as OpenSSH. Between 1 KiB and 1 GiB.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is below 1 KiB or above 1 GiB.</exception>
    public int ChannelWindowSize
    {
        get => _channelWindowSize;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, MinChannelSize);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, MaxChannelWindowSize);
            _channelWindowSize = value;
        }
    }

    private readonly int _channelWindowSize = (int)Protocol.SshChannel.DefaultWindowSize;

    /// <summary>
    /// The most data the server may put in one packet on a channel (RFC 4254 section 5.1). Larger packets mean fewer of them, and less
    /// work per byte, for bulk transfers. It applies to every channel, as <see cref="ChannelWindowSize"/> does, and is capped at it. Default
    /// 32 KiB, as OpenSSH. Between 1 KiB and 255 KiB: SshSharp accepts packets of up to 256 KiB, as OpenSSH does, and the rest is room for
    /// the packet's header, padding and MAC. What the client sends is limited by what the server asks for, not by this.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is below 1 KiB or above 255 KiB.</exception>
    public int ChannelMaxPacketSize
    {
        get => _channelMaxPacketSize;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, MinChannelSize);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, Protocol.SshChannel.MaxDataPerPacket);
            _channelMaxPacketSize = value;
        }
    }

    private readonly int _channelMaxPacketSize = (int)Protocol.SshChannel.DefaultMaxPacketSize;

    /// <summary>The smallest <see cref="ChannelWindowSize"/> and <see cref="ChannelMaxPacketSize"/>.</summary>
    internal const int MinChannelSize = 1024;

    /// <summary>
    /// The largest <see cref="ChannelWindowSize"/>. RFC 4254 allows up to 4 GiB, but every channel may buffer this much unread data, so
    /// the bound keeps a mistake from becoming unbounded memory; 1 GiB covers 10 Gbit/s at 800 ms of round trip.
    /// </summary>
    internal const int MaxChannelWindowSize = 1 << 30;

    /// <summary>
    /// Restrict key exchange, host key, cipher and MAC algorithms to FIPS-approved ones (NIST curves and DH groups, RSA/ECDSA, AES, HMAC-SHA2).
    /// Curve25519, Ed25519 and ChaCha20-Poly1305 are excluded. This limits what is negotiated; it does not make the process FIPS-validated.
    /// </summary>
    public bool FipsMode { get; init; }

    /// <summary>
    /// The key exchange methods to offer, as ssh_config's <c>KexAlgorithms</c>: for example
    /// <c>SshAlgorithmList.Remove("diffie-hellman-group*")</c>, or <c>SshAlgorithmList.Only("mlkem768x25519-sha256", "curve25519-sha256")</c>.
    /// Null (the default) offers SshSharp's defaults, post-quantum hybrids first. ML-KEM methods are dropped where the platform lacks ML-KEM
    /// (before .NET 10), and <see cref="FipsMode"/> still removes what it excludes.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not a key exchange method SshSharp implements.</exception>
    public SshAlgorithmList? KexAlgorithms
    {
        get => _kexAlgorithms;
        init => _kexAlgorithms = Protocol.AlgorithmPreferences.Validate(value, Protocol.AlgorithmKind.Kex, nameof(value));
    }

    private readonly SshAlgorithmList? _kexAlgorithms;

    /// <summary>
    /// The host key algorithms to accept from the server, as ssh_config's <c>HostKeyAlgorithms</c>: for example
    /// <c>SshAlgorithmList.Only("ssh-ed25519")</c>. Certificate algorithms (<c>-cert-v01@openssh.com</c>) may be listed too. Null (the
    /// default) accepts SshSharp's defaults. When the <see cref="HostKeyVerifier"/> trusts a certificate authority for the host, the
    /// certificate versions of the allowed algorithms are asked for first, as ssh does. <see cref="FipsMode"/> still removes Ed25519.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not a host key algorithm SshSharp implements.</exception>
    public SshAlgorithmList? HostKeyAlgorithms
    {
        get => _hostKeyAlgorithms;
        init => _hostKeyAlgorithms = Protocol.AlgorithmPreferences.Validate(value, Protocol.AlgorithmKind.HostKey, nameof(value));
    }

    private readonly SshAlgorithmList? _hostKeyAlgorithms;

    /// <summary>
    /// The ciphers to offer, as ssh_config's <c>Ciphers</c>: for example <c>SshAlgorithmList.Prepend("chacha20-poly1305@openssh.com")</c>.
    /// Null (the default) offers SshSharp's defaults. <see cref="FipsMode"/> still removes ChaCha20-Poly1305.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not a cipher SshSharp implements.</exception>
    public SshAlgorithmList? Ciphers
    {
        get => _ciphers;
        init => _ciphers = Protocol.AlgorithmPreferences.Validate(value, Protocol.AlgorithmKind.Cipher, nameof(value));
    }

    private readonly SshAlgorithmList? _ciphers;

    /// <summary>
    /// The MACs to offer, as ssh_config's <c>MACs</c>: for example <c>SshAlgorithmList.Only("hmac-sha2-512-etm@openssh.com")</c>. Null (the
    /// default) offers SshSharp's defaults. AEAD ciphers (AES-GCM, ChaCha20-Poly1305) authenticate themselves and use no MAC.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not a MAC SshSharp implements.</exception>
    public SshAlgorithmList? Macs
    {
        get => _macs;
        init => _macs = Protocol.AlgorithmPreferences.Validate(value, Protocol.AlgorithmKind.Mac, nameof(value));
    }

    private readonly SshAlgorithmList? _macs;

    /// <summary>
    /// Compress the connection, as ssh's <c>Compression yes</c> (<c>ssh -C</c>): offer <c>zlib@openssh.com</c> before <c>none</c>. The server
    /// decides whether it is used; <see cref="SshClient.Algorithms"/> tells what was negotiated. Compression starts only after
    /// authentication succeeds (OpenSSH's delayed compression; plain <c>zlib</c>, which starts before it, is not supported by design) and
    /// lasts for the rest of the connection. Off by default, as in ssh: it helps on slow links and with text, costs CPU on fast links, and
    /// packet lengths can reveal what compressed well when secrets and data an attacker chooses share the connection. SshSharp compresses
    /// with Huffman coding only, as OpenSSH does, which limits that. On .NET 8 only what the server sends is compressed. Allowed in
    /// <see cref="FipsMode"/>: zlib is not a cryptographic algorithm.
    /// </summary>
    public bool Compression { get; init; }

    /// <summary>
    /// The signature algorithms public-key authentication may use, as ssh_config's <c>PubkeyAcceptedAlgorithms</c>: for example
    /// <c>SshAlgorithmList.Only("ssh-ed25519")</c>, or <c>SshAlgorithmList.Remove("rsa-sha2-*")</c>. A key in <see cref="PrivateKeys"/> is
    /// offered only with an algorithm the list allows, and is skipped when it allows none of the key's: a plain key under its own type
    /// (<c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c>), an RSA key as <c>rsa-sha2-512</c> or <c>rsa-sha2-256</c>, and a key with a
    /// certificate under the certificate's algorithm (<c>ssh-ed25519-cert-v01@openssh.com</c>), which its plain one does not allow. An RSA
    /// key signs with the first of the list's RSA algorithms that the server accepts (its <c>server-sig-algs</c>). Null (the default)
    /// allows every algorithm a key has, in the key's own order (RSA: SHA-512 first). <see cref="FipsMode"/> does not apply to it.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not a public key signature algorithm SshSharp implements (it never signs with SHA-1
    /// <c>ssh-rsa</c>).</exception>
    public SshAlgorithmList? PubkeyAcceptedAlgorithms
    {
        get => _pubkeyAcceptedAlgorithms;
        init => _pubkeyAcceptedAlgorithms = Protocol.AlgorithmPreferences.Validate(value, Protocol.AlgorithmKind.PublicKey, nameof(value));
    }

    private readonly SshAlgorithmList? _pubkeyAcceptedAlgorithms;

    /// <summary>
    /// The smallest RSA host key accepted, in bits, as ssh_config's <c>RequiredRSASize</c>; a smaller one fails the connection with an
    /// <see cref="SshHostKeyException"/>. Default 2048 (ssh's default is 1024). At least 1024, the least ssh accepts.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is below 1024.</exception>
    public int RequiredRsaSize
    {
        get => _requiredRsaSize;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, LowestRequiredRsaSize);
            _requiredRsaSize = value;
        }
    }

    private readonly int _requiredRsaSize = DefaultMinimumRsaBits;

    /// <summary>The algorithms resolved from an ssh_config host, which take the place of the typed lists above (unknown names dropped as ssh_config's are).</summary>
    internal Protocol.AlgorithmPreferences? AlgorithmPreferences { get; init; }

    /// <summary>The smallest RSA host key accepted unless <see cref="RequiredRsaSize"/> says otherwise (ssh's default is 1024).</summary>
    internal const int DefaultMinimumRsaBits = 2048;

    /// <summary>The lowest <see cref="RequiredRsaSize"/>, as for ssh_config's <c>RequiredRSASize</c>: ssh refuses anything below it.</summary>
    internal const int LowestRequiredRsaSize = 1024;
}

/// <summary>The signal that ended a remote program, from the server's <c>exit-signal</c> (RFC 4254 section 6.10).</summary>
/// <param name="Name">The signal name without the <c>SIG</c> prefix, for example <c>KILL</c> or <c>TERM</c>.</param>
/// <param name="CoreDumped">Whether the program dumped core.</param>
/// <param name="ErrorMessage">The server's description, as it sent it; null when it sent none.</param>
public sealed record SshExitSignal(string Name, bool CoreDumped, string? ErrorMessage);

/// <summary>The outcome of a remote command.</summary>
public sealed class SshCommandResult
{
    internal SshCommandResult(int? exitStatus, SshExitSignal? exitSignal, ReadOnlyMemory<byte> standardOutput, ReadOnlyMemory<byte> standardError)
    {
        ExitStatus = exitStatus;
        ExitSignal = exitSignal;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    /// <summary>The exit status, or null if the command ended without one (for example, killed by a signal).</summary>
    public int? ExitStatus { get; }

    /// <summary>The signal that ended the command, if any.</summary>
    public SshExitSignal? ExitSignal { get; }

    /// <summary>Everything the command wrote to standard output.</summary>
    public ReadOnlyMemory<byte> StandardOutput { get; }

    /// <summary>Everything the command wrote to standard error.</summary>
    public ReadOnlyMemory<byte> StandardError { get; }

    /// <summary>Standard output decoded as UTF-8.</summary>
    public string StandardOutputText => System.Text.Encoding.UTF8.GetString(StandardOutput.Span);

    /// <summary>Standard error decoded as UTF-8.</summary>
    public string StandardErrorText => System.Text.Encoding.UTF8.GetString(StandardError.Span);

    /// <summary>
    /// Throws unless the command succeeded, that is, exited with status 0; returns this result when it did, so calls chain:
    /// <c>(await client.RunCommandAsync("make")).EnsureSuccess().StandardOutputText</c>.
    /// </summary>
    /// <returns>This result.</returns>
    /// <exception cref="SshCommandException">The command exited with a non-zero status, was ended by a signal, or ended without
    /// reporting either. The exception carries the status, the signal and the last 4 KiB of standard error, but not standard output.</exception>
    public SshCommandResult EnsureSuccess()
    {
        if (ExitStatus == 0)
        {
            return this;
        }

        var message = (ExitStatus, ExitSignal) switch
        {
            ({ } status, _) => $"The command failed with exit status {status}.",
            (null, { } signal) => $"The command was ended by signal {signal.Name}{(signal.CoreDumped ? " (core dumped)" : "")}.",
            _ => "The command ended without reporting an exit status.",
        };
        throw new SshCommandException(message, ExitStatus, ExitSignal, StandardError);
    }
}