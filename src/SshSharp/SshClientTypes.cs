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

    private static bool IsAead(string cipher) => Protocol.SshAlgorithms.TryGetCipher(cipher, out var info) && info.IsAead;
}

/// <summary>Options for <see cref="SshClient"/>.</summary>
public sealed class SshClientOptions
{
    /// <summary>The user to authenticate as.</summary>
    public required string UserName { get; init; }

    /// <summary>
    /// The password, if used. Tried after <see cref="PrivateKeys"/> and <see cref="KeyboardInteractive"/> with the <c>password</c> method.
    /// When the server offers only <c>keyboard-interactive</c> (common with PAM) and there is no handler, it answers a round that asks
    /// for exactly one hidden input.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Answers keyboard-interactive authentication (RFC 4256): one-time codes, PAM prompts, or a password the server asks for this way.
    /// Called once per round with the server's questions; return one answer per prompt, or null to give up on the method. Tried after
    /// <see cref="PrivateKeys"/> and before <see cref="Password"/>, like ssh.
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
    /// </summary>
    public SshAgent? ForwardAgent { get; init; }

    /// <summary>The methods to try and their order (ssh's <c>PreferredAuthentications</c>); null for publickey, keyboard-interactive, password.</summary>
    internal IReadOnlyList<string>? AuthenticationOrder { get; init; }

    /// <summary>
    /// Keys for public-key authentication, tried in order (load them with <see cref="SshPrivateKey.LoadFileAsync"/>). The client does not
    /// dispose them. The server is asked whether it accepts each key before anything is signed.
    /// </summary>
    public IReadOnlyList<SshPrivateKey> PrivateKeys { get; init; } = [];

    /// <summary>
    /// Decides whether to trust the server's host key: a <see cref="KnownHostsVerifier"/>, <see cref="SshHostKeyVerifier.Pinned"/>,
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
    /// Send a keep-alive when the server has been silent this long (OpenSSH's <c>ServerAliveInterval</c>). Null (the default) sends none.
    /// Keep-alives detect a dead connection and stop idle NAT and firewall timeouts from dropping it.
    /// </summary>
    public TimeSpan? KeepAliveInterval { get; init; }

    /// <summary>
    /// After this many keep-alive intervals without hearing from the server, the connection is declared dead and fails with
    /// <see cref="SshFailureReason.Timeout"/> (OpenSSH's <c>ServerAliveCountMax</c>). Default 3.
    /// </summary>
    public int KeepAliveCountMax { get; init; } = 3;

    /// <summary>The clock for rekey and keep-alive timing; replaceable in tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>The most output (stdout plus stderr) <see cref="SshClient.RunCommandAsync"/> will collect before failing. Default 128 MiB.</summary>
    public long MaxCommandOutputBytes { get; init; } = 128L * 1024 * 1024;

    /// <summary>
    /// Negotiate new keys after this many bytes have been transferred under the current ones. Default 1 GiB (RFC 4253 section 9).
    /// Values above 64 GiB (2^32 cipher blocks, the limit OpenSSH applies) are capped, and keys are also renewed every 2^31 packets.
    /// </summary>
    public long RekeyAfterBytes { get; init; } = 1L << 30;

    /// <summary>The largest effective <see cref="RekeyAfterBytes"/>: 2^32 blocks of a 128-bit cipher.</summary>
    internal const long MaxRekeyAfterBytes = 1L << 36;

    /// <summary>Negotiate new keys after the current ones have been in use this long. Default 1 hour (RFC 4253 section 9).</summary>
    public TimeSpan RekeyAfterTime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Receives diagnostics (connection, algorithms, authentication outcome, channels, rekeys). Never receives passwords or command text. Default: no logging.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>
    /// Restrict key exchange, host key, cipher and MAC algorithms to FIPS-approved ones (NIST curves and DH groups, RSA/ECDSA, AES, HMAC-SHA2).
    /// Curve25519, Ed25519 and ChaCha20-Poly1305 are excluded. This limits what is negotiated; it does not make the process FIPS-validated.
    /// </summary>
    public bool FipsMode { get; init; }

    internal Protocol.AlgorithmPreferences? AlgorithmPreferences { get; init; }

    internal int MinimumRsaBits { get; init; } = 2048;
}

/// <summary>The outcome of a remote command.</summary>
public sealed class SshCommandResult
{
    internal SshCommandResult(int? exitStatus, string? exitSignal, ReadOnlyMemory<byte> standardOutput, ReadOnlyMemory<byte> standardError)
    {
        ExitStatus = exitStatus;
        ExitSignal = exitSignal;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    /// <summary>The exit status, or null if the command ended without one (for example, killed by a signal).</summary>
    public int? ExitStatus { get; }

    /// <summary>The name of the signal that ended the command, if any.</summary>
    public string? ExitSignal { get; }

    /// <summary>Everything the command wrote to standard output.</summary>
    public ReadOnlyMemory<byte> StandardOutput { get; }

    /// <summary>Everything the command wrote to standard error.</summary>
    public ReadOnlyMemory<byte> StandardError { get; }

    /// <summary>Standard output decoded as UTF-8.</summary>
    public string StandardOutputText => System.Text.Encoding.UTF8.GetString(StandardOutput.Span);

    /// <summary>Standard error decoded as UTF-8.</summary>
    public string StandardErrorText => System.Text.Encoding.UTF8.GetString(StandardError.Span);
}