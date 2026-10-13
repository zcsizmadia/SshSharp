using Microsoft.Extensions.Logging;

namespace SshSharp;

/// <summary>The host key the server proved possession of during key exchange. Decide whether to trust it in <see cref="SshClientOptions.HostKeyVerifier"/>.</summary>
/// <param name="Algorithm">The negotiated signature algorithm, for example <c>rsa-sha2-512</c>.</param>
/// <param name="KeyType">The key type, for example <c>ssh-rsa</c>.</param>
/// <param name="Fingerprint">The OpenSSH-style SHA-256 fingerprint (<c>SHA256:...</c>).</param>
/// <param name="PublicKey">The public key in SSH wire format, as stored in <c>known_hosts</c> after base64 decoding.</param>
/// <param name="KeySizeBits">The key size in bits.</param>
public sealed record SshHostKey(string Algorithm, string KeyType, string Fingerprint, ReadOnlyMemory<byte> PublicKey, int KeySizeBits);

/// <summary>Options for <see cref="SshClient"/>.</summary>
public sealed class SshClientOptions
{
    /// <summary>The user to authenticate as.</summary>
    public required string UserName { get; init; }

    /// <summary>The password for password authentication, if used.</summary>
    public string? Password { get; init; }

    /// <summary>
    /// Decides whether to trust the server's host key. There is deliberately no default: accepting unknown keys silently would
    /// defeat the purpose of host authentication.
    /// </summary>
    public required Func<SshHostKey, CancellationToken, ValueTask<bool>> HostKeyVerifier { get; init; }

    /// <summary>The most output (stdout plus stderr) <see cref="SshClient.RunCommandAsync"/> will collect before failing. Default 128 MiB.</summary>
    public long MaxCommandOutputBytes { get; init; } = 128L * 1024 * 1024;

    /// <summary>Negotiate new keys after this many bytes have been transferred under the current ones. Default 1 GiB (RFC 4253 section 9).</summary>
    public long RekeyAfterBytes { get; init; } = 1L << 30;

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