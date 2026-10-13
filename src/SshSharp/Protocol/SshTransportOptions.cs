using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SshSharp.Protocol;

/// <summary>What a host key verifier is shown: the key the server proved possession of.</summary>
/// <param name="Algorithm">The negotiated host key signature algorithm, for example <c>rsa-sha2-512</c>.</param>
/// <param name="KeyType">The key type, for example <c>ssh-rsa</c>.</param>
/// <param name="Fingerprint">The OpenSSH SHA-256 fingerprint.</param>
/// <param name="KeySizeBits">The key size in bits.</param>
/// <param name="Blob">The plain public key (for a certificate, the certified key).</param>
/// <param name="Presented">What the server sent: the key, or its certificate.</param>
/// <param name="Certificate">The host certificate, when the server presented one.</param>
internal sealed record HostKeyInfo(string Algorithm, string KeyType, ReadOnlyMemory<byte> Blob, string Fingerprint, int KeySizeBits, ReadOnlyMemory<byte> Presented, SshCertificate? Certificate);

/// <summary>Settings for <see cref="SshTransport"/>.</summary>
internal sealed class SshTransportOptions
{
    /// <summary>The identification string sent to the server.</summary>
    public SshIdentification ClientIdentification { get; init; } = SshIdentification.ForClient();

    /// <summary>The algorithm preferences offered in KEXINIT.</summary>
    public AlgorithmPreferences Preferences { get; init; } = new();

    /// <summary>
    /// Decides whether to trust the server's host key (known_hosts policy). It runs after the key's signature over the exchange hash
    /// has been verified. There is deliberately no default: an unconfigured client must not silently trust any key.
    /// </summary>
    public required Func<HostKeyInfo, CancellationToken, ValueTask<bool>> VerifyHostKey { get; init; }

    /// <summary>RSA host keys smaller than this are rejected.</summary>
    public int MinimumRsaBits { get; init; } = 2048;

    /// <summary>Start a new key exchange after this many payload bytes have been sent and received under the current keys (RFC 4253 section 9 recommends 1 GiB).</summary>
    public long RekeyBytes { get; init; } = 1L << 30;

    /// <summary>
    /// Start a new key exchange after this many packets in either direction under the current keys. Sequence numbers are 32 bits and
    /// ChaCha20-Poly1305 uses them as its nonce, so they must never wrap under one key; OpenSSH uses the same limit (2^31).
    /// </summary>
    public long RekeyPackets { get; init; } = 1L << 31;

    /// <summary>Start a new key exchange after the current keys have been in use this long (RFC 4253 section 9 recommends 1 hour).</summary>
    public TimeSpan RekeyInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Where diagnostics go. Never receives secrets.</summary>
    public ILogger Logger { get; init; } = NullLogger.Instance;

    /// <summary>The clock used for <see cref="RekeyInterval"/>; replaceable in tests.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}