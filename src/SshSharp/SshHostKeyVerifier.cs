namespace SshSharp;

/// <summary>What a <see cref="SshHostKeyVerifier"/> is asked to decide: which host this is and the key it proved it holds.</summary>
public sealed class SshHostKeyContext
{
    internal SshHostKeyContext(string? host, int port, string? hostKeyAlias, SshHostKey hostKey)
    {
        Host = host;
        Port = port;
        HostKeyAlias = hostKeyAlias;
        HostKey = hostKey;
    }

    /// <summary>The host name or address that was connected to, or null when connecting over a caller-supplied stream.</summary>
    public string? Host { get; }

    /// <summary>The port that was connected to (22 when connecting over a stream).</summary>
    public int Port { get; }

    /// <summary>The <see cref="SshClientOptions.HostKeyAlias"/>, if set: host keys are looked up and recorded under this name instead.</summary>
    public string? HostKeyAlias { get; }

    /// <summary>The key the server proved possession of during key exchange.</summary>
    public SshHostKey HostKey { get; }

    /// <summary>
    /// The name and port to look the key up under in <c>known_hosts</c>, as <c>ssh</c> does: the alias (with the default port) when set,
    /// otherwise the host and port. Null when neither is known.
    /// </summary>
    public KnownHostsLookup? KnownHostsLookup => HostKeyAlias is { } alias ? new(alias, 22) : Host is { } host ? new(host, Port) : null;
}

/// <summary>The name and port a host key is looked up under in <c>known_hosts</c> (see <see cref="SshHostKeyContext.KnownHostsLookup"/>).</summary>
/// <param name="Name">The host name, address or <see cref="SshClientOptions.HostKeyAlias"/>.</param>
/// <param name="Port">The port; <c>known_hosts</c> writes a port other than 22 as <c>[name]:port</c>.</param>
public sealed record KnownHostsLookup(string Name, int Port);

/// <summary>A verifier's decision about a host key.</summary>
public readonly record struct SshHostKeyVerdict
{
    private SshHostKeyVerdict(bool isAccepted, string? reason)
    {
        IsAccepted = isAccepted;
        Reason = reason;
    }

    /// <summary>Whether the key is trusted.</summary>
    public bool IsAccepted { get; }

    /// <summary>Why the key was rejected (becomes the <see cref="SshHostKeyException"/> message).</summary>
    public string? Reason { get; }

    /// <summary>Trust the key.</summary>
    public static SshHostKeyVerdict Accept() => new(true, null);

    /// <summary>Refuse the key, with the reason the connection fails with.</summary>
    public static SshHostKeyVerdict Reject(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new(false, reason);
    }
}

/// <summary>
/// Decides whether to trust a server's host key. Use <see cref="KnownHostsVerifier"/> for OpenSSH <c>known_hosts</c> behaviour,
/// <see cref="Pinned(string[])"/> for fixed fingerprints or <see cref="Pinned(SshPublicKey[])"/> for fixed keys, or <see cref="FromDelegate"/> for your own logic.
/// </summary>
public abstract class SshHostKeyVerifier
{
    /// <summary>Decides whether to trust the key in <paramref name="context"/>.</summary>
    public abstract ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken);

    /// <summary>Whether a host certificate would be checked (a certificate authority is trusted for the host), so certificates should be asked for first.</summary>
    internal virtual ValueTask<bool> PrefersCertificatesAsync(string? host, int port, string? hostKeyAlias, CancellationToken cancellationToken) =>
        ValueTask.FromResult(false);

    /// <summary>A verifier that calls <paramref name="verify"/>: true trusts the key.</summary>
    public static SshHostKeyVerifier FromDelegate(Func<SshHostKeyContext, CancellationToken, ValueTask<bool>> verify)
    {
        ArgumentNullException.ThrowIfNull(verify);
        return new DelegateVerifier(verify);
    }

    /// <summary>Trusts only keys with one of these OpenSSH SHA-256 fingerprints (<c>SHA256:...</c>, as <c>ssh-keygen -lf</c> prints).</summary>
    public static SshHostKeyVerifier Pinned(params string[] fingerprints)
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        if (fingerprints.Length == 0)
        {
            throw new ArgumentException("At least one fingerprint is required.", nameof(fingerprints));
        }

        return new PinnedVerifier([.. fingerprints]);
    }

    /// <summary>
    /// Trusts only these keys: the server's key must be one of them, byte for byte (for a host certificate, the certified key). Read
    /// them with <see cref="SshPublicKey.Parse"/> from the server's <c>/etc/ssh/ssh_host_*_key.pub</c> files.
    /// </summary>
    /// <exception cref="ArgumentException">No key was given, or a key is null.</exception>
    public static SshHostKeyVerifier Pinned(params SshPublicKey[] keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Length == 0)
        {
            throw new ArgumentException("At least one key is required.", nameof(keys));
        }

        if (Array.Exists(keys, k => k is null))
        {
            throw new ArgumentException("A pinned key must not be null.", nameof(keys));
        }

        return new PinnedKeysVerifier([.. keys]);
    }

    private sealed class DelegateVerifier(Func<SshHostKeyContext, CancellationToken, ValueTask<bool>> verify) : SshHostKeyVerifier
    {
        public override async ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken) =>
            await verify(context, cancellationToken).ConfigureAwait(false)
                ? SshHostKeyVerdict.Accept()
                : SshHostKeyVerdict.Reject($"The host key {context.HostKey.Fingerprint} was not accepted.");
    }

    private sealed class PinnedVerifier(string[] fingerprints) : SshHostKeyVerifier
    {
        public override ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Array.Exists(fingerprints, f => string.Equals(f, context.HostKey.Fingerprint, StringComparison.Ordinal))
                ? SshHostKeyVerdict.Accept()
                : SshHostKeyVerdict.Reject($"The host key {context.HostKey.Fingerprint} is not one of the pinned fingerprints."));
    }

    private sealed class PinnedKeysVerifier(SshPublicKey[] keys) : SshHostKeyVerifier
    {
        public override ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Array.Exists(keys, k => k.Blob.Span.SequenceEqual(context.HostKey.PublicKey.Span))
                ? SshHostKeyVerdict.Accept()
                : SshHostKeyVerdict.Reject($"The host key {context.HostKey.Fingerprint} is not one of the pinned keys."));
    }
}
