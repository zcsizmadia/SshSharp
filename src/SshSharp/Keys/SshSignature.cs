using System.Security.Cryptography;
using System.Text;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// An SSH signature over a file or a message (OpenSSH's SSHSIG format, <c>ssh-keygen -Y sign</c>), as git uses for signed commits
/// with <c>gpg.format=ssh</c>. Make one with <see cref="SignAsync(SshPrivateKey, ReadOnlyMemory{byte}, string, string, CancellationToken)"/>
/// (any key, an agent's too), write it with <see cref="ToString"/>, and read one with <see cref="Parse"/>.
/// </summary>
/// <remarks>
/// <see cref="Verify(ReadOnlySpan{byte}, string)"/> proves only that the holder of <see cref="PublicKey"/> signed the message; whether that
/// key belongs to whom it claims is a separate question, answered by <see cref="SshAllowedSigners"/> (<c>ssh-keygen -Y verify</c>), or
/// by <see cref="Verify(ReadOnlySpan{byte}, string, SshPublicKey)"/> when you know the one key that must have signed.
/// The namespace (<c>git</c>, <c>file</c>, or your application's own, such as <c>backup@example.com</c>) keeps a signature made for one
/// purpose from being accepted for another.
/// </remarks>
public sealed class SshSignature
{
    private const string BeginMarker = "-----BEGIN SSH SIGNATURE-----";
    private const string EndMarker = "-----END SSH SIGNATURE-----";
    private const uint Version = 1;
    private static ReadOnlySpan<byte> Magic => "SSHSIG"u8;

    private readonly byte[] _blob;
    private readonly byte[] _signature;

    private SshSignature(byte[] blob, byte[] publicKey, string @namespace, string hashAlgorithm, byte[] signature)
    {
        _blob = blob;
        PublicKey = publicKey;
        Namespace = @namespace;
        HashAlgorithm = hashAlgorithm;
        _signature = signature;
        KeyType = new SshReader(publicKey).ReadUtf8String();
        if (SshCertificate.IsCertificateAlgorithm(KeyType))
        {
            try
            {
                Certificate = SshCertificate.FromBlob(publicKey);
            }
            catch (SshProtocolException)
            {
                // A certificate type SshSharp does not read (a security key's): the signature cannot be verified here.
            }
        }
    }

    /// <summary>The signer's public key in SSH wire format, or its certificate when it signed with one.</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The signer's key type, for example <c>ssh-ed25519</c> (or <c>ssh-ed25519-cert-v01@openssh.com</c> for a certificate).</summary>
    public string KeyType { get; }

    /// <summary>The signer's certificate, when it signed with one.</summary>
    public SshCertificate? Certificate { get; }

    /// <summary>The SHA-256 fingerprint of the signer's key (of the certified key, for a certificate), as <c>ssh-keygen</c> prints it.</summary>
    public string Fingerprint => Certificate?.Fingerprint ?? "SHA256:" + Convert.ToBase64String(SHA256.HashData(PublicKey.Span)).TrimEnd('=');

    /// <summary>
    /// The signer's key as an <see cref="SshPublicKey"/> (the certified key, when it signed with a certificate), to compare with a key you
    /// trust: <see cref="Verify(ReadOnlySpan{byte}, string)"/> proves only that this key signed.
    /// </summary>
    /// <exception cref="FormatException">The key is one <see cref="SshPublicKey"/> does not read (a FIDO security-key certificate).</exception>
    public SshPublicKey GetPublicKey() => Certificate is { } certificate ? certificate.GetPublicKey() : SshPublicKey.Read(PublicKey.Span);

    /// <summary>What the signature is for, for example <c>git</c> or <c>file</c>; it must match when verifying.</summary>
    public string Namespace { get; }

    /// <summary>The hash of the message that was signed: <c>sha512</c> (the default) or <c>sha256</c>.</summary>
    public string HashAlgorithm { get; }

    /// <summary>Signs <paramref name="message"/>, as <c>ssh-keygen -Y sign -n <paramref name="namespace"/></c> does.</summary>
    /// <param name="key">The key to sign with: one loaded from a file, generated, or held by an <see cref="SshAgent"/>.</param>
    /// <param name="message">What to sign.</param>
    /// <param name="namespace">What the signature is for, for example <c>git</c>, <c>file</c>, or your application's own name.</param>
    /// <param name="hashAlgorithm"><c>sha512</c> (as ssh-keygen) or <c>sha256</c>.</param>
    /// <param name="cancellationToken">Cancels an agent's signing.</param>
    /// <exception cref="ArgumentException">The namespace is empty, or the hash algorithm is not one of the two.</exception>
    public static Task<SshSignature> SignAsync(SshPrivateKey key, ReadOnlyMemory<byte> message, string @namespace, string hashAlgorithm = "sha512",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        Validate(@namespace, hashAlgorithm);
        return SignHashAsync(key, Hash(hashAlgorithm, message.Span), @namespace, hashAlgorithm, cancellationToken);
    }

    /// <summary>Signs what <paramref name="message"/> reads to its end, as <c>ssh-keygen -Y sign</c> signs a file.</summary>
    /// <inheritdoc cref="SignAsync(SshPrivateKey, ReadOnlyMemory{byte}, string, string, CancellationToken)"/>
    public static async Task<SshSignature> SignAsync(SshPrivateKey key, Stream message, string @namespace, string hashAlgorithm = "sha512",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(message);
        Validate(@namespace, hashAlgorithm);
        var digest = await HashAsync(hashAlgorithm, message, cancellationToken).ConfigureAwait(false);
        return await SignHashAsync(key, digest, @namespace, hashAlgorithm, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses an armored signature (<c>-----BEGIN SSH SIGNATURE-----</c>), as <c>ssh-keygen -Y sign</c> writes to <c>.sig</c> files.</summary>
    /// <exception cref="FormatException">The text is not an SSH signature, or a version or hash algorithm this library does not know.</exception>
    public static SshSignature Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var begin = text.IndexOf(BeginMarker, StringComparison.Ordinal);
        var end = begin < 0 ? -1 : text.IndexOf(EndMarker, begin, StringComparison.Ordinal);
        if (begin < 0 || end < 0)
        {
            throw new FormatException("Not an SSH signature (expected '" + BeginMarker + "').");
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(text[(begin + BeginMarker.Length)..end]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("The SSH signature's base64 is malformed.", ex);
        }

        try
        {
            var reader = new SshReader(blob);
            if (!reader.ReadBytes(Magic.Length).SequenceEqual(Magic))
            {
                throw new FormatException("The SSH signature does not start with SSHSIG.");
            }

            var version = reader.ReadUInt32();
            if (version != Version)
            {
                throw new FormatException($"SSH signature version {version} is not supported (only {Version}).");
            }

            var publicKey = reader.ReadString().ToArray();
            var @namespace = reader.ReadUtf8String();
            reader.ReadString(); // reserved
            var hashAlgorithm = reader.ReadUtf8String();
            var signature = reader.ReadString().ToArray();
            if (!reader.IsEmpty)
            {
                throw new FormatException("Trailing data after the SSH signature.");
            }

            if (hashAlgorithm is not ("sha256" or "sha512"))
            {
                throw new FormatException($"The SSH signature's hash algorithm '{hashAlgorithm}' is not supported.");
            }

            if (@namespace.Length == 0)
            {
                throw new FormatException("The SSH signature has no namespace.");
            }

            return new SshSignature(blob, publicKey, @namespace, hashAlgorithm, signature);
        }
        catch (SshProtocolException ex)
        {
            throw new FormatException($"The SSH signature is malformed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Whether this is a valid signature over <paramref name="message"/> by <see cref="PublicKey"/>, for <paramref name="namespace"/>.
    /// It does not say whether to trust the key: check that with <see cref="SshAllowedSigners"/>, or compare <see cref="PublicKey"/>
    /// with the key you expect.
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> message, string @namespace)
    {
        ArgumentNullException.ThrowIfNull(@namespace);
        return VerifyHash(Hash(HashAlgorithm, message), @namespace);
    }

    /// <summary>Like <see cref="Verify(ReadOnlySpan{byte}, string)"/>, over what <paramref name="message"/> reads to its end.</summary>
    public async Task<bool> VerifyAsync(Stream message, string @namespace, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(@namespace);
        return VerifyHash(await HashAsync(HashAlgorithm, message, cancellationToken).ConfigureAwait(false), @namespace);
    }

    /// <summary>
    /// Whether this is a valid signature over <paramref name="message"/>, for <paramref name="namespace"/>, by <paramref name="expectedKey"/>:
    /// <see cref="Verify(ReadOnlySpan{byte}, string)"/>, and the signer's key is the one you trust, as <c>ssh-keygen -Y check-novalidate</c>
    /// with a known key. A signature made with a certificate counts as its certified key's (<see cref="GetPublicKey"/>); the certificate
    /// itself is not checked.
    /// </summary>
    /// <param name="message">The message that was signed.</param>
    /// <param name="namespace">What the signature must be for, for example <c>git</c> or <c>file</c>.</param>
    /// <param name="expectedKey">The key that must have signed. Its comment is ignored.</param>
    /// <returns>True when <paramref name="expectedKey"/> made this signature over the message for the namespace; false otherwise.</returns>
    public bool Verify(ReadOnlySpan<byte> message, string @namespace, SshPublicKey expectedKey)
    {
        ArgumentNullException.ThrowIfNull(@namespace);
        ArgumentNullException.ThrowIfNull(expectedKey);
        return IsBy(expectedKey) && VerifyHash(Hash(HashAlgorithm, message), @namespace);
    }

    /// <summary>Like <see cref="Verify(ReadOnlySpan{byte}, string, SshPublicKey)"/>, over what <paramref name="message"/> reads to its end.</summary>
    /// <param name="message">The message that was signed, read to its end.</param>
    /// <param name="namespace">What the signature must be for.</param>
    /// <param name="expectedKey">The key that must have signed.</param>
    /// <param name="cancellationToken">Cancels reading the message.</param>
    public async Task<bool> VerifyAsync(Stream message, string @namespace, SshPublicKey expectedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(@namespace);
        ArgumentNullException.ThrowIfNull(expectedKey);

        // Checked first: a signature by another key needs no hash of the message.
        return IsBy(expectedKey)
            && VerifyHash(await HashAsync(HashAlgorithm, message, cancellationToken).ConfigureAwait(false), @namespace);
    }

    /// <summary>Whether the signer's key (the certified key, for a certificate) is <paramref name="key"/>.</summary>
    private bool IsBy(SshPublicKey key) => (Certificate?.PublicKey ?? PublicKey).Span.SequenceEqual(key.Blob.Span);

    /// <summary>The armored signature, as <c>ssh-keygen -Y sign</c> writes it (base64 in lines of 70 characters).</summary>
    public override string ToString()
    {
        var base64 = Convert.ToBase64String(_blob);
        var text = new StringBuilder(BeginMarker.Length + EndMarker.Length + base64.Length + (base64.Length / 70) + 4);
        text.Append(BeginMarker).Append('\n');
        for (var i = 0; i < base64.Length; i += 70)
        {
            text.Append(base64.AsSpan(i, Math.Min(70, base64.Length - i))).Append('\n');
        }

        return text.Append(EndMarker).Append('\n').ToString();
    }

    /// <summary>Checks the signature over a message digest made with <see cref="HashAlgorithm"/>.</summary>
    internal bool VerifyHash(byte[] digest, string @namespace)
    {
        if (@namespace != Namespace)
        {
            return false;
        }

        VerifyingKey key;
        try
        {
            key = Certificate?.Key ?? VerifyingKey.Parse(PublicKey.Span);
        }
        catch (SshProtocolException)
        {
            return false; // a key type SshSharp cannot verify
        }

        string algorithm;
        try
        {
            algorithm = new SshReader(_signature).ReadUtf8String();
        }
        catch (SshProtocolException)
        {
            return false;
        }

        // VerifySignature accepts only the algorithms the key type allows; for RSA that excludes SHA-1 (ssh-rsa), as OpenSSH does.
        return key.VerifySignature(algorithm, _signature, SignedData(Namespace, HashAlgorithm, digest));
    }

    internal static byte[] Hash(string hashAlgorithm, ReadOnlySpan<byte> message) =>
        hashAlgorithm == "sha256" ? SHA256.HashData(message) : SHA512.HashData(message);

    internal static async Task<byte[]> HashAsync(string hashAlgorithm, Stream message, CancellationToken cancellationToken) =>
        hashAlgorithm == "sha256"
            ? await SHA256.HashDataAsync(message, cancellationToken).ConfigureAwait(false)
            : await SHA512.HashDataAsync(message, cancellationToken).ConfigureAwait(false);

    private static void Validate(string @namespace, string hashAlgorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(@namespace);
        if (hashAlgorithm is not ("sha256" or "sha512"))
        {
            throw new ArgumentException($"The hash algorithm must be sha512 or sha256, not '{hashAlgorithm}'.", nameof(hashAlgorithm));
        }
    }

    private static async Task<SshSignature> SignHashAsync(SshPrivateKey key, byte[] digest, string @namespace, string hashAlgorithm,
        CancellationToken cancellationToken)
    {
        // The key's preferred algorithm: rsa-sha2-512 for RSA, as ssh-keygen; a certificate signs as its key.
        var request = new SshSignRequest(key.SignatureAlgorithms[0], SignedData(@namespace, hashAlgorithm, digest), SshSignaturePurpose.FileSignature)
        {
            Namespace = @namespace,
        };
        var signature = await key.SignAsync(request, binding: null, cancellationToken).ConfigureAwait(false);
        var publicKey = key.PublicKey.ToArray();
        var blob = SshPrivateKey.Encode(w =>
        {
            w.WriteBytes(Magic);
            w.WriteUInt32(Version);
            w.WriteString(publicKey);
            w.WriteString(@namespace);
            w.WriteString(ReadOnlySpan<byte>.Empty); // reserved
            w.WriteString(hashAlgorithm);
            w.WriteString(signature);
        });
        return new SshSignature(blob, publicKey, @namespace, hashAlgorithm, signature);
    }

    // PROTOCOL.sshsig: what the key signs is the preamble, the namespace, an empty reserved field, the hash algorithm and the message's hash.
    private static byte[] SignedData(string @namespace, string hashAlgorithm, byte[] digest) => SshPrivateKey.Encode(w =>
    {
        w.WriteBytes(Magic);
        w.WriteString(@namespace);
        w.WriteString(ReadOnlySpan<byte>.Empty);
        w.WriteString(hashAlgorithm);
        w.WriteString(digest);
    });
}
