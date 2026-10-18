using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// An SSH public key: what a <c>.pub</c> file, an <c>authorized_keys</c> line or a <c>known_hosts</c> line holds. Read one with
/// <see cref="Parse"/> (a line of text) or <see cref="FromBlob"/> (the SSH wire format), and get one from a key the library already has:
/// <see cref="SshPrivateKey.GetPublicKey"/>, <see cref="SshHostKey.GetPublicKey"/>, <see cref="Config.KnownHostsEntry.GetPublicKey"/>,
/// <see cref="SshCertificate.GetPublicKey"/>. Key types: Ed25519, ECDSA (nistp256/384/521), RSA, and the FIDO security-key types
/// <c>sk-ssh-ed25519@openssh.com</c> and <c>sk-ecdsa-sha2-nistp256@openssh.com</c>.
/// </summary>
/// <remarks>
/// <para>
/// Immutable and thread-safe. Two keys are equal when their key bytes are (<see cref="Blob"/>, which includes the key type); the
/// <see cref="Comment"/> is not part of the key and is ignored.
/// </para>
/// <para>
/// Parsing checks what verifying a signature relies on, as for a server's host key: an ECDSA point must be on its curve, an RSA key's
/// modulus and exponent must be sane. Hostile input fails with <see cref="FormatException"/>.
/// </para>
/// </remarks>
public sealed class SshPublicKey : IEquatable<SshPublicKey>
{
    /// <summary>The largest blob accepted: a 16384-bit RSA key (the largest OpenSSH accepts) is about 2 KiB.</summary>
    internal const int MaxBlobLength = 8192;

    private const string SkEd25519 = "sk-ssh-ed25519@openssh.com";
    private const string SkEcdsaNistp256 = "sk-ecdsa-sha2-nistp256@openssh.com";

    private readonly ReadOnlyMemory<byte> _blob;
    private readonly int _hashCode;

    // Null for the FIDO security-key types: their signatures carry authenticator data and a policy (user presence), which is not
    // verified here.
    private readonly VerifyingKey? _verifier;

    private SshPublicKey(string keyType, ReadOnlyMemory<byte> blob, int keySizeBits, VerifyingKey? verifier, string? comment)
    {
        KeyType = keyType;
        _blob = blob;
        KeySizeBits = keySizeBits;
        _verifier = verifier;
        Comment = string.IsNullOrEmpty(comment) ? null : comment;
        var hash = new HashCode();
        hash.AddBytes(blob.Span);
        _hashCode = hash.ToHashCode();
    }

    /// <summary>
    /// The key type name, for example <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c> or <c>ssh-rsa</c>, as <see cref="SshPrivateKey.KeyType"/>
    /// and <see cref="SshHostKey.KeyType"/> name it. An RSA key's type is <c>ssh-rsa</c> whichever signature algorithm it signs with.
    /// </summary>
    public string KeyType { get; }

    /// <summary>The key size in bits: 256 for Ed25519, the curve size for ECDSA (256, 384, 521), the modulus size for RSA.</summary>
    public int KeySizeBits { get; }

    /// <summary>The comment that came with the key (often <c>user@host</c>), or null (never empty). It is not part of the key.</summary>
    public string? Comment { get; }

    /// <summary>The key in SSH wire format (RFC 4253 section 6.6): what the base64 field of a <c>.pub</c> line decodes to.</summary>
    public ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>The OpenSSH SHA-256 fingerprint (<c>SHA256:</c> and unpadded base64), as <c>ssh-keygen -lf</c> prints it.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(_blob.Span)).TrimEnd('=');

    /// <summary>
    /// Parses one line in the OpenSSH public key format, <c>&lt;type&gt; &lt;base64&gt; [comment]</c>: a <c>.pub</c> file, the output of
    /// <c>ssh-keygen -y</c>, or an <c>authorized_keys</c> line without options. White space around the line is ignored.
    /// </summary>
    /// <param name="line">The line.</param>
    /// <remarks>
    /// <c>authorized_keys</c> options (<c>restrict,command="..." ssh-ed25519 ...</c>) are not parsed: a line that starts with them is
    /// refused rather than read without the restrictions they carry. Certificates (<c>-cert.pub</c>) are read by
    /// <see cref="SshCertificate.Parse"/>.
    /// </remarks>
    /// <exception cref="FormatException">The line is not a single public key line of a supported type, the base64 is invalid, the key is
    /// malformed, or the type field does not match the key's own type.</exception>
    public static SshPublicKey Parse(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        return ParseLine(line, out var key) is { } error ? throw new FormatException(error) : key!;
    }

    /// <summary>Parses a line as <see cref="Parse"/> does, without throwing.</summary>
    /// <param name="line">The line; null gives false.</param>
    /// <param name="key">The key, when the line is one.</param>
    /// <returns>Whether the line is a supported public key.</returns>
    public static bool TryParse([NotNullWhen(true)] string? line, [NotNullWhen(true)] out SshPublicKey? key)
    {
        key = null;
        return line is not null && ParseLine(line, out key) is null;
    }

    /// <summary>Reads a key in SSH wire format, as <see cref="SshHostKey.PublicKey"/> and the other blob members hold it.</summary>
    /// <param name="blob">The key blob. It is copied.</param>
    /// <param name="comment">A comment to carry with the key, or null.</param>
    /// <exception cref="FormatException">The blob is malformed or not a supported key type.</exception>
    /// <exception cref="ArgumentException"><paramref name="comment"/> contains a line break.</exception>
    public static SshPublicKey FromBlob(ReadOnlyMemory<byte> blob, string? comment = null)
    {
        if (comment is not null && comment.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            // A comment is written at the end of an authorized_keys or known_hosts line; a line break would add a line of its own.
            throw new ArgumentException("A key comment must not contain a line break.", nameof(comment));
        }

        return ParseBlob(blob.Span, comment, out var key) is { } error ? throw new FormatException(error) : key!;
    }

    /// <summary>
    /// The fingerprint with <paramref name="hashAlgorithm"/>, as <c>ssh-keygen -l -E</c> prints it: <see cref="HashAlgorithmName.SHA256"/>
    /// gives <see cref="Fingerprint"/>, and <see cref="HashAlgorithmName.MD5"/> the legacy <c>MD5:aa:bb:...</c> form that older tools and
    /// inventories still show.
    /// </summary>
    /// <param name="hashAlgorithm">SHA256 or MD5.</param>
    /// <exception cref="ArgumentException"><paramref name="hashAlgorithm"/> is not SHA256 or MD5.</exception>
    [SuppressMessage("Security", "CA5351", Justification = "An MD5 fingerprint only names a key for display, as ssh-keygen -E md5 does; nothing is trusted on it.")]
    public string GetFingerprint(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return Fingerprint;
        }

        if (hashAlgorithm == HashAlgorithmName.MD5)
        {
            Span<byte> hash = stackalloc byte[MD5.HashSizeInBytes];
            MD5.HashData(_blob.Span, hash);
            var text = new StringBuilder("MD5:", 4 + (3 * MD5.HashSizeInBytes));
            for (var i = 0; i < hash.Length; i++)
            {
                text.Append(i == 0 ? string.Empty : ":").Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
            }

            return text.ToString();
        }

        throw new ArgumentException($"Fingerprints are SHA256 or MD5, not '{hashAlgorithm.Name}'.", nameof(hashAlgorithm));
    }

    /// <summary>
    /// Verifies an SSH signature made by this key's private key over <paramref name="data"/>. The signature is in the SSH encoding
    /// (<c>string algorithm || string signature</c>, RFC 4253 section 6.6), as agents and <see cref="SshKeySigner"/> produce it, and its
    /// algorithm must be one the key type signs with: <c>ssh-ed25519</c>, the key's <c>ecdsa-sha2-*</c>, or <c>rsa-sha2-256</c> and
    /// <c>rsa-sha2-512</c> for an RSA key (SHA-1 <c>ssh-rsa</c> signatures are refused).
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature blob.</param>
    /// <returns>True when the signature is valid; false for a wrong, malformed or mismatched signature.</returns>
    /// <exception cref="NotSupportedException">The key is a FIDO security key (<c>sk-</c>), whose signatures are not verified here.</exception>
    public bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (_verifier is null)
        {
            throw new NotSupportedException($"Signatures of {KeyType} keys carry security-key data and are not verified by SshPublicKey.");
        }

        string algorithm;
        try
        {
            algorithm = new SshReader(signature).ReadUtf8String();
        }
        catch (SshProtocolException)
        {
            return false;
        }

        return _verifier.VerifySignature(algorithm, signature, data);
    }

    /// <summary>The key as an <c>authorized_keys</c> or <c>.pub</c> line: type, base64 and the comment, if any.</summary>
    public string ToAuthorizedKeysLine() =>
        $"{KeyType} {Convert.ToBase64String(_blob.Span)}{(Comment is null ? string.Empty : " " + Comment)}";

    /// <summary>The key as <see cref="ToAuthorizedKeysLine"/> writes it.</summary>
    public override string ToString() => ToAuthorizedKeysLine();

    /// <summary>Whether <paramref name="other"/> is the same key: the same key bytes. The comment is ignored.</summary>
    public bool Equals([NotNullWhen(true)] SshPublicKey? other) =>
        other is not null && (ReferenceEquals(this, other) || _blob.Span.SequenceEqual(other._blob.Span));

    /// <inheritdoc/>
    public override bool Equals([NotNullWhen(true)] object? obj) => Equals(obj as SshPublicKey);

    /// <inheritdoc/>
    public override int GetHashCode() => _hashCode;

    /// <summary>Whether two keys are the same key (see <see cref="Equals(SshPublicKey)"/>).</summary>
    public static bool operator ==(SshPublicKey? left, SshPublicKey? right) => left is null ? right is null : left.Equals(right);

    /// <summary>Whether two keys are different keys (see <see cref="Equals(SshPublicKey)"/>).</summary>
    public static bool operator !=(SshPublicKey? left, SshPublicKey? right) => !(left == right);

    /// <summary>Wraps a key the library already parsed and checked; the comment is taken as <see cref="Read"/> takes it.</summary>
    internal static SshPublicKey FromVerifyingKey(VerifyingKey key, string? comment = null) =>
        new(key.KeyType, key.Blob, key.KeySizeBits, key, SingleLine(comment));

    /// <summary>
    /// Reads a blob another public type holds (a host key, a known_hosts entry, a private key's public half), throwing
    /// <see cref="FormatException"/> when it is not a key this type reads. A comment with a line break (an OpenSSH private key's comment
    /// can hold one) is left out rather than refused: it would add a line to whatever the key is written into.
    /// </summary>
    internal static SshPublicKey Read(ReadOnlySpan<byte> blob, string? comment = null) =>
        ParseBlob(blob, SingleLine(comment), out var key) is { } error ? throw new FormatException(error) : key!;

    private static string? SingleLine(string? comment) =>
        comment is not null && comment.AsSpan().IndexOfAny('\r', '\n') < 0 ? comment : null;

    /// <summary>Parses a line; returns the reason it is not a key, or null and the key.</summary>
    private static string? ParseLine(string line, out SshPublicKey? key)
    {
        key = null;
        var text = line.AsSpan().Trim();
        if (text.IndexOfAny('\r', '\n') >= 0)
        {
            return "A public key line must be a single line.";
        }

        // Fields are separated by spaces or tabs, as OpenSSH reads them; the comment is the rest of the line.
        var typeEnd = text.IndexOfAny(' ', '\t');
        if (typeEnd < 0)
        {
            return "A public key line is '<type> <base64> [comment]'.";
        }

        var type = text[..typeEnd].ToString();
        if (!IsSupportedType(type))
        {
            return SshCertificate.IsCertificateAlgorithm(type)
                ? "The line is a certificate; read it with SshCertificate.Parse."
                : "The line does not start with a supported key type (authorized_keys options are not parsed: pass the key part of the line).";
        }

        var rest = text[typeEnd..].TrimStart(" \t");
        var dataEnd = rest.IndexOfAny(' ', '\t');
        var data = dataEnd < 0 ? rest : rest[..dataEnd];
        var comment = dataEnd < 0 ? null : rest[dataEnd..].Trim(" \t").ToString();

        // Refuse an oversized field before decoding it.
        if (data.Length > ((MaxBlobLength + 2) / 3 * 4))
        {
            return "The public key is too large.";
        }

        var blob = new byte[data.Length / 4 * 3];
        if (!Convert.TryFromBase64Chars(data, blob, out var written))
        {
            return "The public key's base64 field is invalid.";
        }

        if (ParseBlob(blob.AsSpan(0, written), comment, out key) is { } error)
        {
            return error;
        }

        if (key!.KeyType != type)
        {
            key = null;
            return "The line's type field does not match the key's own type.";
        }

        return null;
    }

    /// <summary>Parses a blob; returns the reason it is not a key, or null and the key.</summary>
    private static string? ParseBlob(ReadOnlySpan<byte> blob, string? comment, out SshPublicKey? key)
    {
        key = null;
        if (blob.Length > MaxBlobLength)
        {
            return "The public key is too large.";
        }

        try
        {
            var type = new SshReader(blob).ReadUtf8String();
            if (!IsSupportedType(type))
            {
                return SshCertificate.IsCertificateAlgorithm(type)
                    ? "The blob is a certificate, not a plain public key."
                    : "The public key is not of a supported type.";
            }

            key = type is SkEd25519 or SkEcdsaNistp256
                ? ParseSecurityKey(type, blob, comment)
                : FromVerifyingKey(VerifyingKey.Parse(blob), comment);
            return null;
        }
        catch (SshProtocolException ex)
        {
            // The parser's messages say what is wrong with the key ("The ECDSA public key is not a point on the curve.").
            return "The public key is malformed: " + ex.Message;
        }
        catch (CryptographicException)
        {
            return "The public key is malformed.";
        }
    }

    /// <summary>
    /// A FIDO security key (PROTOCOL.u2f): the Ed25519 key or ECDSA P-256 point, then the application string (<c>ssh:</c> by default)
    /// the authenticator bound it to.
    /// </summary>
    private static SshPublicKey ParseSecurityKey(string type, ReadOnlySpan<byte> blob, string? comment)
    {
        var reader = new SshReader(blob);
        reader.ReadUtf8String();
        if (type == SkEd25519)
        {
            if (reader.ReadString().Length != Ed25519.PublicKeySize)
            {
                throw new SshProtocolException("An Ed25519 public key must be 32 bytes.");
            }
        }
        else
        {
            var curve = NistCurve.P256;
            if (reader.ReadUtf8String() != curve.Name)
            {
                throw new SshProtocolException($"The curve does not match key type '{type}'.");
            }

            var point = reader.ReadString();
            if (point.Length != 1 + (2 * curve.FieldSize) || point[0] != 4)
            {
                throw new SshProtocolException("An ECDSA public key must be an uncompressed point.");
            }

            if (!curve.IsOnCurve(point.Slice(1, curve.FieldSize), point[(1 + curve.FieldSize)..]))
            {
                throw new SshProtocolException("The ECDSA public key is not a point on the curve.");
            }
        }

        reader.ReadUtf8String(); // the application
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data after the public key.");
        }

        return new SshPublicKey(type, blob.ToArray(), 256, verifier: null, comment);
    }

    private static bool IsSupportedType(string type) => type is SshAlgorithms.SshEd25519 or SshAlgorithms.EcdsaNistp256
        or SshAlgorithms.EcdsaNistp384 or SshAlgorithms.EcdsaNistp521 or "ssh-rsa" or SkEd25519 or SkEcdsaNistp256;
}
