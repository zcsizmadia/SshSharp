using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>Whether an OpenSSH certificate certifies a user or a host.</summary>
public enum SshCertificateType
{
    /// <summary>A user certificate (type 1), for authenticating a client.</summary>
    User = 1,

    /// <summary>A host certificate (type 2), for authenticating a server.</summary>
    Host = 2,
}

/// <summary>
/// An OpenSSH certificate (PROTOCOL.certkeys): a public key signed by a certificate authority, limited to some principals, a validity
/// window, and options. Presented by servers as host keys and used by clients for public-key authentication. Read one with
/// <see cref="Parse"/>, check one with <see cref="IsValidFor"/> (or its parts, <see cref="VerifySignature"/> and <see cref="IsValidAt"/>),
/// and issue one with <see cref="SshCertificateBuilder"/>.
/// </summary>
/// <remarks>
/// A certificate proves only that the holder of <see cref="AuthorityKey"/> signed it. Anyone can make a certificate authority, so what
/// makes a certificate trustworthy is that its authority is one you trust: compare <see cref="GetAuthorityKey"/> with it, as
/// <see cref="IsValidFor"/> does.
/// </remarks>
public sealed class SshCertificate
{
    private const string Suffix = "-cert-v01@openssh.com";

    /// <summary>The smallest RSA authority key whose signature is accepted, as for every other RSA key the library checks by default.</summary>
    private const int MinimumAuthorityRsaBits = SshClientOptions.DefaultMinimumRsaBits;

    private SshCertificate(string certificateType, byte[] blob, VerifyingKey key, byte[] publicKeyBlob, ulong serial, SshCertificateType type,
        string keyId, IReadOnlyList<string> principals, ulong validAfter, ulong validBefore, IReadOnlyDictionary<string, string> criticalOptions,
        IReadOnlyList<string> extensions, byte[] authorityKey, byte[] signedData, byte[] signature, string? comment)
    {
        Comment = comment;
        Algorithm = certificateType;
        Blob = blob;
        Key = key;
        PublicKey = publicKeyBlob;
        Serial = serial;
        Type = type;
        KeyId = keyId;
        Principals = principals;
        ValidAfterSeconds = validAfter;
        ValidBeforeSeconds = validBefore;
        CriticalOptions = criticalOptions;
        Extensions = extensions;
        AuthorityKey = authorityKey;
        SignedData = signedData;
        Signature = signature;
    }

    /// <summary>The certificate's type name, for example <c>ssh-ed25519-cert-v01@openssh.com</c>.</summary>
    public string Algorithm { get; }

    /// <summary>The certified key's type, for example <c>ssh-ed25519</c>.</summary>
    public string KeyType => Key.KeyType;

    /// <summary>The certificate in SSH wire format.</summary>
    public ReadOnlyMemory<byte> Blob { get; }

    /// <summary>The certified public key, in SSH wire format.</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The certified key's SHA-256 fingerprint.</summary>
    public string Fingerprint => Key.Fingerprint;

    /// <summary>The serial number the authority gave the certificate.</summary>
    public ulong Serial { get; }

    /// <summary>Whether this certifies a user or a host.</summary>
    public SshCertificateType Type { get; }

    /// <summary>The key identifier the authority chose (it appears in server logs).</summary>
    public string KeyId { get; }

    /// <summary>
    /// The user or host names the certificate is valid for. An empty list is refused by <see cref="IsValidFor"/>, by sshd for
    /// <c>TrustedUserCAKeys</c> and by ssh for host certificates; only an <c>authorized_keys</c> <c>cert-authority</c> line without
    /// <c>principals=</c> takes it as any user.
    /// </summary>
    public IReadOnlyList<string> Principals { get; }

    /// <summary>The start of the validity window (inclusive): <see cref="DateTimeOffset.UnixEpoch"/> for "always".</summary>
    public DateTimeOffset ValidAfter => ToTime(ValidAfterSeconds);

    /// <summary>The end of the validity window (exclusive): <see cref="DateTimeOffset.MaxValue"/> for "forever".</summary>
    public DateTimeOffset ValidBefore => ToTime(ValidBeforeSeconds);

    /// <summary>The comment after the certificate on its line (<see cref="Parse"/>), often the certified key's; null when there is none.</summary>
    public string? Comment { get; }

    /// <summary>Critical options (for example <c>force-command</c>, <c>source-address</c>); a verifier must refuse ones it does not understand.</summary>
    public IReadOnlyDictionary<string, string> CriticalOptions { get; }

    /// <summary>Extensions (for example <c>permit-pty</c>).</summary>
    public IReadOnlyList<string> Extensions { get; }

    /// <summary>The certificate authority's public key, in SSH wire format (what <c>@cert-authority</c> lines hold).</summary>
    public ReadOnlyMemory<byte> AuthorityKey { get; }

    /// <summary>The certificate authority's SHA-256 fingerprint.</summary>
    public string AuthorityFingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(AuthorityKey.Span)).TrimEnd('=');

    /// <summary><see cref="PublicKey"/>, the certified key, as an <see cref="SshPublicKey"/>.</summary>
    public SshPublicKey GetPublicKey() => SshPublicKey.FromVerifyingKey(Key);

    /// <summary>
    /// <see cref="AuthorityKey"/>, the certificate authority's key, as an <see cref="SshPublicKey"/>: compare it with the authority you
    /// trust (<c>certificate.GetAuthorityKey() == trustedCa</c>).
    /// </summary>
    /// <exception cref="FormatException">The authority's key is not one <see cref="SshPublicKey"/> reads.</exception>
    public SshPublicKey GetAuthorityKey() => SshPublicKey.Read(AuthorityKey.Span);

    internal VerifyingKey Key { get; }

    internal ulong ValidAfterSeconds { get; }

    internal ulong ValidBeforeSeconds { get; }

    private byte[] SignedData { get; }

    private byte[] Signature { get; }

    /// <summary>Parses a certificate from an OpenSSH <c>-cert.pub</c> file's contents (<c>type base64 [comment]</c>).</summary>
    /// <exception cref="FormatException">The text is not a supported certificate.</exception>
    public static SshCertificate Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var fields = text.Trim().Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !fields[0].EndsWith(Suffix, StringComparison.Ordinal))
        {
            throw new FormatException("Not an OpenSSH certificate line (expected '<type>-cert-v01@openssh.com <base64> [comment]').");
        }

        // The comment is the rest of the line; one that runs onto further lines is left out rather than carried into a line it is written to.
        var comment = fields.Length == 3 ? fields[2].Trim() : null;
        if (comment is not null && comment.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            comment = null;
        }

        try
        {
            var certificate = FromBlob(Convert.FromBase64String(fields[1]), comment);
            return certificate.Algorithm == fields[0]
                ? certificate
                : throw new FormatException("The certificate's type does not match the line's type field.");
        }
        catch (SshProtocolException ex)
        {
            throw new FormatException($"The certificate is malformed: {ex.Message}", ex);
        }
    }

    /// <summary>Whether <paramref name="algorithm"/> is a certificate algorithm (<c>...-cert-v01@openssh.com</c>).</summary>
    internal static bool IsCertificateAlgorithm(string algorithm) => algorithm.EndsWith(Suffix, StringComparison.Ordinal);

    private const string OpenSshDomain = "@openssh.com";

    /// <summary>
    /// The plain signature algorithm behind a certificate algorithm: <c>rsa-sha2-512-cert-v01@openssh.com</c> signs as <c>rsa-sha2-512</c>.
    /// Security-key types keep their domain: <c>sk-ssh-ed25519-cert-v01@openssh.com</c> signs as <c>sk-ssh-ed25519@openssh.com</c>.
    /// </summary>
    internal static string BaseAlgorithm(string certificateAlgorithm)
    {
        if (!IsCertificateAlgorithm(certificateAlgorithm))
        {
            return certificateAlgorithm;
        }

        var name = certificateAlgorithm[..^Suffix.Length];
        return name.StartsWith("sk-", StringComparison.Ordinal) ? name + OpenSshDomain : name;
    }

    /// <summary>The certificate key type for a signature algorithm: RSA certificates are <c>ssh-rsa-cert-v01@openssh.com</c> whatever the hash.</summary>
    internal static string CertificateKeyType(string certificateAlgorithm) => BaseAlgorithm(certificateAlgorithm) switch
    {
        SshAlgorithms.RsaSha2_256 or SshAlgorithms.RsaSha2_512 => "ssh-rsa" + Suffix,
        var sk when sk.StartsWith("sk-", StringComparison.Ordinal) && sk.EndsWith(OpenSshDomain, StringComparison.Ordinal) => sk[..^OpenSshDomain.Length] + Suffix,
        var other => other + Suffix,
    };

    /// <summary>Parses a certificate blob (wire format). Throws <see cref="SshProtocolException"/> when it is malformed.</summary>
    internal static SshCertificate FromBlob(ReadOnlySpan<byte> blob, string? comment = null)
    {
        var reader = new SshReader(blob);
        var certificateType = reader.ReadUtf8String();
        if (!IsCertificateAlgorithm(certificateType))
        {
            throw new SshProtocolException($"'{certificateType}' is not a certificate type.");
        }

        reader.ReadString(); // nonce
        var keyType = certificateType[..^Suffix.Length];

        // The key fields follow the nonce; re-encode them as a plain public key of the base type.
        byte[] plain;
        switch (keyType)
        {
            case SshAlgorithms.SshEd25519:
            {
                var key = reader.ReadString().ToArray();
                plain = SshPrivateKey.Encode(w => { w.WriteString(keyType); w.WriteString(key); });
                break;
            }

            case SshAlgorithms.EcdsaNistp256 or SshAlgorithms.EcdsaNistp384 or SshAlgorithms.EcdsaNistp521:
            {
                var curve = reader.ReadString().ToArray();
                var point = reader.ReadString().ToArray();
                plain = SshPrivateKey.Encode(w => { w.WriteString(keyType); w.WriteString(curve); w.WriteString(point); });
                break;
            }

            case "ssh-rsa":
            {
                var e = reader.ReadMpint().ToArray();
                var n = reader.ReadMpint().ToArray();
                plain = SshPrivateKey.Encode(w => { w.WriteString(keyType); w.WriteMpint(e); w.WriteMpint(n); });
                break;
            }

            default:
                throw new SshProtocolException($"Unsupported certificate key type '{keyType}'.");
        }

        var parsedKey = VerifyingKey.Parse(plain);
        var serial = reader.ReadUInt64();
        var type = reader.ReadUInt32() switch
        {
            1 => SshCertificateType.User,
            2 => SshCertificateType.Host,
            var other => throw new SshProtocolException($"Unknown certificate type {other}."),
        };
        var keyId = reader.ReadUtf8String();
        var principals = ReadStrings(reader.ReadString());
        var validAfter = reader.ReadUInt64();
        var validBefore = reader.ReadUInt64();
        var criticalOptions = ReadOptions(reader.ReadString());
        var extensions = ReadOptions(reader.ReadString()).Keys.ToList();
        reader.ReadString(); // reserved
        var authorityKey = reader.ReadString().ToArray();
        var signedLength = blob.Length - reader.Remaining.Length;
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data after the certificate.");
        }

        if (IsCertificateAlgorithm(new SshReader(authorityKey).ReadUtf8String()))
        {
            throw new SshProtocolException("A certificate authority's key cannot itself be a certificate.");
        }

        return new SshCertificate(certificateType, blob.ToArray(), parsedKey, plain, serial, type, keyId, principals, validAfter, validBefore,
            criticalOptions, extensions, authorityKey, blob[..signedLength].ToArray(), signature, comment);
    }

    /// <summary>
    /// Whether <see cref="AuthorityKey"/>'s signature over the certificate is valid, with the rules the library applies to every
    /// certificate it checks: SHA-1 (<c>ssh-rsa</c>) signatures are refused, an RSA authority must have at least 2048 bits, and Ed25519
    /// signatures are checked strictly (RFC 8032: a non-canonical signature or a small-order key fails).
    /// </summary>
    /// <returns>True when the signature is valid; false for a wrong, malformed or refused signature, or an authority key that cannot
    /// verify (a FIDO security key's).</returns>
    /// <remarks>
    /// This proves only that the holder of <see cref="AuthorityKey"/> issued the certificate, not that you trust that authority: check
    /// that with <see cref="GetAuthorityKey"/>, or use <see cref="IsValidFor"/>, which checks both.
    /// </remarks>
    public bool VerifySignature()
    {
        try
        {
            var authority = VerifyingKey.Parse(AuthorityKey.Span);
            if (authority.KeyType == "ssh-rsa" && authority.KeySizeBits < MinimumAuthorityRsaBits)
            {
                return false;
            }

            var algorithm = new SshReader(Signature).ReadUtf8String();
            return authority.VerifySignature(algorithm, Signature, SignedData);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="time"/> is within the validity window, as OpenSSH has it: <c>valid_after &lt;= time &lt; valid_before</c>,
    /// in whole seconds. The window's start is inclusive and its end exclusive; "always" and "forever" (<c>0xffffffffffffffff</c>) are
    /// the ends of time.
    /// </summary>
    /// <param name="time">The time to check, usually now.</param>
    public bool IsValidAt(DateTimeOffset time)
    {
        var seconds = (ulong)Math.Max(0, time.ToUnixTimeSeconds());
        return seconds >= ValidAfterSeconds && seconds < ValidBeforeSeconds;
    }

    /// <summary>
    /// Checks the certificate as sshd checks a user certificate from a <c>TrustedUserCAKeys</c> authority, and ssh a host certificate
    /// from an <c>@cert-authority</c>: issued by <paramref name="authority"/>, of <paramref name="type"/>, with a valid signature
    /// (<see cref="VerifySignature"/>), valid at <paramref name="time"/> (<see cref="IsValidAt"/>), for <paramref name="principal"/>, and
    /// without critical options.
    /// </summary>
    /// <param name="authority">The certificate authority you trust.</param>
    /// <param name="type">The type the certificate must be: <see cref="SshCertificateType.User"/> for a user logging in,
    /// <see cref="SshCertificateType.Host"/> for a server.</param>
    /// <param name="principal">The user name, or the host name, the certificate is presented for. A user certificate's principals must
    /// include it exactly; a host certificate's principals are patterns (<c>*.example.com</c>), matched without regard to case as DNS
    /// names are. A certificate without principals is no one's, as sshd and ssh have it (not everyone's).</param>
    /// <param name="time">The time to check at, usually <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <param name="reason">Why the certificate is not acceptable, as a short phrase (for example "it is valid only from ... to ..."), or
    /// null when it is.</param>
    /// <returns>Whether the certificate is acceptable.</returns>
    /// <remarks>
    /// A certificate with critical options (<c>force-command</c>, <c>source-address</c>, <c>verify-required</c>) is refused: they restrict
    /// what the certificate allows, and this check cannot enforce them. An application that does enforce them checks the parts itself:
    /// <see cref="GetAuthorityKey"/>, <see cref="Type"/>, <see cref="VerifySignature"/>, <see cref="IsValidAt"/>, <see cref="Principals"/>
    /// and <see cref="CriticalOptions"/>. Revocation is not checked.
    /// </remarks>
    public bool IsValidFor(SshPublicKey authority, SshCertificateType type, string principal, DateTimeOffset time,
        [NotNullWhen(false)] out string? reason)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(principal);
        reason = AuthorityKey.Span.SequenceEqual(authority.Blob.Span)
            ? Check(type, principal, time)
            : $"it is issued by another authority ({AuthorityFingerprint})";
        return reason is null;
    }

    /// <summary>The certificate as its <c>-cert.pub</c> file holds it: the certificate type, the base64 certificate and the comment, if any.</summary>
    public string ToAuthorizedKeysLine() =>
        $"{Algorithm} {Convert.ToBase64String(Blob.Span)}{(Comment is null ? string.Empty : " " + Comment)}";

    /// <summary>The certificate as <see cref="ToAuthorizedKeysLine"/> writes it.</summary>
    public override string ToString() => ToAuthorizedKeysLine();

    /// <summary>
    /// Checks the certificate as a host's (<see cref="IsValidFor"/> with <see cref="SshCertificateType.Host"/>, for an authority the caller
    /// already matched). Returns why it is not acceptable, or null. As OpenSSH's client: a certificate without principals is no host's
    /// (not any host's, which would let a key its authority certified by mistake pose as every host).
    /// </summary>
    internal string? CheckForHost(string hostName, DateTimeOffset now) => Check(SshCertificateType.Host, hostName, now);

    /// <summary>The checks of <see cref="IsValidFor"/> after the authority: why the certificate is not acceptable, or null.</summary>
    private string? Check(SshCertificateType type, string principal, DateTimeOffset time)
    {
        if (Type != type)
        {
            return Type == SshCertificateType.User ? "it is a user certificate, not a host certificate" : "it is a host certificate, not a user certificate";
        }

        if (!VerifySignature())
        {
            return "its authority's signature is invalid";
        }

        if (!IsValidAt(time))
        {
            return $"it is valid only from {ValidAfter:u} to {ValidBefore:u}";
        }

        if (Principals.Count == 0)
        {
            return type == SshCertificateType.Host ? "it lists no principals, so it is no host's" : "it lists no principals, so it is no user's";
        }

        // sshd compares user names exactly; host names are patterns, and DNS names have no case.
        var matches = type == SshCertificateType.Host
            ? Principals.Any(p => Config.Glob.IsMatch(p, principal, ignoreCase: true))
            : Principals.Contains(principal, StringComparer.Ordinal);
        if (!matches)
        {
            return $"it is not issued for {principal}";
        }

        return CriticalOptions.Count > 0 ? $"it has critical options this check cannot enforce ({string.Join(", ", CriticalOptions.Keys)})" : null;
    }

    private static DateTimeOffset ToTime(ulong seconds) =>
        seconds >= (ulong)DateTimeOffset.MaxValue.ToUnixTimeSeconds() ? DateTimeOffset.MaxValue : DateTimeOffset.FromUnixTimeSeconds((long)seconds);

    private static List<string> ReadStrings(ReadOnlySpan<byte> packed)
    {
        var reader = new SshReader(packed);
        var values = new List<string>();
        while (!reader.IsEmpty)
        {
            values.Add(reader.ReadUtf8String());
        }

        return values;
    }

    /// <summary>Options and extensions: name, then a string holding the value (itself a string, or empty).</summary>
    private static Dictionary<string, string> ReadOptions(ReadOnlySpan<byte> packed)
    {
        var reader = new SshReader(packed);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        while (!reader.IsEmpty)
        {
            var name = reader.ReadUtf8String();
            var data = reader.ReadString();
            var value = data.IsEmpty ? string.Empty : Encoding.UTF8.GetString(new SshReader(data).ReadString());
            if (!values.TryAdd(name, value))
            {
                throw new SshProtocolException($"The certificate option '{name}' appears twice.");
            }
        }

        return values;
    }
}
