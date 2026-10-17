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
/// window, and options. Presented by servers as host keys and used by clients for public-key authentication.
/// </summary>
public sealed class SshCertificate
{
    private const string Suffix = "-cert-v01@openssh.com";

    private SshCertificate(string certificateType, byte[] blob, SshPublicKey key, byte[] publicKeyBlob, ulong serial, SshCertificateType type,
        string keyId, IReadOnlyList<string> principals, ulong validAfter, ulong validBefore, IReadOnlyDictionary<string, string> criticalOptions,
        IReadOnlyList<string> extensions, byte[] authorityKey, byte[] signedData, byte[] signature)
    {
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

    /// <summary>The user or host names the certificate is valid for; empty means any.</summary>
    public IReadOnlyList<string> Principals { get; }

    /// <summary>The start of the validity window.</summary>
    public DateTimeOffset ValidAfter => ToTime(ValidAfterSeconds);

    /// <summary>The end of the validity window (<see cref="DateTimeOffset.MaxValue"/> for "forever").</summary>
    public DateTimeOffset ValidBefore => ToTime(ValidBeforeSeconds);

    /// <summary>Critical options (for example <c>force-command</c>, <c>source-address</c>); a verifier must refuse ones it does not understand.</summary>
    public IReadOnlyDictionary<string, string> CriticalOptions { get; }

    /// <summary>Extensions (for example <c>permit-pty</c>).</summary>
    public IReadOnlyList<string> Extensions { get; }

    /// <summary>The certificate authority's public key, in SSH wire format (what <c>@cert-authority</c> lines hold).</summary>
    public ReadOnlyMemory<byte> AuthorityKey { get; }

    /// <summary>The certificate authority's SHA-256 fingerprint.</summary>
    public string AuthorityFingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(AuthorityKey.Span)).TrimEnd('=');

    internal SshPublicKey Key { get; }

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

        try
        {
            var certificate = FromBlob(Convert.FromBase64String(fields[1]));
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
    internal static SshCertificate FromBlob(ReadOnlySpan<byte> blob)
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

        var parsedKey = SshPublicKey.Parse(plain);
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
            criticalOptions, extensions, authorityKey, blob[..signedLength].ToArray(), signature);
    }

    /// <summary>Whether the authority's signature over the certificate is valid (with SHA-2 algorithms only).</summary>
    internal bool HasValidAuthoritySignature()
    {
        try
        {
            var algorithm = new SshReader(Signature).ReadUtf8String();
            return SshPublicKey.Parse(AuthorityKey.Span).VerifySignature(algorithm, Signature, SignedData);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks the certificate as a host's: a host certificate, signed by its authority, valid at <paramref name="now"/>, with a
    /// principal that matches <paramref name="hostName"/>, and with no critical options (none are defined for host certificates).
    /// Returns why it is not acceptable, or null. As OpenSSH's client: a certificate without principals is no host's (not any host's,
    /// which would let a key its authority certified by mistake pose as every host), and principals are patterns (<c>*.example.com</c>).
    /// Host names are compared without regard to case, as DNS names are.
    /// </summary>
    internal string? CheckForHost(string hostName, DateTimeOffset now)
    {
        if (Type != SshCertificateType.Host)
        {
            return "it is a user certificate, not a host certificate";
        }

        if (!HasValidAuthoritySignature())
        {
            return "its authority's signature is invalid";
        }

        var seconds = (ulong)Math.Max(0, now.ToUnixTimeSeconds());
        if (seconds < ValidAfterSeconds || seconds >= ValidBeforeSeconds)
        {
            return $"it is valid only from {ValidAfter:u} to {ValidBefore:u}";
        }

        if (Principals.Count == 0)
        {
            return "it lists no principals, so it is no host's";
        }

        if (!Principals.Any(p => Config.Glob.IsMatch(p, hostName, ignoreCase: true)))
        {
            return $"it is not issued for {hostName}";
        }

        return CriticalOptions.Count > 0 ? $"it has critical options this client does not understand ({string.Join(", ", CriticalOptions.Keys)})" : null;
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
