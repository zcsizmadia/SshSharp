using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// Issues an OpenSSH certificate (PROTOCOL.certkeys) as its certificate authority, as <c>ssh-keygen -s</c> does: set what the
/// certificate allows, then sign it with the authority's key (<see cref="SignAsync"/>). The key can be one an SSH agent, a key vault or
/// a KMS holds (<see cref="SshPrivateKey.FromSigner"/>), so the authority's private key need never be in the process.
/// </summary>
/// <remarks>
/// <para>
/// The validity window has no default end: set <see cref="ValidBefore"/>, as short as the use allows (minutes to hours for a CI job or
/// a bastion session). A certificate is hard to take back once issued; one that expires on its own needs no revocation.
/// </para>
/// <para>
/// A user certificate starts with the extensions <c>ssh-keygen</c> gives one (<c>permit-X11-forwarding</c>, <c>permit-agent-forwarding</c>,
/// <c>permit-port-forwarding</c>, <c>permit-pty</c>, <c>permit-user-rc</c>); remove the ones the user does not need, or call
/// <c>Extensions.Clear()</c> for none, as <c>ssh-keygen -O clear</c> does. A host certificate starts with none.
/// </para>
/// <para>
/// The builder checks what it signs: at least one principal, option and extension names that are the standard ones or a vendor's own
/// (<c>name@example.com</c>), values where the option needs one (and none where it takes none), parseable <c>source-address</c>
/// lists, no critical options on a host certificate, and a validity window that is not empty. Names are written sorted and once each, as
/// PROTOCOL.certkeys requires. A builder is not thread-safe; it can sign any number of certificates, each with a fresh nonce.
/// </para>
/// </remarks>
public sealed class SshCertificateBuilder
{
    /// <summary>The <c>force-command</c> critical option: the command the server runs instead of the one the user asks for.</summary>
    public const string ForceCommand = "force-command";

    /// <summary>The <c>source-address</c> critical option: the client addresses, as a comma-separated CIDR list, the certificate is valid from.</summary>
    public const string SourceAddress = "source-address";

    /// <summary>The <c>verify-required</c> critical option: a FIDO key must verify its user (a PIN) for each signature, not only see a touch.</summary>
    public const string VerifyRequired = "verify-required";

    private const string NoTouchRequired = "no-touch-required";
    private const string PermitX11Forwarding = "permit-X11-forwarding";
    private const string PermitAgentForwarding = "permit-agent-forwarding";
    private const string PermitPortForwarding = "permit-port-forwarding";
    private const string PermitPty = "permit-pty";
    private const string PermitUserRc = "permit-user-rc";

    private const int NonceLength = 32;

    /// <summary>The extensions <c>ssh-keygen</c> gives a user certificate by default.</summary>
    private static readonly string[] DefaultUserExtensions = [PermitX11Forwarding, PermitAgentForwarding, PermitPortForwarding, PermitPty, PermitUserRc];

    private static readonly string[] StandardExtensions = [NoTouchRequired, .. DefaultUserExtensions];

    /// <summary>Creates a builder for a certificate of <paramref name="type"/> for <paramref name="publicKey"/>.</summary>
    /// <param name="publicKey">The key to certify: Ed25519, ECDSA (nistp256/384/521) or RSA (2048 bits or more). Its comment becomes the
    /// certificate's <see cref="SshCertificate.Comment"/>.</param>
    /// <param name="type">A user certificate, for logging in, or a host certificate, for a server.</param>
    /// <param name="keyId">The key identifier (<c>ssh-keygen -I</c>): sshd logs it when the certificate is used, so make it say who or what
    /// the certificate is for, for example <c>ci-build-1234</c>.</param>
    /// <exception cref="ArgumentException">The key is of a type certificates are not issued for here (a FIDO security key), an RSA key under
    /// 2048 bits, or the key identifier is empty or holds a control character.</exception>
    public SshCertificateBuilder(SshPublicKey publicKey, SshCertificateType type, string keyId)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        if (publicKey.KeyType is not (SshAlgorithms.SshEd25519 or SshAlgorithms.EcdsaNistp256 or SshAlgorithms.EcdsaNistp384
            or SshAlgorithms.EcdsaNistp521 or "ssh-rsa"))
        {
            throw new ArgumentException($"Certificates are issued for Ed25519, ECDSA and RSA keys, not {publicKey.KeyType}.", nameof(publicKey));
        }

        if (publicKey.KeyType == "ssh-rsa" && publicKey.KeySizeBits < SshClientOptions.DefaultMinimumRsaBits)
        {
            throw new ArgumentException($"RSA keys must be at least {SshClientOptions.DefaultMinimumRsaBits} bits; this one is {publicKey.KeySizeBits}.",
                nameof(publicKey));
        }

        if (type is not (SshCertificateType.User or SshCertificateType.Host))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "A certificate is a user or a host certificate.");
        }

        if (HasControlCharacter(keyId))
        {
            throw new ArgumentException("The key identifier must not contain control characters (sshd writes it to its log).", nameof(keyId));
        }

        PublicKey = publicKey;
        Type = type;
        KeyId = keyId;
        if (type == SshCertificateType.User)
        {
            foreach (var extension in DefaultUserExtensions)
            {
                Extensions.Add(extension, string.Empty);
            }
        }
    }

    /// <summary>The key the certificate certifies.</summary>
    public SshPublicKey PublicKey { get; }

    /// <summary>Whether the certificate is for a user or a host.</summary>
    public SshCertificateType Type { get; }

    /// <summary>The key identifier, which sshd logs when the certificate is used.</summary>
    public string KeyId { get; }

    /// <summary>
    /// The serial number (<c>ssh-keygen -z</c>), 0 by default. Give each certificate its own, from a counter you keep: a revocation list
    /// (<c>ssh-keygen -k</c>) revokes certificates by serial.
    /// </summary>
    public ulong Serial { get; set; }

    /// <summary>
    /// The user names (for a user certificate) or host names (for a host certificate, where <c>*</c> and <c>?</c> are wildcards) the
    /// certificate is valid for (<c>ssh-keygen -n</c>). At least one is required: a certificate without principals would be valid for any
    /// user where a server's <c>authorized_keys</c> trusts the authority without <c>principals=</c>.
    /// </summary>
    public IList<string> Principals { get; } = [];

    /// <summary>
    /// When the certificate becomes valid. Null (the default) is one minute before signing, so that a server whose clock is a little
    /// behind accepts a new certificate at once. <see cref="DateTimeOffset.UnixEpoch"/> or earlier is "always".
    /// </summary>
    public DateTimeOffset? ValidAfter { get; set; }

    /// <summary>
    /// When the certificate stops being valid (exclusive). Required: there is no default, so that no certificate is valid forever by
    /// accident. <see cref="DateTimeOffset.MaxValue"/> is "forever", as <c>ssh-keygen</c> issues without <c>-V</c>.
    /// </summary>
    public DateTimeOffset? ValidBefore { get; set; }

    /// <summary>
    /// Critical options, by name, with their values: <see cref="ForceCommand"/> and <see cref="SourceAddress"/> take a value,
    /// <see cref="VerifyRequired"/> takes none (an empty string). A server refuses a certificate with a critical option it does not know,
    /// so a vendor's own (<c>name@example.com</c>) works only with servers that know it. Host certificates have none.
    /// </summary>
    public IDictionary<string, string> CriticalOptions { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Extensions, by name, with their values (an empty string for none; the standard ones take none). A user certificate starts with
    /// those <c>ssh-keygen</c> sets by default, a host certificate with none. The standard ones are <c>permit-X11-forwarding</c>,
    /// <c>permit-agent-forwarding</c>, <c>permit-port-forwarding</c>, <c>permit-pty</c>, <c>permit-user-rc</c> and
    /// <c>no-touch-required</c>; servers ignore extensions they do not know, so a vendor's own (<c>name@example.com</c>) may carry a value.
    /// </summary>
    public IDictionary<string, string> Extensions { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Signs the certificate with <paramref name="authority"/>, the certificate authority's key, as <c>ssh-keygen -s</c> does. An RSA
    /// authority signs with <c>rsa-sha2-512</c> (as <c>ssh-keygen</c> by default) or, when its signer offers only that, <c>rsa-sha2-256</c>;
    /// never with SHA-1 <c>ssh-rsa</c>. The signer is asked with <see cref="SshSignaturePurpose.Certificate"/>, and the signature is
    /// checked against the authority's public key before the certificate is returned.
    /// </summary>
    /// <param name="authority">The authority's key: one loaded or generated, one in an SSH agent, or one a key vault, KMS or HSM holds
    /// (<see cref="SshPrivateKey.FromSigner"/>).</param>
    /// <param name="cancellationToken">Cancels an agent's or a signer's signing.</param>
    /// <returns>The certificate; write it with <see cref="SshCertificate.ToAuthorizedKeysLine"/> to <c>id_ed25519-cert.pub</c> (next to
    /// the key) or wherever the server or client reads it.</returns>
    /// <exception cref="ArgumentException">The authority's key is paired with a certificate (an authority's key cannot itself be a
    /// certificate), or is a FIDO security key, whose signatures SshSharp cannot check.</exception>
    /// <exception cref="InvalidOperationException">What the builder holds is not a valid certificate: no <see cref="ValidBefore"/>, an
    /// empty validity window, no principals, or an invalid option, extension or value. The message says which.</exception>
    /// <exception cref="CryptographicException">The authority's signature does not verify against its public key, or an
    /// <see cref="SshKeySigner"/> returned one that does not.</exception>
    /// <exception cref="SshException">An SSH agent holding the authority's key refused to sign, or signed with another algorithm (an old
    /// agent that signs RSA with SHA-1); <see cref="SshException.Reason"/> is <see cref="SshFailureReason.AgentFailed"/>.</exception>
    public async Task<SshCertificate> SignAsync(SshPrivateKey authority, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (authority.Certificate is not null)
        {
            throw new ArgumentException("A certificate authority's key cannot itself be a certificate: sign with the key it was made from.", nameof(authority));
        }

        try
        {
            VerifyingKey.Parse(authority.PublicKey.Span);
        }
        catch (SshProtocolException ex)
        {
            throw new ArgumentException($"A {authority.KeyType} key cannot be a certificate authority here: {ex.Message}", nameof(authority), ex);
        }

        var body = Encode(authority.PublicKey.Span, DateTimeOffset.UtcNow);
        var algorithm = authority.SignatureAlgorithms.Contains(SshAlgorithms.RsaSha2_512, StringComparer.Ordinal)
            ? SshAlgorithms.RsaSha2_512
            : authority.SignatureAlgorithms[0];
        var signature = await authority.SignAsync(new SshSignRequest(algorithm, body, SshSignaturePurpose.Certificate), binding: null, cancellationToken)
            .ConfigureAwait(false);

        var blob = SshPrivateKey.Encode(w =>
        {
            w.WriteBytes(body);
            w.WriteString(signature);
        });
        var certificate = SshCertificate.FromBlob(blob, PublicKey.Comment);
        if (!certificate.VerifySignature())
        {
            throw new CryptographicException(
                $"The certificate authority's signature ({authority.Fingerprint}) does not verify: an RSA key's signer or agent must sign with rsa-sha2-512 or rsa-sha2-256.");
        }

        return certificate;
    }

    /// <summary>The certificate up to its signature (PROTOCOL.certkeys), after checking what goes into it.</summary>
    private byte[] Encode(ReadOnlySpan<byte> authorityKey, DateTimeOffset now)
    {
        var after = ValidAfter ?? now.AddMinutes(-1);
        var before = ValidBefore
            ?? throw new InvalidOperationException("Set ValidBefore: a certificate has no default end (DateTimeOffset.MaxValue for one that never expires).");
        var validAfter = ToSeconds(after);
        var validBefore = ToSeconds(before);
        if (validAfter >= validBefore)
        {
            throw new InvalidOperationException($"The validity window is empty: ValidAfter ({after:u}) is not before ValidBefore ({before:u}).");
        }

        var principals = CheckPrincipals();
        var criticalOptions = CheckCriticalOptions();
        var extensions = CheckExtensions();

        // The certified key's fields follow its type name in its plain encoding, and come in the same order in the certificate.
        var reader = new SshReader(PublicKey.Blob.Span);
        var keyType = reader.ReadUtf8String();
        var keyFields = reader.Remaining.ToArray();
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var authority = authorityKey.ToArray();
        return SshPrivateKey.Encode(w =>
        {
            w.WriteString(keyType + "-cert-v01@openssh.com");
            w.WriteString(nonce);
            w.WriteBytes(keyFields);
            w.WriteUInt64(Serial);
            w.WriteUInt32((uint)Type);
            w.WriteString(KeyId);
            w.WriteString(SshPrivateKey.Encode(p =>
            {
                foreach (var principal in principals)
                {
                    p.WriteString(principal);
                }
            }));
            w.WriteUInt64(validAfter);
            w.WriteUInt64(validBefore);
            w.WriteString(EncodeOptions(criticalOptions));
            w.WriteString(EncodeOptions(extensions));
            w.WriteString(ReadOnlySpan<byte>.Empty); // reserved
            w.WriteString(authority);
        });
    }

    private List<string> CheckPrincipals()
    {
        var principals = new List<string>(Principals.Count);
        foreach (var principal in Principals)
        {
            if (string.IsNullOrEmpty(principal) || HasControlCharacter(principal))
            {
                throw new InvalidOperationException("A principal must not be empty or contain control characters.");
            }

            if (principals.Contains(principal, StringComparer.Ordinal))
            {
                // Not the principal itself: it is usually a user name, and exception messages are logged (docs/reference/errors.md).
                throw new InvalidOperationException($"A principal is listed twice (principal {principals.Count + 1} repeats an earlier one).");
            }

            principals.Add(principal);
        }

        return principals.Count > 0
            ? principals
            : throw new InvalidOperationException("Add at least one principal: the user names or host names the certificate is for.");
    }

    private List<KeyValuePair<string, string>> CheckCriticalOptions()
    {
        if (Type == SshCertificateType.Host && CriticalOptions.Count > 0)
        {
            throw new InvalidOperationException("Host certificates have no critical options; ssh refuses a host certificate with any.");
        }

        var options = Sorted(CriticalOptions, "critical option");
        foreach (var (name, value) in options)
        {
            switch (name)
            {
                case ForceCommand when value.Length == 0:
                    throw new InvalidOperationException("The force-command option needs the command as its value.");
                case SourceAddress:
                    CheckSourceAddress(value);
                    break;
                case VerifyRequired when value.Length > 0:
                    throw new InvalidOperationException("The verify-required option takes no value.");
                case ForceCommand or VerifyRequired:
                    break;
                default:
                    RequireVendorName(name, "critical option", ForceCommand + ", " + SourceAddress + ", " + VerifyRequired);
                    break;
            }
        }

        return options;
    }

    private List<KeyValuePair<string, string>> CheckExtensions()
    {
        var extensions = Sorted(Extensions, "extension");
        foreach (var (name, value) in extensions)
        {
            if (StandardExtensions.Contains(name, StringComparer.Ordinal))
            {
                if (value.Length > 0)
                {
                    throw new InvalidOperationException($"The {name} extension takes no value.");
                }
            }
            else
            {
                RequireVendorName(name, "extension", string.Join(", ", StandardExtensions));
            }
        }

        return extensions;
    }

    /// <summary>
    /// Options and extensions sorted by name, as PROTOCOL.certkeys requires ("lexically ordered"). Names are printable ASCII, so ordinal
    /// order is the byte order OpenSSH compares in. A dictionary holds each name once.
    /// </summary>
    private static List<KeyValuePair<string, string>> Sorted(IDictionary<string, string> values, string what)
    {
        foreach (var (name, value) in values)
        {
            if (name.Length == 0 || name.Any(c => c is <= ' ' or > '~' or ','))
            {
                throw new InvalidOperationException($"The {what} name '{name}' is not a valid name: printable ASCII without spaces or commas.");
            }

            if (value is null || value.Contains('\0', StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"The {what} {name} has a null value or one with a NUL character; use an empty string for none.");
            }
        }

        return [.. values.OrderBy(pair => pair.Key, StringComparer.Ordinal)];
    }

    /// <summary>
    /// A name that is not one of the standard ones must be a vendor's own (PROTOCOL.certkeys: "my-option@example.com"), so that a typo of
    /// a standard name is caught here rather than by every server that refuses (or ignores) it.
    /// </summary>
    private static void RequireVendorName(string name, string what, string standard)
    {
        var at = name.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0 || at == name.Length - 1)
        {
            throw new InvalidOperationException($"Unknown {what} '{name}': the standard ones are {standard}; another must be a vendor's own, named name@domain.");
        }
    }

    /// <summary>sshd refuses a certificate whose source-address list does not parse, so check it here: address or address/prefix, comma-separated.</summary>
    private static void CheckSourceAddress(string value)
    {
        if (value.Length == 0)
        {
            throw new InvalidOperationException("The source-address option needs a comma-separated list of addresses or CIDR blocks.");
        }

        foreach (var entry in value.Split(','))
        {
            var slash = entry.IndexOf('/', StringComparison.Ordinal);
            var address = slash < 0 ? entry : entry[..slash];
            // IPAddress also reads shortened IPv4 forms ("192.0.2"), which sshd does not: an IPv4 address has its four parts.
            var valid = IPAddress.TryParse(address, out var parsed) && !address.Contains('%', StringComparison.Ordinal)
                && (parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || address.Count(c => c == '.') == 3);
            if (valid && slash >= 0)
            {
                var maxBits = parsed!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                valid = int.TryParse(entry.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var bits) && bits <= maxBits;
            }

            if (!valid)
            {
                throw new InvalidOperationException($"The source-address entry '{entry}' is not an address or a CIDR block (192.0.2.0/24, 2001:db8::/32).");
            }
        }
    }

    /// <summary>Options and extensions: the name, then the value as a string inside a string, or an empty string for none.</summary>
    private static byte[] EncodeOptions(List<KeyValuePair<string, string>> options) => SshPrivateKey.Encode(w =>
    {
        foreach (var (name, value) in options)
        {
            w.WriteString(name);
            w.WriteString(value.Length == 0 ? [] : SshPrivateKey.Encode(v => v.WriteString(value)));
        }
    });

    /// <summary>Seconds since the epoch: the epoch or before is 0 ("always"), <see cref="DateTimeOffset.MaxValue"/> is "forever".</summary>
    private static ulong ToSeconds(DateTimeOffset time) =>
        time == DateTimeOffset.MaxValue ? ulong.MaxValue : (ulong)Math.Max(0, time.ToUnixTimeSeconds());

    private static bool HasControlCharacter(string text) => text.Any(char.IsControl);
}
