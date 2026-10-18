using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>How a cipher is built into a packet protector.</summary>
internal enum CipherKind
{
    ChaCha20Poly1305,
    AesGcm,
    AesCtr,
}

/// <summary>A packet cipher: key and IV sizes derived from the key exchange (RFC 4253 section 7.2).</summary>
internal sealed record CipherInfo(string Name, CipherKind Kind, int KeyLength, int IvLength, bool IsFipsApproved)
{
    /// <summary>True for AEAD ciphers, which carry their own authentication and ignore the negotiated MAC.</summary>
    public bool IsAead => Kind is CipherKind.ChaCha20Poly1305 or CipherKind.AesGcm;
}

/// <summary>
/// An HMAC integrity algorithm. <paramref name="EncryptThenMac"/> is true for the <c>-etm@openssh.com</c> variants, which MAC the encrypted
/// packet and leave its length in clear, and false for the plain ones of RFC 4253 section 6.4, which MAC the plaintext packet and encrypt
/// its length.
/// </summary>
internal sealed record MacInfo(string Name, HashAlgorithmName Hash, int KeyLength, bool EncryptThenMac, bool IsFipsApproved);

/// <summary>Algorithm names (RFC 4250 and OpenSSH extensions), their defaults, and the capabilities this library implements.</summary>
internal static class SshAlgorithms
{
    // Key exchange
    public const string MlKem768X25519Sha256 = "mlkem768x25519-sha256";
    public const string MlKem768Nistp256Sha256 = "mlkem768nistp256-sha256";
    public const string MlKem1024Nistp384Sha384 = "mlkem1024nistp384-sha384";
    public const string Sntrup761X25519Sha512 = "sntrup761x25519-sha512";
    public const string Sntrup761X25519Sha512OpenSsh = "sntrup761x25519-sha512@openssh.com";
    public const string Curve25519Sha256 = "curve25519-sha256";
    public const string Curve25519Sha256Libssh = "curve25519-sha256@libssh.org";
    public const string EcdhNistp256 = "ecdh-sha2-nistp256";
    public const string EcdhNistp384 = "ecdh-sha2-nistp384";
    public const string EcdhNistp521 = "ecdh-sha2-nistp521";
    public const string DhGroup14Sha256 = "diffie-hellman-group14-sha256";
    public const string DhGroupExchangeSha256 = "diffie-hellman-group-exchange-sha256";
    public const string DhGroup16Sha512 = "diffie-hellman-group16-sha512";
    public const string DhGroup18Sha512 = "diffie-hellman-group18-sha512";

    /// <summary>Whether a key exchange method resists a future quantum computer (a hybrid with a post-quantum KEM), as OpenSSH's WarnWeakCrypto judges it.</summary>
    public static bool IsPostQuantum(string kex) =>
        kex is MlKem768X25519Sha256 or MlKem768Nistp256Sha256 or MlKem1024Nistp384Sha384 or Sntrup761X25519Sha512 or Sntrup761X25519Sha512OpenSsh;

    // Extension and strict-KEX markers carried in the kex_algorithms list.
    public const string ExtInfoClient = "ext-info-c";
    public const string ExtInfoServer = "ext-info-s";
    public const string StrictKexClient = "kex-strict-c-v00@openssh.com";
    public const string StrictKexServer = "kex-strict-s-v00@openssh.com";

    // Host keys
    public const string SshEd25519 = "ssh-ed25519";
    public const string EcdsaNistp256 = "ecdsa-sha2-nistp256";
    public const string EcdsaNistp384 = "ecdsa-sha2-nistp384";
    public const string EcdsaNistp521 = "ecdsa-sha2-nistp521";
    public const string RsaSha2_512 = "rsa-sha2-512";
    public const string RsaSha2_256 = "rsa-sha2-256";

    // Compression
    public const string CompressionNone = "none";

    // OpenSSH's client order. Declared before DefaultKex, which reads it during static initialization.
    private static readonly string[] ClassicKex =
    [
        Curve25519Sha256, Curve25519Sha256Libssh, EcdhNistp256, EcdhNistp384, EcdhNistp521, DhGroupExchangeSha256, DhGroup16Sha512, DhGroup18Sha512,
        DhGroup14Sha256,
    ];

    /// <summary>
    /// The post-quantum hybrids first. Where the platform has ML-KEM (.NET 10 with OpenSSL 3.5+ or a recent Windows): the X25519 one, as
    /// OpenSSH 10 orders it, then the NIST-curve ones of RFC 10042 (the FIPS-compatible choices). Then sntrup761 (managed, so everywhere),
    /// which OpenSSH 8.5 to 9.8 servers offer as their only post-quantum method; then the classic methods.
    /// </summary>
    public static IReadOnlyList<string> DefaultKex { get; } = HasMlKem
        ? [MlKem768X25519Sha256, MlKem768Nistp256Sha256, MlKem1024Nistp384Sha384, Sntrup761X25519Sha512, Sntrup761X25519Sha512OpenSsh, .. ClassicKex]
        : [Sntrup761X25519Sha512, Sntrup761X25519Sha512OpenSsh, .. ClassicKex];

#if NET10_0_OR_GREATER
    internal static bool HasMlKem => System.Security.Cryptography.MLKem.IsSupported;
#else
    internal static bool HasMlKem => false;
#endif

    public static IReadOnlyList<string> DefaultHostKeys { get; } =
    [
        SshEd25519, EcdsaNistp256, EcdsaNistp384, EcdsaNistp521, RsaSha2_512, RsaSha2_256,
    ];

    /// <summary>OpenSSH certificate host key algorithms (PROTOCOL.certkeys), offered first when a certificate authority is trusted for the host.</summary>
    public static IReadOnlyList<string> CertificateHostKeys { get; } =
    [
        "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
    ];

    private static readonly bool HardwareAes = System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported;

    /// <summary>
    /// With AES instructions AES-GCM is much faster than our managed ChaCha20-Poly1305, so it goes first; without them ChaCha20-Poly1305 does
    /// (the same trade-off OpenSSH makes).
    /// </summary>
    public static IReadOnlyList<string> DefaultCiphers { get; } = HardwareAes
        ? ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"]
        : ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"];

    /// <summary>
    /// Encrypt-then-MAC first. The plain MACs of RFC 4253 follow, in OpenSSH's order, for servers (often network equipment) that offer
    /// only those with <c>aes*-ctr</c>.
    /// </summary>
    public static IReadOnlyList<string> DefaultMacs { get; } =
    [
        "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512",
    ];

    public static IReadOnlyList<string> DefaultCompression { get; } = [CompressionNone];

    private static readonly Dictionary<string, CipherInfo> Ciphers = new(StringComparer.Ordinal)
    {
        ["chacha20-poly1305@openssh.com"] = new("chacha20-poly1305@openssh.com", CipherKind.ChaCha20Poly1305, 64, 0, false),
        ["aes256-gcm@openssh.com"] = new("aes256-gcm@openssh.com", CipherKind.AesGcm, 32, 12, true),
        ["aes128-gcm@openssh.com"] = new("aes128-gcm@openssh.com", CipherKind.AesGcm, 16, 12, true),
        ["aes256-ctr"] = new("aes256-ctr", CipherKind.AesCtr, 32, 16, true),
        ["aes192-ctr"] = new("aes192-ctr", CipherKind.AesCtr, 24, 16, true),
        ["aes128-ctr"] = new("aes128-ctr", CipherKind.AesCtr, 16, 16, true),
    };

    private static readonly Dictionary<string, MacInfo> Macs = new(StringComparer.Ordinal)
    {
        ["hmac-sha2-512-etm@openssh.com"] = new("hmac-sha2-512-etm@openssh.com", HashAlgorithmName.SHA512, 64, true, true),
        ["hmac-sha2-256-etm@openssh.com"] = new("hmac-sha2-256-etm@openssh.com", HashAlgorithmName.SHA256, 32, true, true),
        ["hmac-sha2-256"] = new("hmac-sha2-256", HashAlgorithmName.SHA256, 32, false, true),
        ["hmac-sha2-512"] = new("hmac-sha2-512", HashAlgorithmName.SHA512, 64, false, true),
    };

    private static readonly HashSet<string> FipsKex = new(StringComparer.Ordinal)
    {
        // ML-KEM (FIPS 203) with a NIST curve and SHA-2: both halves are FIPS-approved, unlike the X25519 hybrid. Finite-field DH only in
        // the fixed RFC 3526 groups, which SP 800-56A rev. 3 approves; not group exchange, where the server picks an arbitrary group.
        MlKem768Nistp256Sha256, MlKem1024Nistp384Sha384, EcdhNistp256, EcdhNistp384, EcdhNistp521, DhGroup16Sha512, DhGroup18Sha512,
        DhGroup14Sha256,
    };

    private static readonly HashSet<string> FipsHostKeys = new(StringComparer.Ordinal)
    {
        EcdsaNistp256, EcdsaNistp384, EcdsaNistp521, RsaSha2_512, RsaSha2_256,
    };

    public static bool TryGetCipher(string name, out CipherInfo cipher) => Ciphers.TryGetValue(name, out cipher!);

    public static bool TryGetMac(string name, out MacInfo mac) => Macs.TryGetValue(name, out mac!);

    /// <summary>Whether this library implements the cipher.</summary>
    public static bool IsKnownCipher(string name) => Ciphers.ContainsKey(name);

    /// <summary>Whether this library implements the MAC.</summary>
    public static bool IsKnownMac(string name) => Macs.ContainsKey(name);

    /// <summary>
    /// Restricts a list to FIPS-approved algorithms (RFC and NIST curves/groups, AES, HMAC-SHA2). Curve25519, Ed25519 and
    /// ChaCha20-Poly1305 are excluded: they are not part of the widely validated FIPS 140 modules.
    /// </summary>
    public static IReadOnlyList<string> FilterFips(IEnumerable<string> names, AlgorithmKind kind) =>
        [.. names.Where(n => kind switch
        {
            AlgorithmKind.Kex => FipsKex.Contains(n),
            AlgorithmKind.HostKey => FipsHostKeys.Contains(n),
            AlgorithmKind.Cipher => Ciphers.TryGetValue(n, out var c) && c.IsFipsApproved,
            AlgorithmKind.Mac => Macs.TryGetValue(n, out var m) && m.IsFipsApproved,
            _ => true,
        })];
}

/// <summary>The category of an algorithm list.</summary>
internal enum AlgorithmKind
{
    Kex,
    HostKey,
    Cipher,
    Mac,
    Compression,
}