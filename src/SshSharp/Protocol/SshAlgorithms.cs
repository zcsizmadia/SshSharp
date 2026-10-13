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

/// <summary>An encrypt-then-MAC integrity algorithm.</summary>
internal sealed record MacInfo(string Name, HashAlgorithmName Hash, int KeyLength, bool IsFipsApproved);

/// <summary>Algorithm names (RFC 4250 and OpenSSH extensions), their defaults, and the capabilities this library implements.</summary>
internal static class SshAlgorithms
{
    // Key exchange
    public const string Curve25519Sha256 = "curve25519-sha256";
    public const string Curve25519Sha256Libssh = "curve25519-sha256@libssh.org";
    public const string EcdhNistp256 = "ecdh-sha2-nistp256";
    public const string EcdhNistp384 = "ecdh-sha2-nistp384";
    public const string EcdhNistp521 = "ecdh-sha2-nistp521";
    public const string DhGroup14Sha256 = "diffie-hellman-group14-sha256";
    public const string DhGroup16Sha512 = "diffie-hellman-group16-sha512";

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

    public static IReadOnlyList<string> DefaultKex { get; } =
    [
        Curve25519Sha256, Curve25519Sha256Libssh, EcdhNistp256, EcdhNistp384, EcdhNistp521, DhGroup16Sha512, DhGroup14Sha256,
    ];

    public static IReadOnlyList<string> DefaultHostKeys { get; } =
    [
        SshEd25519, EcdsaNistp256, EcdsaNistp384, EcdsaNistp521, RsaSha2_512, RsaSha2_256,
    ];

    private static readonly bool HardwareAes = System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported;

    /// <summary>
    /// With AES instructions AES-GCM is much faster than our managed ChaCha20-Poly1305, so it goes first; without them ChaCha20-Poly1305 does
    /// (the same trade-off OpenSSH makes).
    /// </summary>
    public static IReadOnlyList<string> DefaultCiphers { get; } = HardwareAes
        ? ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"]
        : ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"];

    public static IReadOnlyList<string> DefaultMacs { get; } =
    [
        "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
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
        ["hmac-sha2-512-etm@openssh.com"] = new("hmac-sha2-512-etm@openssh.com", HashAlgorithmName.SHA512, 64, true),
        ["hmac-sha2-256-etm@openssh.com"] = new("hmac-sha2-256-etm@openssh.com", HashAlgorithmName.SHA256, 32, true),
    };

    private static readonly HashSet<string> FipsKex = new(StringComparer.Ordinal)
    {
        EcdhNistp256, EcdhNistp384, EcdhNistp521, DhGroup16Sha512, DhGroup14Sha256,
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