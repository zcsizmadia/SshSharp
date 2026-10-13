using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A private key for public-key authentication. Load one with <see cref="Parse"/> or <see cref="LoadFileAsync"/>. Supported formats:
/// the OpenSSH key format (<c>BEGIN OPENSSH PRIVATE KEY</c>, as <c>ssh-keygen</c> writes by default, also passphrase-protected), PuTTY
/// <c>.ppk</c> (versions 2 and 3, also encrypted), PKCS#8 (<c>BEGIN PRIVATE KEY</c>,
/// and <c>BEGIN ENCRYPTED PRIVATE KEY</c> for RSA and ECDSA), and PKCS#1/SEC1 PEM (<c>BEGIN RSA PRIVATE KEY</c>, <c>BEGIN EC PRIVATE KEY</c>).
/// Key types: Ed25519, ECDSA (nistp256/384/521) and RSA (2048 bits or more).
/// </summary>
public abstract class SshPrivateKey : IDisposable
{
    private protected SshPrivateKey(string keyType, byte[] publicKey, string? comment)
    {
        KeyType = keyType;
        PublicKey = publicKey;
        Comment = comment;
    }

    /// <summary>The key type name, for example <c>ssh-ed25519</c>.</summary>
    public string KeyType { get; }

    /// <summary>The comment stored with the key (often <c>user@host</c>), if the format has one.</summary>
    public string? Comment { get; }

    /// <summary>The public key in SSH wire format (what <c>authorized_keys</c> holds, base64-decoded).</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The OpenSSH-style SHA-256 fingerprint of the public key, as <c>ssh-keygen -lf</c> prints it.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(PublicKey.Span)).TrimEnd('=');

    /// <summary>The public key as an <c>authorized_keys</c> line (type, base64, comment).</summary>
    public string ToAuthorizedKeysLine() =>
        $"{KeyType} {Convert.ToBase64String(PublicKey.Span)}{(string.IsNullOrEmpty(Comment) ? string.Empty : " " + Comment)}";

    /// <summary>Signature algorithms this key can sign with, most preferred first.</summary>
    internal abstract IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Signs <paramref name="data"/> and returns the SSH signature blob (<c>string algorithm || string signature</c>).</summary>
    internal abstract byte[] Sign(string algorithm, ReadOnlySpan<byte> data);

    /// <summary>Parses a private key.</summary>
    /// <param name="text">The key file's contents.</param>
    /// <param name="passphrase">The passphrase of an encrypted key; ignored for unencrypted keys.</param>
    /// <exception cref="FormatException">The text is not a supported private key, or the passphrase is wrong or missing.</exception>
    public static SshPrivateKey Parse(string text, string? passphrase = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        return PrivateKeyParser.Parse(text, passphrase);
    }

    /// <summary>Reads and parses a private key file.</summary>
    /// <inheritdoc cref="Parse" path="/exception"/>
    public static async Task<SshPrivateKey> LoadFileAsync(string path, string? passphrase = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false), passphrase);
    }

    /// <summary>The user certificate this key authenticates with, if it was paired with one (<see cref="WithCertificate"/>).</summary>
    public SshCertificate? Certificate { get; private protected init; }

    /// <summary>
    /// This key paired with an OpenSSH user certificate for it (<c>id_ed25519-cert.pub</c>, made with <c>ssh-keygen -s</c>): authentication
    /// then presents the certificate, which servers that trust its authority (<c>TrustedUserCAKeys</c>) accept without an authorized_keys
    /// entry. The returned key shares this key's private material: disposing this key disposes both.
    /// </summary>
    /// <exception cref="ArgumentException">The certificate is not a user certificate, or certifies a different key.</exception>
    public SshPrivateKey WithCertificate(SshCertificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (certificate.Type != SshCertificateType.User)
        {
            throw new ArgumentException("Only user certificates can be used to authenticate.", nameof(certificate));
        }

        if (!certificate.PublicKey.Span.SequenceEqual(PublicKey.Span))
        {
            throw new ArgumentException($"The certificate is for key {certificate.Fingerprint}, not this key ({Fingerprint}).", nameof(certificate));
        }

        return new CertifiedKey(this, certificate);
    }

    /// <summary>Clears the private key material.</summary>
    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private protected abstract void DisposeCore();

    internal static byte[] Encode(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] SignatureBlob(string algorithm, ReadOnlySpan<byte> signature)
    {
        var buffer = new ArrayBufferWriter<byte>(algorithm.Length + signature.Length + 8);
        var writer = new SshWriter(buffer);
        writer.WriteString(algorithm);
        writer.WriteString(signature);
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>A key presented with its certificate: the public key is the certificate, and signatures are the base key's (PROTOCOL.certkeys).</summary>
    private sealed class CertifiedKey : SshPrivateKey
    {
        private readonly SshPrivateKey _key;

        public CertifiedKey(SshPrivateKey key, SshCertificate certificate)
            : base(certificate.CertificateType, certificate.Blob.ToArray(), key.Comment)
        {
            _key = key;
            Certificate = certificate;
            SignatureAlgorithms = [.. key.SignatureAlgorithms.Select(a => a + "-cert-v01@openssh.com")];
        }

        internal override IReadOnlyList<string> SignatureAlgorithms { get; }

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) => _key.Sign(SshCertificate.BaseAlgorithm(algorithm), data);

        private protected override void DisposeCore()
        {
            // The private material belongs to the key this was made from.
        }
    }

    internal sealed class Ed25519Key : SshPrivateKey
    {
        private readonly byte[] _seed;

        public Ed25519Key(byte[] seed, string? comment)
            : base(SshAlgorithms.SshEd25519, PublicBlob(seed), comment) => _seed = seed;

        internal override IReadOnlyList<string> SignatureAlgorithms { get; } = [SshAlgorithms.SshEd25519];

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
        {
            RequireAlgorithm(algorithm, SshAlgorithms.SshEd25519);
            Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];
            Ed25519.Sign(_seed, data, signature);
            return SignatureBlob(algorithm, signature);
        }

        private protected override void DisposeCore() => CryptographicOperations.ZeroMemory(_seed);

        internal static byte[] PublicBlob(ReadOnlySpan<byte> seed)
        {
            Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];
            Ed25519.GetPublicKey(seed, publicKey);
            var key = publicKey.ToArray();
            return Encode(w =>
            {
                w.WriteString(SshAlgorithms.SshEd25519);
                w.WriteString(key);
            });
        }
    }

    internal sealed class EcdsaKey : SshPrivateKey
    {
        private readonly ECDsa _ecdsa;
        private readonly int _fieldSize;
        private readonly HashAlgorithmName _hash;

        public EcdsaKey(NistCurve curve, ECDsa ecdsa, string? comment)
            : base("ecdsa-sha2-" + curve.Name, PublicBlob(curve, ecdsa), comment)
        {
            _ecdsa = ecdsa;
            _fieldSize = curve.FieldSize;
            _hash = curve.Hash;
        }

        internal override IReadOnlyList<string> SignatureAlgorithms => [KeyType];

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
        {
            RequireAlgorithm(algorithm, KeyType);

            // SSH wants the signature as two mpints (r, s), not the fixed-width r || s the framework produces.
            var rs = _ecdsa.SignData(data, _hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var inner = Encode(w =>
            {
                w.WriteMpint(rs.AsSpan(0, _fieldSize));
                w.WriteMpint(rs.AsSpan(_fieldSize));
            });
            return SignatureBlob(algorithm, inner);
        }

        private protected override void DisposeCore() => _ecdsa.Dispose();

        private static byte[] PublicBlob(NistCurve curve, ECDsa ecdsa)
        {
            var q = ecdsa.ExportParameters(false).Q;
            byte[] point = [4, .. Pad(q.X!, curve.FieldSize), .. Pad(q.Y!, curve.FieldSize)];
            return Encode(w =>
            {
                w.WriteString("ecdsa-sha2-" + curve.Name);
                w.WriteString(curve.Name);
                w.WriteString(point);
            });
        }
    }

    internal sealed class RsaKey : SshPrivateKey
    {
        private readonly RSA _rsa;

        public RsaKey(RSA rsa, string? comment)
            : base("ssh-rsa", PublicBlob(rsa), comment) => _rsa = rsa;

        // SHA-1 ("ssh-rsa") signatures are never produced.
        internal override IReadOnlyList<string> SignatureAlgorithms { get; } = [SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256];

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
        {
            var hash = algorithm switch
            {
                SshAlgorithms.RsaSha2_256 => HashAlgorithmName.SHA256,
                SshAlgorithms.RsaSha2_512 => HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"An RSA key signs only with rsa-sha2-256 or rsa-sha2-512, not '{algorithm}'.", nameof(algorithm)),
            };
            return SignatureBlob(algorithm, _rsa.SignData(data, hash, RSASignaturePadding.Pkcs1));
        }

        /// <summary>Builds the key from OpenSSH's field order (n, e, d, iqmp, p, q), deriving the CRT exponents the framework needs.</summary>
        public static RsaKey FromComponents(ReadOnlySpan<byte> n, ReadOnlySpan<byte> e, ReadOnlySpan<byte> d, ReadOnlySpan<byte> iqmp,
            ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, string? comment)
        {
            var modulus = n.TrimStart((byte)0).ToArray();
            var half = (modulus.Length + 1) / 2;
            var pInt = ToInteger(p);
            var qInt = ToInteger(q);
            var dInt = ToInteger(d);
            var parameters = new RSAParameters
            {
                Modulus = modulus,
                Exponent = e.TrimStart((byte)0).ToArray(),
                D = Fixed(dInt, modulus.Length),
                P = Fixed(pInt, half),
                Q = Fixed(qInt, half),
                DP = Fixed(dInt % (pInt - 1), half),
                DQ = Fixed(dInt % (qInt - 1), half),
                InverseQ = Fixed(ToInteger(iqmp), half),
            };

            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(parameters);
            }
            catch (CryptographicException ex)
            {
                rsa.Dispose();
                throw new FormatException("The RSA private key is inconsistent.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(parameters.D);
                CryptographicOperations.ZeroMemory(parameters.P);
                CryptographicOperations.ZeroMemory(parameters.Q);
                CryptographicOperations.ZeroMemory(parameters.DP);
                CryptographicOperations.ZeroMemory(parameters.DQ);
                CryptographicOperations.ZeroMemory(parameters.InverseQ);
            }

            return new RsaKey(rsa, comment);
        }

        private protected override void DisposeCore() => _rsa.Dispose();

        private static BigInteger ToInteger(ReadOnlySpan<byte> unsignedBigEndian) => new(unsignedBigEndian, isUnsigned: true, isBigEndian: true);

        private static byte[] Fixed(BigInteger value, int length) => Pad(value.ToByteArray(isUnsigned: true, isBigEndian: true), length);

        private static byte[] PublicBlob(RSA rsa)
        {
            var p = rsa.ExportParameters(false);
            return Encode(w =>
            {
                w.WriteString("ssh-rsa");
                w.WriteMpint(p.Exponent);
                w.WriteMpint(p.Modulus);
            });
        }
    }

    private static void RequireAlgorithm(string algorithm, string expected)
    {
        if (algorithm != expected)
        {
            throw new ArgumentException($"A {expected} key cannot sign with '{algorithm}'.", nameof(algorithm));
        }
    }

    private static byte[] Pad(byte[] value, int length)
    {
        if (value.Length == length)
        {
            return value;
        }

        if (value.Length > length)
        {
            throw new FormatException("A key component is larger than the key size.");
        }

        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }
}
