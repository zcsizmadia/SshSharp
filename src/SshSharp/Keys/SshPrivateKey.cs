using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A private key for public-key authentication. Load one with <see cref="Parse"/> or <see cref="LoadAsync"/>. Supported formats:
/// the OpenSSH key format (<c>BEGIN OPENSSH PRIVATE KEY</c>, as <c>ssh-keygen</c> writes by default, also passphrase-protected), PuTTY
/// <c>.ppk</c> (versions 2 and 3, also encrypted), PKCS#8 (<c>BEGIN PRIVATE KEY</c>,
/// and <c>BEGIN ENCRYPTED PRIVATE KEY</c> for RSA and ECDSA), and PKCS#1/SEC1 PEM (<c>BEGIN RSA PRIVATE KEY</c>, <c>BEGIN EC PRIVATE KEY</c>).
/// Key types: Ed25519, ECDSA (nistp256/384/521) and RSA (2048 bits or more).
/// </summary>
public abstract class SshPrivateKey : IDisposable
{
    // Made on first use; two threads racing make equal keys, and either may be kept.
    private SshPublicKey? _publicKey;

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

    /// <summary>
    /// The public key as an <see cref="SshPublicKey"/>, with this key's <see cref="Comment"/>. For a key paired with a certificate
    /// (<see cref="WithCertificate"/>), it is the certified key, not the certificate that <see cref="PublicKey"/> holds then.
    /// </summary>
    /// <exception cref="FormatException">The key is one <see cref="SshPublicKey"/> does not read: an agent's FIDO security-key
    /// certificate.</exception>
    public SshPublicKey GetPublicKey() =>
        _publicKey ??= Certificate is { } certificate
            ? SshPublicKey.FromVerifyingKey(certificate.Key, Comment)
            : SshPublicKey.Read(PublicKey.Span, Comment);

    /// <summary>The public key as an <c>authorized_keys</c> line (type, base64, comment).</summary>
    public string ToAuthorizedKeysLine() =>
        $"{KeyType} {Convert.ToBase64String(PublicKey.Span)}{(string.IsNullOrEmpty(Comment) ? string.Empty : " " + Comment)}";

    /// <summary>Signature algorithms this key can sign with, most preferred first.</summary>
    internal abstract IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Signs <paramref name="data"/> and returns the SSH signature blob (<c>string algorithm || string signature</c>).</summary>
    internal abstract byte[] Sign(string algorithm, ReadOnlySpan<byte> data);

    /// <summary>
    /// Signs like <see cref="Sign"/>; keys held elsewhere (an SSH agent, an external signer) sign only this way. <paramref name="binding"/>
    /// is the SSH session an agent connection is bound to before signing (for destination-constrained agent keys); local keys ignore it.
    /// </summary>
    internal virtual ValueTask<byte[]> SignAsync(SshSignRequest request, AgentBinding? binding, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Sign(request.Algorithm, request.Data.Span));

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
    public static async Task<SshPrivateKey> LoadAsync(string path, string? passphrase = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false), passphrase);
    }

    /// <summary>
    /// Generates a new key pair, as <c>ssh-keygen -t</c> does. Write it with <see cref="SaveAsync"/> or <see cref="ToOpenSshPrivateKey"/>,
    /// and give the server <see cref="ToAuthorizedKeysLine"/>.
    /// </summary>
    /// <param name="type">The key type. Ed25519 is the usual choice; ECDSA or RSA where FIPS-approved algorithms are required.</param>
    /// <param name="comment">The comment stored with the key, often <c>user@host</c>.</param>
    /// <param name="rsaBits">The RSA key size: 3072 by default (as ssh-keygen), from 2048 to 16384. Ignored for other types.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="rsaBits"/> is not a supported RSA key size.</exception>
    public static SshPrivateKey Generate(SshKeyType type, string? comment = null, int rsaBits = 3072)
    {
        switch (type)
        {
            case SshKeyType.Ed25519:
                return new Ed25519Key(RandomNumberGenerator.GetBytes(Ed25519.SeedSize), comment);

            case SshKeyType.EcdsaNistp256 or SshKeyType.EcdsaNistp384 or SshKeyType.EcdsaNistp521:
                var curve = type switch
                {
                    SshKeyType.EcdsaNistp256 => NistCurve.P256,
                    SshKeyType.EcdsaNistp384 => NistCurve.P384,
                    _ => NistCurve.P521,
                };
                return new EcdsaKey(curve, ECDsa.Create(curve.Curve), comment);

            case SshKeyType.Rsa:
                if (rsaBits is < 2048 or > 16384 || rsaBits % 8 != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(rsaBits), rsaBits, "RSA keys are 2048 to 16384 bits, in whole bytes.");
                }

                RSA rsa;
                try
                {
                    rsa = RSA.Create(rsaBits);
                }
                catch (CryptographicException ex)
                {
                    throw new ArgumentOutOfRangeException($"This platform cannot generate {rsaBits}-bit RSA keys: {ex.Message}", ex);
                }

                return new RsaKey(rsa, comment);

            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown key type.");
        }
    }

    /// <summary>
    /// A key that .NET's <see cref="RSA"/> holds, used without exporting it: a software key, or a non-exportable one in Windows CNG (a
    /// TPM through the Microsoft Platform Crypto Provider, Windows Hello) or in any provider that implements <see cref="RSA"/>. Only the
    /// public key is read. Signs with <c>rsa-sha2-512</c> or <c>rsa-sha2-256</c>.
    /// </summary>
    /// <param name="rsa">The key. It stays the caller's: disposing the returned key does not dispose it.</param>
    /// <param name="comment">A comment for the key, often <c>user@host</c>.</param>
    /// <exception cref="ArgumentException">The key is under 2048 bits.</exception>
    /// <remarks>The returned key cannot be exported or added to an agent.</remarks>
    public static SshPrivateKey FromRsa(RSA rsa, string? comment = null)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        try
        {
            return new ExternalKey(new ExternalKey.RsaSigner(rsa), comment);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException(ex.Message, nameof(rsa), ex); // the key given is unusable, as FromECDsa reports a wrong curve
        }
    }

    /// <summary>
    /// A key that .NET's <see cref="ECDsa"/> holds, on P-256, P-384 or P-521, used without exporting it, as <see cref="FromRsa"/>
    /// does for RSA.
    /// </summary>
    /// <param name="ecdsa">The key. It stays the caller's: disposing the returned key does not dispose it.</param>
    /// <param name="comment">A comment for the key, often <c>user@host</c>.</param>
    /// <exception cref="ArgumentException">The key is not on one of the NIST curves SSH uses.</exception>
    /// <remarks>The returned key cannot be exported or added to an agent.</remarks>
    public static SshPrivateKey FromECDsa(ECDsa ecdsa, string? comment = null)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);
        return new ExternalKey(new ExternalKey.EcdsaSigner(ecdsa, ExternalKey.CurveOf(ecdsa)), comment);
    }

    /// <summary>
    /// A key that signs through <paramref name="signer"/>: one in a key vault, a KMS, an HSM or on a smart card. Usable wherever a key
    /// is: <see cref="SshClientOptions.PrivateKeys"/>, <see cref="WithCertificate"/>, <see cref="SshSignature"/>. Each signature is
    /// checked against the public key before it is used.
    /// </summary>
    /// <param name="signer">The signer. It stays the caller's: disposing the returned key does nothing to it.</param>
    /// <param name="comment">A comment for the key, often <c>user@host</c>.</param>
    /// <exception cref="ArgumentException">The signer's <see cref="SshKeySigner.SignatureAlgorithms"/> include one its key type cannot use.</exception>
    /// <remarks>The returned key cannot be exported or added to an agent.</remarks>
    public static SshPrivateKey FromSigner(SshKeySigner signer, string? comment = null)
    {
        ArgumentNullException.ThrowIfNull(signer);
        return new ExternalKey(signer, comment);
    }

    /// <summary>
    /// The key in the OpenSSH private key format (<c>BEGIN OPENSSH PRIVATE KEY</c>), as <c>ssh-keygen</c> writes it: encrypted with
    /// <c>aes256-ctr</c> and <c>bcrypt_pbkdf</c> when <paramref name="passphrase"/> is given, otherwise unencrypted. The text holds the
    /// private key: do not log it, and write it only to files other users cannot read (<see cref="SaveAsync"/> does).
    /// </summary>
    /// <param name="passphrase">The passphrase to encrypt with; null or empty for an unencrypted key.</param>
    /// <param name="kdfRounds">bcrypt_pbkdf rounds (<c>ssh-keygen -a</c>): 16 by default; more make guessing the passphrase slower, and
    /// loading the key too.</param>
    /// <exception cref="NotSupportedException">The private key is not available: a key held by an agent or an external signer, or one
    /// paired with a certificate (export the key it was made from).</exception>
    public string ToOpenSshPrivateKey(string? passphrase = null, int kdfRounds = 16)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(kdfRounds, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(kdfRounds, OpenSshKeyWriter.MaxRounds);
        var bytes = OpenSshKeyWriter.Write(this, passphrase, kdfRounds);
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Writes the key as <c>ssh-keygen</c> does: the private key to <paramref name="path"/> (<see cref="ToOpenSshPrivateKey"/>), readable
    /// only by the current user (mode 0600 on Unix, an owner-only ACL on Windows), and the public key to <paramref name="path"/><c>.pub</c>.
    /// Neither file may exist yet: an existing key is never overwritten.
    /// </summary>
    /// <param name="path">The private key file, for example <c>~/.ssh/id_ed25519</c>.</param>
    /// <param name="passphrase">The passphrase to encrypt with; null or empty for an unencrypted key.</param>
    /// <param name="cancellationToken">Cancels writing.</param>
    /// <exception cref="IOException">One of the files exists already, or could not be written.</exception>
    /// <inheritdoc cref="ToOpenSshPrivateKey" path="/exception"/>
    public async Task SaveAsync(string path, string? passphrase = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var publicPath = path + ".pub";
        if (File.Exists(path) || File.Exists(publicPath))
        {
            throw new IOException($"'{(File.Exists(path) ? path : publicPath)}' exists already; a key file is never overwritten.");
        }

        var bytes = OpenSshKeyWriter.Write(this, passphrase, 16); // bytes, not a string, so they can be cleared afterwards
        bool createdPrivate = false, createdPublic = false;
        try
        {
            await using (var stream = OpenSshKeyWriter.CreateOwnerOnly(path))
            {
                createdPrivate = true;
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            }

            await using (var stream = new FileStream(publicPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
            {
                createdPublic = true;
                await stream.WriteAsync(Encoding.UTF8.GetBytes(ToAuthorizedKeysLine() + "\n"), cancellationToken).ConfigureAwait(false);
            }
        }
        catch
        {
            // All or nothing, and only the files this call created (another process may have made one in between).
            if (createdPublic)
            {
                File.Delete(publicPath);
            }

            if (createdPrivate)
            {
                File.Delete(path);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Writes the key as an SSH agent's ADD_IDENTITY carries it (draft-miller-ssh-agent section 3.2): the key type, then the type's
    /// private fields, which are those of the OpenSSH private key format.
    /// </summary>
    internal virtual void WriteAgentIdentity(SshWriter writer)
    {
        writer.WriteString(KeyType);
        WritePrivateFields(writer);
    }

    /// <summary>Writes the type-specific private fields of the OpenSSH private key format (PROTOCOL.key), after the key type.</summary>
    internal virtual void WritePrivateFields(SshWriter writer) =>
        throw new NotSupportedException("This key's private material cannot be exported: it is held by an agent, or paired with a certificate (export the key it was made from).");

    /// <summary>
    /// Whether the private material is here, in this process: false for a key an agent or an external signer holds (and a certificate
    /// paired with one), which can be neither exported nor added to an agent.
    /// </summary>
    internal virtual bool HasLocalPrivateMaterial => true;

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
            : base(certificate.Algorithm, certificate.Blob.ToArray(), key.Comment)
        {
            _key = key;
            Certificate = certificate;
            SignatureAlgorithms = [.. key.SignatureAlgorithms.Select(a => a + "-cert-v01@openssh.com")];
        }

        internal override IReadOnlyList<string> SignatureAlgorithms { get; }

        internal override bool HasLocalPrivateMaterial => _key.HasLocalPrivateMaterial;

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) => _key.Sign(SshCertificate.BaseAlgorithm(algorithm), data);

        internal override ValueTask<byte[]> SignAsync(SshSignRequest request, AgentBinding? binding, CancellationToken cancellationToken) =>
            _key.SignAsync(request.WithAlgorithm(SshCertificate.BaseAlgorithm(request.Algorithm)), binding, cancellationToken);

        /// <summary>
        /// A certified key as an agent takes it (PROTOCOL.certkeys): the certificate type and the certificate, then the private fields
        /// that are not in the certificate: Ed25519 the public key and seed as for a plain key, ECDSA only d, RSA d, iqmp, p and q.
        /// </summary>
        internal override void WriteAgentIdentity(SshWriter writer)
        {
            writer.WriteString(KeyType);
            writer.WriteString(Certificate!.Blob.Span);
            using var fields = new ZeroingBufferWriter(4096);
            _key.WritePrivateFields(new SshWriter(fields));
            var reader = new SshReader(fields.WrittenSpan);
            switch (_key.KeyType)
            {
                case "ssh-rsa":
                    reader.ReadMpint(); // n
                    reader.ReadMpint(); // e
                    break;
                case SshAlgorithms.SshEd25519:
                    break;
                default: // ECDSA
                    reader.ReadString(); // curve
                    reader.ReadString(); // Q
                    break;
            }

            writer.WriteBytes(reader.Remaining);
        }

        private protected override void DisposeCore()
        {
            // The private material belongs to the key this was made from.
        }
    }

    internal sealed class Ed25519Key : SshPrivateKey
    {
        private readonly byte[] _seed;

        // Derived from _seed here and nowhere else, so signing can skip deriving it again. A public key from a key file is never stored
        // in its place: the parsers compare it with this one and refuse the file when they differ (Ed25519.Sign says why that matters).
        private readonly byte[] _rawPublicKey;

        private bool _disposed;

        public Ed25519Key(byte[] seed, string? comment)
            : this(seed, DerivePublicKey(seed), comment)
        {
        }

        private Ed25519Key(byte[] seed, byte[] publicKey, string? comment)
            : base(SshAlgorithms.SshEd25519, PublicBlob(publicKey), comment)
        {
            _seed = seed;
            _rawPublicKey = publicKey;
        }

        internal override IReadOnlyList<string> SignatureAlgorithms { get; } = [SshAlgorithms.SshEd25519];

        internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
        {
            RequireAlgorithm(algorithm, SshAlgorithms.SshEd25519);

            // A disposed key's seed is zeros, which no longer match the public key.
            ObjectDisposedException.ThrowIf(_disposed, this);
            Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];
            Ed25519.Sign(_seed, _rawPublicKey, data, signature);
            return SignatureBlob(algorithm, signature);
        }

        private protected override void DisposeCore()
        {
            _disposed = true;
            CryptographicOperations.ZeroMemory(_seed);
        }

        // string public key, string (seed || public key).
        internal override void WritePrivateFields(SshWriter writer)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Span<byte> secret = stackalloc byte[Ed25519.SeedSize + Ed25519.PublicKeySize];
            try
            {
                _seed.CopyTo(secret);
                _rawPublicKey.CopyTo(secret[Ed25519.SeedSize..]);
                writer.WriteString(_rawPublicKey);
                writer.WriteString(secret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        private static byte[] DerivePublicKey(ReadOnlySpan<byte> seed)
        {
            var publicKey = new byte[Ed25519.PublicKeySize];
            Ed25519.GetPublicKey(seed, publicKey);
            return publicKey;
        }

        private static byte[] PublicBlob(byte[] publicKey) => Encode(w =>
        {
            w.WriteString(SshAlgorithms.SshEd25519);
            w.WriteString(publicKey);
        });
    }

    internal sealed class EcdsaKey : SshPrivateKey
    {
        private readonly ECDsa _ecdsa;
        private readonly NistCurve _curve;
        private readonly int _fieldSize;
        private readonly HashAlgorithmName _hash;

        public EcdsaKey(NistCurve curve, ECDsa ecdsa, string? comment)
            : base("ecdsa-sha2-" + curve.Name, PublicBlob(curve, ecdsa), comment)
        {
            _ecdsa = ecdsa;
            _curve = curve;
            _fieldSize = curve.FieldSize;
            _hash = curve.Hash;
        }

        // string curve, string public point, mpint private scalar.
        internal override void WritePrivateFields(SshWriter writer)
        {
            var parameters = _ecdsa.ExportParameters(true);
            try
            {
                var reader = new SshReader(PublicKey.Span);
                reader.ReadString(); // key type
                reader.ReadString(); // curve
                writer.WriteString(_curve.Name);
                writer.WriteString(reader.ReadString());
                writer.WriteMpint(parameters.D);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
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

        internal static byte[] PublicBlob(NistCurve curve, ECDsa ecdsa)
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

        // mpint n, e, d, iqmp, p, q. The framework's InverseQ is q^-1 mod p, which is OpenSSH's iqmp.
        internal override void WritePrivateFields(SshWriter writer)
        {
            var p = _rsa.ExportParameters(true);
            try
            {
                writer.WriteMpint(p.Modulus);
                writer.WriteMpint(p.Exponent);
                writer.WriteMpint(p.D);
                writer.WriteMpint(p.InverseQ);
                writer.WriteMpint(p.P);
                writer.WriteMpint(p.Q);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(p.D);
                CryptographicOperations.ZeroMemory(p.P);
                CryptographicOperations.ZeroMemory(p.Q);
                CryptographicOperations.ZeroMemory(p.DP);
                CryptographicOperations.ZeroMemory(p.DQ);
                CryptographicOperations.ZeroMemory(p.InverseQ);
            }
        }

        private static BigInteger ToInteger(ReadOnlySpan<byte> unsignedBigEndian) => new(unsignedBigEndian, isUnsigned: true, isBigEndian: true);

        private static byte[] Fixed(BigInteger value, int length) => Pad(value.ToByteArray(isUnsigned: true, isBigEndian: true), length);

        internal static byte[] PublicBlob(RSA rsa)
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
