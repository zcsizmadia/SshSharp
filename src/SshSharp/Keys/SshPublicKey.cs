using System.Buffers;
using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Keys;

/// <summary>An SSH public key (RFC 4253 section 6.6): parses the wire blob and verifies signatures made by the matching private key.</summary>
internal abstract class SshPublicKey
{
    protected SshPublicKey(string keyType, ReadOnlyMemory<byte> blob)
    {
        KeyType = keyType;
        Blob = blob;
    }

    /// <summary>The key type name, for example <c>ssh-ed25519</c>.</summary>
    public string KeyType { get; }

    /// <summary>The wire encoding of the key.</summary>
    public ReadOnlyMemory<byte> Blob { get; }

    /// <summary>The key size in bits (256 for Ed25519, the curve size for ECDSA, the modulus size for RSA), for key-strength policy checks.</summary>
    public abstract int KeySizeBits { get; }

    /// <summary>The OpenSSH-style SHA-256 fingerprint: <c>SHA256:</c> followed by unpadded base64.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(Blob.Span)).TrimEnd('=');

    /// <summary>Parses a public key blob. Throws <see cref="SshProtocolException"/> for malformed or unsupported keys.</summary>
    public static SshPublicKey Parse(ReadOnlySpan<byte> blob)
    {
        var reader = new SshReader(blob);
        var type = reader.ReadUtf8String();
        var copy = blob.ToArray();
        SshPublicKey key = type switch
        {
            SshAlgorithms.SshEd25519 => ParseEd25519(ref reader, copy),
            SshAlgorithms.EcdsaNistp256 or SshAlgorithms.EcdsaNistp384 or SshAlgorithms.EcdsaNistp521 => ParseEcdsa(type, ref reader, copy),
            "ssh-rsa" => ParseRsa(ref reader, copy),
            _ => throw new SshProtocolException($"Unsupported host key type '{type}'."),
        };
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data after the public key.");
        }

        return key;
    }

    /// <summary>
    /// Verifies <paramref name="signatureBlob"/> (<c>string type || string signature</c>) over <paramref name="data"/>.
    /// <paramref name="algorithm"/> is the negotiated signature algorithm and must match the type inside the blob.
    /// Returns false for any mismatch or malformed signature.
    /// </summary>
    public bool VerifySignature(string algorithm, ReadOnlySpan<byte> signatureBlob, ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new SshReader(signatureBlob);
            var type = reader.ReadUtf8String();
            var signature = reader.ReadString();
            if (!reader.IsEmpty || type != algorithm || !SupportsAlgorithm(algorithm))
            {
                return false;
            }

            return VerifyRaw(algorithm, signature, data);
        }
        catch (SshProtocolException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Whether this key can verify signatures made with <paramref name="algorithm"/>.</summary>
    protected abstract bool SupportsAlgorithm(string algorithm);

    /// <summary>Verifies the algorithm-specific signature bytes.</summary>
    protected abstract bool VerifyRaw(string algorithm, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data);

    private static Ed25519PublicKey ParseEd25519(ref SshReader reader, byte[] blob)
    {
        var key = reader.ReadString();
        if (key.Length != Ed25519.PublicKeySize)
        {
            throw new SshProtocolException("An Ed25519 public key must be 32 bytes.");
        }

        return new Ed25519PublicKey(key.ToArray(), blob);
    }

    private static EcdsaPublicKey ParseEcdsa(string type, ref SshReader reader, byte[] blob)
    {
        var curve = NistCurve.FromSshName(type["ecdsa-sha2-".Length..]);
        var id = reader.ReadUtf8String();
        var point = reader.ReadString();
        if (id != curve.Name)
        {
            throw new SshProtocolException($"Curve '{id}' does not match key type '{type}'.");
        }

        var fieldSize = curve.FieldSize;
        if (point.Length != 1 + (2 * fieldSize) || point[0] != 4)
        {
            throw new SshProtocolException("An ECDSA public key must be an uncompressed point.");
        }

        var x = point.Slice(1, fieldSize);
        var y = point[(1 + fieldSize)..];
        if (!curve.IsOnCurve(x, y))
        {
            throw new SshProtocolException("The ECDSA public key is not a point on the curve.");
        }

        var parameters = new ECParameters { Curve = curve.Curve, Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() } };
        return new EcdsaPublicKey(type, parameters, fieldSize, blob);
    }

    private static RsaPublicKey ParseRsa(ref SshReader reader, byte[] blob)
    {
        var exponent = reader.ReadMpint().ToArray();
        var modulus = reader.ReadMpint().ToArray();
        if (modulus.Length < 64 || exponent.Length == 0)
        {
            throw new SshProtocolException("The RSA public key is too small or malformed.");
        }

        return new RsaPublicKey(new RSAParameters { Exponent = exponent, Modulus = modulus }, blob);
    }

    private sealed class Ed25519PublicKey(byte[] key, byte[] blob) : SshPublicKey(SshAlgorithms.SshEd25519, blob)
    {
        public override int KeySizeBits => 256;

        protected override bool SupportsAlgorithm(string algorithm) => algorithm == SshAlgorithms.SshEd25519;

        protected override bool VerifyRaw(string algorithm, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data) =>
            signature.Length == Ed25519.SignatureSize && Ed25519.Verify(key, data, signature);
    }

    private sealed class EcdsaPublicKey(string type, ECParameters parameters, int fieldSize, byte[] blob) : SshPublicKey(type, blob)
    {
        public override int KeySizeBits => fieldSize == 66 ? 521 : fieldSize * 8;

        protected override bool SupportsAlgorithm(string algorithm) => algorithm == KeyType;

        protected override bool VerifyRaw(string algorithm, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data)
        {
            // The signature is two mpints (r, s); the framework wants fixed-width r || s.
            var reader = new SshReader(signature);
            var r = reader.ReadMpint();
            var s = reader.ReadMpint();
            if (!reader.IsEmpty || r.Length > fieldSize || s.Length > fieldSize)
            {
                return false;
            }

            Span<byte> fixedWidth = stackalloc byte[2 * fieldSize];
            fixedWidth.Clear();
            r.CopyTo(fixedWidth[(fieldSize - r.Length)..fieldSize]);
            s.CopyTo(fixedWidth[((2 * fieldSize) - s.Length)..]);

            using var ecdsa = ECDsa.Create(parameters);
            var hash = fieldSize switch
            {
                32 => HashAlgorithmName.SHA256,
                48 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA512,
            };
            return ecdsa.VerifyData(data, fixedWidth, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    private sealed class RsaPublicKey(RSAParameters parameters, byte[] blob) : SshPublicKey("ssh-rsa", blob)
    {
        public override int KeySizeBits => (parameters.Modulus!.Length * 8) - System.Numerics.BitOperations.LeadingZeroCount((uint)parameters.Modulus[0]) + 24;

        protected override bool SupportsAlgorithm(string algorithm) => algorithm is SshAlgorithms.RsaSha2_256 or SshAlgorithms.RsaSha2_512;

        protected override bool VerifyRaw(string algorithm, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            var hash = algorithm == SshAlgorithms.RsaSha2_256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
            return rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1);
        }
    }
}