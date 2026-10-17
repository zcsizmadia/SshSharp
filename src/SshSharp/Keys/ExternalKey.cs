using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// A key whose private half SshSharp never holds (<see cref="SshPrivateKey.FromSigner"/>, <see cref="SshPrivateKey.FromRsa"/>,
/// <see cref="SshPrivateKey.FromECDsa"/>): it signs through an <see cref="SshKeySigner"/>, and every signature is checked against the
/// public key before it is used. It cannot be exported or added to an agent.
/// </summary>
internal sealed class ExternalKey : SshPrivateKey
{
    private readonly SshKeySigner _signer;
    private readonly SshPublicKey _publicKey;

    public ExternalKey(SshKeySigner signer, string? comment)
        : base(signer.KeyType, signer.PublicKey.ToArray(), comment)
    {
        _signer = signer;
        _publicKey = SshPublicKey.Parse(signer.PublicKey.Span);
        string[] supported = signer.KeyType == "ssh-rsa" ? [SshAlgorithms.RsaSha2_512, SshAlgorithms.RsaSha2_256] : [signer.KeyType];
        var offered = signer.SignatureAlgorithms;
        if (offered is null || offered.Count == 0 || offered.Any(a => !supported.Contains(a, StringComparer.Ordinal)))
        {
            throw new ArgumentException(
                $"The signer's SignatureAlgorithms must be one or more of {string.Join(", ", supported)} for a {signer.KeyType} key.", nameof(signer));
        }

        SignatureAlgorithms = [.. offered];
    }

    internal override IReadOnlyList<string> SignatureAlgorithms { get; }

    internal override bool HasLocalPrivateMaterial => false;

    internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) =>
        throw new NotSupportedException("A key held by an external signer signs only asynchronously.");

    internal override async ValueTask<byte[]> SignAsync(SshSignRequest request, AgentBinding? binding, CancellationToken cancellationToken)
    {
        var algorithm = request.Algorithm;
        if (!SignatureAlgorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            throw new ArgumentException($"This {KeyType} key does not sign with '{algorithm}'.", nameof(request));
        }

        var signature = await _signer.SignAsync(request, cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException("The key's signer returned no signature.");
        var blob = Encode(w =>
        {
            w.WriteString(algorithm);
            w.WriteString(KeyType.StartsWith("ecdsa-", StringComparison.Ordinal) ? EcdsaSignature(signature) : signature);
        });

        if (!_publicKey.VerifySignature(algorithm, blob, request.Data.Span))
        {
            throw new CryptographicException(
                $"The {KeyType} key's signer returned a signature that does not verify against its public key ({Fingerprint}): check that it " +
                "signs with this key, with the hash the algorithm names, and returns the format SshKeySigner.SignAsync describes.");
        }

        return blob;
    }

    internal override void WritePrivateFields(SshWriter writer) =>
        throw new NotSupportedException("This key's private material is held by an external signer: it cannot be exported or added to an agent.");

    private protected override void DisposeCore()
    {
        // The signer, and any key behind it, belongs to the caller.
    }

    /// <summary>An ECDSA signature as SSH carries it: r and s as two mpints, from the signer's r || s or DER form.</summary>
    private byte[] EcdsaSignature(byte[] signature)
    {
        byte[] r, s;
        if (_signer.EcdsaSignatureFormat == DSASignatureFormat.Rfc3279DerSequence)
        {
            (r, s) = ReadDerSignature(signature);
        }
        else
        {
            if (signature.Length == 0 || signature.Length % 2 != 0)
            {
                throw new CryptographicException($"An r || s ECDSA signature has an even length; the signer returned {signature.Length} bytes.");
            }

            r = signature[..(signature.Length / 2)];
            s = signature[(signature.Length / 2)..];
        }

        return Encode(w =>
        {
            w.WriteMpint(r);
            w.WriteMpint(s);
        });
    }

    /// <summary>SEQUENCE { INTEGER r, INTEGER s } in DER, as unsigned big-endian r and s.</summary>
    private static (byte[] R, byte[] S) ReadDerSignature(ReadOnlySpan<byte> der)
    {
        var position = 0;
        if (ReadTag(der, ref position, 0x30) != der.Length - position)
        {
            throw new CryptographicException("The ECDSA signature is not a DER SEQUENCE of two INTEGERs.");
        }

        var r = ReadInteger(der, ref position);
        var s = ReadInteger(der, ref position);
        if (position != der.Length)
        {
            throw new CryptographicException("The ECDSA signature has data after its two INTEGERs.");
        }

        return (r, s);

        static byte[] ReadInteger(ReadOnlySpan<byte> der, ref int position)
        {
            var length = ReadTag(der, ref position, 0x02);
            if (length == 0 || position + length > der.Length || (der[position] & 0x80) != 0)
            {
                throw new CryptographicException("The ECDSA signature has a malformed or negative INTEGER.");
            }

            var value = der.Slice(position, length).TrimStart((byte)0).ToArray();
            position += length;
            return value;
        }

        static int ReadTag(ReadOnlySpan<byte> der, ref int position, byte tag)
        {
            if (position + 2 > der.Length || der[position] != tag)
            {
                throw new CryptographicException("The ECDSA signature is not a DER SEQUENCE of two INTEGERs.");
            }

            int length = der[position + 1];
            position += 2;
            if (length == 0x81 && position < der.Length)
            {
                length = der[position++];
            }
            else if (length > 0x7F)
            {
                throw new CryptographicException("The ECDSA signature uses a DER length form an ECDSA signature never needs.");
            }

            return length;
        }
    }

    /// <summary>Signs with an <see cref="RSA"/> instance the caller owns (<see cref="SshPrivateKey.FromRsa"/>).</summary>
    internal sealed class RsaSigner(RSA rsa) : SshKeySigner(RsaKey.PublicBlob(rsa))
    {
        public override ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken)
        {
            var hash = request.Algorithm == SshAlgorithms.RsaSha2_256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
            return ValueTask.FromResult(rsa.SignData(request.Data.Span, hash, RSASignaturePadding.Pkcs1));
        }
    }

    /// <summary>Signs with an <see cref="ECDsa"/> instance the caller owns (<see cref="SshPrivateKey.FromECDsa"/>).</summary>
    internal sealed class EcdsaSigner(ECDsa ecdsa, NistCurve curve) : SshKeySigner(EcdsaKey.PublicBlob(curve, ecdsa))
    {
        public override ValueTask<byte[]> SignAsync(SshSignRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ecdsa.SignData(request.Data.Span, curve.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    /// <summary>The NIST curve of <paramref name="ecdsa"/>: by its OID or name where the platform reports one, otherwise by its size.</summary>
    internal static NistCurve CurveOf(ECDsa ecdsa)
    {
        var curve = ecdsa.ExportParameters(false).Curve;
        var oid = curve.Oid?.Value;
        var name = curve.Oid?.FriendlyName;
        var byName = (oid, name) switch
        {
            ("1.2.840.10045.3.1.7", _) or (_, "nistP256" or "ECDSA_P256" or "secp256r1") => NistCurve.P256,
            ("1.3.132.0.34", _) or (_, "nistP384" or "ECDSA_P384" or "secp384r1") => NistCurve.P384,
            ("1.3.132.0.35", _) or (_, "nistP521" or "ECDSA_P521" or "secp521r1") => NistCurve.P521,
            _ => null,
        };
        if (byName is not null)
        {
            return byName;
        }

        if (oid is not null || name is not null)
        {
            throw new ArgumentException($"SSH uses only the NIST curves P-256, P-384 and P-521, not {name ?? oid}.", nameof(ecdsa));
        }

        return ecdsa.KeySize switch
        {
            256 => NistCurve.P256,
            384 => NistCurve.P384,
            521 => NistCurve.P521,
            _ => throw new ArgumentException($"SSH uses only the NIST curves P-256, P-384 and P-521, not a {ecdsa.KeySize}-bit curve.", nameof(ecdsa)),
        };
    }
}
