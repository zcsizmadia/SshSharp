using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Protocol;

/// <summary>What the transport needs to know about one exchange: both identification strings and both KEXINIT payloads.</summary>
internal sealed record KexContext(string ClientVersion, string ServerVersion, byte[] ClientKexInit, byte[] ServerKexInit);

/// <summary>The outcome of a key exchange. The host key signature over <see cref="ExchangeHash"/> still has to be verified by the caller.</summary>
internal sealed class KexResult : IDisposable
{
    /// <summary>K, as an unsigned big-endian magnitude.</summary>
    public required byte[] SharedSecret { get; init; }

    /// <summary>H.</summary>
    public required byte[] ExchangeHash { get; init; }

    /// <summary>The server's host key blob (K_S).</summary>
    public required byte[] HostKeyBlob { get; init; }

    /// <summary>The signature blob over H (<c>string type || string signature</c>).</summary>
    public required byte[] Signature { get; init; }

    /// <summary>K is encoded as a string rather than an mpint in key derivation (the post-quantum hybrid methods).</summary>
    public bool SharedSecretIsString { get; init; }

    public void Dispose() => CryptographicOperations.ZeroMemory(SharedSecret);
}

/// <summary>The client side of one key exchange method (RFC 4253 section 8, RFC 5656, RFC 8731).</summary>
internal abstract class ClientKeyExchange : IDisposable
{
    /// <summary>The hash used for the exchange hash and key derivation.</summary>
    public abstract HashAlgorithmName Hash { get; }

    /// <summary>The first key exchange message (including its message number): <c>SSH_MSG_KEX*_INIT</c>.</summary>
    public abstract byte[] CreateInit();

    /// <summary>Processes the server's reply message (including its message number), computes K and H.</summary>
    /// <exception cref="SshProtocolException">The reply is malformed.</exception>
    /// <exception cref="SshException">The server sent an unacceptable value (low-order point, point off the curve, DH value out of range).</exception>
    public abstract KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context);

    public abstract void Dispose();

    /// <summary>Creates the client side of the named method.</summary>
    public static ClientKeyExchange Create(string name) => name switch
    {
#if NET10_0_OR_GREATER
        SshAlgorithms.MlKem768X25519Sha256 when MLKem.IsSupported => new MlKem768X25519KeyExchange(),
        SshAlgorithms.MlKem768Nistp256Sha256 when MLKem.IsSupported => new MlKemNistKeyExchange(MLKemAlgorithm.MLKem768, NistCurve.P256),
        SshAlgorithms.MlKem1024Nistp384Sha384 when MLKem.IsSupported => new MlKemNistKeyExchange(MLKemAlgorithm.MLKem1024, NistCurve.P384),
#endif
        SshAlgorithms.Sntrup761X25519Sha512 or SshAlgorithms.Sntrup761X25519Sha512OpenSsh => new Sntrup761X25519KeyExchange(),
        SshAlgorithms.Curve25519Sha256 or SshAlgorithms.Curve25519Sha256Libssh => new Curve25519KeyExchange(),
        SshAlgorithms.EcdhNistp256 => new EcdhKeyExchange(NistCurve.P256),
        SshAlgorithms.EcdhNistp384 => new EcdhKeyExchange(NistCurve.P384),
        SshAlgorithms.EcdhNistp521 => new EcdhKeyExchange(NistCurve.P521),
        SshAlgorithms.DhGroup14Sha256 => new DhKeyExchange(ModpGroup.Group14, HashAlgorithmName.SHA256),
        SshAlgorithms.DhGroup16Sha512 => new DhKeyExchange(ModpGroup.Group16, HashAlgorithmName.SHA512),
        _ => throw new ArgumentException($"Unsupported key exchange method '{name}'.", nameof(name)),
    };

    protected static byte[] BuildInit(byte messageNumber, Action<SshWriter> writeBody)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new SshWriter(buffer);
        writer.WriteByte(messageNumber);
        writeBody(writer);
        return buffer.WrittenSpan.ToArray();
    }

    protected static byte[] ExpectReply(ref SshReader reader)
    {
        var type = reader.ReadByte();
        if (type != SshMessage.KexEcdhReply)
        {
            throw new SshProtocolException($"Expected the key exchange reply (31), got message {type}.");
        }

        return reader.ReadString().ToArray(); // K_S
    }

    protected static KexResult Finish(
        HashAlgorithmName hash, KexContext context, byte[] hostKey, byte[] signature, Action<SshWriter> writeKexSpecific, ReadOnlySpan<byte> sharedSecret,
        bool sharedSecretIsString = false)
    {
        var h = ExchangeHash.Compute(hash, context.ClientVersion, context.ServerVersion, context.ClientKexInit, context.ServerKexInit, hostKey, writeKexSpecific,
            sharedSecret, sharedSecretIsString);
        return new KexResult
        {
            SharedSecret = sharedSecret.ToArray(), ExchangeHash = h, HostKeyBlob = hostKey, Signature = signature, SharedSecretIsString = sharedSecretIsString,
        };
    }
}

/// <summary><c>curve25519-sha256</c> (RFC 8731).</summary>
internal sealed class Curve25519KeyExchange : ClientKeyExchange
{
    private readonly byte[] _privateKey = RandomNumberGenerator.GetBytes(X25519.KeySize);
    private readonly byte[] _publicKey = new byte[X25519.KeySize];

    public Curve25519KeyExchange() => X25519.GetPublicKey(_privateKey, _publicKey);

    public override HashAlgorithmName Hash => HashAlgorithmName.SHA256;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexEcdhInit, w => w.WriteString(_publicKey));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var serverPublic = reader.ReadString().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        if (serverPublic.Length != X25519.KeySize)
        {
            throw new SshProtocolException("A Curve25519 public value must be 32 bytes.");
        }

        var shared = new byte[X25519.KeySize];
        if (!X25519.TryAgree(_privateKey, serverPublic, shared))
        {
            throw new SshException(SshFailureReason.KeyExchangeFailed, "The server sent a low-order Curve25519 point.");
        }

        try
        {
            return Finish(Hash, context, hostKey, signature, w =>
            {
                w.WriteString(_publicKey);
                w.WriteString(serverPublic);
            }, shared);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    public override void Dispose()
    {
        CryptographicOperations.ZeroMemory(_privateKey);
    }
}

/// <summary><c>ecdh-sha2-nistp256/384/521</c> (RFC 5656).</summary>
internal sealed class EcdhKeyExchange : ClientKeyExchange
{
    private readonly NistCurve _curve;
    private readonly ECDiffieHellman _key;
    private readonly byte[] _publicPoint;

    public EcdhKeyExchange(NistCurve curve)
    {
        _curve = curve;
        _key = ECDiffieHellman.Create(curve.Curve);
        var q = _key.ExportParameters(false).Q;
        _publicPoint = new byte[1 + (2 * curve.FieldSize)];
        _publicPoint[0] = 4;
        q.X!.CopyTo(_publicPoint, 1 + curve.FieldSize - q.X.Length);
        q.Y!.CopyTo(_publicPoint, 1 + (2 * curve.FieldSize) - q.Y.Length);
    }

    public override HashAlgorithmName Hash => _curve.Hash;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexEcdhInit, w => w.WriteString(_publicPoint));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var serverPoint = reader.ReadString().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        var size = _curve.FieldSize;
        if (serverPoint.Length != 1 + (2 * size) || serverPoint[0] != 4)
        {
            throw new SshProtocolException("The server's ECDH value must be an uncompressed point.");
        }

        // Never trust the platform to validate the peer's point (Windows CNG does not): TryDeriveSecret checks it explicitly.
        byte[]? secret;
        try
        {
            secret = _curve.TryDeriveSecret(_key, serverPoint.AsSpan(1, size), serverPoint.AsSpan(1 + size));
        }
        catch (CryptographicException ex)
        {
            throw new SshException(SshFailureReason.KeyExchangeFailed, $"ECDH failed: {ex.Message}", ex);
        }

        if (secret is null)
        {
            throw new SshException(SshFailureReason.KeyExchangeFailed, "The server's ECDH point is not on the curve.");
        }

        try
        {
            return Finish(Hash, context, hostKey, signature, w =>
            {
                w.WriteString(_publicPoint);
                w.WriteString(serverPoint);
            }, secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public override void Dispose() => _key.Dispose();
}

/// <summary><c>diffie-hellman-group14-sha256</c> and <c>diffie-hellman-group16-sha512</c> (RFC 4253 section 8, RFC 8268).</summary>
internal sealed class DhKeyExchange : ClientKeyExchange
{
    private readonly ModpGroup _group;
    private readonly HashAlgorithmName _hash;
    private readonly BigInteger _x;
    private readonly BigInteger _e;

    public DhKeyExchange(ModpGroup group, HashAlgorithmName hash)
    {
        _group = group;
        _hash = hash;

        // A random exponent of ExponentBits bits with the top bit set, so it is never tiny.
        var bytes = RandomNumberGenerator.GetBytes(group.ExponentBits / 8);
        bytes[0] |= 0x80;
        _x = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        CryptographicOperations.ZeroMemory(bytes);

        // BigInteger.ModPow is not constant-time and its internals cannot be wiped. The exponent is ephemeral and used for one
        // exchange, so remote timing attacks are impractical; curve25519 and ECDH are preferred over DH by default anyway.
        _e = BigInteger.ModPow(ModpGroup.Generator, _x, group.Prime);
    }

    public override HashAlgorithmName Hash => _hash;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexDhInit, w => w.WriteMpint(Magnitude(_e)));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var fMagnitude = reader.ReadMpint().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        var f = new BigInteger(fMagnitude, isUnsigned: true, isBigEndian: true);
        var p = _group.Prime;
        if (f <= BigInteger.One || f >= p - BigInteger.One)
        {
            throw new SshException(SshFailureReason.KeyExchangeFailed, "The server's Diffie-Hellman value is out of range.");
        }

        var k = BigInteger.ModPow(f, _x, p);
        var kBytes = Magnitude(k);
        try
        {
            return Finish(_hash, context, hostKey, signature, w =>
            {
                w.WriteMpint(Magnitude(_e));
                w.WriteMpint(fMagnitude);
            }, kBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kBytes);
        }
    }

    public override void Dispose()
    {
        // BigInteger values cannot be wiped; they are ephemeral and only live as long as this exchange.
    }

    private static byte[] Magnitude(BigInteger value) => value.ToByteArray(isUnsigned: true, isBigEndian: true);
}

/// <summary>
/// <c>sntrup761x25519-sha512</c> (RFC 9941; <c>sntrup761x25519-sha512@openssh.com</c> in OpenSSH 8.5 to 9.8): Streamlined NTRU Prime 761
/// combined with X25519, so the session keys stay secret unless both are broken. The client sends its sntrup761 public key and X25519
/// public key; the server answers with the sntrup761 ciphertext and its X25519 public key; K = SHA-512(sntrup761 secret || X25519 secret),
/// encoded as a string. Managed (<see cref="Sntrup761"/>), so it works on every platform and on .NET 8.
/// </summary>
internal sealed class Sntrup761X25519KeyExchange : ClientKeyExchange
{
    private readonly byte[] _secretKey = new byte[Sntrup761.SecretKeySize];
    private readonly byte[] _privateKey = RandomNumberGenerator.GetBytes(X25519.KeySize);
    private readonly byte[] _clientInit = new byte[Sntrup761.PublicKeySize + X25519.KeySize];

    public Sntrup761X25519KeyExchange()
    {
        Sntrup761.GenerateKeyPair(_clientInit.AsSpan(0, Sntrup761.PublicKeySize), _secretKey);
        X25519.GetPublicKey(_privateKey, _clientInit.AsSpan(Sntrup761.PublicKeySize));
    }

    public override HashAlgorithmName Hash => HashAlgorithmName.SHA512;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexEcdhInit, w => w.WriteString(_clientInit));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var serverReply = reader.ReadString().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        if (serverReply.Length != Sntrup761.CiphertextSize + X25519.KeySize)
        {
            throw new SshProtocolException($"The sntrup761/X25519 reply must be {Sntrup761.CiphertextSize + X25519.KeySize} bytes.");
        }

        // Both secrets, then K = SHA-512(sntrup761 secret || X25519 secret). A tampered ciphertext decapsulates to an unrelated secret,
        // so the mismatch shows as a failed host signature check, as with OpenSSH.
        var secrets = new byte[Sntrup761.SharedSecretSize + X25519.KeySize];
        var shared = new byte[64];
        try
        {
            Sntrup761.Decapsulate(secrets.AsSpan(0, Sntrup761.SharedSecretSize), serverReply.AsSpan(0, Sntrup761.CiphertextSize), _secretKey);
            if (!X25519.TryAgree(_privateKey, serverReply.AsSpan(Sntrup761.CiphertextSize), secrets.AsSpan(Sntrup761.SharedSecretSize)))
            {
                throw new SshException(SshFailureReason.KeyExchangeFailed, "The server sent a low-order Curve25519 point.");
            }

            SHA512.HashData(secrets, shared);
            return Finish(Hash, context, hostKey, signature, w =>
            {
                w.WriteString(_clientInit);
                w.WriteString(serverReply);
            }, shared, sharedSecretIsString: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secrets);
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    public override void Dispose()
    {
        CryptographicOperations.ZeroMemory(_secretKey);
        CryptographicOperations.ZeroMemory(_privateKey);
    }
}

#if NET10_0_OR_GREATER
/// <summary>
/// <c>mlkem768x25519-sha256</c> (draft-ietf-sshm-mlkem-hybrid-kex, OpenSSH 9.9+): ML-KEM-768 (FIPS 203) combined with X25519, so the session
/// keys stay secret unless both are broken, including by a future quantum computer that records today's traffic. The client sends its
/// ML-KEM encapsulation key and X25519 public key; the server answers with the ML-KEM ciphertext and its X25519 public key;
/// K = SHA-256(ML-KEM secret || X25519 secret), encoded as a string. Needs the platform's ML-KEM (<see cref="MLKem.IsSupported"/>).
/// </summary>
internal sealed class MlKem768X25519KeyExchange : ClientKeyExchange
{
    private const int EncapsulationKeySize = 1184;
    private const int CiphertextSize = 1088;

    private readonly MLKem _mlkem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    private readonly byte[] _privateKey = RandomNumberGenerator.GetBytes(X25519.KeySize);
    private readonly byte[] _clientInit;

    public MlKem768X25519KeyExchange()
    {
        _clientInit = new byte[EncapsulationKeySize + X25519.KeySize];
        _mlkem.ExportEncapsulationKey(_clientInit.AsSpan(0, EncapsulationKeySize));
        X25519.GetPublicKey(_privateKey, _clientInit.AsSpan(EncapsulationKeySize));
    }

    public override HashAlgorithmName Hash => HashAlgorithmName.SHA256;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexEcdhInit, w => w.WriteString(_clientInit));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var serverReply = reader.ReadString().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        if (serverReply.Length != CiphertextSize + X25519.KeySize)
        {
            throw new SshProtocolException($"The ML-KEM/X25519 reply must be {CiphertextSize + X25519.KeySize} bytes.");
        }

        // Both secrets, then K = SHA-256(ML-KEM secret || X25519 secret).
        var secrets = new byte[32 + X25519.KeySize];
        var shared = new byte[32];
        try
        {
            try
            {
                _mlkem.Decapsulate(serverReply.AsSpan(0, CiphertextSize), secrets.AsSpan(0, 32));
            }
            catch (CryptographicException ex)
            {
                throw new SshException(SshFailureReason.KeyExchangeFailed, $"ML-KEM decapsulation failed: {ex.Message}", ex);
            }

            if (!X25519.TryAgree(_privateKey, serverReply.AsSpan(CiphertextSize), secrets.AsSpan(32)))
            {
                throw new SshException(SshFailureReason.KeyExchangeFailed, "The server sent a low-order Curve25519 point.");
            }

            SHA256.HashData(secrets, shared);
            return Finish(Hash, context, hostKey, signature, w =>
            {
                w.WriteString(_clientInit);
                w.WriteString(serverReply);
            }, shared, sharedSecretIsString: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secrets);
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    public override void Dispose()
    {
        _mlkem.Dispose();
        CryptographicOperations.ZeroMemory(_privateKey);
    }
}

/// <summary>
/// <c>mlkem768nistp256-sha256</c> and <c>mlkem1024nistp384-sha384</c> (RFC 10042): ML-KEM (FIPS 203) combined with ECDH on a NIST curve,
/// so both halves are FIPS-approved. The same construction as <see cref="MlKem768X25519KeyExchange"/>: the client sends its ML-KEM
/// encapsulation key followed by its uncompressed ECDH point; the server answers with the ML-KEM ciphertext followed by its point;
/// K = HASH(ML-KEM secret || ECDH secret), the ECDH secret as a fixed-length x coordinate, K encoded as a string. HASH is the curve's:
/// SHA-256 for P-256, SHA-384 for P-384.
/// </summary>
internal sealed class MlKemNistKeyExchange : ClientKeyExchange
{
    private readonly MLKemAlgorithm _algorithm;
    private readonly NistCurve _curve;
    private readonly MLKem _mlkem;
    private readonly ECDiffieHellman _ecdh;
    private readonly byte[] _clientInit;

    public MlKemNistKeyExchange(MLKemAlgorithm algorithm, NistCurve curve)
    {
        _algorithm = algorithm;
        _curve = curve;
        _mlkem = MLKem.GenerateKey(algorithm);
        _ecdh = ECDiffieHellman.Create(curve.Curve);

        var keySize = algorithm.EncapsulationKeySizeInBytes;
        var q = _ecdh.ExportParameters(false).Q;
        _clientInit = new byte[keySize + 1 + (2 * curve.FieldSize)];
        _mlkem.ExportEncapsulationKey(_clientInit.AsSpan(0, keySize));
        _clientInit[keySize] = 4; // uncompressed point (SEC 1 section 2.3.3)
        q.X!.CopyTo(_clientInit, keySize + 1 + curve.FieldSize - q.X.Length);
        q.Y!.CopyTo(_clientInit, keySize + 1 + (2 * curve.FieldSize) - q.Y.Length);
    }

    public override HashAlgorithmName Hash => _curve.Hash;

    public override byte[] CreateInit() => BuildInit(SshMessage.KexEcdhInit, w => w.WriteString(_clientInit));

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader);
        var serverReply = reader.ReadString().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        // The ciphertext, then the server's point. RFC 10042 allows compressed points; servers send uncompressed ones, and that is the
        // only form accepted here (as for plain ECDH, RFC 5656).
        var ciphertextSize = _algorithm.CiphertextSizeInBytes;
        var size = _curve.FieldSize;
        if (serverReply.Length != ciphertextSize + 1 + (2 * size) || serverReply[ciphertextSize] != 4)
        {
            throw new SshProtocolException($"The ML-KEM/ECDH reply must be {ciphertextSize} bytes of ciphertext and an uncompressed point.");
        }

        var pqSize = _algorithm.SharedSecretSizeInBytes;
        var secrets = new byte[pqSize + size];
        byte[]? classic = null;
        var shared = new byte[_curve.Hash == HashAlgorithmName.SHA384 ? 48 : 32];
        try
        {
            try
            {
                _mlkem.Decapsulate(serverReply.AsSpan(0, ciphertextSize), secrets.AsSpan(0, pqSize));
                classic = _curve.TryDeriveSecret(_ecdh, serverReply.AsSpan(ciphertextSize + 1, size), serverReply.AsSpan(ciphertextSize + 1 + size, size));
            }
            catch (CryptographicException ex)
            {
                throw new SshException(SshFailureReason.KeyExchangeFailed, $"The ML-KEM/ECDH exchange failed: {ex.Message}", ex);
            }

            if (classic is null)
            {
                throw new SshException(SshFailureReason.KeyExchangeFailed, "The server's ECDH point is not on the curve.");
            }

            // The ECDH secret as a fixed-length byte array (the x coordinate, FieldSize bytes), not an mpint.
            classic.CopyTo(secrets.AsSpan(pqSize + size - classic.Length));
            if (_curve.Hash == HashAlgorithmName.SHA384)
            {
                SHA384.HashData(secrets, shared);
            }
            else
            {
                SHA256.HashData(secrets, shared);
            }

            return Finish(Hash, context, hostKey, signature, w =>
            {
                w.WriteString(_clientInit);
                w.WriteString(serverReply);
            }, shared, sharedSecretIsString: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secrets);
            CryptographicOperations.ZeroMemory(shared);
            if (classic is not null)
            {
                CryptographicOperations.ZeroMemory(classic);
            }
        }
    }

    public override void Dispose()
    {
        _mlkem.Dispose();
        _ecdh.Dispose();
    }
}
#endif