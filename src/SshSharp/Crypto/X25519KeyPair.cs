using System.Security.Cryptography;

namespace SshSharp.Crypto;

/// <summary>
/// An ephemeral X25519 key pair for one key exchange: the platform's (<c>X25519DiffieHellman</c>, .NET 11, where the OS provides it) or
/// the managed Montgomery ladder (<see cref="X25519"/>) otherwise. Both reject a peer's low-order point the same way: a shared secret of
/// all zeros (RFC 7748 section 6.1, RFC 8731 section 3.1).
/// </summary>
internal sealed class X25519KeyPair : IDisposable
{
#if NET11_0_OR_GREATER
    private readonly X25519DiffieHellman? _platform;
#endif
    private readonly byte[]? _privateKey;
    private readonly byte[] _publicKey = new byte[X25519.KeySize];

    private X25519KeyPair(bool platform, ReadOnlySpan<byte> privateKey)
    {
#if NET11_0_OR_GREATER
        if (platform)
        {
            _platform = privateKey.IsEmpty ? X25519DiffieHellman.GenerateKey() : X25519DiffieHellman.ImportPrivateKey(privateKey);
            _platform.ExportPublicKey(_publicKey);
            return;
        }
#endif
        _privateKey = privateKey.IsEmpty ? RandomNumberGenerator.GetBytes(X25519.KeySize) : privateKey.ToArray();
        X25519.GetPublicKey(_privateKey, _publicKey);
    }

    /// <summary>Whether new key pairs use the platform's X25519 (.NET 11 on an OS that provides it).</summary>
    public static bool UsesPlatform =>
#if NET11_0_OR_GREATER
        X25519DiffieHellman.IsSupported;
#else
        false;
#endif

    /// <summary>A new random key pair.</summary>
    public static X25519KeyPair Generate() => new(UsesPlatform, default);

    /// <summary>A key pair from a known private key, on the platform or managed path (for tests that compare the two).</summary>
    internal static X25519KeyPair FromPrivateKey(ReadOnlySpan<byte> privateKey, bool platform) =>
        privateKey.Length == X25519.KeySize ? new(platform, privateKey) : throw new ArgumentException("X25519 keys must be 32 bytes.");

    /// <summary>Whether this pair is the platform's (the managed one holds its private key itself).</summary>
    public bool IsPlatform => _privateKey is null;

    /// <summary>The 32-byte public key.</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    /// <summary>
    /// Computes the shared secret with the peer's public key. Returns false when the peer's key is a low-order point (the secret is all
    /// zeros, or the platform refuses the key): the key exchange must then be aborted.
    /// </summary>
    public bool TryAgree(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        if (peerPublicKey.Length != X25519.KeySize || sharedSecret.Length < X25519.KeySize)
        {
            throw new ArgumentException("X25519 keys must be 32 bytes.");
        }

#if NET11_0_OR_GREATER
        if (_platform is not null)
        {
            try
            {
                _platform.DeriveRawSecretAgreement(peerPublicKey, sharedSecret[..X25519.KeySize]);
            }
            catch (CryptographicException)
            {
                // A platform that refuses a low-order point itself: the same outcome as an all-zero secret.
                CryptographicOperations.ZeroMemory(sharedSecret[..X25519.KeySize]);
                return false;
            }

            Span<byte> zero = stackalloc byte[X25519.KeySize];
            return !CryptographicOperations.FixedTimeEquals(sharedSecret[..X25519.KeySize], zero);
        }
#endif
        return X25519.TryAgree(_privateKey!, peerPublicKey, sharedSecret);
    }

    public void Dispose()
    {
#if NET11_0_OR_GREATER
        _platform?.Dispose();
#endif
        if (_privateKey is not null)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
        }
    }
}
