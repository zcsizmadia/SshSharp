using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>The six keys derived from a key exchange (RFC 4253 section 7.2).</summary>
internal sealed class SessionKeys : IDisposable
{
    public required byte[] IvClientToServer { get; init; }

    public required byte[] IvServerToClient { get; init; }

    public required byte[] EncryptionKeyClientToServer { get; init; }

    public required byte[] EncryptionKeyServerToClient { get; init; }

    public required byte[] IntegrityKeyClientToServer { get; init; }

    public required byte[] IntegrityKeyServerToClient { get; init; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(IvClientToServer);
        CryptographicOperations.ZeroMemory(IvServerToClient);
        CryptographicOperations.ZeroMemory(EncryptionKeyClientToServer);
        CryptographicOperations.ZeroMemory(EncryptionKeyServerToClient);
        CryptographicOperations.ZeroMemory(IntegrityKeyClientToServer);
        CryptographicOperations.ZeroMemory(IntegrityKeyServerToClient);
    }
}

/// <summary>Key derivation from the shared secret K and exchange hash H.</summary>
internal static class KeyDerivation
{
    /// <summary>
    /// Derives <paramref name="length"/> bytes: <c>K1 = HASH(K || H || letter || session_id)</c>, extended with
    /// <c>Kn = HASH(K || H || K1 || ... || Kn-1)</c> until there are enough bytes.
    /// </summary>
    /// <param name="hash">The key exchange's hash algorithm.</param>
    /// <param name="sharedSecret">K as an unsigned big-endian magnitude (it is encoded as an mpint here).</param>
    /// <param name="exchangeHash">H of this exchange.</param>
    /// <param name="letter">'A' to 'F'.</param>
    /// <param name="sessionId">H of the first key exchange.</param>
    /// <param name="length">The number of bytes needed.</param>
    /// <param name="sharedSecretIsString">K is encoded as a string, not an mpint (the post-quantum hybrid methods).</param>
    public static byte[] Derive(HashAlgorithmName hash, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> exchangeHash, char letter, ReadOnlySpan<byte> sessionId, int length,
        bool sharedSecretIsString = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        var result = new byte[length];
        if (length == 0)
        {
            return result;
        }

        // Sized up front so the writer never grows and leaves an unwiped copy of K behind (Clear zeroes what was written).
        var prefix = new ArrayBufferWriter<byte>(sharedSecret.Length + exchangeHash.Length + 8);
        if (sharedSecretIsString)
        {
            new SshWriter(prefix).WriteString(sharedSecret);
        }
        else
        {
            new SshWriter(prefix).WriteMpint(sharedSecret);
        }
        prefix.Write(exchangeHash);

        using var hasher = IncrementalHash.CreateHash(hash);
        var hashLength = hasher.HashLengthInBytes;

        // K1 || K2 || ... : each further block hashes everything generated so far (RFC 4253 section 7.2).
        var generated = new byte[(length + hashLength - 1) / hashLength * hashLength];
        hasher.AppendData(prefix.WrittenSpan);
        hasher.AppendData([(byte)letter]);
        hasher.AppendData(sessionId);
        hasher.GetHashAndReset(generated.AsSpan(0, hashLength));

        for (var produced = hashLength; produced < length; produced += hashLength)
        {
            hasher.AppendData(prefix.WrittenSpan);
            hasher.AppendData(generated.AsSpan(0, produced));
            hasher.GetHashAndReset(generated.AsSpan(produced, hashLength));
        }

        generated.AsSpan(0, length).CopyTo(result);
        prefix.Clear();
        CryptographicOperations.ZeroMemory(generated);
        return result;
    }

    /// <summary>Derives all six keys for the negotiated cipher and MAC of each direction.</summary>
    public static SessionKeys DeriveAll(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> exchangeHash,
        ReadOnlySpan<byte> sessionId,
        CipherInfo cipherClientToServer,
        CipherInfo cipherServerToClient,
        MacInfo? macClientToServer,
        MacInfo? macServerToClient,
        bool sharedSecretIsString = false) => new()
        {
            IvClientToServer = Derive(hash, sharedSecret, exchangeHash, 'A', sessionId, cipherClientToServer.IvLength, sharedSecretIsString),
            IvServerToClient = Derive(hash, sharedSecret, exchangeHash, 'B', sessionId, cipherServerToClient.IvLength, sharedSecretIsString),
            EncryptionKeyClientToServer = Derive(hash, sharedSecret, exchangeHash, 'C', sessionId, cipherClientToServer.KeyLength, sharedSecretIsString),
            EncryptionKeyServerToClient = Derive(hash, sharedSecret, exchangeHash, 'D', sessionId, cipherServerToClient.KeyLength, sharedSecretIsString),
            IntegrityKeyClientToServer = Derive(hash, sharedSecret, exchangeHash, 'E', sessionId, cipherClientToServer.IsAead ? 0 : macClientToServer?.KeyLength ?? 0, sharedSecretIsString),
            IntegrityKeyServerToClient = Derive(hash, sharedSecret, exchangeHash, 'F', sessionId, cipherServerToClient.IsAead ? 0 : macServerToClient?.KeyLength ?? 0, sharedSecretIsString),
        };
}