using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>Computes the exchange hash H (RFC 4253 section 8, RFC 5656 section 4, RFC 8731 section 3.1).</summary>
internal static class ExchangeHash
{
    /// <summary>
    /// H = HASH(V_C || V_S || I_C || I_S || K_S || kexSpecific || K), each string length-prefixed and K as an mpint.
    /// </summary>
    /// <param name="hash">The key exchange's hash algorithm.</param>
    /// <param name="clientVersion">The client identification string without CR LF.</param>
    /// <param name="serverVersion">The server identification string without CR LF.</param>
    /// <param name="clientKexInit">The client's KEXINIT payload (including the message number).</param>
    /// <param name="serverKexInit">The server's KEXINIT payload.</param>
    /// <param name="hostKeyBlob">The server host key blob K_S.</param>
    /// <param name="writeKexSpecific">Writes the method-specific values: e, f for DH; Q_C, Q_S for ECDH and X25519.</param>
    /// <param name="sharedSecret">K as an unsigned big-endian magnitude.</param>
    public static byte[] Compute(
        HashAlgorithmName hash,
        string clientVersion,
        string serverVersion,
        ReadOnlySpan<byte> clientKexInit,
        ReadOnlySpan<byte> serverKexInit,
        ReadOnlySpan<byte> hostKeyBlob,
        Action<SshWriter> writeKexSpecific,
        ReadOnlySpan<byte> sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(writeKexSpecific);
        var buffer = new ArrayBufferWriter<byte>(1024);
        var writer = new SshWriter(buffer);
        writer.WriteString(clientVersion);
        writer.WriteString(serverVersion);
        writer.WriteString(clientKexInit);
        writer.WriteString(serverKexInit);
        writer.WriteString(hostKeyBlob);
        writeKexSpecific(writer);
        writer.WriteMpint(sharedSecret);

        var result = new byte[HashSize(hash)];
        using var hasher = IncrementalHash.CreateHash(hash);
        hasher.AppendData(buffer.WrittenSpan);
        hasher.GetHashAndReset(result);
        buffer.Clear();
        return result;
    }

    public static int HashSize(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new ArgumentException($"Unsupported hash {hash.Name}.", nameof(hash)),
    };
}