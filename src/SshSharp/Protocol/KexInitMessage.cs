using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary><c>SSH_MSG_KEXINIT</c> (RFC 4253 section 7.1).</summary>
internal sealed class KexInitMessage
{
    public const int CookieSize = 16;

    public required byte[] Cookie { get; init; }

    public required IReadOnlyList<string> KexAlgorithms { get; init; }

    public required IReadOnlyList<string> ServerHostKeyAlgorithms { get; init; }

    public required IReadOnlyList<string> EncryptionClientToServer { get; init; }

    public required IReadOnlyList<string> EncryptionServerToClient { get; init; }

    public required IReadOnlyList<string> MacClientToServer { get; init; }

    public required IReadOnlyList<string> MacServerToClient { get; init; }

    public required IReadOnlyList<string> CompressionClientToServer { get; init; }

    public required IReadOnlyList<string> CompressionServerToClient { get; init; }

    public IReadOnlyList<string> LanguagesClientToServer { get; init; } = [];

    public IReadOnlyList<string> LanguagesServerToClient { get; init; } = [];

    public bool FirstKexPacketFollows { get; init; }

    /// <summary>Parses a KEXINIT payload (including the leading message number byte).</summary>
    public static KexInitMessage Parse(ReadOnlySpan<byte> payload)
    {
        var reader = new SshReader(payload);
        var type = reader.ReadByte();
        if (type != SshMessage.KexInit)
        {
            throw new SshProtocolException($"Expected SSH_MSG_KEXINIT (20), got {type}.");
        }

        var cookie = reader.ReadBytes(CookieSize).ToArray();
        var message = new KexInitMessage
        {
            Cookie = cookie,
            KexAlgorithms = reader.ReadNameList(),
            ServerHostKeyAlgorithms = reader.ReadNameList(),
            EncryptionClientToServer = reader.ReadNameList(),
            EncryptionServerToClient = reader.ReadNameList(),
            MacClientToServer = reader.ReadNameList(),
            MacServerToClient = reader.ReadNameList(),
            CompressionClientToServer = reader.ReadNameList(),
            CompressionServerToClient = reader.ReadNameList(),
            LanguagesClientToServer = reader.ReadNameList(),
            LanguagesServerToClient = reader.ReadNameList(),
            FirstKexPacketFollows = reader.ReadBoolean(),
        };
        reader.ReadUInt32(); // reserved
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data after SSH_MSG_KEXINIT.");
        }

        return message;
    }

    /// <summary>Writes the KEXINIT payload (including the leading message number byte).</summary>
    public void Write(IBufferWriter<byte> output)
    {
        var writer = new SshWriter(output);
        writer.WriteByte(SshMessage.KexInit);
        writer.WriteBytes(Cookie);
        writer.WriteNameList(KexAlgorithms);
        writer.WriteNameList(ServerHostKeyAlgorithms);
        writer.WriteNameList(EncryptionClientToServer);
        writer.WriteNameList(EncryptionServerToClient);
        writer.WriteNameList(MacClientToServer);
        writer.WriteNameList(MacServerToClient);
        writer.WriteNameList(CompressionClientToServer);
        writer.WriteNameList(CompressionServerToClient);
        writer.WriteNameList(LanguagesClientToServer);
        writer.WriteNameList(LanguagesServerToClient);
        writer.WriteBoolean(FirstKexPacketFollows);
        writer.WriteUInt32(0);
    }

    /// <summary>Builds a client KEXINIT from preferences, with a fresh random cookie and the strict-KEX and ext-info markers.</summary>
    public static KexInitMessage ForClient(AlgorithmPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        var cookie = new byte[CookieSize];
        RandomNumberGenerator.Fill(cookie);
        return new KexInitMessage
        {
            Cookie = cookie,
            KexAlgorithms = [.. preferences.Kex, SshAlgorithms.ExtInfoClient, SshAlgorithms.StrictKexClient],
            ServerHostKeyAlgorithms = preferences.HostKeys,
            EncryptionClientToServer = preferences.Ciphers,
            EncryptionServerToClient = preferences.Ciphers,
            MacClientToServer = preferences.Macs,
            MacServerToClient = preferences.Macs,
            CompressionClientToServer = preferences.Compression,
            CompressionServerToClient = preferences.Compression,
        };
    }
}