using System.Numerics;
using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Protocol;

/// <summary>
/// <c>diffie-hellman-group-exchange-sha256</c> (RFC 4419): the client asks for a group of <see cref="MinBits"/> to <see cref="MaxBits"/>
/// bits, preferring the size <see cref="PreferredBits"/> picks; the server answers with a prime p and generator g, which are checked
/// (<see cref="DhGroupValidator"/>) before the exchange runs in that group as <see cref="DhKeyExchange"/> does in a fixed one. The exchange
/// hash also covers min, n, max, p and g.
/// </summary>
internal sealed class DhGroupExchangeKeyExchange : ClientKeyExchange
{
    /// <summary>OpenSSH's DH_GRP_MIN: smaller groups give less than 112 bits of security (NIST SP 800-57).</summary>
    public const int MinBits = 2048;

    /// <summary>OpenSSH's DH_GRP_MAX.</summary>
    public const int MaxBits = 8192;

    private readonly int _preferredBits;
    private Group? _group;

    public DhGroupExchangeKeyExchange(int preferredBits) => _preferredBits = preferredBits;

    public override HashAlgorithmName Hash => HashAlgorithmName.SHA256;

    public override byte ReplyMessage => SshMessage.KexDhGexReply;

    /// <summary>
    /// The group size to ask for, as OpenSSH's client picks it (<c>dh_estimate</c>): from the largest key, IV, block or MAC key that the
    /// negotiated ciphers and MACs use in either direction (the MAC only with a non-AEAD cipher). Up to 112 bits asks for 2048, up to
    /// 128 bits for 3072, up to 192 bits for 7680, and more for 8192. Cisco's 1.x servers fail on groups over 4096 bits, so they are
    /// asked for at most that, as OpenSSH does (SSH_BUG_DHGEX_LARGE).
    /// </summary>
    public static int PreferredBits(string serverSoftware, CipherInfo clientToServer, CipherInfo serverToClient, MacInfo? macClientToServer,
        MacInfo? macServerToClient)
    {
        var need = Math.Max(Need(clientToServer, macClientToServer), Need(serverToClient, macServerToClient)) * 8;
        var bits = need <= 112 ? 2048 : need <= 128 ? 3072 : need <= 192 ? 7680 : 8192;
        return serverSoftware.StartsWith("Cisco-1.", StringComparison.Ordinal) ? Math.Min(bits, 4096) : bits;
    }

    // In bytes. AES has 16-byte blocks and ChaCha20 8; an AEAD cipher uses no MAC.
    private static int Need(CipherInfo cipher, MacInfo? mac)
    {
        var block = cipher.Kind == CipherKind.ChaCha20Poly1305 ? 8 : 16;
        var macKey = cipher.IsAead || mac is null ? 0 : mac.KeyLength;
        return Math.Max(Math.Max(cipher.KeyLength, cipher.IvLength), Math.Max(block, macKey));
    }

    /// <summary>The private exponent's size: as for the fixed group of the nearest size above (<see cref="ModpGroup.ExponentBits"/>).</summary>
    internal static int ExponentBits(long primeBits) => primeBits <= 2048 ? 512 : primeBits <= 4096 ? 768 : 1024;

    public override byte[] CreateGroupRequest() => BuildInit(SshMessage.KexDhGexRequest, WriteSizes);

    public override void ProcessGroup(ReadOnlySpan<byte> message)
    {
        var reader = new SshReader(message);
        var type = reader.ReadByte();
        if (type != SshMessage.KexDhGexGroup)
        {
            throw new SshProtocolException($"Expected the key exchange group ({SshMessage.KexDhGexGroup}), got message {type}.");
        }

        var p = reader.ReadMpint().ToArray();
        var g = reader.ReadMpint().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange group.");
        }

        var prime = new BigInteger(p, isUnsigned: true, isBigEndian: true);
        var generator = new BigInteger(g, isUnsigned: true, isBigEndian: true);
        DhGroupValidator.Validate(prime, generator, MinBits, MaxBits);

        var x = DhKeyExchange.NewExponent(ExponentBits(prime.GetBitLength()));
        _group = new Group(p, g, prime, x, DhKeyExchange.Magnitude(BigInteger.ModPow(generator, x, prime)));
    }

    public override byte[] CreateInit()
    {
        var group = _group ?? throw new InvalidOperationException("The server's group has not been received.");
        return BuildInit(SshMessage.KexDhGexInit, w => w.WriteMpint(group.E));
    }

    public override KexResult ProcessReply(ReadOnlySpan<byte> reply, KexContext context)
    {
        var group = _group ?? throw new InvalidOperationException("The server's group has not been received.");
        var reader = new SshReader(reply);
        var hostKey = ExpectReply(ref reader, SshMessage.KexDhGexReply);
        var fMagnitude = reader.ReadMpint().ToArray();
        var signature = reader.ReadString().ToArray();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Trailing data in the key exchange reply.");
        }

        // RFC 4419 section 3: H = HASH(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K).
        var k = DhKeyExchange.Agree(fMagnitude, group.X, group.Prime);
        var h = ExchangeHash.Compute(Hash, context.ClientVersion, context.ServerVersion, context.ClientKexInit, context.ServerKexInit, hostKey, w =>
        {
            WriteSizes(w);
            w.WriteMpint(group.P);
            w.WriteMpint(group.G);
            w.WriteMpint(group.E);
            w.WriteMpint(fMagnitude);
        }, k);

        // K is handed over rather than copied, so the only copy is the one KexResult wipes.
        return new KexResult { SharedSecret = k, ExchangeHash = h, HostKeyBlob = hostKey, Signature = signature };
    }

    public override void Dispose()
    {
        // BigInteger values cannot be wiped; they are ephemeral and only live as long as this exchange.
    }

    private void WriteSizes(SshWriter writer)
    {
        writer.WriteUInt32(MinBits);
        writer.WriteUInt32((uint)_preferredBits);
        writer.WriteUInt32(MaxBits);
    }

    /// <summary>The server's group as sent (p and g), p as a number, the client's exponent x and its public value e.</summary>
    private sealed record Group(byte[] P, byte[] G, BigInteger Prime, BigInteger X, byte[] E);
}
