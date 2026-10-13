using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>
/// Freshly generated private keys written in the formats SshPrivateKey reads, so no private key is ever committed. The OpenSSH writer
/// follows PROTOCOL.key; interop CI checks the reader against keys made by the real ssh-keygen.
/// </summary>
internal static class TestKeys
{
    public static string OpenSshEd25519(out byte[] publicBlob, string comment = "test@example", int? checkOverride = null, byte[]? padding = null)
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        publicBlob = Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString("ssh-ed25519");
            w.WriteString(pub);
            w.WriteString([.. seed, .. pub]);
        }, comment, checkOverride, padding);
    }

    public static string OpenSshEcdsa(ECCurve curve, string curveName, out byte[] publicBlob, string comment = "")
    {
        using var ecdsa = ECDsa.Create(curve);
        var p = ecdsa.ExportParameters(true);
        byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
        var type = "ecdsa-sha2-" + curveName;
        publicBlob = Blob(w => { w.WriteString(type); w.WriteString(curveName); w.WriteString(point); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString(type);
            w.WriteString(curveName);
            w.WriteString(point);
            w.WriteMpint(p.D);
        }, comment);
    }

    public static string OpenSshRsa(int bits, out byte[] publicBlob)
    {
        using var rsa = RSA.Create(bits);
        var p = rsa.ExportParameters(true);
        publicBlob = Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent); w.WriteMpint(p.Modulus); });
        return OpenSsh(publicBlob, w =>
        {
            w.WriteString("ssh-rsa");
            w.WriteMpint(p.Modulus);
            w.WriteMpint(p.Exponent);
            w.WriteMpint(p.D);
            w.WriteMpint(p.InverseQ);
            w.WriteMpint(p.P);
            w.WriteMpint(p.Q);
        }, "rsa-key");
    }

    /// <summary>RFC 8410 PKCS#8 for an Ed25519 seed.</summary>
    public static string Pkcs8Ed25519(out byte[] publicBlob)
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Ed25519.GetPublicKey(seed, pub);
        publicBlob = Blob(w => { w.WriteString("ssh-ed25519"); w.WriteString(pub); });

        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteOctetString(seed);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.112");
            }

            writer.WriteOctetString(inner.Encode());
        }

        return PemEncoding.WriteString("PRIVATE KEY", writer.Encode()) + "\n";
    }

    public static byte[] RsaPublicBlob(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        return Blob(w => { w.WriteString("ssh-rsa"); w.WriteMpint(p.Exponent); w.WriteMpint(p.Modulus); });
    }

    public static byte[] EcdsaPublicBlob(ECDsa ecdsa, string curveName)
    {
        var q = ecdsa.ExportParameters(false).Q;
        return Blob(w => { w.WriteString("ecdsa-sha2-" + curveName); w.WriteString(curveName); w.WriteString([4, .. q.X!, .. q.Y!]); });
    }

    public static byte[] Blob(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static string OpenSsh(byte[] publicBlob, Action<SshWriter> writeKey, string comment, int? checkOverride = null, byte[]? padding = null)
    {
        var check = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        var section = Blob(w =>
        {
            w.WriteUInt32(check);
            w.WriteUInt32(checkOverride is { } other ? (uint)other : check);
            writeKey(w);
            w.WriteString(comment);
        });
        var pad = padding ?? Enumerable.Range(1, (8 - (section.Length % 8)) % 8).Select(i => (byte)i).ToArray();
        byte[] privateSection = [.. section, .. pad];

        var body = Blob(w =>
        {
            w.WriteBytes("openssh-key-v1\0"u8);
            w.WriteString("none");
            w.WriteString("none");
            w.WriteString(ReadOnlySpan<byte>.Empty);
            w.WriteUInt32(1);
            w.WriteString(publicBlob);
            w.WriteString(privateSection);
        });

        var base64 = Convert.ToBase64String(body);
        var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < base64.Length; i += 70)
        {
            sb.Append(base64.AsSpan(i, Math.Min(70, base64.Length - i))).Append('\n');
        }

        return sb.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
    }
}
