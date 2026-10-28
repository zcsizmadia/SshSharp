using System.Security.Cryptography;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Config;

/// <summary>
/// The keys <c>RevokedHostKeys</c> names, as OpenSSH reads them (authfile.c <c>sshkey_check_revoked</c>): an OpenSSH Key Revocation List
/// (PROTOCOL.krl, the binary file <c>ssh-keygen -k</c> writes), or, when the file is not a KRL, a list of public keys, one per line as in
/// <c>authorized_keys</c> (lines that do not parse are skipped, as ssh does).
/// </summary>
/// <remarks>
/// A KRL revokes plain keys (explicitly, or by SHA-1 or SHA-256 fingerprint) and certificates (by serial number, serial range or bitmap,
/// or key id, for one certificate authority or for any). A host certificate is also revoked when its authority's key is. A KRL's signature
/// sections are parsed and skipped, not verified: the file is trusted as a local configuration file, which is how ssh uses it too (it
/// checks a signature only against the KRL's own keys, which proves nothing about who wrote the file).
/// </remarks>
internal sealed class RevokedKeyList
{
    /// <summary>Larger files are refused rather than read into memory.</summary>
    internal const int MaxFileSize = 16 * 1024 * 1024;

    /// <summary>The message of the <see cref="IOException"/> for a file over <see cref="MaxFileSize"/>, which names no path.</summary>
    internal const string TooLargeMessage = "The revoked keys file is larger than 16 MiB.";

    /// <summary>The most bits of one serial bitmap section that are expanded.</summary>
    private const int MaxBitmapBytes = 1024 * 1024;

    private static ReadOnlySpan<byte> Magic => "SSHKRL\n\0"u8;

    private const uint FormatVersion = 1;
    private const byte SectionCertificates = 1;
    private const byte SectionExplicitKey = 2;
    private const byte SectionFingerprintSha1 = 3;
    private const byte SectionSignature = 4;
    private const byte SectionFingerprintSha256 = 5;
    private const byte SectionExtension = 255;
    private const byte CertSerialList = 0x20;
    private const byte CertSerialRange = 0x21;
    private const byte CertSerialBitmap = 0x22;
    private const byte CertKeyId = 0x23;
    private const byte CertExtension = 0x39;

    private readonly HashSet<string> _keys = new(StringComparer.Ordinal); // plain key blobs, hex
    private readonly HashSet<string> _sha1 = new(StringComparer.Ordinal);
    private readonly HashSet<string> _sha256 = new(StringComparer.Ordinal);
    private readonly List<CertificateRevocations> _certificates = [];

    /// <summary>
    /// Parsed files by full path, with the SHA-256 of the bytes they were parsed from. The file is still read on every check (it is
    /// security configuration: an edit must take effect at once, whatever the file times say), but parsed again only when it changed.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (byte[] Hash, RevokedKeyList List, long LastUsed)> Parsed = new();

    /// <summary>How many parsed files <see cref="Parsed"/> keeps; past that, the least recently used one goes.</summary>
    internal const int MaxCachedFiles = 32;

    private RevokedKeyList(bool isKrl) => IsKrl = isKrl;

    /// <summary>Whether the file was a KRL (otherwise a list of public keys).</summary>
    public bool IsKrl { get; }

    /// <summary>Certificates revoked for one authority (<see cref="Authority"/> null: any authority).</summary>
    private sealed class CertificateRevocations(byte[]? authority)
    {
        public byte[]? Authority { get; } = authority;

        /// <summary>Serial lists and ranges while parsing; sorted and merged by <see cref="Seal"/>, then searched by binary search.</summary>
        public List<(ulong Low, ulong High)> Serials { get; private set; } = [];

        /// <summary>Serial bitmaps as written: bit i, from the least significant end of <c>Bits</c>, revokes <c>Offset + i</c>.</summary>
        public List<(ulong Offset, byte[] Bits)> Bitmaps { get; } = [];

        public HashSet<string> KeyIds { get; } = new(StringComparer.Ordinal); // raw bytes, hex

        public void Seal()
        {
            Serials.Sort((a, b) => a.Low.CompareTo(b.Low));
            var merged = new List<(ulong Low, ulong High)>(Serials.Count);
            foreach (var (low, high) in Serials)
            {
                // Stryker disable once Equality,Arithmetic : ranges that only touch, left apart, are still found; only overlapping ones must merge
                if (merged.Count > 0 && merged[^1].High != ulong.MaxValue && low <= merged[^1].High + 1)
                {
                    merged[^1] = (merged[^1].Low, Math.Max(merged[^1].High, high));
                }
                else
                {
                    merged.Add((low, high));
                }
            }

            Serials = merged;
        }

        public bool IsSerialRevoked(ulong serial)
        {
            // The last range starting at or below the serial is the only one that can hold it (the ranges are merged).
            int lo = 0, hi = Serials.Count - 1;
            while (lo <= hi)
            {
                var mid = lo + ((hi - lo) / 2);
                if (Serials[mid].Low <= serial)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            if (hi >= 0 && serial <= Serials[hi].High)
            {
                return true;
            }

            foreach (var (offset, bits) in Bitmaps)
            {
                if (serial >= offset && serial - offset < (ulong)bits.Length * 8)
                {
                    var i = serial - offset;
                    if ((bits[bits.Length - 1 - (int)(i / 8)] & (1 << (int)(i % 8))) != 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }

    /// <summary>Reads a revoked keys file, parsing it again only when its contents changed since the last read of the same path.</summary>
    /// <exception cref="FormatException">The file is a malformed KRL, or uses a KRL feature this library does not know.</exception>
    /// <exception cref="IOException">The file cannot be read, or is too large.</exception>
    public static async Task<RevokedKeyList> LoadAsync(string path, CancellationToken cancellationToken)
    {
        byte[] data;
        await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
        {
            if (stream.Length > MaxFileSize)
            {
                throw new IOException(TooLargeMessage);
            }

            data = new byte[stream.Length];
            await stream.ReadExactlyAsync(data, cancellationToken).ConfigureAwait(false);
        }

        var key = Path.GetFullPath(path);
        var hash = SHA256.HashData(data);
        if (Parsed.TryGetValue(key, out var cached) && cached.Hash.AsSpan().SequenceEqual(hash))
        {
            Parsed[key] = cached with { LastUsed = Environment.TickCount64 };
            return cached.List;
        }

        var list = Parse(data);
        MakeRoom(Parsed, key);
        Parsed[key] = (hash, list, Environment.TickCount64);
        return list;
    }

    /// <summary>
    /// Before <paramref name="key"/> goes into <paramref name="cache"/>: when the cache is full and the key is new, drops the file used
    /// longest ago. RevokedHostKeys can name a file per host (%h), so the cache is bounded; clearing everything instead would parse nearly
    /// every file again once more hosts than that are in use.
    /// </summary>
    internal static void MakeRoom(System.Collections.Concurrent.ConcurrentDictionary<string, (byte[] Hash, RevokedKeyList List, long LastUsed)> cache, string key)
    {
        if (cache.Count >= MaxCachedFiles && !cache.ContainsKey(key))
        {
            var oldest = cache.MinBy(entry => entry.Value.LastUsed).Key;
            if (oldest is not null)
            {
                cache.TryRemove(oldest, out _);
            }
        }
    }

    /// <summary>Parses a KRL, or a list of public keys when the data does not start with the KRL magic.</summary>
    /// <exception cref="FormatException">A malformed KRL, or one with a section or critical extension this library does not know.</exception>
    public static RevokedKeyList Parse(ReadOnlySpan<byte> data)
    {
        if (!data.StartsWith(Magic))
        {
            return ParseKeyList(Encoding.UTF8.GetString(data));
        }

        return ParseKrl(data);
    }

    /// <summary>
    /// Whether the host key is revoked: its plain key (explicitly or by fingerprint), and for a certificate also its authority's key,
    /// its key id, or its serial number (serial 0, which a certificate carries when none was assigned, is never revoked by serial).
    /// </summary>
    public bool IsRevoked(ReadOnlySpan<byte> plainKey, SshCertificate? certificate)
    {
        if (IsKeyRevoked(plainKey) || (certificate is not null && IsKeyRevoked(certificate.AuthorityKey.Span)))
        {
            return true;
        }

        if (certificate is null)
        {
            return false;
        }

        var keyId = Convert.ToHexString(Encoding.UTF8.GetBytes(certificate.KeyId));
        foreach (var revocations in _certificates)
        {
            if (revocations.Authority is { } authority && !authority.AsSpan().SequenceEqual(certificate.AuthorityKey.Span))
            {
                continue;
            }

            if (revocations.KeyIds.Contains(keyId))
            {
                return true;
            }

            var serial = certificate.Serial;
            if (serial != 0 && revocations.IsSerialRevoked(serial))
            {
                return true;
            }
        }

        return false;
    }

    // Stryker disable once Equality : the count only saves hashing a key when no SHA-1 is listed; an empty set contains nothing anyway
    private bool IsKeyRevoked(ReadOnlySpan<byte> blob) =>
        _keys.Contains(Convert.ToHexString(blob))
        || (_sha1.Count > 0 && _sha1.Contains(Sha1Fingerprint(blob)))
        || _sha256.Contains(Convert.ToHexString(SHA256.HashData(blob)));

    /// <summary>
    /// The SHA-1 fingerprint a KRL's SHA-1 section lists keys by (PROTOCOL.krl). SHA-1 here only looks a key up in a list the user
    /// wrote; a collision could at most revoke one more key, never accept one.
    /// </summary>
#pragma warning disable CA5350 // the KRL format defines this section with SHA-1
    private static string Sha1Fingerprint(ReadOnlySpan<byte> blob) => Convert.ToHexString(SHA1.HashData(blob));
#pragma warning restore CA5350

    /// <summary>
    /// A list of public keys (sshkey_in_file): <c>type base64 [comment]</c> per line; blank lines, comments and lines that do not parse
    /// are skipped. A certificate line revokes the key it certifies (ssh compares the keys, not the certificates), FIDO security-key
    /// certificates included. A certificate line of a type SshSharp accepts (Ed25519, ECDSA, RSA, FIDO) that cannot be read (bad base64,
    /// a truncated certificate, a malformed key) refuses the whole list: skipping it would leave a key the list means to revoke accepted.
    /// A certificate of another type (<c>ssh-dss-cert-v01@openssh.com</c>, or one this library does not know) is skipped: its key is
    /// never accepted anyway. Its authority is not checked, so a certificate whose authority key is itself a certificate still revokes.
    /// </summary>
    /// <exception cref="FormatException">A certificate line's certified key cannot be read.</exception>
    private static RevokedKeyList ParseKeyList(string text)
    {
        var list = new RevokedKeyList(isKrl: false);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var fields = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2)
            {
                continue;
            }

            var certificate = SshCertificate.IsCertificateAlgorithm(fields[0]);
            if (certificate && !SshCertificate.IsAcceptedCertificateKeyType(fields[0]))
            {
                // A DSA certificate, or a type this library does not know: it certifies a key SshSharp never accepts, so there is
                // nothing for the line to revoke here. Skipped, as OpenSSH skips lines it cannot use.
                continue;
            }

            byte[] blob;
            try
            {
                blob = Convert.FromBase64String(fields[1]);
                if (new SshReader(blob).ReadUtf8String() != fields[0])
                {
                    throw new FormatException("The key's type does not match the line's.");
                }

                if (certificate)
                {
                    blob = SshCertificate.ReadCertifiedKey(blob);
                }
            }
            catch (Exception ex) when (ex is FormatException or SshProtocolException)
            {
                if (certificate)
                {
                    // A certificate of a type SshSharp accepts, malformed: skipping it would leave a key the list means to revoke accepted.
                    throw new FormatException("A certificate in the revoked keys list cannot be read, so the list is refused.", ex);
                }

                continue;
            }

            list._keys.Add(Convert.ToHexString(blob));
        }

        return list;
    }

    /// <summary>PROTOCOL.krl: the header, then sections, signature sections (if any) last.</summary>
    private static RevokedKeyList ParseKrl(ReadOnlySpan<byte> data)
    {
        var list = new RevokedKeyList(isKrl: true);
        var reader = new KrlReader(data[Magic.Length..]);
        var version = reader.ReadUInt32();
        if (version != FormatVersion)
        {
            throw new FormatException($"KRL format version {version} is not supported.");
        }

        reader.ReadUInt64(); // krl_version
        reader.ReadUInt64(); // generated_date
        reader.ReadUInt64(); // flags
        reader.ReadString(); // reserved
        reader.ReadString(); // comment

        var signed = false;
        while (!reader.IsEmpty)
        {
            var type = reader.ReadByte();
            var section = new KrlReader(reader.ReadString());
            if (signed && type != SectionSignature)
            {
                throw new FormatException("The KRL has a section after its signature.");
            }

            switch (type)
            {
                case SectionCertificates:
                    list.ParseCertificates(ref section);
                    break;

                case SectionExplicitKey:
                    while (!section.IsEmpty)
                    {
                        list._keys.Add(Convert.ToHexString(section.ReadString()));
                    }

                    break;

                case SectionFingerprintSha1 or SectionFingerprintSha256:
                    while (!section.IsEmpty)
                    {
                        var hash = section.ReadString();
                        if (hash.Length != (type == SectionFingerprintSha1 ? 20 : 32))
                        {
                            throw new FormatException("A KRL fingerprint has the wrong length.");
                        }

                        (type == SectionFingerprintSha1 ? list._sha1 : list._sha256).Add(Convert.ToHexString(hash));
                    }

                    break;

                case SectionSignature:
                    // Unlike other sections, the string after the type is the signing key, and the signature follows it as another
                    // string (PROTOCOL.krl: byte type, string signature_key, string signature). Parsed, so a truncated one is an
                    // error; not verified.
                    reader.ReadString();
                    signed = true;
                    break;

                case SectionExtension:
                    SkipExtension(ref section);
                    break;

                default:
                    throw new FormatException($"KRL section type {type} is not supported.");
            }
        }

        return list;
    }

    private void ParseCertificates(ref KrlReader section)
    {
        var authority = section.ReadString().ToArray();
        section.ReadString(); // reserved
        if (authority.Length > 0)
        {
            // A key blob (any type: ssh checks it parses; a type this library cannot verify still names the authority exactly).
            new KrlReader(authority).ReadString();
        }

        var revocations = new CertificateRevocations(authority.Length == 0 ? null : authority);
        _certificates.Add(revocations);
        while (!section.IsEmpty)
        {
            var type = section.ReadByte();
            var sub = new KrlReader(section.ReadString());
            switch (type)
            {
                case CertSerialList:
                    while (!sub.IsEmpty)
                    {
                        var serial = sub.ReadUInt64();
                        AddSerials(revocations, serial, serial);
                    }

                    break;

                case CertSerialRange:
                    AddSerials(revocations, sub.ReadUInt64(), sub.ReadUInt64());
                    Expect(sub.IsEmpty, "Trailing data in a KRL serial range.");
                    break;

                case CertSerialBitmap:
                {
                    var offset = sub.ReadUInt64();
                    var bitmap = sub.ReadMpint(); // big-endian, bit i (from the least significant end) revokes offset + i
                    Expect(sub.IsEmpty, "Trailing data in a KRL serial bitmap.");
                    if (bitmap.Length > MaxBitmapBytes)
                    {
                        throw new FormatException("A KRL serial bitmap is too large.");
                    }

                    // Kept as written and tested bit by bit, rather than expanded into one entry per set bit (8 million for a full
                    // 1 MiB bitmap). The same checks as before: no serial 0 (offset 0 with bit 0 set) and no overflow past 2^64 - 1.
                    if (!bitmap.IsEmpty)
                    {
                        Expect(offset != 0 || (bitmap[^1] & 1) == 0, "A KRL revokes serial 0 or has an empty serial range.");
                        var highestBit = ((ulong)bitmap.Length * 8) - 1 - (ulong)System.Numerics.BitOperations.LeadingZeroCount((uint)bitmap[0] << 24);
                        Expect(offset + highestBit >= offset, "A KRL serial bitmap overflows.");
                        revocations.Bitmaps.Add((offset, bitmap.ToArray()));
                    }

                    break;
                }

                case CertKeyId:
                    while (!sub.IsEmpty)
                    {
                        revocations.KeyIds.Add(Convert.ToHexString(sub.ReadString()));
                    }

                    break;

                case CertExtension:
                    SkipExtension(ref sub);
                    break;

                default:
                    throw new FormatException($"KRL certificate section type {type} is not supported.");
            }
        }

        revocations.Seal();
    }

    /// <summary>As krl.c: a range is lo &lt;= hi, and serial 0 cannot be revoked.</summary>
    private static void AddSerials(CertificateRevocations revocations, ulong low, ulong high)
    {
        Expect(low != 0 && low <= high, "A KRL revokes serial 0 or has an empty serial range.");
        revocations.Serials.Add((low, high));
    }

    /// <summary>An extension: <c>string name, bool critical, string data</c>. A critical one this library does not know makes the KRL unusable.</summary>
    private static void SkipExtension(ref KrlReader section)
    {
        var name = section.ReadUtf8String();
        var critical = section.ReadBoolean();
        section.ReadString();
        Expect(section.IsEmpty, "Trailing data in a KRL extension.");
        if (critical)
        {
            throw new FormatException($"The KRL has a critical extension '{name}' that is not supported.");
        }
    }

    private static void Expect(bool condition, string message)
    {
        if (!condition)
        {
            throw new FormatException(message);
        }
    }

    /// <summary>
    /// SSH wire encoding over a KRL: like <see cref="SshReader"/>, but strings are bounded only by the data (a KRL section with many keys is
    /// larger than any protocol message), and every malformation is a <see cref="FormatException"/>.
    /// </summary>
    private ref struct KrlReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _data = data;

        public readonly bool IsEmpty => _data.IsEmpty;

        public byte ReadByte() => Take(1)[0];

        public bool ReadBoolean() => ReadByte() != 0;

        public uint ReadUInt32() => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        public ulong ReadUInt64() => System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(Take(8));

        public ReadOnlySpan<byte> ReadString()
        {
            var length = ReadUInt32();
            return length > (uint)_data.Length ? throw new FormatException("A KRL field runs past the end of its section.") : Take((int)length);
        }

        public string ReadUtf8String()
        {
            var bytes = ReadString();
            return System.Text.Unicode.Utf8.IsValid(bytes) ? Encoding.UTF8.GetString(bytes) : throw new FormatException("A KRL name is not valid UTF-8.");
        }

        /// <summary>A non-negative mpint, without its leading zero byte.</summary>
        public ReadOnlySpan<byte> ReadMpint()
        {
            var bytes = ReadString();
            if (!bytes.IsEmpty && (bytes[0] & 0x80) != 0)
            {
                throw new FormatException("A KRL bitmap is negative.");
            }

            return bytes.TrimStart((byte)0);
        }

        private ReadOnlySpan<byte> Take(int count)
        {
            if (_data.Length < count)
            {
                throw new FormatException("The KRL is truncated.");
            }

            var taken = _data[..count];
            _data = _data[count..];
            return taken;
        }
    }
}
