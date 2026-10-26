using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>
/// Parsers for the replies to the file hash extensions (<c>check-file</c>, <c>md5-hash</c>) and to raw extended requests, and for
/// what a server announces about them. Every input comes from the server and is parsed as hostile: a malformed one is an
/// <see cref="SshProtocolException"/>.
/// </summary>
internal static class SftpExtensionReplies
{
    /// <summary>The most algorithm names taken from an announcement; a longer list is not one a real server sends.</summary>
    internal const int MaxAnnouncedAlgorithms = 32;

    /// <summary>The digest length of the algorithms draft-ietf-secsh-filexfer-extensions names for <c>check-file</c>; null for others.</summary>
    public static int? HashLength(string algorithm) => algorithm switch
    {
        "md5" => 16,
        "sha1" => 20,
        "sha224" => 28,
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        "crc32" => 4,
        _ => null,
    };

    /// <summary>
    /// The algorithms a server lists in the data of its <c>check-file</c> announcement (<c>md5,sha1,sha256</c>), or null when the data is
    /// not such a list: empty, a version number such as <c>1</c>, or anything with characters an algorithm name does not have.
    /// </summary>
    public static IReadOnlyList<string>? AnnouncedAlgorithms(string data)
    {
        var names = data.Split(',', StringSplitOptions.TrimEntries);
        if (names.Length > MaxAnnouncedAlgorithms)
        {
            return null;
        }

        foreach (var name in names)
        {
            if (!IsAlgorithmName(name))
            {
                return null;
            }
        }

        return names;
    }

    /// <summary>
    /// Whether <paramref name="name"/> can be an algorithm name: lower-case letters, digits, <c>-</c>, <c>.</c> and <c>@</c>, starting
    /// with a letter (so a version number is not one).
    /// </summary>
    public static bool IsAlgorithmName(string name)
    {
        if (name.Length is 0 or > 64 || name[0] is < 'a' or > 'z')
        {
            return false;
        }

        foreach (var c in name)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '.' or '@'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The reply to <c>check-file-name</c> or <c>check-file-handle</c> with a block size of 0 (one hash for the whole range):
    /// <c>string "check-file" || string algorithm || byte[] hash</c>, the hash being the rest of the packet; or, as ProFTPD's mod_sftp
    /// sends it, without the leading name: <c>string algorithm || byte[] hash</c>. The algorithm must be one of
    /// <paramref name="requested"/>, and a hash of an algorithm with a known digest length must have that length.
    /// </summary>
    public static (string Algorithm, byte[] Hash) ParseCheckFile(ref SshReader reader, IReadOnlyList<string> requested)
    {
        // A reply that does not start with the extension's name is read as ProFTPD's form, which starts with the algorithm. The checks
        // below still apply: anything else names an algorithm that was not asked for.
        var start = reader;
        if (!reader.ReadString().SequenceEqual("check-file"u8))
        {
            reader = start;
        }

        var used = reader.ReadUtf8String();
        string? algorithm = null;
        foreach (var name in requested)
        {
            if (string.Equals(name, used, StringComparison.OrdinalIgnoreCase))
            {
                algorithm = name;
                break;
            }
        }

        if (algorithm is null)
        {
            throw new SshProtocolException("The check-file reply names an algorithm that was not asked for.");
        }

        var hash = reader.Remaining;
        if (hash.IsEmpty || (HashLength(algorithm) is { } length && hash.Length != length))
        {
            throw new SshProtocolException($"The check-file reply has a {algorithm} hash of {hash.Length} bytes.");
        }

        return (algorithm, hash.ToArray());
    }

    /// <summary>
    /// The reply to <c>md5-hash</c> or <c>md5-hash-handle</c> sent without a quick-check hash: <c>string "md5-hash" || string hash</c>,
    /// a 16-byte MD5 digest.
    /// </summary>
    public static byte[] ParseMd5Hash(ref SshReader reader)
    {
        if (!reader.ReadString().SequenceEqual("md5-hash"u8))
        {
            throw new SshProtocolException("The md5-hash reply does not start with \"md5-hash\".");
        }

        var hash = reader.ReadString();
        if (hash.Length != 16)
        {
            throw new SshProtocolException($"The md5-hash reply has a hash of {hash.Length} bytes.");
        }

        return hash.ToArray();
    }

    /// <summary>A STATUS reply's body: the code and the message, which some servers leave out (then empty).</summary>
    public static (SftpStatusCode Status, string Message) ParseStatus(ref SshReader reader)
    {
        var status = (SftpStatusCode)reader.ReadUInt32();
        var message = reader.IsEmpty ? string.Empty : SftpChannel.Lenient(reader.ReadString());
        return (status, message);
    }
}
