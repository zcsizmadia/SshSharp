using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp.Config;

/// <summary>The optional marker in front of a <c>known_hosts</c> line.</summary>
public enum KnownHostsMarker
{
    /// <summary>A plain host key.</summary>
    None,

    /// <summary><c>@cert-authority</c>: the key is a certificate authority trusted for the matching hosts.</summary>
    CertAuthority,

    /// <summary><c>@revoked</c>: the key must never be accepted for the matching hosts.</summary>
    Revoked,
}

/// <summary>One parsed <c>known_hosts</c> line.</summary>
public sealed class KnownHostsEntry
{
    private const string HashPrefix = "|1|";

    private static readonly System.Buffers.SearchValues<char> PatternCharacters = System.Buffers.SearchValues.Create(",*?!");

    /// <summary>Refuses a host field that would add fields or lines to known_hosts (white space, a newline, control characters).</summary>
    internal static void RequireSingleField(string host)
    {
        if (host.Any(char.IsWhiteSpace) || host.Any(char.IsControl))
        {
            throw new ArgumentException("A known_hosts host must not contain white space or control characters.", nameof(host));
        }
    }

    /// <summary>
    /// Whether a host name would be recorded as exactly that host: besides what <see cref="RequireSingleField"/> refuses, a comma would add
    /// another host, and <c>*</c>, <c>?</c> or <c>!</c> would make it a pattern that trusts the key for other hosts too.
    /// </summary>
    internal static bool IsLiteralHost(string host) =>
        !host.Any(char.IsWhiteSpace) && !host.Any(char.IsControl) && host.AsSpan().IndexOfAny(PatternCharacters) < 0;

    /// <summary>Creates an entry.</summary>
    /// <param name="hostPatterns">Comma-separated host patterns, or a single hashed host (<c>|1|salt|hash</c>).</param>
    /// <param name="keyType">The key type, for example <c>ssh-ed25519</c>.</param>
    /// <param name="publicKey">The public key blob (the decoded base64 field).</param>
    /// <param name="marker">The optional marker.</param>
    /// <param name="comment">The optional trailing comment.</param>
    public KnownHostsEntry(string hostPatterns, string keyType, ReadOnlyMemory<byte> publicKey,
        KnownHostsMarker marker = KnownHostsMarker.None, string? comment = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostPatterns);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyType);
        HostPatterns = hostPatterns;
        KeyType = keyType;
        PublicKey = publicKey;
        Marker = marker;
        Comment = comment;
    }

    /// <summary>The marker (<c>@cert-authority</c>, <c>@revoked</c>) or <see cref="KnownHostsMarker.None"/>.</summary>
    public KnownHostsMarker Marker { get; }

    /// <summary>The raw host field: comma-separated patterns, or a single hashed host.</summary>
    public string HostPatterns { get; }

    /// <summary>The key type, for example <c>ssh-ed25519</c>.</summary>
    public string KeyType { get; }

    /// <summary>The public key blob.</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The trailing comment, if any.</summary>
    public string? Comment { get; }

    /// <summary><see cref="PublicKey"/> as an <see cref="SshPublicKey"/>, with the entry's <see cref="Comment"/>.</summary>
    /// <exception cref="FormatException">The key is malformed, of a type <see cref="SshPublicKey"/> does not read, or not of the entry's
    /// <see cref="KeyType"/>.</exception>
    public SshPublicKey GetPublicKey()
    {
        var key = SshPublicKey.Read(PublicKey.Span, Comment);
        return key.KeyType == KeyType ? key : throw new FormatException("The entry's key type does not match its key.");
    }

    /// <summary>Whether the host field is hashed (<c>|1|salt|hash</c>).</summary>
    public bool IsHashed => HostPatterns.StartsWith(HashPrefix, StringComparison.Ordinal);

    /// <summary>Formats a host and port the way <c>known_hosts</c> stores them: <c>host</c>, or <c>[host]:port</c> for non-22 ports.</summary>
    public static string FormatHost(string host, int port)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        return port == 22 ? host.ToLowerInvariant() : $"[{host.ToLowerInvariant()}]:{port}";
    }

    /// <summary>Creates a hashed host field (<c>|1|salt|hash</c>) for a host and port.</summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="salt">The 20-byte salt; random when omitted.</param>
    [SuppressMessage("Security", "CA5350", Justification = "HMAC-SHA1 is mandated by the OpenSSH hashed known_hosts format; it is not used for security of the connection.")]
    public static string HashHost(string host, int port, ReadOnlySpan<byte> salt = default)
    {
        Span<byte> salt20 = stackalloc byte[HMACSHA1.HashSizeInBytes];
        if (salt.IsEmpty)
        {
            RandomNumberGenerator.Fill(salt20);
        }
        else if (salt.Length != salt20.Length)
        {
            throw new ArgumentException("The salt must be 20 bytes.", nameof(salt));
        }
        else
        {
            salt.CopyTo(salt20);
        }

        Span<byte> hash = stackalloc byte[HMACSHA1.HashSizeInBytes];
        HMACSHA1.HashData(salt20, Encoding.UTF8.GetBytes(FormatHost(host, port)), hash);
        return $"{HashPrefix}{Convert.ToBase64String(salt20)}|{Convert.ToBase64String(hash)}";
    }

    /// <summary>Whether this entry applies to a host and port.</summary>
    public bool Matches(string host, int port = 22)
    {
        var name = FormatHost(host, port);
        if (IsHashed)
        {
            return MatchesHashed(HostPatterns, name);
        }

        return Glob.IsMatchList(HostPatterns, name);
    }

    /// <summary>Returns a copy with different host patterns.</summary>
    internal KnownHostsEntry WithHostPatterns(string hostPatterns) => new(hostPatterns, KeyType, PublicKey, Marker, Comment);

    /// <summary>Formats the entry as a <c>known_hosts</c> line (no line terminator).</summary>
    public string ToLine()
    {
        var sb = new StringBuilder();
        if (Marker == KnownHostsMarker.CertAuthority)
        {
            sb.Append("@cert-authority ");
        }
        else if (Marker == KnownHostsMarker.Revoked)
        {
            sb.Append("@revoked ");
        }

        sb.Append(HostPatterns).Append(' ').Append(KeyType).Append(' ').Append(Convert.ToBase64String(PublicKey.Span));
        if (!string.IsNullOrEmpty(Comment))
        {
            sb.Append(' ').Append(Comment);
        }

        return sb.ToString();
    }

    [SuppressMessage("Security", "CA5350", Justification = "HMAC-SHA1 is mandated by the OpenSSH hashed known_hosts format; it is not used for security of the connection.")]
    private static bool MatchesHashed(string field, string name)
    {
        // |1|<base64 salt>|<base64 hash>
        var parts = field.Split('|');
        if (parts.Length != 4 || parts[1] != "1")
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            Span<byte> actual = stackalloc byte[HMACSHA1.HashSizeInBytes];
            HMACSHA1.HashData(salt, Encoding.UTF8.GetBytes(name), actual);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}