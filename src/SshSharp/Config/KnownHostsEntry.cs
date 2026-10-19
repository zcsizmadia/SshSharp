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
    internal static void RequireSingleField(string host) => RequireField(host, nameof(host));

    /// <summary>Refuses a field (host patterns, a key type) that would add fields or lines to known_hosts.</summary>
    private static void RequireField(string field, string parameterName)
    {
        if (field.Any(char.IsWhiteSpace) || field.Any(char.IsControl))
        {
            throw new ArgumentException("A known_hosts field must not contain white space or control characters.", parameterName);
        }
    }

    /// <summary>
    /// Refuses a comment that would end the line (CR, LF) or carries other control characters. Spaces and tabs are allowed: the comment
    /// is the rest of the line, and OpenSSH keeps them in it.
    /// </summary>
    private static void RequireComment(string? comment)
    {
        if (comment is not null && comment.Any(c => char.IsControl(c) && c != '\t'))
        {
            throw new ArgumentException("A known_hosts comment must not contain control characters other than a tab.", nameof(comment));
        }
    }

    /// <summary>Creates an entry from a parsed line's fields, as they are (see the private constructor).</summary>
    internal static KnownHostsEntry FromParsedFields(string hostPatterns, string keyType, ReadOnlyMemory<byte> publicKey,
        KnownHostsMarker marker, string? comment) => new(hostPatterns, keyType, publicKey, marker, comment, validate: false);

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
    /// <exception cref="ArgumentException"><paramref name="hostPatterns"/> or <paramref name="keyType"/> is empty or contains white space or
    /// control characters, or <paramref name="comment"/> contains control characters other than a tab. Any of them would let
    /// <see cref="ToLine"/> write extra fields or extra lines (a <c>@cert-authority</c> line, say) into <c>known_hosts</c>.</exception>
    public KnownHostsEntry(string hostPatterns, string keyType, ReadOnlyMemory<byte> publicKey,
        KnownHostsMarker marker = KnownHostsMarker.None, string? comment = null)
        : this(hostPatterns, keyType, publicKey, marker, comment, validate: true)
    {
    }

    /// <summary>
    /// Creates an entry. The parser passes <paramref name="validate"/> false: its fields come from one line already split at spaces and
    /// tabs, so they cannot add a line, and an odd character in a file being read must not make the file unreadable.
    /// </summary>
    private KnownHostsEntry(string hostPatterns, string keyType, ReadOnlyMemory<byte> publicKey, KnownHostsMarker marker, string? comment,
        bool validate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostPatterns);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyType);
        if (validate)
        {
            RequireField(hostPatterns, nameof(hostPatterns));
            RequireField(keyType, nameof(keyType));
            RequireComment(comment);
        }

        HostPatterns = hostPatterns;
        KeyType = keyType;
        PublicKey = publicKey;
        Marker = marker;
        Comment = comment;
    }

    /// <summary>Creates an entry for <paramref name="key"/>, with its type and blob. The key's own <see cref="SshPublicKey.Comment"/> is not used.</summary>
    /// <param name="hostPatterns">Comma-separated host patterns, or a single hashed host (<see cref="HashHost"/>).</param>
    /// <param name="key">The key.</param>
    /// <param name="marker">The optional marker.</param>
    /// <param name="comment">The optional trailing comment.</param>
    public KnownHostsEntry(string hostPatterns, SshPublicKey key, KnownHostsMarker marker = KnownHostsMarker.None, string? comment = null)
        : this(hostPatterns, (key ?? throw new ArgumentNullException(nameof(key))).KeyType, key.Blob, marker, comment)
    {
    }

    /// <summary>
    /// Creates the entry <c>ssh</c> writes for one host's key: the host as <see cref="FormatHost"/> stores it (<c>[host]:port</c> for a
    /// port other than 22), or hashed (<see cref="HashHost"/>, with a random salt) as with <c>HashKnownHosts yes</c>.
    /// <see cref="KnownHostsFile.Add(string, int, SshPublicKey, bool, string?, KnownHostsMarker)"/> and
    /// <see cref="KnownHostsFile.AppendAsync(string, string, int, SshPublicKey, bool, string?, KnownHostsMarker, CancellationToken)"/>
    /// write the same.
    /// </summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="key">The host's key. Its own comment is not used.</param>
    /// <param name="hash">Whether to store the host hashed.</param>
    /// <param name="comment">An optional comment.</param>
    /// <param name="marker">An optional marker.</param>
    /// <exception cref="ArgumentException"><paramref name="host"/> contains white space or control characters, or <paramref name="comment"/>
    /// contains control characters other than a tab.</exception>
    public static KnownHostsEntry ForHost(string host, int port, SshPublicKey key, bool hash = false, string? comment = null,
        KnownHostsMarker marker = KnownHostsMarker.None)
    {
        ArgumentNullException.ThrowIfNull(key);
        return ForHost(host, port, key.KeyType, key.Blob, hash, comment, marker);
    }

    /// <summary>
    /// The entry for one host's key, as <see cref="ForHost(string, int, SshPublicKey, bool, string?, KnownHostsMarker)"/>. The entry keeps
    /// <paramref name="publicKey"/> as it is: the caller passes memory nothing else changes.
    /// </summary>
    internal static KnownHostsEntry ForHost(string host, int port, string keyType, ReadOnlyMemory<byte> publicKey, bool hash, string? comment,
        KnownHostsMarker marker)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        RequireSingleField(host);
        var field = hash ? HashHost(host, port) : FormatHost(host, port);
        return new KnownHostsEntry(field, keyType, publicKey, marker, comment);
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
    internal KnownHostsEntry WithHostPatterns(string hostPatterns) => new(hostPatterns, KeyType, PublicKey, Marker, Comment, validate: false);

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