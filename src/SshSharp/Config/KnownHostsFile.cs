using System.Text;

namespace SshSharp.Config;

/// <summary>The result of checking a presented host key against a <see cref="KnownHostsFile"/>.</summary>
public enum KnownHostsCheckResult
{
    /// <summary>No entry for this host and key type.</summary>
    Unknown,

    /// <summary>An entry for this host has exactly this key.</summary>
    Match,

    /// <summary>The host has an entry of the same key type with a different key (possible attack).</summary>
    Changed,

    /// <summary>The key is listed with <c>@revoked</c> for this host.</summary>
    Revoked,
}

/// <summary>
/// An OpenSSH <c>known_hosts</c> file. Comments, blank lines and unrecognized lines are preserved when the file is saved.
/// </summary>
public sealed class KnownHostsFile
{
    private readonly List<Line> _lines = [];

    /// <summary>Creates an empty file.</summary>
    public KnownHostsFile()
    {
    }

    /// <summary>The valid entries, in file order.</summary>
    public IReadOnlyList<KnownHostsEntry> Entries => [.. _lines.Where(l => l.Entry is not null).Select(l => l.Entry!)];

    /// <summary>The number of lines that could not be parsed (kept as-is).</summary>
    public int InvalidLineCount => _lines.Count(l => l.Entry is null && l.IsInvalid);

    /// <summary>Parses <c>known_hosts</c> text.</summary>
    public static KnownHostsFile Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var file = new KnownHostsFile();
        var content = text.Length > 0 && text[^1] == '\n' ? text[..^1] : text;
        if (text.Length == 0)
        {
            return file;
        }

        foreach (var raw in content.Split('\n'))
        {
            file._lines.Add(ParseLine(raw.TrimEnd('\r')));
        }

        return file;
    }

    /// <summary>Loads a file. A missing file gives an empty <see cref="KnownHostsFile"/>.</summary>
    public static async Task<KnownHostsFile> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path) ? Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false)) : new KnownHostsFile();
    }

    /// <summary>Loads a file. A missing file gives an empty <see cref="KnownHostsFile"/>.</summary>
    public static KnownHostsFile Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.Exists(path) ? Parse(File.ReadAllText(path)) : new KnownHostsFile();
    }

    /// <summary>Finds the entries that apply to a host and port.</summary>
    public IEnumerable<KnownHostsEntry> Find(string host, int port = 22) =>
        _lines.Where(l => l.Entry is not null && l.Entry.Matches(host, port)).Select(l => l.Entry!);

    /// <summary>Finds <c>@cert-authority</c> keys that apply to a host and port.</summary>
    public IEnumerable<KnownHostsEntry> FindCertificateAuthorities(string host, int port = 22) =>
        Find(host, port).Where(e => e.Marker == KnownHostsMarker.CertAuthority);

    /// <summary>Checks a presented host key. <c>@revoked</c> wins over everything; a matching key wins over a changed one.</summary>
    public KnownHostsCheckResult Check(string host, int port, string keyType, ReadOnlySpan<byte> publicKey)
    {
        var matched = false;
        var changed = false;
        foreach (var entry in Find(host, port))
        {
            if (entry.Marker == KnownHostsMarker.CertAuthority)
            {
                continue;
            }

            var sameKey = entry.KeyType == keyType && entry.PublicKey.Span.SequenceEqual(publicKey);
            if (entry.Marker == KnownHostsMarker.Revoked)
            {
                if (sameKey)
                {
                    return KnownHostsCheckResult.Revoked;
                }
            }
            else if (sameKey)
            {
                matched = true;
            }
            else if (entry.KeyType == keyType)
            {
                changed = true;
            }
        }

        return matched ? KnownHostsCheckResult.Match : changed ? KnownHostsCheckResult.Changed : KnownHostsCheckResult.Unknown;
    }

    /// <summary>Appends an entry for a host.</summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="keyType">The key type, for example <c>ssh-ed25519</c>.</param>
    /// <param name="publicKey">The public key blob.</param>
    /// <param name="hash">Whether to store the host hashed (<c>HashKnownHosts</c>).</param>
    /// <param name="comment">An optional comment.</param>
    /// <param name="marker">An optional marker.</param>
    public KnownHostsEntry Add(string host, int port, string keyType, ReadOnlySpan<byte> publicKey, bool hash = false,
        string? comment = null, KnownHostsMarker marker = KnownHostsMarker.None)
    {
        var field = hash ? KnownHostsEntry.HashHost(host, port) : KnownHostsEntry.FormatHost(host, port);
        var entry = new KnownHostsEntry(field, keyType, publicKey.ToArray(), marker, comment);
        _lines.Add(new Line(entry.ToLine(), entry, false));
        return entry;
    }

    /// <summary>
    /// Removes a host. A line that only names this host is dropped; on a line with several host patterns only the matching
    /// pattern is removed. Returns the number of entries changed or removed.
    /// </summary>
    public int Remove(string host, int port = 22)
    {
        var name = KnownHostsEntry.FormatHost(host, port);
        var count = 0;
        for (var i = _lines.Count - 1; i >= 0; i--)
        {
            var entry = _lines[i].Entry;
            if (entry is null || !entry.Matches(host, port))
            {
                continue;
            }

            count++;
            var remaining = entry.IsHashed
                ? []
                : entry.HostPatterns.Split(',').Where(p => !p.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (remaining.Length == 0 || remaining.Length == entry.HostPatterns.Split(',').Length)
            {
                _lines.RemoveAt(i);
            }
            else
            {
                var updated = entry.WithHostPatterns(string.Join(',', remaining));
                _lines[i] = new Line(updated.ToLine(), updated, false);
            }
        }

        return count;
    }

    /// <summary>Formats the file as text, with <c>\n</c> line endings.</summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        foreach (var line in _lines)
        {
            sb.Append(line.Raw).Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>Saves the file, replacing it atomically and creating the directory if needed.</summary>
    public async Task SaveAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var temp = PrepareTemp(path);
        try
        {
            await File.WriteAllTextAsync(temp, ToString(), cancellationToken).ConfigureAwait(false);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    /// <summary>Saves the file, replacing it atomically and creating the directory if needed.</summary>
    public void Save(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var temp = PrepareTemp(path);
        try
        {
            File.WriteAllText(temp, ToString());
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    private static string PrepareTemp(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
    }

    private static Line ParseLine(string raw)
    {
        var span = raw.AsSpan().Trim();
        if (span.IsEmpty || span[0] == '#')
        {
            return new Line(raw, null, false);
        }

        var fields = new List<string>(4);
        while (!span.IsEmpty && fields.Count < 4)
        {
            var end = span.IndexOfAny(' ', '\t');
            if (end < 0)
            {
                fields.Add(span.ToString());
                span = default;
                break;
            }

            fields.Add(span[..end].ToString());
            span = span[end..].TrimStart(" \t");
            if (fields.Count == 3)
            {
                break;
            }
        }

        var comment = span.IsEmpty ? null : span.ToString();
        var marker = KnownHostsMarker.None;
        if (fields.Count > 0 && fields[0].StartsWith('@'))
        {
            marker = fields[0] switch
            {
                "@cert-authority" => KnownHostsMarker.CertAuthority,
                "@revoked" => KnownHostsMarker.Revoked,
                _ => (KnownHostsMarker)(-1),
            };
            if (marker < 0)
            {
                return new Line(raw, null, true);
            }

            fields.RemoveAt(0);
            if (fields.Count < 3 && comment is not null)
            {
                // The comment was split off before the marker shifted the fields.
                var rest = comment.AsSpan();
                var end = rest.IndexOfAny(' ', '\t');
                fields.Add(end < 0 ? rest.ToString() : rest[..end].ToString());
                comment = end < 0 ? null : rest[end..].TrimStart(" \t").ToString();
                if (string.IsNullOrEmpty(comment))
                {
                    comment = null;
                }
            }
        }

        if (fields.Count < 3 || !TryDecode(fields[2], out var key))
        {
            return new Line(raw, null, true);
        }

        return new Line(raw, new KnownHostsEntry(fields[0], fields[1], key, marker, comment), false);
    }

    private static bool TryDecode(string base64, out byte[] key)
    {
        try
        {
            key = Convert.FromBase64String(base64);
            return key.Length > 0;
        }
        catch (FormatException)
        {
            key = [];
            return false;
        }
    }

    private readonly record struct Line(string Raw, KnownHostsEntry? Entry, bool IsInvalid);
}