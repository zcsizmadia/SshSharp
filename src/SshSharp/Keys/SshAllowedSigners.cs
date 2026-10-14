using System.Globalization;
using SshSharp.Config;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// An allowed-signers file (ssh-keygen's ALLOWED SIGNERS format, git's <c>gpg.ssh.allowedSignersFile</c>): which keys may sign as which
/// principals, for <see cref="SshSignature"/> verification as <c>ssh-keygen -Y verify</c> and <c>-Y find-principals</c> do.
/// </summary>
/// <remarks>
/// Each line is <c>principals [options] keytype base64 [comment]</c>. The principals are a comma-separated list of patterns
/// (<c>*</c>, <c>?</c>, <c>!</c> to exclude; case-sensitive). The options are <c>cert-authority</c> (the key is a certificate authority, and
/// a signature by any user certificate it issued for the principal is accepted), <c>namespaces="git,file"</c> (patterns, too), and
/// <c>valid-after</c> / <c>valid-before</c> (<c>YYYYMMDD[HHMM[SS]]</c>, with a trailing <c>Z</c> for UTC, otherwise local time).
/// </remarks>
public sealed class SshAllowedSigners
{
    private readonly List<Entry> _entries;

    private SshAllowedSigners(List<Entry> entries) => _entries = entries;

    /// <summary>How many signers (lines) the file has.</summary>
    public int Count => _entries.Count;

    /// <summary>Parses an allowed-signers file's contents; blank lines and lines starting with <c>#</c> are skipped.</summary>
    /// <exception cref="FormatException">A line is malformed, or has an option this library does not know. As in ssh-keygen, one bad line
    /// rejects the file rather than being skipped.</exception>
    public static SshAllowedSigners Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var entries = new List<Entry>();
        var number = 0;
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            try
            {
                entries.Add(ParseLine(line));
            }
            catch (FormatException ex)
            {
                throw new FormatException($"Allowed signers line {number}: {ex.Message}", ex);
            }
        }

        return new SshAllowedSigners(entries);
    }

    /// <summary>Reads and parses an allowed-signers file.</summary>
    /// <inheritdoc cref="Parse" path="/exception"/>
    public static async Task<SshAllowedSigners> LoadFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Parse(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>
    /// Whether <paramref name="signature"/> is a valid signature over <paramref name="message"/>, for <paramref name="namespace"/>, by a key
    /// this file allows to sign as <paramref name="principal"/> at <paramref name="time"/> (now by default), as
    /// <c>ssh-keygen -Y verify -I principal -n namespace</c> checks.
    /// </summary>
    public bool Verify(SshSignature signature, string principal, ReadOnlySpan<byte> message, string @namespace, DateTimeOffset? time = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(@namespace);
        return IsAllowed(signature, principal, @namespace, time ?? DateTimeOffset.UtcNow)
            && signature.VerifyHash(SshSignature.Hash(signature.HashAlgorithm, message), @namespace);
    }

    /// <summary>Like <see cref="Verify"/>, over what <paramref name="message"/> reads to its end.</summary>
    public async Task<bool> VerifyAsync(SshSignature signature, string principal, Stream message, string @namespace, DateTimeOffset? time = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(@namespace);
        if (!IsAllowed(signature, principal, @namespace, time ?? DateTimeOffset.UtcNow))
        {
            return false;
        }

        var digest = await SshSignature.HashAsync(signature.HashAlgorithm, message, cancellationToken).ConfigureAwait(false);
        return signature.VerifyHash(digest, @namespace);
    }

    /// <summary>
    /// The principals this file allows the signature's key to sign as, at <paramref name="time"/> (now by default), as
    /// <c>ssh-keygen -Y find-principals</c> prints them: a line's principal patterns for a plain key, and for a certificate, its principals
    /// that a <c>cert-authority</c> line for its authority allows. It does not check the signature itself.
    /// </summary>
    public IReadOnlyList<string> FindPrincipals(SshSignature signature, DateTimeOffset? time = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        var at = time ?? DateTimeOffset.UtcNow;
        var found = new List<string>();
        foreach (var entry in _entries)
        {
            if (!entry.IsValidAt(at))
            {
                continue;
            }

            if (entry.CertificateAuthority)
            {
                if (UsableCertificate(signature, entry, at) is { } certificate)
                {
                    found.AddRange(certificate.Principals.Where(p => Glob.IsMatchList(entry.Principals, p, ignoreCase: false)));
                }
            }
            else if (signature.PublicKey.Span.SequenceEqual(entry.Key))
            {
                found.AddRange(entry.Principals.Split(',', StringSplitOptions.RemoveEmptyEntries));
            }
        }

        return found.Distinct(StringComparer.Ordinal).ToList();
    }

    private bool IsAllowed(SshSignature signature, string principal, string @namespace, DateTimeOffset at)
    {
        foreach (var entry in _entries)
        {
            if (!entry.IsValidAt(at) || !Glob.IsMatchList(entry.Principals, principal, ignoreCase: false)
                || (entry.Namespaces is { } namespaces && !Glob.IsMatchList(namespaces, @namespace, ignoreCase: false)))
            {
                continue;
            }

            if (entry.CertificateAuthority
                ? UsableCertificate(signature, entry, at) is { } certificate && certificate.Principals.Contains(principal, StringComparer.Ordinal)
                : signature.PublicKey.Span.SequenceEqual(entry.Key))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The signature's user certificate when <paramref name="entry"/>'s authority issued it, its signature holds and it is valid at the time.</summary>
    private static SshCertificate? UsableCertificate(SshSignature signature, Entry entry, DateTimeOffset at) =>
        signature.Certificate is { Type: SshCertificateType.User } certificate
            && certificate.AuthorityKey.Span.SequenceEqual(entry.Key)
            && at >= certificate.ValidAfter && at < certificate.ValidBefore
            && certificate.HasValidAuthoritySignature()
            ? certificate
            : null;

    private static Entry ParseLine(string line)
    {
        var rest = line.AsSpan();
        var principals = Unquote(NextField(ref rest));
        if (principals.Length == 0)
        {
            throw new FormatException("missing principals.");
        }

        // Options come before the key type when the next field is not a key type.
        var field = NextField(ref rest);
        bool certificateAuthority = false;
        string? namespaces = null;
        DateTimeOffset? validAfter = null, validBefore = null;
        if (!LooksLikeKeyType(field))
        {
            foreach (var option in SplitOptions(field))
            {
                var equals = option.IndexOf('=');
                var name = (equals < 0 ? option : option[..equals]).ToLowerInvariant();
                var value = equals < 0 ? null : Unquote(option[(equals + 1)..]);
                switch (name)
                {
                    case "cert-authority" when value is null:
                        certificateAuthority = true;
                        break;
                    case "namespaces" when value is not null:
                        namespaces = value;
                        break;
                    case "valid-after" when value is not null:
                        validAfter = ParseTime(value);
                        break;
                    case "valid-before" when value is not null:
                        validBefore = ParseTime(value);
                        break;
                    default:
                        throw new FormatException($"unknown or malformed option '{option}'.");
                }
            }

            field = NextField(ref rest);
        }

        var keyType = field;
        var base64 = NextField(ref rest);
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
            if (keyType.Length == 0 || new SshReader(key).ReadUtf8String() != keyType)
            {
                throw new FormatException("the key's type does not match its type field.");
            }
        }
        catch (Exception ex) when (ex is FormatException or SshProtocolException)
        {
            throw new FormatException($"the key is malformed: {ex.Message}", ex);
        }

        return new Entry(principals, certificateAuthority, namespaces, validAfter, validBefore, key);
    }

    private static bool LooksLikeKeyType(string field) =>
        field.StartsWith("ssh-", StringComparison.Ordinal) || field.StartsWith("ecdsa-", StringComparison.Ordinal)
        || field.StartsWith("sk-", StringComparison.Ordinal);

    /// <summary>The next whitespace-separated field, as written: double quotes group spaces (and are kept, for the caller to remove).</summary>
    private static string NextField(ref ReadOnlySpan<char> rest)
    {
        rest = rest.TrimStart();
        var inQuotes = false;
        var i = 0;
        for (; i < rest.Length && (inQuotes || !char.IsWhiteSpace(rest[i])); i++)
        {
            if (rest[i] == '"')
            {
                inQuotes = !inQuotes;
            }
        }

        if (inQuotes)
        {
            throw new FormatException("an unterminated quote.");
        }

        var field = rest[..i].ToString();
        rest = rest[i..];
        return field;
    }

    /// <summary>Splits an option list on commas outside double quotes.</summary>
    private static IEnumerable<string> SplitOptions(string options)
    {
        var start = 0;
        var inQuotes = false;
        for (var i = 0; i <= options.Length; i++)
        {
            if (i < options.Length && options[i] == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (i == options.Length || (options[i] == ',' && !inQuotes))
            {
                if (i > start)
                {
                    yield return options[start..i];
                }

                start = i + 1;
            }
        }
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && value[0] == '"' && value[^1] == '"' ? value[1..^1] : value;

    /// <summary>YYYYMMDD, YYYYMMDDHHMM or YYYYMMDDHHMMSS, with a trailing Z for UTC (otherwise local time), as ssh-keygen reads it.</summary>
    private static DateTimeOffset ParseTime(string value)
    {
        var utc = value.EndsWith('Z') || value.EndsWith('z');
        var digits = utc ? value[..^1] : value;
        var format = digits.Length switch
        {
            8 => "yyyyMMdd",
            12 => "yyyyMMddHHmm",
            14 => "yyyyMMddHHmmss",
            _ => throw new FormatException($"the time '{value}' is not YYYYMMDD[HHMM[SS]][Z]."),
        };
        if (!DateTime.TryParseExact(digits, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
        {
            throw new FormatException($"the time '{value}' is not a valid date.");
        }

        return utc ? new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)) : new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Local));
    }

    private sealed record Entry(string Principals, bool CertificateAuthority, string? Namespaces, DateTimeOffset? ValidAfter, DateTimeOffset? ValidBefore,
        byte[] Key)
    {
        public bool IsValidAt(DateTimeOffset at) => (ValidAfter is not { } after || at >= after) && (ValidBefore is not { } before || at <= before);
    }
}
