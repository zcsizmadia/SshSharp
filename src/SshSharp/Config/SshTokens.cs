using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp.Config;

/// <summary>Values for the <c>%</c> tokens and <c>~</c>/<c>${VAR}</c> expansion in <c>ssh_config</c> values.</summary>
internal sealed record SshTokenContext(
    string OriginalHost,
    string Host,
    int Port,
    string RemoteUser,
    string LocalUser,
    string HomeDirectory,
    string LocalHostName,
    Func<string, string?> GetEnvironmentVariable)
{
    /// <summary>Expands <c>%h %n %p %r %u %d %l %L %C %%</c>. An unknown token throws <see cref="FormatException"/>.</summary>
    public string ExpandTokens(string value)
    {
        if (!value.Contains('%', StringComparison.Ordinal))
        {
            return value;
        }

        var sb = new StringBuilder(value.Length + 16);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '%')
            {
                sb.Append(value[i]);
                continue;
            }

            if (++i >= value.Length)
            {
                throw new FormatException($"Trailing '%' in '{value}'.");
            }

            sb.Append(value[i] switch
            {
                '%' => "%",
                'h' => Host,
                'n' => OriginalHost,
                'p' => Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                'r' => RemoteUser,
                'u' => LocalUser,
                'd' => HomeDirectory,
                'l' => LocalHostName,
                'L' => ShortLocalHostName(),
                'C' => ConnectionHash(),
                _ => throw new FormatException($"Unknown token '%{value[i]}' in '{value}'."),
            });
        }

        return sb.ToString();
    }

    /// <summary>Expands a leading <c>~</c> and <c>${VAR}</c> references (an unset variable throws <see cref="FormatException"/>).</summary>
    public string ExpandPath(string value)
    {
        var path = value;
        if (path == "~")
        {
            path = HomeDirectory;
        }
        else if (path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
        {
            path = HomeDirectory + path[1..];
        }

        if (!path.Contains("${", StringComparison.Ordinal))
        {
            return path;
        }

        var sb = new StringBuilder();
        for (var i = 0; i < path.Length; i++)
        {
            if (path[i] == '$' && i + 1 < path.Length && path[i + 1] == '{')
            {
                var close = path.IndexOf('}', i + 2);
                if (close < 0)
                {
                    throw new FormatException($"Unterminated '${{' in '{value}'.");
                }

                var name = path[(i + 2)..close];
                sb.Append(GetEnvironmentVariable(name) ?? throw new FormatException($"Environment variable '{name}' is not set."));
                i = close;
            }
            else
            {
                sb.Append(path[i]);
            }
        }

        return sb.ToString();
    }

    private string ShortLocalHostName()
    {
        var dot = LocalHostName.IndexOf('.', StringComparison.Ordinal);
        return dot < 0 ? LocalHostName : LocalHostName[..dot];
    }

    [SuppressMessage("Security", "CA5350", Justification = "SHA-1 is how OpenSSH defines the %C token; it is a file-name hash, not a security control.")]
    private string ConnectionHash()
    {
        var data = Encoding.UTF8.GetBytes(LocalHostName + Host + Port.ToString(System.Globalization.CultureInfo.InvariantCulture) + RemoteUser);
        return Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();
    }
}