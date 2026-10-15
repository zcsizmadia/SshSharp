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
    /// <summary>The <c>HostKeyAlias</c>, if set (<c>%k</c> falls back to the host name).</summary>
    public string? HostKeyAlias { get; init; }

    /// <summary>The <c>ProxyJump</c> value, or empty (<c>%j</c>).</summary>
    public string ProxyJump { get; init; } = string.Empty;

    /// <summary>Tokens only some keywords have (<c>KnownHostsCommand</c>'s <c>%H %I %K %f %t</c>), by letter.</summary>
    public IReadOnlyDictionary<char, string>? Extra { get; init; }

    /// <summary>
    /// Expands <c>%h %n %p %r %u %d %l %L %C %k %j %i %T %%</c>. An unknown token throws <see cref="FormatException"/>, as in OpenSSH.
    /// </summary>
    public string ExpandTokens(string value) => Expand(value, variables: false);

    /// <summary>
    /// Expands <c>${VAR}</c> and the <c>%</c> tokens in one pass, as OpenSSH's percent_dollar_expand does for <c>KnownHostsCommand</c>
    /// arguments: a variable's value is inserted as it is, not expanded again. An unset or empty-named variable throws
    /// <see cref="FormatException"/>, as do unknown tokens.
    /// </summary>
    public string ExpandTokensAndVariables(string value) => Expand(value, variables: true);

    private string Expand(string value, bool variables)
    {
        if (!value.Contains('%', StringComparison.Ordinal) && !(variables && value.Contains("${", StringComparison.Ordinal)))
        {
            return value;
        }

        var sb = new StringBuilder(value.Length + 16);
        for (var i = 0; i < value.Length; i++)
        {
            if (variables && value[i] == '$' && i + 1 < value.Length && value[i + 1] == '{')
            {
                var close = value.IndexOf('}', i + 2);
                if (close < 0)
                {
                    throw new FormatException($"Unterminated '${{' in '{value}'.");
                }

                var name = value[(i + 2)..close];
                if (name.Length == 0)
                {
                    throw new FormatException($"An empty '${{}}' in '{value}'.");
                }

                sb.Append(GetEnvironmentVariable(name) ?? throw new FormatException($"Environment variable '{name}' is not set."));
                i = close;
                continue;
            }

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
                'k' => HostKeyAlias ?? Host,
                'j' => ProxyJump,
                'i' => LocalUserId(),
                'T' => "NONE", // no tun device is ever opened
                var other when Extra is not null && Extra.TryGetValue(other, out var extra) => extra,
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

    /// <summary>OpenSSH's <c>%C</c>: SHA-1 of <c>%l%h%p%r%j</c> (an empty <c>%j</c> gives the pre-9.x value).</summary>
    [SuppressMessage("Security", "CA5350", Justification = "SHA-1 is how OpenSSH defines the %C token; it is a file-name hash, not a security control.")]
    private string ConnectionHash()
    {
        var data = Encoding.UTF8.GetBytes(LocalHostName + Host + Port.ToString(System.Globalization.CultureInfo.InvariantCulture) + RemoteUser + ProxyJump);
        return Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();
    }

    private static string LocalUserId() => OperatingSystem.IsWindows()
        ? throw new FormatException("The %i token (local user id) is not available on Windows.")
        : NativeMethods.GetUid().ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "getuid")]
        [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.SafeDirectories)]
        public static extern uint GetUid();
    }
}