using System.Globalization;

namespace SshSharp.Config;

/// <summary>Where a forwarding listens: an optional bind address (<c>localhost</c>, <c>*</c>, an address) and a port.</summary>
internal readonly record struct ForwardListen(string? Bind, int Port);

/// <summary>Where a forwarding connects: a host and port.</summary>
internal readonly record struct ForwardTarget(string Host, int Port);

/// <summary>A <c>PermitRemoteOpen</c> entry: a host (<c>*</c> for any) and a port (null for any).</summary>
internal readonly record struct PermitOpen(string Host, int? Port);

/// <summary>
/// Parses the <c>LocalForward</c>, <c>RemoteForward</c> and <c>DynamicForward</c> arguments of ssh_config: <c>[bind_address:]port</c>
/// (an IPv6 bind address in brackets) and <c>host:hostport</c>. Unix-socket forms (a path) are not supported and parse as null.
/// </summary>
internal static class ForwardSpec
{
    /// <summary>A LocalForward or RemoteForward value: the listen part and the target, or null when it is not a TCP forwarding.</summary>
    public static (ForwardListen Listen, ForwardTarget Target)? ParseForward(string value)
    {
        var parts = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || ParseListen(parts[0]) is not { } listen || ParseTarget(parts[1]) is not { } target)
        {
            return null;
        }

        return (listen, target);
    }

    /// <summary><c>[bind_address:]port</c>, or null when it is not one (a socket path, a bad port).</summary>
    public static ForwardListen? ParseListen(string text)
    {
        text = text.Trim();
        if (text.Length == 0 || text[0] == '/')
        {
            return null;
        }

        string? bind = null;
        string port;
        if (text[0] == '[')
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);

            // Stryker disable once Equality : text[0] is '[', so ']' is never at 0
            if (close < 0 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return null;
            }

            bind = text[1..close];
            port = text[(close + 2)..];
        }
        else if (text.LastIndexOf(':') is var colon and >= 0)
        {
            bind = text[..colon];
            port = text[(colon + 1)..];
        }
        else
        {
            port = text;
        }

        return TryPort(port, allowZero: true) is { } number ? new ForwardListen(bind, number) : null;
    }

    /// <summary><c>host:hostport</c> (an IPv6 host in brackets), or null when it is not one (a socket path, a bad port).</summary>
    public static ForwardTarget? ParseTarget(string text)
    {
        text = text.Trim();
        if (text.Length == 0 || text[0] == '/')
        {
            return null;
        }

        string host;
        string port;
        if (text[0] == '[')
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 2 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return null; // no port, or no host in the brackets
            }

            host = text[1..close];
            port = text[(close + 2)..];
        }
        else if (text.LastIndexOf(':') is var colon and > 0)
        {
            host = text[..colon];
            port = text[(colon + 1)..];
        }
        else
        {
            return null;
        }

        return TryPort(port, allowZero: false) is { } number && !host.Any(char.IsControl) ? new ForwardTarget(host, number) : null;
    }

    /// <summary>
    /// <c>PermitRemoteOpen</c>'s arguments: null for none given or <c>any</c> (everything allowed), empty for <c>none</c>, otherwise the
    /// entries that parse (see <see cref="ParsePermitOpen"/>). <c>any</c> and <c>none</c> count only alone, as ssh refuses them among
    /// other entries; here they are left out like any entry that does not parse, which allows less, never more.
    /// </summary>
    public static IReadOnlyList<string>? ParsePermitRemoteOpen(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0 || (arguments.Count == 1 && arguments[0].Equals("any", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        return [.. arguments.Where(a => ParsePermitOpen(a) is not null)];
    }

    /// <summary>
    /// One <c>PermitRemoteOpen</c> entry: <c>host:port</c>, <c>[ipv6]:port</c>, with <c>*</c> for any host or any port (a null
    /// <see cref="PermitOpen.Port"/>). Null when it is not one: an IPv6 address must be in brackets, as ssh splits at the first colon.
    /// </summary>
    public static PermitOpen? ParsePermitOpen(string text)
    {
        string host;
        string port;
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 2 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return null;
            }

            host = text[1..close];
            port = text[(close + 2)..];
        }
        else
        {
            var colon = text.IndexOf(':', StringComparison.Ordinal);
            if (colon < 1)
            {
                return null;
            }

            host = text[..colon];
            port = text[(colon + 1)..];
        }

        if (host.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
        {
            return null;
        }

        return port == "*" ? new PermitOpen(host, null)
            : TryPort(port, allowZero: false) is { } number ? new PermitOpen(host, number)
            : null;
    }

    /// <summary>
    /// The destination filter for <c>PermitRemoteOpen</c> entries: a host and port are allowed when an entry names both (or <c>*</c>).
    /// As in ssh, there is no pattern matching beyond a whole <c>*</c>: a name matches the same name (ignoring case, as DNS does), an
    /// address the same address in any spelling.
    /// </summary>
    public static Func<string, int, bool> PermitOpenFilter(IReadOnlyList<string> entries)
    {
        var permits = entries.Select(ParsePermitOpen).OfType<PermitOpen>().ToArray();
        return (host, port) => permits.Any(p => (p.Port is null || p.Port == port) && HostMatches(p.Host, host));
    }

    private static bool HostMatches(string permitted, string requested)
    {
        if (permitted == "*")
        {
            return true;
        }

        var permittedAddress = SshRemotePortForwarder.ParseAddressLiteral(permitted);
        var requestedAddress = SshRemotePortForwarder.ParseAddressLiteral(requested);

        // Stryker disable once Logical : when only one is an address, the texts differ (equal texts parse alike), so comparing them is false too
        if (permittedAddress is not null || requestedAddress is not null)
        {
            return permittedAddress is not null && permittedAddress.Equals(requestedAddress);
        }

        return permitted.Equals(requested, StringComparison.OrdinalIgnoreCase);
    }

    private static int? TryPort(string text, bool allowZero) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port <= 65535 && (port > 0 || allowZero) ? port : null;
}
