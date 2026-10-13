using System.Globalization;

namespace SshSharp.Config;

/// <summary>Where a forwarding listens: an optional bind address (<c>localhost</c>, <c>*</c>, an address) and a port.</summary>
internal readonly record struct ForwardListen(string? Bind, int Port);

/// <summary>Where a forwarding connects: a host and port.</summary>
internal readonly record struct ForwardTarget(string Host, int Port);

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
            if (close < 1 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return null;
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

    private static int? TryPort(string text, bool allowZero) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port <= 65535 && (port > 0 || allowZero) ? port : null;
}
