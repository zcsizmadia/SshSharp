using System.Reflection;

namespace SshSharp;

/// <summary>Build and identification information about the library.</summary>
public static class SshSharpInfo
{
    /// <summary>The SSH software version string sent during version exchange (RFC 4253 section 4.2).</summary>
    public static string SoftwareVersion { get; } = ForIdentification($"SshSharp_{LibraryVersion()}");

    /// <summary>
    /// RFC 4253 section 4.2: the software version is printable US-ASCII without spaces or '-', so a prerelease version such as
    /// <c>1.0.0-preview.1</c> becomes <c>1.0.0_preview.1</c>.
    /// </summary>
    internal static string ForIdentification(string version) =>
        string.Create(version.Length, version, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c is > ' ' and < (char)127 and not '-' ? c : '_';
            }
        });

    private static string LibraryVersion()
    {
        var version = typeof(SshSharpInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "0.0.0";
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? version : version[..plus];
    }
}