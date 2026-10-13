using System.Reflection;

namespace SshSharp;

/// <summary>Build and identification information about the library.</summary>
public static class SshSharpInfo
{
    /// <summary>The SSH software version string sent during version exchange (RFC 4253 section 4.2).</summary>
    public static string SoftwareVersion { get; } = $"SshSharp_{LibraryVersion()}";

    private static string LibraryVersion()
    {
        var version = typeof(SshSharpInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "0.0.0";
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? version : version[..plus];
    }
}