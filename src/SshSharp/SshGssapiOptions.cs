using System.Net;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// Kerberos authentication (<c>gssapi-with-mic</c>, RFC 4462; ssh's <c>GSSAPIAuthentication yes</c>), set on
/// <see cref="SshClientOptions.Gssapi"/>. The ticket comes from the platform: the logon session on Windows (SSPI), the credential cache
/// (<c>kinit</c>) elsewhere (MIT or Heimdal GSS-API). Needs .NET 10; on .NET 8 the method is not offered.
/// </summary>
public sealed class SshGssapiOptions
{
    /// <summary>
    /// The host name of the server's service principal (<c>host/&lt;name&gt;@REALM</c>). Null for the host name connected to; set it when
    /// connecting over a stream or by address, since Kerberos names the service by its DNS name.
    /// </summary>
    public string? TargetHost { get; init; }

    /// <summary>
    /// Forwards the Kerberos ticket to the server (ssh's <c>GSSAPIDelegateCredentials yes</c>), so programs there can authenticate onward
    /// as you. Off by default: only delegate to servers you trust.
    /// </summary>
    public bool DelegateCredentials { get; init; }

    /// <summary>Explicit credentials (user, password and realm) instead of the current ticket; null to use the ticket cache or logon session.</summary>
    public NetworkCredential? Credential { get; init; }

    /// <summary>Whether this build can authenticate with Kerberos: true on .NET 10, false on .NET 8.</summary>
    public static bool IsSupported => Gssapi.IsSupported;

    /// <summary>Makes the GSS-API context; replaceable in tests (host, credential, delegate).</summary>
    internal Func<string, NetworkCredential?, bool, IGssapiContext> ContextFactory { get; init; } = Gssapi.Create;
}
