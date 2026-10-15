using System.Buffers;
using System.Net;
#if NET10_0_OR_GREATER
using System.Net.Security;
using System.Security.Principal;
#endif

namespace SshSharp.Protocol;

/// <summary>
/// One GSS-API security context, client side (RFC 2743), as <c>gssapi-with-mic</c> (RFC 4462 section 3) drives it: tokens go back and forth
/// until the context is established, then a MIC over the session's authentication data proves it.
/// </summary>
internal interface IGssapiContext : IDisposable
{
    /// <summary>
    /// Takes the server's token (empty for the first call) and returns the next token for the server, or null when there is none.
    /// <paramref name="complete"/> is true once the context is established.
    /// </summary>
    /// <exception cref="SshException">The GSS-API layer failed (no ticket, unknown service principal, ...): <see cref="SshFailureReason.AuthenticationFailed"/>.</exception>
    byte[]? Step(ReadOnlySpan<byte> incoming, out bool complete);

    /// <summary>The message integrity code (gss_get_mic) over <paramref name="data"/>.</summary>
    byte[] GetMic(ReadOnlySpan<byte> data);
}

/// <summary>Kerberos through the platform: SSPI on Windows, GSS-API (MIT or Heimdal) elsewhere, via <c>NegotiateAuthentication</c>.</summary>
internal static class Gssapi
{
    /// <summary>The Kerberos 5 mechanism, 1.2.840.113554.1.2.2, DER-encoded (tag 6, length 9), as RFC 4462 section 3.2 sends it.</summary>
    internal static readonly byte[] Krb5Oid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

    /// <summary>
    /// Whether this build can do <c>gssapi-with-mic</c>: it needs <c>NegotiateAuthentication.ComputeIntegrityCheck</c>, which .NET 9 added,
    /// so of this library's targets (net8.0, net10.0) only the net10.0 build has it.
    /// </summary>
#if NET10_0_OR_GREATER
    internal const bool IsSupported = true;
#else
    internal const bool IsSupported = false;
#endif

    /// <summary>The platform's context for the <c>host</c> service on <paramref name="host"/> (<c>host/&lt;host&gt;</c>, as ssh asks for it).</summary>
    internal static IGssapiContext Create(string host, NetworkCredential? credential, bool delegateCredentials)
    {
#if NET10_0_OR_GREATER
        return new NegotiateContext(host, credential, delegateCredentials);
#else
        throw new PlatformNotSupportedException("gssapi-with-mic needs .NET 10.");
#endif
    }

#if NET10_0_OR_GREATER
    private sealed class NegotiateContext : IGssapiContext
    {
        private readonly NegotiateAuthentication _context;

        public NegotiateContext(string host, NetworkCredential? credential, bool delegateCredentials)
        {
            _context = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
            {
                // Kerberos itself, not SPNEGO: the SSH server asked for the krb5 mechanism, and the tokens are krb5's.
                Package = "Kerberos",
                Credential = credential ?? CredentialCache.DefaultNetworkCredentials,

                // The host service principal (host/<name>@REALM), as ssh imports GSS_C_NT_HOSTBASED_SERVICE "host@<name>".
                TargetName = "host/" + host,
                RequiredProtectionLevel = ProtectionLevel.Sign,
                RequireMutualAuthentication = true,
                AllowedImpersonationLevel = delegateCredentials ? TokenImpersonationLevel.Delegation : TokenImpersonationLevel.Identification,
            });
        }

        public byte[]? Step(ReadOnlySpan<byte> incoming, out bool complete)
        {
            var token = _context.GetOutgoingBlob(incoming, out var status);
            switch (status)
            {
                case NegotiateAuthenticationStatusCode.Completed:
                    complete = true;
                    return token is { Length: > 0 } ? token : null;
                case NegotiateAuthenticationStatusCode.ContinueNeeded:
                    complete = false;
                    return token;
                default:
                    throw new SshException(SshFailureReason.AuthenticationFailed, $"Kerberos (GSS-API) failed: {status}.");
            }
        }

        public byte[] GetMic(ReadOnlySpan<byte> data)
        {
            var mic = new ArrayBufferWriter<byte>(64);
            _context.ComputeIntegrityCheck(data, mic);
            return mic.WrittenSpan.ToArray();
        }

        public void Dispose() => _context.Dispose();
    }
#endif
}
