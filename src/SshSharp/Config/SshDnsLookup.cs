using System.Net;
using System.Net.Sockets;

namespace SshSharp.Config;

/// <summary>The system resolver's answer for <see cref="SshConfigResolveOptions.UseDnsCanonicalizer"/>.</summary>
internal static class SshDnsLookup
{
    /// <summary>
    /// Looks <paramref name="name"/> up as ssh's <c>resolve_host</c> does for canonicalization: through the system's resolver (the hosts
    /// file, DNS and whatever else it is set up for), for addresses of <paramref name="family"/>. Returns the canonical name it reports,
    /// which for a CNAME is the end of the chain (getaddrinfo's <c>AI_CANONNAME</c>), or the name itself when it reports none; null when
    /// the name does not resolve. .NET has no portable way to ask DNS for the CNAME records themselves, so the chain's middle is not seen.
    /// </summary>
    public static async ValueTask<string?> CanonicalNameAsync(string name, SshAddressFamily family, CancellationToken cancellationToken)
    {
        try
        {
            var entry = family switch
            {
                SshAddressFamily.Inet => await Dns.GetHostEntryAsync(name, AddressFamily.InterNetwork, cancellationToken).ConfigureAwait(false),
                SshAddressFamily.Inet6 => await Dns.GetHostEntryAsync(name, AddressFamily.InterNetworkV6, cancellationToken).ConfigureAwait(false),
                _ => await Dns.GetHostEntryAsync(name, cancellationToken).ConfigureAwait(false),
            };
            if (entry.AddressList.Length == 0)
            {
                return null;
            }

            return string.IsNullOrEmpty(entry.HostName) ? name.TrimEnd('.') : entry.HostName.TrimEnd('.');
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            // Not found, no data, a name the resolver will not take (too long, bad characters): not a canonical name.
            return null;
        }
    }
}
