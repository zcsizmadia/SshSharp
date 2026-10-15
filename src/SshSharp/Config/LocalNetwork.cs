using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SshSharp.Config;

/// <summary><c>Match localnetwork</c>: whether an address of an active local interface lies in one of a list of networks (CIDR).</summary>
internal static class LocalNetwork
{
    /// <summary>The unicast addresses of the interfaces that are up, as OpenSSH reads them with getifaddrs (loopback included).</summary>
    public static IReadOnlyList<IPAddress> InterfaceAddresses()
    {
        try
        {
            return [.. NetworkInterface.GetAllNetworkInterfaces()
                .Where(i => i.OperationalStatus == OperationalStatus.Up)
                .SelectMany(i => i.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address)
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)];
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            // No interfaces to read (a platform without the API, such as a browser): no local network matches.
            return [];
        }
    }

    /// <summary>
    /// Whether any of <paramref name="addresses"/> is inside a network of <paramref name="networks"/>: a comma-separated list of
    /// <c>address/length</c> (IPv4 or IPv6; a bare address is a single host), as OpenSSH's addr_match_cidr_list reads it.
    /// </summary>
    /// <exception cref="FormatException">An entry is not a network in CIDR form.</exception>
    public static bool AnyInside(IReadOnlyList<IPAddress> addresses, string networks)
    {
        var parsed = networks.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Parse).ToList();
        if (parsed.Count == 0)
        {
            throw new FormatException("Match localnetwork needs at least one network.");
        }

        return addresses.Any(address => parsed.Any(network => Contains(network, address)));
    }

    private static (IPAddress Network, int Length) Parse(string entry)
    {
        var slash = entry.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? entry : entry[..slash];
        if (!IPAddress.TryParse(addressText, out var network) || addressText.Contains('%', StringComparison.Ordinal))
        {
            throw new FormatException($"Match localnetwork: '{entry}' is not a network in CIDR form.");
        }

        var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var length = bits;
        if (slash >= 0 && (!int.TryParse(entry.AsSpan(slash + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out length)
            || length > bits))
        {
            throw new FormatException($"Match localnetwork: '{entry}' has an invalid prefix length.");
        }

        return (network, length);
    }

    private static bool Contains((IPAddress Network, int Length) network, IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6 && network.Network.AddressFamily == AddressFamily.InterNetwork)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != network.Network.AddressFamily)
        {
            return false;
        }

        var a = address.GetAddressBytes();
        var n = network.Network.GetAddressBytes();
        var whole = network.Length / 8;
        if (!a.AsSpan(0, whole).SequenceEqual(n.AsSpan(0, whole)))
        {
            return false;
        }

        var rest = network.Length % 8;
        if (rest == 0)
        {
            return true;
        }

        var mask = (byte)(0xff << (8 - rest));
        return (a[whole] & mask) == (n[whole] & mask);
    }
}
