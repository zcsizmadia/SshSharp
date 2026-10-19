using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SshSharp.Config;

namespace SshSharp.Protocol;

/// <summary>
/// Opens the TCP connection to a server or proxy: from any local address, or from given ones (<c>BindAddress</c>, <c>BindInterface</c>,
/// <see cref="SshClientOptions.LocalEndPoint"/>). The name is resolved here and its addresses tried in order, each with a new socket. A
/// socket bound to an IPv4 address reaches only IPv4 destinations and an IPv6 one only IPv6, so with a bind the destination's addresses
/// are filtered to the families the local addresses have.
/// </summary>
internal static class TcpConnector
{
    /// <summary>Connects to <paramref name="host"/>:<paramref name="port"/>; the returned stream owns the socket.</summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="local">Local endpoints to connect from (one per address family at most is used), or null for any.</param>
    /// <param name="family">The <c>AddressFamily</c> restriction.</param>
    /// <param name="what">"the server" or "the proxy", for the error message.</param>
    /// <param name="cancellationToken">Cancels resolving and connecting.</param>
    public static Task<NetworkStream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, SshAddressFamily family, string what, CancellationToken cancellationToken) =>
        ConnectAsync(host, port, local, family, what, configure: null, cancellationToken);

    /// <summary>
    /// Connects like <see cref="ConnectAsync(string, int, IReadOnlyList{IPEndPoint}?, SshAddressFamily, string, CancellationToken)"/>, and
    /// calls <paramref name="configure"/> with each socket before it connects (<see cref="SshClientOptions.ConfigureSocket"/>).
    /// </summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="local">Local endpoints to connect from, or null for any.</param>
    /// <param name="family">The <c>AddressFamily</c> restriction.</param>
    /// <param name="what">"the server" or "the proxy", for the error message.</param>
    /// <param name="configure">Sets the caller's socket options; what it throws is thrown as it is, not reported as a failure to connect.</param>
    /// <param name="cancellationToken">Cancels resolving and connecting.</param>
    public static Task<NetworkStream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, SshAddressFamily family, string what,
        Action<Socket>? configure, CancellationToken cancellationToken) =>
        ConnectAsync(host, port, local, family, what, configure, Dns.GetHostAddressesAsync, cancellationToken);

    /// <summary>
    /// Connects as above, resolving names with <paramref name="resolve"/> (tests give a name the addresses they need).
    /// </summary>
    /// <remarks>
    /// Each address is tried with a socket of its own, created, bound and configured afresh, not with one socket reused from address to
    /// address as <c>TcpClient.ConnectAsync(host, port)</c> does: on Linux and macOS a socket with a raw option set (<c>IPV6_TCLASS</c>
    /// for <c>IPQoS</c>, or whatever <paramref name="configure"/> sets) cannot be connected again after a failed attempt, so that
    /// gives up after the first address.
    /// </remarks>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="local">Local endpoints to connect from, or null for any.</param>
    /// <param name="family">The <c>AddressFamily</c> restriction.</param>
    /// <param name="what">"the server" or "the proxy", for the error message.</param>
    /// <param name="configure">Sets the caller's socket options.</param>
    /// <param name="resolve">Resolves a host name to its addresses.</param>
    /// <param name="cancellationToken">Cancels resolving and connecting.</param>
    internal static Task<NetworkStream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, SshAddressFamily family, string what,
        Action<Socket>? configure, Func<string, CancellationToken, Task<IPAddress[]>> resolve, CancellationToken cancellationToken) =>
        ConnectAsync(host, port, local, family, what, configure, resolve, OSSupports, cancellationToken);

    /// <summary>
    /// Connects as above, trying only addresses of the families <paramref name="supports"/> says the system has (tests stand in for a
    /// system without IPv6).
    /// </summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port.</param>
    /// <param name="local">Local endpoints to connect from, or null for any.</param>
    /// <param name="family">The <c>AddressFamily</c> restriction.</param>
    /// <param name="what">"the server" or "the proxy", for the error message.</param>
    /// <param name="configure">Sets the caller's socket options.</param>
    /// <param name="resolve">Resolves a host name to its addresses.</param>
    /// <param name="supports">Whether the system can create sockets of an address family.</param>
    /// <param name="cancellationToken">Cancels resolving and connecting.</param>
    internal static async Task<NetworkStream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, SshAddressFamily family, string what,
        Action<Socket>? configure, Func<string, CancellationToken, Task<IPAddress[]>> resolve, Func<AddressFamily, bool> supports,
        CancellationToken cancellationToken)
    {
        // An address of the other family has nothing to try (the socket would refuse it with a NotSupportedException).
        if (family != SshAddressFamily.Any && IPAddress.TryParse(host, out var address)
            && Unmapped(address).AddressFamily !=(family == SshAddressFamily.Inet ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6))
        {
            throw new SshException(SshFailureReason.ConnectFailed,
                $"The address of {what} is not {(family == SshAddressFamily.Inet ? "IPv4" : "IPv6")}, the only family AddressFamily allows.");
        }

        IPAddress[] destinations;
        try
        {
            destinations = IPAddress.TryParse(host, out var literal) ? [literal] : await resolve(host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new SshException(SshFailureReason.ConnectFailed, $"Could not resolve the address of {what}: {ex.SocketErrorCode}.", ex);
        }

        // An IPv4-mapped IPv6 address (::ffff:192.0.2.10, given as HostName or returned by a resolver) is an IPv4 destination. An IPv6
        // socket reaches it only in dual mode, which these sockets are not (Windows refuses the connect with AddressNotAvailable), and
        // the bind address for it is an IPv4 one. It is connected to over IPv4, with an IPv4 socket.
        var allowed = destinations
            .Select(Unmapped)
            .Where(d => family switch
            {
                SshAddressFamily.Inet => d.AddressFamily == AddressFamily.InterNetwork,
                SshAddressFamily.Inet6 => d.AddressFamily == AddressFamily.InterNetworkV6,
                _ => d.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6,
            })
            .ToList();
        if (allowed.Count == 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed, family == SshAddressFamily.Any
                ? $"Could not resolve the address of {what}: it has no IP address."
                : $"None of the addresses of {what} is {(family == SshAddressFamily.Inet ? "IPv4" : "IPv6")}, the only family AddressFamily allows.");
        }

        // With a bind, a destination is reachable only from a local address of its own family.
        var bind = local is { Count: > 0 };
        var candidates = allowed
            .Select(d => (Destination: d, Local: bind ? local!.FirstOrDefault(l => l.AddressFamily == d.AddressFamily) : null))
            .Where(pair => !bind || pair.Local is not null)
            .ToList();
        if (candidates.Count == 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed,
                $"None of the addresses of {what} is of the bind address's family ({string.Join(" or ", local!.Select(l => l.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6").Distinct())}).");
        }

        // A family the system has no sockets for (IPv6 turned off) is skipped, as ssh goes on when socket() fails: what is reported is then
        // why the addresses that could be tried failed, not that the system has no IPv6.
        candidates = candidates.Where(c => supports(c.Destination.AddressFamily)).ToList();
        if (candidates.Count == 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed,
                $"None of the addresses of {what} is of an address family this system supports.");
        }

        SocketException? last = null;
        foreach (var (destination, from) in candidates)
        {
            Socket? socket = null;
            var configuring = false;
            try
            {
                // A socket of the destination's family. Where creating one still fails (the family is not there after all), the next
                // address is tried.
                socket = new Socket(destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                if (from is not null)
                {
                    socket.Bind(from);
                }

                configuring = true;
                configure?.Invoke(socket);
                configuring = false;
                await socket.ConnectAsync(destination, port, cancellationToken).ConfigureAwait(false);

                // A cancellation racing the connect's completion can close the socket and still let ConnectAsync return (seen on .NET 8
                // under load); the stream would then fail on first use. The caller asked to cancel: say so.
                cancellationToken.ThrowIfCancellationRequested();
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex) when (!configuring)
            {
                socket?.Dispose();
                if (from is not null && ex.SocketErrorCode is SocketError.AddressNotAvailable or SocketError.AddressAlreadyInUse)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, $"Could not bind to the local address: {ex.SocketErrorCode}.", ex);
                }

                // A connect's error says more than a family the system turned out not to have, whichever of them came last.
                if (last is null || ex.SocketErrorCode != SocketError.AddressFamilyNotSupported)
                {
                    last = ex;
                }
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        throw new SshException(SshFailureReason.ConnectFailed, $"Could not connect to {what}: {last!.SocketErrorCode}.", last);
    }

    /// <summary>The address, or the IPv4 address an IPv4-mapped IPv6 address carries.</summary>
    private static IPAddress Unmapped(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>Whether the system can create sockets of <paramref name="family"/>.</summary>
    private static bool OSSupports(AddressFamily family) => family switch
    {
        AddressFamily.InterNetwork => Socket.OSSupportsIPv4,
        AddressFamily.InterNetworkV6 => Socket.OSSupportsIPv6,
        _ => false,
    };

    /// <summary>
    /// ssh_config's socket settings followed by the caller's <paramref name="then"/> (<see cref="SshConfigConnectOptions.ConfigureSocket"/>),
    /// which runs last so that what it sets wins: <c>TCPKeepAlive</c> turns on <c>SO_KEEPALIVE</c>, and <c>IPQoS</c> sets the type of
    /// service. Both are best effort, as in ssh: an option the platform refuses is logged, and the connection goes ahead without it.
    /// </summary>
    /// <param name="keepAlive">Whether to turn on TCP keep-alive.</param>
    /// <param name="typeOfService">The type-of-service byte (DSCP in its upper six bits), or null to leave the system's.</param>
    /// <param name="then">The caller's own settings, or null.</param>
    /// <param name="logger">Where options that could not be set are reported.</param>
    public static Action<Socket>? Configure(bool keepAlive, int? typeOfService, Action<Socket>? then, ILogger logger)
    {
        if (!keepAlive && typeOfService is null)
        {
            return then;
        }

        return socket =>
        {
            if (keepAlive)
            {
                TrySet(logger, "SO_KEEPALIVE", () => socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true));
            }

            if (typeOfService is { } tos)
            {
                SetTypeOfService(socket, tos, logger);
            }

            then?.Invoke(socket);
        };
    }

    /// <summary>
    /// Sets the type of service as ssh's <c>set_sock_tos</c> does: <c>IP_TOS</c> for IPv4 and <c>IPV6_TCLASS</c> for IPv6. A dual-mode
    /// socket gets both, since which one applies depends on the address it reaches. Windows accepts the IPv4 option but ignores it
    /// unless a system policy allows applications to set it.
    /// </summary>
    internal static void SetTypeOfService(Socket socket, int typeOfService, ILogger logger)
    {
        var ipv6 = socket.AddressFamily == AddressFamily.InterNetworkV6;
        if (!ipv6 || socket.DualMode)
        {
            TrySet(logger, "IP_TOS", () => socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, typeOfService));
        }

        if (ipv6 && Ipv6TrafficClass is { } option)
        {
            // .NET has no name for IPV6_TCLASS; its number differs by platform. The value is a native int, as for setsockopt.
            TrySet(logger, "IPV6_TCLASS", () => socket.SetRawSocketOption(Ipv6Level, option, BitConverter.GetBytes(typeOfService)));
        }
    }

    /// <summary><c>IPPROTO_IPV6</c>, the same everywhere.</summary>
    internal const int Ipv6Level = 41;

    /// <summary><c>IPV6_TCLASS</c> on this platform, or null where it is not known.</summary>
    internal static int? Ipv6TrafficClass =>
        OperatingSystem.IsLinux() || OperatingSystem.IsAndroid() ? 67
        : OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsTvOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsFreeBSD() ? 36
        : OperatingSystem.IsWindows() ? 39
        : null;

    private static void TrySet(ILogger logger, string option, Action set)
    {
        try
        {
            set();
        }
        catch (SocketException ex)
        {
            SshLog.SocketOptionNotSet(logger, option, ex.SocketErrorCode);
        }
    }

    /// <summary>
    /// The local endpoints for <c>BindAddress</c> and <c>BindInterface</c>: the address, or the interface's addresses (link-local IPv6
    /// addresses left out, since they need a scope the destination shares). Null when neither is set.
    /// </summary>
    /// <exception cref="SshException">The address is not an IP address, or no interface has the name.</exception>
    public static IReadOnlyList<IPEndPoint>? FromConfig(string? bindAddress, string? bindInterface)
    {
        if (!string.IsNullOrEmpty(bindAddress))
        {
            if (!IPAddress.TryParse(bindAddress, out var address))
            {
                throw new SshException(SshFailureReason.ConnectFailed, $"BindAddress '{bindAddress}' is not an IP address.");
            }

            return [new IPEndPoint(address, 0)];
        }

        if (string.IsNullOrEmpty(bindInterface))
        {
            return null;
        }

        var nic = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => string.Equals(n.Name, bindInterface, StringComparison.OrdinalIgnoreCase) || n.Id == bindInterface)
            ?? throw new SshException(SshFailureReason.ConnectFailed, $"BindInterface '{bindInterface}': no such network interface.");
        var addresses = nic.GetIPProperties().UnicastAddresses
            .Select(u => u.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork || (a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal))
            .Select(a => new IPEndPoint(a, 0))
            .ToList();
        return addresses.Count > 0
            ? addresses
            : throw new SshException(SshFailureReason.ConnectFailed, $"BindInterface '{bindInterface}' has no usable address.");
    }
}
