using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SshSharp.Config;

namespace SshSharp.Protocol;

/// <summary>
/// Opens the TCP connection to a server or proxy: from any local address, or from given ones (<c>BindAddress</c>, <c>BindInterface</c>,
/// <see cref="SshClientOptions.LocalEndPoint"/>). A socket bound to an IPv4 address reaches only IPv4 destinations and an IPv6 one only
/// IPv6, so with a bind the destination's addresses are filtered to the families the local addresses have, and tried in order.
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
    public static async Task<NetworkStream> ConnectAsync(string host, int port, IReadOnlyList<IPEndPoint>? local, SshAddressFamily family, string what,
        Action<Socket>? configure, CancellationToken cancellationToken)
    {
        // An address of the other family has nothing to try (the socket would refuse it with a NotSupportedException).
        if (family != SshAddressFamily.Any && IPAddress.TryParse(host, out var address)
            && address.AddressFamily != (family == SshAddressFamily.Inet ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6))
        {
            throw new SshException(SshFailureReason.ConnectFailed,
                $"The address of {what} is not {(family == SshAddressFamily.Inet ? "IPv4" : "IPv6")}, the only family AddressFamily allows.");
        }

        if (local is null || local.Count == 0)
        {
            var tcp = family switch
            {
                SshAddressFamily.Inet => new TcpClient(AddressFamily.InterNetwork),
                SshAddressFamily.Inet6 => new TcpClient(AddressFamily.InterNetworkV6),
                _ => new TcpClient(),
            };
            tcp.NoDelay = true;
            var configuring = false;
            try
            {
                // TcpClient connects this same socket, to each of the name's addresses in turn.
                configuring = true;
                configure?.Invoke(tcp.Client);
                configuring = false;
                await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);

                // A cancellation racing the connect's completion can close the socket and still let ConnectAsync return (seen on
                // .NET 8 under load); GetStream would then throw InvalidOperationException. The caller asked to cancel: say so.
                cancellationToken.ThrowIfCancellationRequested();
                return tcp.GetStream();
            }
            catch (SocketException ex) when (!configuring)
            {
                tcp.Dispose();
                throw new SshException(SshFailureReason.ConnectFailed, $"Could not connect to {what}: {ex.SocketErrorCode}.", ex);
            }
            catch
            {
                tcp.Dispose();
                throw;
            }
        }

        IPAddress[] destinations;
        try
        {
            destinations = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new SshException(SshFailureReason.ConnectFailed, $"Could not resolve the address of {what}: {ex.SocketErrorCode}.", ex);
        }

        var candidates = destinations
            .Where(d => family switch
            {
                SshAddressFamily.Inet => d.AddressFamily == AddressFamily.InterNetwork,
                SshAddressFamily.Inet6 => d.AddressFamily == AddressFamily.InterNetworkV6,
                _ => true,
            })
            .Select(d => (Destination: d, Local: local.FirstOrDefault(l => l.AddressFamily == d.AddressFamily)))
            .Where(pair => pair.Local is not null)
            .ToList();
        if (candidates.Count == 0)
        {
            throw new SshException(SshFailureReason.ConnectFailed,
                $"None of the addresses of {what} is of the bind address's family ({string.Join(" or ", local.Select(l => l.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6").Distinct())}).");
        }

        SocketException? last = null;
        foreach (var (destination, from) in candidates)
        {
            var socket = new Socket(from!.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var configuring = false;
            try
            {
                socket.Bind(from);
                configuring = true;
                configure?.Invoke(socket);
                configuring = false;
                await socket.ConnectAsync(destination, port, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested(); // as above: a cancelled connect must not surface as a closed socket
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex) when (!configuring)
            {
                socket.Dispose();
                if (ex.SocketErrorCode is SocketError.AddressNotAvailable or SocketError.AddressAlreadyInUse)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, $"Could not bind to the local address: {ex.SocketErrorCode}.", ex);
                }

                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw new SshException(SshFailureReason.ConnectFailed, $"Could not connect to {what}: {last!.SocketErrorCode}.", last);
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
