using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    /// <summary>
    /// Connects a chain of <paramref name="hops"/> jump hosts, each through the one before (<paramref name="connectHop"/> makes hop
    /// <c>i</c> through the client given, null for the first), then opens a tunnel through the last one to <paramref name="host"/>:<paramref name="port"/>.
    /// Shared by ssh_config's <c>ProxyJump</c> and <see cref="SshClientOptions.JumpHosts"/>. Each hop owns the one before it and the
    /// tunnel owns the last, so disposing what the tunnel's owner is handed to tears down the whole chain (ProxyJump a,b: the client owns
    /// b, and b owns a).
    /// </summary>
    private static async Task<(Stream Stream, Owned Owner)> ConnectChainAsync(int hops, Func<int, SshClient?, CancellationToken, Task<SshClient>> connectHop,
        string host, int port, CancellationToken cancellationToken)
    {
        SshClient? hop = null;
        try
        {
            for (var i = 0; i < hops; i++)
            {
                // A hop that fails has disposed what it took over (or left it here, in hop, which the catch disposes; twice is harmless).
                hop = await connectHop(i, hop, cancellationToken).ConfigureAwait(false);
            }
        }
        catch
        {
            if (hop is not null)
            {
                await hop.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }

        return await TunnelAsync(hop!, host, port, ownsVia: true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Opens a <c>direct-tcpip</c> channel through <paramref name="via"/> to <paramref name="host"/>:<paramref name="port"/>, as a stream.</summary>
    private static async Task<(Stream Stream, Owned Owner)> TunnelAsync(SshClient via, string host, int port, bool ownsVia, CancellationToken cancellationToken)
    {
        try
        {
            var channel = await via.Connection.OpenDirectTcpIpAsync(host, port, "127.0.0.1", 0, cancellationToken).ConfigureAwait(false);
            var stream = new SshChannelStream(channel);
            var owner = new Owned(stream);
            if (ownsVia)
            {
                owner.Add(via);
            }

            return (stream, owner);
        }
        catch (SshException ex) when (ex is not SshProtocolException)
        {
            if (ownsVia)
            {
                await via.DisposeAsync().ConfigureAwait(false);
            }

            throw new SshException(SshFailureReason.ConnectFailed, "The jump host could not open a connection to the next host: " + ex.Message, ex);
        }
        catch when (ownsVia)
        {
            // Cancelled, or the connection failed: the hop it would have owned goes with it.
            await via.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// The chain of <see cref="SshClientOptions.JumpHosts"/> up to a tunnel to <paramref name="host"/>:<paramref name="port"/>; the first
    /// network connection goes through the destination's proxy, from its local endpoint, with its address family.
    /// </summary>
    private static Task<(Stream Stream, Owned Owner)> ConnectThroughJumpHostsAsync(string host, int port, SshClientOptions options,
        IReadOnlyList<IPEndPoint>? local, CancellationToken cancellationToken)
    {
        var hops = options.JumpHosts;
        return ConnectChainAsync(hops.Count, (index, via, token) => ConnectJumpHostAsync(hops[index], via, options, local, token), host, port, cancellationToken);
    }

    /// <summary>
    /// Connects one of <see cref="SshClientOptions.JumpHosts"/>: over the network when it is the first (<paramref name="via"/> is null),
    /// otherwise through <paramref name="via"/>, which it then owns. Its own options log in and verify it; its own ConnectTimeout bounds
    /// it, within the destination's.
    /// </summary>
    private static async Task<SshClient> ConnectJumpHostAsync(SshJumpHost jump, SshClient? via, SshClientOptions destination,
        IReadOnlyList<IPEndPoint>? local, CancellationToken cancellationToken)
    {
        using var deadline = new ConnectDeadline(jump.Options.ConnectTimeout, cancellationToken, destination.TimeProvider);
        using var measurement = new ConnectMeasurement(via is null && destination.Proxy is null ? jump.Port : null);
        Owned? owner = null;
        try
        {
            Stream stream;
            if (via is null)
            {
                stream = await OpenStreamAsync(jump.Host, jump.Port, destination, local, "the jump host", deadline.Token).ConfigureAwait(false);
            }
            else
            {
                (stream, owner) = await TunnelAsync(via, jump.Host, jump.Port, ownsVia: true, deadline.Token).ConfigureAwait(false);
            }

            var client = await ConnectCoreAsync(stream, jump.Options, leaveOpen: false, owner, jump.Host, jump.Port, measurement, deadline.Token)
                .ConfigureAwait(false);
            owner = null; // the client owns it now
            return client;
        }
        catch (OperationCanceledException) when (deadline.Expired)
        {
            var error = deadline.Error();
            measurement.Failed(error);
            throw error;
        }
        catch (Exception ex)
        {
            measurement.Failed(ex); // unless the handshake already recorded its own failure
            throw;
        }
        finally
        {
            if (owner is not null)
            {
                await owner.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The first network connection: through <see cref="SshClientOptions.Proxy"/> when set, otherwise TCP; tried up to
    /// <see cref="SshClientOptions.ConnectionAttempts"/> times, as the ssh_config path does.
    /// </summary>
    private static async Task<Stream> OpenStreamAsync(string host, int port, SshClientOptions options, IReadOnlyList<IPEndPoint>? local, string what,
        CancellationToken cancellationToken) =>
        await WithConnectionAttemptsAsync(
            async ct => options.Proxy is { } proxy
                ? await proxy.ConnectAsync(host, port, local, ct).ConfigureAwait(false)
                : (Stream)await TcpConnector.ConnectAsync(host, port, local, options.AddressFamily, what, options.ConfigureSocket, ct).ConfigureAwait(false),
            options.ConnectionAttempts, options.TimeProvider, options.Logger ?? NullLogger.Instance, cancellationToken).ConfigureAwait(false);
}
