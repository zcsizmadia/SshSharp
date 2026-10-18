using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// One connection the server forwarded to a handler in this process: a remote forwarding started with
/// <see cref="SshClient.ForwardRemotePortAsync(string, int, Func{SshForwardedConnection, CancellationToken, Task}, int, CancellationToken)"/>
/// or <see cref="SshClient.ForwardRemoteUnixSocketAsync(string, Func{SshForwardedConnection, CancellationToken, Task}, int, CancellationToken)"/>.
/// The handler owns <see cref="Stream"/>: disposing it closes the connection, and it is disposed for the handler when the handler returns.
/// </summary>
/// <remarks>
/// Everything here except <see cref="Stream"/> is what the server reported when it opened the connection. It describes the
/// connection; it does not authenticate the program at the other end, which anyone who can reach the forwarded port or socket on the
/// server can be.
/// </remarks>
public sealed class SshForwardedConnection
{
    internal SshForwardedConnection(Stream stream, string? boundAddress, int? boundPort, string? remoteSocketPath, string? originatorAddress, int? originatorPort)
    {
        Stream = stream;
        BoundAddress = boundAddress;
        BoundPort = boundPort;
        RemoteSocketPath = remoteSocketPath;
        OriginatorAddress = originatorAddress;
        OriginatorPort = originatorPort;
    }

    /// <summary>
    /// The connection as a duplex stream (asynchronous only): reads return what the remote program sends, and reads end (return 0) when
    /// it has finished sending. Writes go to it. Disposing the stream closes the connection. While nothing reads it, the server is not
    /// allowed to send more than the channel's window (2 MiB), so a handler that stops reading slows the remote program down rather than
    /// buffering without limit.
    /// </summary>
    public Stream Stream { get; }

    /// <summary>For a forwarded port: the address that was connected on the server, as it reports it. Null for a Unix socket.</summary>
    public string? BoundAddress { get; }

    /// <summary>For a forwarded port: the port that was connected on the server. Null for a Unix socket.</summary>
    public int? BoundPort { get; }

    /// <summary>For a forwarded Unix socket: the socket path that was connected on the server. Null for a forwarded port.</summary>
    public string? RemoteSocketPath { get; }

    /// <summary>
    /// For a forwarded port: the address of the program that connected, as the server reports it. Null for a Unix socket (the server
    /// does not say who connected), or when the server sent none.
    /// </summary>
    public string? OriginatorAddress { get; }

    /// <summary>For a forwarded port: the port of the program that connected, as the server reports it. Null for a Unix socket.</summary>
    public int? OriginatorPort { get; }

    /// <summary>
    /// A <c>forwarded-tcpip</c> connection (RFC 4254 section 7.2): the address and port that were connected, then the originator's. A
    /// server that leaves the originator out, or sends one that cannot be read, gets null for it rather than a refused connection.
    /// </summary>
    internal static SshForwardedConnection ForTcp(Stream stream, byte[] data)
    {
        var reader = new SshReader(data);
        var boundAddress = reader.ReadUtf8String();
        var boundPort = (int)reader.ReadUInt32();
        string? originatorAddress = null;
        int? originatorPort = null;
        try
        {
            originatorAddress = reader.ReadUtf8String();
            originatorPort = (int)reader.ReadUInt32();
        }
        catch (SshProtocolException)
        {
            originatorAddress = null;
            originatorPort = null;
        }

        return new SshForwardedConnection(stream, boundAddress, boundPort, null, originatorAddress, originatorPort);
    }

    /// <summary>A <c>forwarded-streamlocal@openssh.com</c> connection: only the socket path that was connected.</summary>
    internal static SshForwardedConnection ForUnixSocket(Stream stream, string socketPath) =>
        new(stream, null, null, socketPath, null, null);
}
