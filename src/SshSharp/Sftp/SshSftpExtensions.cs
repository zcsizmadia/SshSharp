
namespace SshSharp.Sftp;

/// <summary>SFTP on an <see cref="SshClient"/>.</summary>
public static class SshSftpExtensions
{
    /// <summary>
    /// Starts an SFTP session (the server's <c>sftp</c> subsystem) on this connection. Dispose it when done; the connection stays up.
    /// </summary>
    /// <exception cref="SshException">The server offers no <c>sftp</c> subsystem (<see cref="SshFailureReason.ChannelClosed"/>), or does not
    /// speak SFTP version 3 (<see cref="SshFailureReason.ProtocolError"/>).</exception>
    public static async Task<SftpClient> OpenSftpAsync(this SshClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        var session = await client.StartSubsystemAsync("sftp", cancellationToken: cancellationToken).ConfigureAwait(false);
        try
        {
            var sftp = await SftpClient.StartAsync(session, client.Connection.ServerSoftware, cancellationToken).ConfigureAwait(false);
            sftp.OpenSibling = token => client.OpenSftpAsync(token); // more sessions on this connection, for segmented transfers
            return sftp;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
