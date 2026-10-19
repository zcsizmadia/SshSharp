using System.Net.Sockets;
using SshSharp;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/tune-and-inspect-connections.md and docs/connecting.md.</summary>
internal static class ConnectionTuning
{
    public static async Task ConfigureSocketAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <configure-socket>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            Password = Environment.GetEnvironmentVariable("DEPLOY_PASSWORD"),
            HostKeyVerifier = verifier,
            // Called with the socket before it connects.
            ConfigureSocket = socket =>
            {
                // TCP keep-alive: the system probes an idle connection after 60 s, so a firewall keeps its state.
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 60);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 10);

                // A larger receive buffer, set before connecting so that TCP window scaling can use it.
                socket.ReceiveBufferSize = 4 * 1024 * 1024;
            },
        }, cancellationToken);
        // </configure-socket>
    }

    public static async Task VersionAddendumAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <version-addendum>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [await SshPrivateKey.LoadAsync("/etc/myapp/deploy_ed25519", cancellationToken: cancellationToken)],
            HostKeyVerifier = verifier,
            // The server logs "SSH-2.0-SshSharp_1.2.0 inventory-sync/3.4": tell your application's connections apart.
            VersionAddendum = "inventory-sync/3.4",
        }, cancellationToken);
        // </version-addendum>
    }

    public static async Task ChannelWindowAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <channel-window>
        // A fast link with a long round trip: 16 MiB in flight per channel instead of 2 MiB, in packets of up to 255 KiB.
        await using var client = await SshClient.ConnectAsync("backup.example.com", 22, new SshClientOptions
        {
            UserName = "backup",
            PrivateKeys = [await SshPrivateKey.LoadAsync("/etc/myapp/backup_ed25519", cancellationToken: cancellationToken)],
            HostKeyVerifier = verifier,
            ChannelWindowSize = 16 * 1024 * 1024,
            ChannelMaxPacketSize = 255 * 1024,
        }, cancellationToken);

        await using var sftp = await client.OpenSftpAsync(cancellationToken);
        await sftp.DownloadFileAsync("dumps/db.tar.zst", "db.tar.zst", cancellationToken: cancellationToken);
        // </channel-window>
    }

    public static void Inspect(SshClient client)
    {
        // <inspect-connection>
        Console.WriteLine($"server:     {client.ServerIdentification}");         // SSH-2.0-OpenSSH_9.9
        Console.WriteLine($"remote:     {client.RemoteEndPoint}");               // 192.0.2.10:22 (null over a stream that is no socket)
        Console.WriteLine($"local:      {client.LocalEndPoint}");                // 198.51.100.7:50514
        Console.WriteLine($"connected:  {client.ConnectedAt:u} ({DateTimeOffset.UtcNow - client.ConnectedAt:hh\\:mm\\:ss} ago)");
        Console.WriteLine($"session id: {Convert.ToHexString(client.SessionId.Span)}");
        Console.WriteLine($"traffic:    {client.BytesSent:N0} bytes sent, {client.BytesReceived:N0} received");
        Console.WriteLine($"cipher:     {client.Algorithms.EncryptionClientToServer}");
        // </inspect-connection>
    }

    public static async Task RekeyAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <rekey>
        // New keys now, as ssh's ~R escape: for example before a sensitive transfer on a connection that has been up for a while.
        await client.RekeyAsync(cancellationToken);
        // </rekey>
    }
}
