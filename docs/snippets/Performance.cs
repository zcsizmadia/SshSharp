using SshSharp;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/performance-tuning.md.</summary>
internal static class Performance
{
    public static async Task LongLinkAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <long-link>
        // A fast link with a long round trip (here 1 Gbit/s at 100 ms): bandwidth × round trip is about 12.5 MB, so each channel gets a
        // 16 MiB window, and the socket a receive buffer to match, set before it connects so that TCP window scaling can use it.
        await using var client = await SshClient.ConnectAsync("backup.example.com", 22, new SshClientOptions
        {
            UserName = "backup",
            PrivateKeys = [await SshPrivateKey.LoadAsync("/etc/myapp/backup_ed25519", cancellationToken: cancellationToken)],
            HostKeyVerifier = verifier,
            ChannelWindowSize = 16 * 1024 * 1024,
            ChannelMaxPacketSize = 255 * 1024,
            ConfigureSocket = socket => socket.ReceiveBufferSize = 16 * 1024 * 1024,
        }, cancellationToken);
        // </long-link>
    }

    public static async Task CipherAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <cipher>
        // The client's order decides which cipher is used. The default already puts AES-GCM first on CPUs with AES instructions and
        // ChaCha20-Poly1305 first on CPUs without; this pins AES-GCM first whatever the CPU, for example to measure the difference.
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [await SshPrivateKey.LoadAsync("/etc/myapp/deploy_ed25519", cancellationToken: cancellationToken)],
            HostKeyVerifier = verifier,
            Ciphers = SshAlgorithmList.Prepend("aes128-gcm@openssh.com", "aes256-gcm@openssh.com"),
        }, cancellationToken);
        Console.WriteLine($"cipher: {client.Algorithms.EncryptionClientToServer}");
        // </cipher>
    }

    public static async Task SftpAsync(SftpClient sftp, CancellationToken cancellationToken)
    {
        // <sftp>
        // One large file over a link with latency: more reads in flight, and four ranges over four sessions.
        await sftp.DownloadFileAsync("images/vm.qcow2", "vm.qcow2",
            new SftpTransferOptions { MaxRequestsInFlight = 128, Segments = 4 }, cancellationToken);

        // A tree of many small files: eight files at a time, sharing the 64 requests in flight.
        await sftp.UploadDirectoryAsync("site", "/srv/www/site", new SftpTransferOptions { MaxConcurrentFiles = 8 }, cancellationToken);

        // Streaming into a remote file: large writes keep the 16 writes in flight full; tiny ones would each be a request.
        await using var source = File.OpenRead("report.csv");
        await using var target = await sftp.OpenWriteAsync("reports/report.csv", cancellationToken);
        await source.CopyToAsync(target, 256 * 1024, cancellationToken);
        // </sftp>
    }
}
