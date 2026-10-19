using System.Text;
using SshSharp.Protocol;
using SshSharp.Sftp;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Delayed compression (<c>zlib@openssh.com</c>) against the real servers: a command's output, a forced re-exchange in the middle (each
/// exchange starts new zlib streams, which both sides must agree on), and an SFTP file. OpenSSH's sshd offers it unless configured with
/// <c>Compression no</c>; the other servers may not, and then the tests skip, saying so.
/// </summary>
public class CompressionInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    /// <summary>
    /// Whether the server must offer it: OpenSSH on Linux, as CI runs it (no <c>Compression</c> line, so its default <c>yes</c>). The
    /// Windows port and the other implementations are checked when they offer it.
    /// </summary>
    private static bool MustOffer => RealServer.IsOpenSsh && !RealServer.IsWindows;

    private static async Task<SshClient?> ConnectAsync(long? rekeyAfterBytes = null)
    {
        if (RealServer.Endpoint is not var (host, port) || await RealServer.OptionsAsync(rekeyAfterBytes: rekeyAfterBytes, compression: true) is not { } options)
        {
            Skip.Test("SSHSHARP_TEST_SSHD and SSHSHARP_TEST_USER with a password or key are needed.");
            return null;
        }

        var client = await SshClient.ConnectAsync(host, port, options, Timeout());
        if (client.Algorithms.CompressionServerToClient != SshAlgorithms.CompressionZlibOpenSsh)
        {
            await client.DisposeAsync();
            if (MustOffer)
            {
                throw new InvalidOperationException(
                    $"OpenSSH negotiated {client.Algorithms.CompressionServerToClient} compression; zlib@openssh.com was expected (is sshd set to Compression no?).");
            }

            Skip.Test($"The server ({RealServer.Software}) does not offer zlib@openssh.com.");
            return null;
        }

        // Client to server: never on .NET 8 (SshSharp does not offer it there). Otherwise the server's choice: OpenSSH accepts it, but
        // Dropbear 2025.88 disabled decompression on the server ("Decompression is disabled on the server, compression is still
        // supported", its CHANGES) and offers only none for that direction.
        var toServer = client.Algorithms.CompressionClientToServer;
        var allowed = !SshAlgorithms.CanCompressOutgoing
            ? toServer == SshAlgorithms.CompressionNone
            : toServer == SshAlgorithms.CompressionZlibOpenSsh || (!MustOffer && toServer == SshAlgorithms.CompressionNone);
        if (!allowed)
        {
            var expected = SshAlgorithms.CanCompressOutgoing ? SshAlgorithms.CompressionZlibOpenSsh : SshAlgorithms.CompressionNone;
            await client.DisposeAsync();
            throw new InvalidOperationException($"Client-to-server compression is {client.Algorithms.CompressionClientToServer}, expected {expected}.");
        }

        return client;
    }

    /// <summary>Base64 of zero bytes is all 'A' (and compresses well): any corruption shows up in the text.</summary>
    private static async Task AssertBase64OfZerosAsync(SshCommandResult result, int bytes)
    {
        var lines = result.StandardOutputText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        await Assert.That(result.ExitStatus).IsEqualTo(0);
        await Assert.That(lines.Length).IsEqualTo((bytes * 4 / 3 / 76) + 1);
        await Assert.That(lines.Take(lines.Length - 1).All(l => l.Length == 76 && l.All(c => c == 'A'))).IsTrue();
    }

    [Test]
    public async Task CommandOutput_AndInput_OverACompressedConnection_AcrossAReexchange()
    {
        RealServer.SkipUnlessItRunsCommands();
        await using var client = await ConnectAsync();
        if (client is null)
        {
            return;
        }

        const int bytes = 2_000_000;
        var first = await client.RunCommandAsync($"head -c {bytes} /dev/zero | base64", Timeout());
        await AssertBase64OfZerosAsync(first, bytes);

        // The counters count what the application sent and received, uncompressed: at least the output itself.
        await Assert.That(client.BytesReceived).IsGreaterThan((long)first.StandardOutput.Length);

        // A re-exchange in the middle of the connection: both sides start new zlib streams with the new keys.
        var exchanges = client.Connection.KeyExchangeCount;
        await client.RekeyAsync(Timeout());
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThan(exchanges);

        // Input the other way (compressed where SshSharp compresses), echoed back. OpenSSH for Windows deadlocks when a command's
        // output backs up while its input is being closed (#86, see SessionInteropTests): its log shows rcvd eof, obuf empty and
        // chan_shutdown_write, and then nothing, with or without compression. So against Windows the server hashes the input instead,
        // which still proves every byte arrived, with only one line back through sshd's stdout pipe.
        var input = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compressible line of text\n", 20_000)));
        if (RealServer.IsWindows)
        {
            var hashed = await client.RunCommandAsync("sha256sum", null, SshCommandInput.FromBytes(input), Timeout());
            await Assert.That(hashed.ExitStatus).IsEqualTo(0);
            await Assert.That(hashed.StandardOutputText.Split(' ')[0])
                .IsEqualTo(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input)).ToLowerInvariant());
        }
        else
        {
            var echoed = await client.RunCommandAsync("cat", null, SshCommandInput.FromBytes(input), Timeout());
            await Assert.That(echoed.ExitStatus).IsEqualTo(0);
            await Assert.That(echoed.StandardOutput.Span.SequenceEqual(input)).IsTrue();
        }

        var after = await client.RunCommandAsync("echo still-here", Timeout());
        await Assert.That(after.StandardOutputText).IsEqualTo("still-here\n");
    }

    [Test]
    public async Task ManyReexchangesWhileCompressedOutputStreamsIn()
    {
        RealServer.SkipUnlessItRunsCommands();

        // The client re-keys every 100 KB (counted uncompressed), and sshd in CI every 32 KiB as well: new zlib streams in both
        // directions, again and again, in the middle of the output. As in RekeyInteropTests, how many exchanges complete depends on
        // timing; at least one per threshold plus channel window of output (about 5.4 MB here at 100 KB + 2 MiB a round) always does.
        await using var client = await ConnectAsync(rekeyAfterBytes: 100_000);
        if (client is null)
        {
            return;
        }

        const int bytes = 6_000_000;
        var result = await client.RunCommandAsync($"head -c {bytes} /dev/zero | base64", Timeout());
        await AssertBase64OfZerosAsync(result, bytes);
        await Assert.That(client.Connection.KeyExchangeCount).IsGreaterThanOrEqualTo(3);
        await Assert.That(client.Algorithms.CompressionServerToClient).IsEqualTo(SshAlgorithms.CompressionZlibOpenSsh);

        var after = await client.RunCommandAsync("echo still-here", Timeout());
        await Assert.That(after.StandardOutputText).IsEqualTo("still-here\n");
    }

    [Test]
    public async Task AnSftpFile_RoundTripsOverACompressedConnection()
    {
        if (!RealServer.HasSftp)
        {
            Skip.Test("The Dropbear test image has no sftp-server.");
            return;
        }

        await using var client = await ConnectAsync();
        if (client is null)
        {
            return;
        }

        await using var sftp = await client.OpenSftpAsync(Timeout());
        var remote = RealServer.SftpPath(".sshsharp-compressed-" + Guid.NewGuid().ToString("N")[..12]);
        var content = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 60_000).Select(i => $"line {i % 977} of a log file\n")));
        try
        {
            await sftp.WriteAllBytesAsync(remote, content, Timeout());
            var back = await sftp.ReadAllBytesAsync(remote, Timeout());
            await Assert.That(back.AsSpan().SequenceEqual(content)).IsTrue();
        }
        finally
        {
            await sftp.DeleteFileAsync(remote, Timeout());
        }
    }
}
