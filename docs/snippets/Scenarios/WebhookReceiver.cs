using System.Security.Cryptography;
using System.Text;
using SshSharp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/webhook-receiver.md.</summary>
internal static class WebhookReceiver
{
    // <receiver>
    /// <summary>
    /// Receives webhook POSTs that arrive at a port on a public server, in this process: one request per connection, size-limited,
    /// signature-checked, then queued for the application.
    /// </summary>
    public sealed class Receiver(byte[] signingKey, Func<byte[], CancellationToken, ValueTask> enqueue)
    {
        private const int MaxHeaderBytes = 16 * 1024;
        private const int MaxBodyBytes = 1024 * 1024;

        public async Task HandleAsync(SshForwardedConnection connection, CancellationToken cancellationToken)
        {
            // Anyone who reaches the server's port can connect: bound the time and the size of everything read.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var stream = connection.Stream;

            var headers = await ReadHeadersAsync(stream, timeout.Token);
            if (headers is null
                || !headers.TryGetValue("content-length", out var lengthText)
                || !int.TryParse(lengthText, out var length) || length is < 0 or > MaxBodyBytes
                || !headers.TryGetValue("x-signature-sha256", out var signature))
            {
                await RespondAsync(stream, "400 Bad Request", timeout.Token);
                return;
            }

            var body = new byte[length];
            await stream.ReadExactlyAsync(body, timeout.Token);
            if (!IsSignedWith(signingKey, body, signature))
            {
                await RespondAsync(stream, "401 Unauthorized", timeout.Token);
                return;
            }

            await enqueue(body, timeout.Token);
            await RespondAsync(stream, "204 No Content", timeout.Token);
        }   // the stream is disposed when the handler returns, which closes the connection

        /// <summary>The request line and headers (names in lower case), or null when they are too long or malformed.</summary>
        private static async Task<Dictionary<string, string>?> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            // Byte by byte, so nothing of the body is read past the blank line; a real receiver would buffer.
            var header = new List<byte>();
            var one = new byte[1];
            while (!header.EndsWith("\r\n\r\n"u8))
            {
                if (header.Count >= MaxHeaderBytes || await stream.ReadAsync(one, cancellationToken) == 0)
                {
                    return null;
                }

                header.Add(one[0]);
            }

            var lines = Encoding.ASCII.GetString([.. header]).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0 || !lines[0].StartsWith("POST ", StringComparison.Ordinal))
            {
                return null;
            }

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var line in lines.Skip(1))
            {
                var colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon > 0)
                {
                    result[line[..colon].Trim().ToLowerInvariant()] = line[(colon + 1)..].Trim();
                }
            }

            return result;
        }

        private static bool IsSignedWith(byte[] key, byte[] body, string signatureHex)
        {
            var expected = HMACSHA256.HashData(key, body);
            try
            {
                return CryptographicOperations.FixedTimeEquals(expected, Convert.FromHexString(signatureHex));
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static async Task RespondAsync(Stream stream, string status, CancellationToken cancellationToken) =>
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), cancellationToken);
    }
    // </receiver>

    private static bool EndsWith(this List<byte> bytes, ReadOnlySpan<byte> suffix) =>
        bytes.Count >= suffix.Length && System.Runtime.InteropServices.CollectionsMarshal.AsSpan(bytes)[^suffix.Length..].SequenceEqual(suffix);

    public static async Task RunAsync(CancellationToken cancellationToken)
    {
        // <run>
        // The key the webhook sender signs with, from the environment or a secret store.
        var signingKey = Convert.FromHexString(Environment.GetEnvironmentVariable("WEBHOOK_SIGNING_KEY")
            ?? throw new InvalidOperationException("WEBHOOK_SIGNING_KEY is not set."));
        var queue = System.Threading.Channels.Channel.CreateBounded<byte[]>(1000);
        var receiver = new Receiver(signingKey, (body, ct) => queue.Writer.WriteAsync(body, ct));

        // "relay" is the public server's alias in ~/.ssh/config. Its reverse proxy (TLS) passes /hooks to its own localhost:9000.
        await using var relay = await SshClient.ConnectAsync("relay", cancellationToken: cancellationToken);
        await using var forwarding = await relay.ForwardRemotePortAsync("localhost", 9000, receiver.HandleAsync,
            maxConnections: 50, cancellationToken);

        await foreach (var body in queue.Reader.ReadAllAsync(cancellationToken))
        {
            Console.WriteLine($"Webhook received: {body.Length} bytes");
        }
        // </run>
    }
}
