using System.Net.Sockets;

namespace SshSharp.Tests.Integration;

/// <summary>
/// Locates a real OpenSSH server for interop tests: set SSHSHARP_TEST_SSHD to host:port (for example 127.0.0.1:22222).
/// The tests skip when it is not set, so they never fail on machines without a server. CI starts sshd and sets it.
/// </summary>
internal static class RealServer
{
    public static (string Host, int Port)? Endpoint
    {
        get
        {
            var value = Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD");
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var colon = value.LastIndexOf(':');
            return (value[..colon], int.Parse(value[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture));
        }
    }

    public static async Task<Stream> ConnectAsync()
    {
        var (host, port) = Endpoint ?? throw new InvalidOperationException("SSHSHARP_TEST_SSHD is not set.");
        var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(host, port);
        return client.GetStream();
    }

    public static bool IsAvailable => Endpoint is not null;
}