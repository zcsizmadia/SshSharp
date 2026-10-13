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

    /// <summary>
    /// Client options for the test account (SSHSHARP_TEST_USER with SSHSHARP_TEST_PASSWORD or the ed25519 key in SSHSHARP_TEST_KEYDIR),
    /// or null when no server or account is configured.
    /// </summary>
    public static async Task<SshClientOptions?> OptionsAsync(SshHostKeyVerifier? verifier = null, TimeSpan? keepAlive = null)
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (Endpoint is null || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadFileAsync(keyFile) : null;
        return new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = verifier ?? SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KeepAliveInterval = keepAlive,
            KeepAliveCountMax = 3,
        };
    }

    /// <summary>The server software (SSHSHARP_TEST_SERVER, default OpenSSH), for expectations that differ, such as Dropbear's.</summary>
    public static string Software => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER") is { Length: > 0 } name ? name : "OpenSSH";

    public static bool IsOpenSsh => Software == "OpenSSH";

    /// <summary>Whether the server supports strict KEX (OpenSSH 9.6+, Dropbear 2024.84+); SSHSHARP_TEST_SERVER_STRICTKEX=0 for older ones.</summary>
    public static bool SupportsStrictKex => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER_STRICTKEX") != "0";
}