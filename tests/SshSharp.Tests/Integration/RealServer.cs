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
    public static async Task<SshClientOptions?> OptionsAsync(
        SshHostKeyVerifier? verifier = null, TimeSpan? keepAlive = null, int keepAliveCountMax = 3, long? rekeyAfterBytes = null)
    {
        if (!HasAccount)
        {
            return null;
        }

        var key = KeyFile is { } keyFile && File.Exists(keyFile) ? await SshPrivateKey.LoadFileAsync(keyFile) : null;
        return new SshClientOptions
        {
            UserName = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER")!,
            Password = Password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = verifier ?? SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            KeepAliveInterval = keepAlive,
            KeepAliveCountMax = keepAliveCountMax,
            RekeyAfterBytes = rekeyAfterBytes ?? 1L << 30, // SshClientOptions' default
        };
    }

    /// <summary>Whether a server and a test account (a password, or the ed25519 key in SSHSHARP_TEST_KEYDIR) are configured.</summary>
    public static bool HasAccount =>
        Endpoint is not null
        && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER"))
        && (Password is not null || KeyFile is not null);

    /// <summary>The test account's password (SSHSHARP_TEST_PASSWORD), or null when the server takes only keys.</summary>
    public static string? Password => Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD") is { Length: > 0 } password ? password : null;

    private static string? KeyFile => Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;

    /// <summary>The server software (SSHSHARP_TEST_SERVER, default OpenSSH), for expectations that differ, such as Dropbear's.</summary>
    public static string Software => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER") is { Length: > 0 } name ? name : "OpenSSH";

    public static bool IsOpenSsh => Software == "OpenSSH";

    /// <summary>Whether the server is the CI matrix's AsyncSSH container (tests/docker/asyncssh_server.py).</summary>
    public static bool IsAsyncSsh => Software == "AsyncSSH";

    /// <summary>
    /// Whether the server is the CI matrix's Apache MINA SSHD container (tests/docker/MinaServer.java), which identifies itself as
    /// APACHE-SSHD. It runs shells and commands as plain processes: no pseudo-terminal, and a killed process ends with an exit status.
    /// </summary>
    public static bool IsMina => Software == "APACHE-SSHD";

    /// <summary>
    /// Whether the server is the CI job's Erlang/OTP ssh container (tests/docker/erlang_server.escript): transport, authentication and
    /// SFTP only, no shells or commands.
    /// </summary>
    public static bool IsErlang => Software == "Erlang";

    /// <summary>Skips a test that needs to run a command, against a server that runs none (the Erlang/OTP container).</summary>
    public static void SkipUnlessItRunsCommands()
    {
        if (IsErlang)
        {
            Skip.Test("The server runs no commands (Erlang/OTP's ssh, with shells and commands turned off).");
        }
    }

    /// <summary>
    /// Whether the server has an sftp subsystem: every one tested, and Dropbear when its image has OpenSSH's sftp-server where Dropbear
    /// runs it (SSHSHARP_TEST_DROPBEAR_SFTP=1, set by CI after checking).
    /// </summary>
    public static bool HasSftp => !Software.Equals("dropbear", StringComparison.OrdinalIgnoreCase)
        || Environment.GetEnvironmentVariable("SSHSHARP_TEST_DROPBEAR_SFTP") == "1";

    /// <summary>Whether the server offers only SFTP (no shell or commands), as atmoz/sftp and the pkg/sftp test server do.</summary>
    public static bool SftpOnly => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SFTP_ONLY") == "1";

    /// <summary>
    /// Where the SFTP tests may create files (SSHSHARP_TEST_SFTP_DIR), relative to the login directory: chrooted servers such as
    /// atmoz/sftp allow writing only below it. Empty: the login directory itself.
    /// </summary>
    public static string SftpPath(string name) =>
        Environment.GetEnvironmentVariable("SSHSHARP_TEST_SFTP_DIR") is { Length: > 0 } dir ? dir.TrimEnd('/') + "/" + name : name;

    /// <summary>Whether the server runs on Windows (SSHSHARP_TEST_SERVER_OS=windows): no signals, and a pseudo-terminal through ConPTY.</summary>
    public static bool IsWindows => string.Equals(Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER_OS"), "windows", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the server is an MSYS2 or Cygwin sshd on Windows (SSHSHARP_TEST_SERVER_OS=msys or cygwin), as on a developer's machine:
    /// creating a link may need a privilege it lacks, a link may be made as a copy (winsymlinks), and NTFS keeps the group and other
    /// permission bits. Not inferred from this machine being Windows: a Linux server reached from Windows (WSL, a container) has none
    /// of these, and allowing them there hid an interop bug.
    /// </summary>
    public static bool IsMsys => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER_OS") is { } os
        && (os.Equals("msys", StringComparison.OrdinalIgnoreCase) || os.Equals("cygwin", StringComparison.OrdinalIgnoreCase));

    /// <summary>Whether the server supports strict KEX (OpenSSH 9.6+, Dropbear 2024.84+); SSHSHARP_TEST_SERVER_STRICTKEX=0 for older ones.</summary>
    public static bool SupportsStrictKex => Environment.GetEnvironmentVariable("SSHSHARP_TEST_SERVER_STRICTKEX") != "0";
}