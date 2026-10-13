using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using SshSharp.Config;
using SshSharp.Scp;
using SshNet = Renci.SshNet;

namespace SshSharp.Benchmarks;

/// <summary>
/// SshSharp against SSH.NET on the same server, with the same algorithms forced on both (curve25519-sha256, aes256-gcm@openssh.com,
/// ssh-ed25519): connect, small-command latency, a download, an SCP upload and parallel commands. Point it at a server with
/// SSHSHARP_BENCH_SSHD (host:port), SSHSHARP_BENCH_USER and SSHSHARP_BENCH_PASSWORD (or the SSHSHARP_TEST_* ones, as set by
/// scripts/test-server.ps1). See docs/benchmarks.md for the setup and the results.
/// </summary>
[MemoryDiagnoser]
[ThreadingDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "BenchmarkDotNet disposes through GlobalCleanup.")]
public class ComparisonBenchmarks
{
    /// <summary>The download and upload size: 32 MiB.</summary>
    public const int TransferBytes = 32 * 1024 * 1024;

    private readonly byte[] _payload = new byte[TransferBytes];
    private SshClient _sshSharp = null!;
    private SshNet.SshClient _sshNet = null!;
    private SshNet.ScpClient _sshNetScp = null!;

    /// <summary>A private key to authenticate with instead of the password (SSHSHARP_BENCH_KEY, a file in OpenSSH format).</summary>
    internal static string? KeyFile => Environment.GetEnvironmentVariable("SSHSHARP_BENCH_KEY");

    internal static (string Host, int Port, string User, string Password) Server
    {
        get
        {
            static string? Get(string name) =>
                Environment.GetEnvironmentVariable("SSHSHARP_BENCH_" + name) ?? Environment.GetEnvironmentVariable("SSHSHARP_TEST_" + name);
            var endpoint = Get("SSHD") ?? throw new InvalidOperationException("Set SSHSHARP_BENCH_SSHD (host:port), SSHSHARP_BENCH_USER and SSHSHARP_BENCH_PASSWORD.");
            var colon = endpoint.LastIndexOf(':');
            return (endpoint[..colon], int.Parse(endpoint[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture),
                Get("USER") ?? throw new InvalidOperationException("Set SSHSHARP_BENCH_USER."),
                Get("PASSWORD") ?? (KeyFile is not null ? string.Empty : throw new InvalidOperationException("Set SSHSHARP_BENCH_PASSWORD or SSHSHARP_BENCH_KEY.")));
        }
    }

    /// <summary>SshSharp, through its public ssh_config route to force the algorithms.</summary>
    internal static Task<SshClient> ConnectSshSharpAsync(Microsoft.Extensions.Logging.ILogger? logger = null)
    {
        var (host, port, user, password) = Server;
        var config = $"Host bench\n HostName {host}\n Port {port}\n User {user}\n KexAlgorithms curve25519-sha256\n"
            + " Ciphers aes256-gcm@openssh.com\n HostKeyAlgorithms ssh-ed25519\n StrictHostKeyChecking no\n UserKnownHostsFile none\n"
            // Without a key, no default identity files are loaded (the account running the benchmark may have some); SSH.NET loads none either.
            // One method, as SSH.NET is given: ssh's default order would try keyboard-interactive first, and sshd delays every failure.
            + (KeyFile is null ? " PubkeyAuthentication no\n PreferredAuthentications password\n" : " PreferredAuthentications publickey\n");
        if (KeyFile is not null)
        {
            config += $" IdentityFile \"{KeyFile}\"\n IdentitiesOnly yes\n";
        }

        return SshClient.ConnectAsync("bench", new SshConfigConnectOptions { Config = SshConfig.Parse(config), Password = password.Length > 0 ? password : null, UseAgent = false, Logger = logger });
    }

    /// <summary>SSH.NET with the same algorithms: everything else removed from its tables.</summary>
    internal static SshNet.ConnectionInfo SshNetConnection()
    {
        var (host, port, user, password) = Server;
        SshNet.AuthenticationMethod method = KeyFile is not null
            ? new SshNet.PrivateKeyAuthenticationMethod(user, new SshNet.PrivateKeyFile(KeyFile))
            : new SshNet.PasswordAuthenticationMethod(user, password);
        var info = new SshNet.ConnectionInfo(host, port, user, method);
        Keep(info.KeyExchangeAlgorithms, "curve25519-sha256");
        Keep(info.Encryptions, "aes256-gcm@openssh.com");
        Keep(info.HostKeyAlgorithms, "ssh-ed25519");
        return info;

        static void Keep<T>(IDictionary<string, T> table, string name)
        {
            foreach (var key in table.Keys.Where(k => k != name).ToList())
            {
                table.Remove(key);
            }
        }
    }

    internal static async Task<SshNet.SshClient> ConnectSshNetAsync()
    {
        var client = new SshNet.SshClient(SshNetConnection());
        await client.ConnectAsync(CancellationToken.None);
        return client;
    }

    [GlobalSetup]
    public async Task SetUp()
    {
        _sshSharp = await ConnectSshSharpAsync();
        _sshNet = await ConnectSshNetAsync();
        _sshNetScp = new SshNet.ScpClient(SshNetConnection(), SshNet.RemotePathTransformation.ShellQuote); // quoted, as SshSharp does
        _sshNetScp.Connect();
        Random.Shared.NextBytes(_payload);
    }

    [GlobalCleanup]
    public async Task CleanUp()
    {
        await _sshSharp.RunCommandAsync("rm -f /tmp/sshsharp-bench-*");
        await _sshSharp.DisposeAsync();
        _sshNet.Dispose();
        _sshNetScp.Dispose();
    }

    // ---- connect and authenticate ----

    [Benchmark(Baseline = true), BenchmarkCategory("Connect")]
    public async Task Connect_SshNet()
    {
        using var client = await ConnectSshNetAsync();
    }

    [Benchmark, BenchmarkCategory("Connect")]
    public async Task Connect_SshSharp()
    {
        await using var client = await ConnectSshSharpAsync();
    }

    // ---- a small command on an open connection ----

    [Benchmark(Baseline = true), BenchmarkCategory("Command")]
    public async Task<string> Command_SshNet()
    {
        using var command = _sshNet.CreateCommand("echo hi");
        await command.ExecuteAsync();
        return command.Result;
    }

    [Benchmark, BenchmarkCategory("Command")]
    public async Task<string> Command_SshSharp() => (await _sshSharp.RunCommandAsync("echo hi")).StandardOutputText;

    // ---- 32 MiB of command output, streamed ----

    [Benchmark(Baseline = true), BenchmarkCategory("Download32MiB")]
    public async Task<long> Download_SshNet()
    {
        using var command = _sshNet.CreateCommand($"dd if=/dev/zero bs=1048576 count={TransferBytes / 1048576} 2>/dev/null");
        var run = command.ExecuteAsync();
        var counted = await CountAsync(command.OutputStream);
        await run;
        return Check(counted);
    }

    [Benchmark, BenchmarkCategory("Download32MiB")]
    public async Task<long> Download_SshSharp()
    {
        await using var session = await _sshSharp.StartCommandAsync($"dd if=/dev/zero bs=1048576 count={TransferBytes / 1048576} 2>/dev/null");
        var counted = await CountAsync(session.StandardOutput);
        await session.WaitForExitAsync();
        return Check(counted);
    }

    // ---- 32 MiB uploaded with SCP ----

    [Benchmark(Baseline = true), BenchmarkCategory("ScpUpload32MiB")]
    public void ScpUpload_SshNet() => _sshNetScp.Upload(new MemoryStream(_payload), "/tmp/sshsharp-bench-sshnet.bin");

    [Benchmark, BenchmarkCategory("ScpUpload32MiB")]
    public Task ScpUpload_SshSharp() => _sshSharp.UploadAsync(new MemoryStream(_payload), "/tmp/sshsharp-bench-sshsharp.bin");

    // ---- eight commands at once on one connection ----

    [Benchmark(Baseline = true), BenchmarkCategory("Parallel8")]
    public Task Parallel_SshNet() => Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
    {
        using var command = _sshNet.CreateCommand("echo hi");
        await command.ExecuteAsync();
    }));

    [Benchmark, BenchmarkCategory("Parallel8")]
    public Task Parallel_SshSharp() => Task.WhenAll(Enumerable.Range(0, 8).Select(_ => _sshSharp.RunCommandAsync("echo hi")));

    internal static async Task<long> CountAsync(Stream stream)
    {
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (await stream.ReadAsync(buffer) is var read and > 0)
        {
            total += read;
        }

        return total;
    }

    private static long Check(long counted) =>
        counted == TransferBytes ? counted : throw new InvalidOperationException($"Read {counted} bytes, expected {TransferBytes}.");
}
